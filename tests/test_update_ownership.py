from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from openfetch.core import update_ownership as ownership_module
from openfetch.core.update_ownership import (
    OWNERSHIP_SCHEMA_VERSION,
    OwnershipRecord,
    OwnershipRole,
    TransactionState,
    UpdateOwnershipManager,
    new_transaction_id,
    normalized_target_identity,
)
from openfetch.core.updater import UpdateError

TRANSACTION_A = "A" * 48
TRANSACTION_B = "B" * 48
CURRENT_IDENTITY = "1" * 64
PARENT_A_IDENTITY = "2" * 64
PARENT_B_IDENTITY = "3" * 64
OTHER_HELPER_IDENTITY = "4" * 64
REUSED_PROCESS_IDENTITY = "5" * 64

PARENT_A_PID = 41_001
PARENT_B_PID = 41_002
OTHER_HELPER_PID = 41_003
STALE_PID = 41_004
REUSED_PID = 41_005


class IdentityRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._identities: dict[int, str] = {
            os.getpid(): CURRENT_IDENTITY,
            PARENT_A_PID: PARENT_A_IDENTITY,
            PARENT_B_PID: PARENT_B_IDENTITY,
            OTHER_HELPER_PID: OTHER_HELPER_IDENTITY,
        }

    def __call__(self, pid: int) -> str | None:
        with self._lock:
            return self._identities.get(pid)

    def set(self, pid: int, identity: str | None) -> None:
        with self._lock:
            if identity is None:
                self._identities.pop(pid, None)
            else:
                self._identities[pid] = identity


@pytest.fixture
def identities() -> IdentityRegistry:
    return IdentityRegistry()


@pytest.fixture
def logs() -> list[str]:
    return []


@pytest.fixture
def manager(
    tmp_path: Path,
    identities: IdentityRegistry,
    logs: list[str],
) -> UpdateOwnershipManager:
    return UpdateOwnershipManager(
        tmp_path / "updates",
        identity_provider=identities,
        log_callback=logs.append,
    )


@pytest.fixture
def target_a(tmp_path: Path) -> Path:
    target = tmp_path / "install-a" / "OpenFetch.exe"
    target.parent.mkdir()
    target.write_bytes(b"installed-a")
    return target


@pytest.fixture
def target_b(tmp_path: Path) -> Path:
    target = tmp_path / "install-b" / "OpenFetch.exe"
    target.parent.mkdir()
    target.write_bytes(b"installed-b")
    return target


def timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def write_record(
    manager: UpdateOwnershipManager,
    target: Path,
    *,
    transaction_id: str = TRANSACTION_A,
    owner_pid: int = OTHER_HELPER_PID,
    owner_identity: str = OTHER_HELPER_IDENTITY,
    role: OwnershipRole = OwnershipRole.INSTALLATION,
    state: TransactionState = TransactionState.WAITING_FOR_PARENT_EXIT,
) -> OwnershipRecord:
    now = timestamp()
    record = OwnershipRecord(
        schema_version=OWNERSHIP_SCHEMA_VERSION,
        transaction_id=transaction_id,
        target_identity=normalized_target_identity(target),
        target_name=target.name,
        owner_pid=owner_pid,
        owner_process_created=owner_identity,
        role=role.value,
        state=state.value,
        created_at=now,
        heartbeat_at=now,
    )
    path = manager.path_for_target(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record.to_dict()), encoding="utf-8")
    return record


def reserve(
    manager: UpdateOwnershipManager,
    target: Path,
    transaction_id: str = TRANSACTION_A,
    *,
    parent_pid: int = PARENT_A_PID,
    parent_identity: str = PARENT_A_IDENTITY,
) -> OwnershipRecord:
    return manager.reserve_handoff(
        transaction_id,
        target,
        parent_pid=parent_pid,
        parent_process_created=parent_identity,
    )


def assert_update_error(exc_info: pytest.ExceptionInfo[UpdateError], code: str) -> None:
    assert exc_info.value.code == code


def test_new_transaction_ids_are_random_and_valid() -> None:
    first = new_transaction_id()
    second = new_transaction_id()

    assert first != second
    assert 32 <= len(first) <= 128
    assert OwnershipRecord.from_dict(
        {
            "schema_version": OWNERSHIP_SCHEMA_VERSION,
            "transaction_id": first,
            "target_identity": "a" * 64,
            "target_name": "OpenFetch.exe",
            "owner_pid": 1,
            "owner_process_created": "b" * 64,
            "role": OwnershipRole.HANDOFF.value,
            "state": TransactionState.HANDOFF_PENDING.value,
            "created_at": timestamp(),
            "heartbeat_at": timestamp(),
        }
    ).transaction_id == first


def test_normalized_target_identity_collapses_equivalent_paths(target_a: Path) -> None:
    alternate = target_a.parent / "unused" / ".." / target_a.name

    assert normalized_target_identity(alternate) == normalized_target_identity(target_a)
    if os.name == "nt":
        assert normalized_target_identity(Path(str(target_a).upper())) == normalized_target_identity(
            target_a
        )


def test_ownership_paths_are_scoped_to_normalized_target(
    manager: UpdateOwnershipManager,
    target_a: Path,
    target_b: Path,
) -> None:
    first_path = manager.path_for_target(target_a)
    equivalent_path = manager.path_for_target(target_a.parent / "." / target_a.name)
    second_path = manager.path_for_target(target_b)

    assert first_path == equivalent_path
    assert first_path != second_path
    assert first_path.parent == second_path.parent == manager.directory


def test_same_transaction_gui_to_helper_handoff_succeeds(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    handoff = reserve(manager, target_a)

    claimed = manager.assume_installation(
        TRANSACTION_A,
        target_a,
        parent_pid=PARENT_A_PID,
        parent_process_created=PARENT_A_IDENTITY,
    )

    assert handoff.role == OwnershipRole.HANDOFF.value
    assert handoff.state == TransactionState.HANDOFF_PENDING.value
    assert claimed.transaction_id == TRANSACTION_A
    assert claimed.target_identity == handoff.target_identity
    assert claimed.created_at == handoff.created_at
    assert claimed.owner_pid == os.getpid()
    assert claimed.owner_process_created == CURRENT_IDENTITY
    assert claimed.role == OwnershipRole.INSTALLATION.value
    assert claimed.state == TransactionState.WAITING_FOR_PARENT_EXIT.value
    assert manager.read(target_a) == claimed


def test_live_different_transaction_for_same_target_is_rejected(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    reserve(manager, target_a)

    with pytest.raises(UpdateError) as exc_info:
        reserve(
            manager,
            target_a,
            TRANSACTION_B,
            parent_pid=PARENT_B_PID,
            parent_identity=PARENT_B_IDENTITY,
        )

    assert_update_error(exc_info, "concurrent_update")
    assert manager.read(target_a).transaction_id == TRANSACTION_A  # type: ignore[union-attr]


def test_live_different_transaction_cannot_assume_installation(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    reserve(manager, target_a)

    with pytest.raises(UpdateError) as exc_info:
        manager.assume_installation(
            TRANSACTION_B,
            target_a,
            parent_pid=PARENT_B_PID,
            parent_process_created=PARENT_B_IDENTITY,
        )

    assert_update_error(exc_info, "concurrent_update")
    assert manager.read(target_a).transaction_id == TRANSACTION_A  # type: ignore[union-attr]


def test_different_target_installations_do_not_block_each_other(
    manager: UpdateOwnershipManager,
    target_a: Path,
    target_b: Path,
) -> None:
    first = reserve(manager, target_a, TRANSACTION_A)
    second = reserve(
        manager,
        target_b,
        TRANSACTION_B,
        parent_pid=PARENT_B_PID,
        parent_identity=PARENT_B_IDENTITY,
    )

    assert first.target_identity != second.target_identity
    assert manager.read(target_a) == first
    assert manager.read(target_b) == second


def test_duplicate_live_helper_for_same_transaction_is_rejected(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    original = write_record(manager, target_a)

    with pytest.raises(UpdateError) as exc_info:
        manager.assume_installation(
            TRANSACTION_A,
            target_a,
            parent_pid=PARENT_A_PID,
            parent_process_created=PARENT_A_IDENTITY,
        )

    assert_update_error(exc_info, "duplicate_helper")
    assert manager.read(target_a) == original


def test_repeated_claim_by_exact_same_helper_is_idempotent(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    original = write_record(
        manager,
        target_a,
        owner_pid=os.getpid(),
        owner_identity=CURRENT_IDENTITY,
    )

    claimed = manager.assume_installation(
        TRANSACTION_A,
        target_a,
        parent_pid=PARENT_A_PID,
        parent_process_created=PARENT_A_IDENTITY,
    )

    assert claimed == original
    assert manager.read(target_a) == original


def test_exited_owner_is_recovered_without_reboot(
    manager: UpdateOwnershipManager,
    target_a: Path,
    logs: list[str],
) -> None:
    write_record(
        manager,
        target_a,
        owner_pid=STALE_PID,
        owner_identity="6" * 64,
    )

    events = manager.recover_stale()

    assert len(events) == 1
    assert events[0].transaction_id == TRANSACTION_A
    assert "owner exited" in events[0].reason
    assert manager.read(target_a) is None
    assert any("exited process" in message for message in logs)


def test_reused_pid_creation_identity_is_recovered_as_stale(
    manager: UpdateOwnershipManager,
    target_a: Path,
    identities: IdentityRegistry,
) -> None:
    identities.set(REUSED_PID, REUSED_PROCESS_IDENTITY)
    write_record(
        manager,
        target_a,
        owner_pid=REUSED_PID,
        owner_identity="7" * 64,
    )

    events = manager.recover_stale()

    assert len(events) == 1
    assert "process creation identity changed" in events[0].reason
    assert manager.read(target_a) is None


@pytest.mark.parametrize(
    "malformation",
    ["missing_identity", "invalid_identity", "malformed_pid", "missing_pid", "invalid_json"],
)
def test_malformed_or_missing_ownership_identity_is_recovered(
    manager: UpdateOwnershipManager,
    target_a: Path,
    malformation: str,
) -> None:
    record = write_record(manager, target_a)
    path = manager.path_for_target(target_a)
    payload = record.to_dict()
    if malformation == "missing_identity":
        payload.pop("owner_process_created")
    elif malformation == "invalid_identity":
        payload["owner_process_created"] = "not-an-identity"
    elif malformation == "malformed_pid":
        payload["owner_pid"] = "41003"
    elif malformation == "missing_pid":
        payload.pop("owner_pid")
    else:
        path.write_text("{not-json", encoding="utf-8")
    if malformation != "invalid_json":
        path.write_text(json.dumps(payload), encoding="utf-8")

    events = manager.recover_stale()

    assert len(events) == 1
    assert events[0].transaction_id == "unknown"
    assert events[0].reason == "invalid ownership record"
    assert manager.read(target_a) is None
    assert not path.exists()


@pytest.mark.parametrize("parent_identity", ["", "not-hex", "8" * 64])
def test_reservation_rejects_missing_or_mismatched_parent_identity(
    manager: UpdateOwnershipManager,
    target_a: Path,
    parent_identity: str,
) -> None:
    with pytest.raises(UpdateError) as exc_info:
        reserve(manager, target_a, parent_identity=parent_identity)

    assert_update_error(exc_info, "process_identity_mismatch")
    assert manager.read(target_a) is None


def test_live_matching_process_identity_is_preserved(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    live = write_record(manager, target_a)

    assert manager.recover_stale() == []
    assert manager.read(target_a) == live
    assert manager.path_for_target(target_a).exists()


@pytest.mark.parametrize("identity_error", [PermissionError, OSError])
@pytest.mark.parametrize("operation", ["reserve", "assume", "claim"])
def test_unavailable_owner_identity_is_not_reported_as_concurrent_or_replaced(
    manager: UpdateOwnershipManager,
    target_a: Path,
    identities: IdentityRegistry,
    identity_error: type[OSError],
    operation: str,
) -> None:
    original = write_record(manager, target_a)
    path = manager.path_for_target(target_a)
    original_bytes = path.read_bytes()

    def unreadable_owner(pid: int) -> str | None:
        if pid == original.owner_pid:
            raise identity_error("controlled identity query failure")
        return identities(pid)

    manager.identity_provider = unreadable_owner

    with pytest.raises(UpdateError) as exc_info:
        if operation == "reserve":
            reserve(
                manager,
                target_a,
                TRANSACTION_B,
                parent_pid=PARENT_B_PID,
                parent_identity=PARENT_B_IDENTITY,
            )
        elif operation == "assume":
            manager.assume_installation(
                TRANSACTION_B,
                target_a,
                parent_pid=PARENT_B_PID,
                parent_process_created=PARENT_B_IDENTITY,
            )
        else:
            manager.claim_recovery(
                TRANSACTION_B,
                target_a,
                TransactionState.REPLACING,
            )

    assert_update_error(exc_info, "process_identity_unavailable")
    assert exc_info.value.code != "concurrent_update"
    assert path.read_bytes() == original_bytes
    assert manager.read(target_a) == original


def test_unreadable_ownership_file_is_preserved_during_recovery(
    manager: UpdateOwnershipManager,
    target_a: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_record(manager, target_a)
    path = manager.path_for_target(target_a)
    original_bytes = path.read_bytes()
    real_read_json = ownership_module._read_json

    def unreadable_record(candidate: Path) -> dict[str, object]:
        if Path(candidate) == path:
            raise PermissionError("controlled ownership read failure")
        return real_read_json(candidate)

    monkeypatch.setattr(ownership_module, "_read_json", unreadable_record)

    events = manager.recover_stale()

    assert events == []
    assert path.exists()
    assert path.read_bytes() == original_bytes


def test_release_with_wrong_transaction_preserves_live_owner(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    live = write_record(manager, target_a)

    assert manager.release(TRANSACTION_B, target_a) is False
    assert manager.read(target_a) == live


def test_release_requires_exact_live_owner_even_for_same_transaction(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    live = write_record(manager, target_a)

    assert manager.release(TRANSACTION_A, target_a) is False
    assert manager.read(target_a) == live


def test_exact_owner_can_release_its_transaction(
    manager: UpdateOwnershipManager,
    target_a: Path,
) -> None:
    owned = write_record(
        manager,
        target_a,
        owner_pid=os.getpid(),
        owner_identity=CURRENT_IDENTITY,
    )

    assert manager.read(target_a) == owned
    assert manager.release(TRANSACTION_A, target_a) is True
    assert manager.read(target_a) is None


def test_persisted_ownership_record_contains_only_sanitized_fields(
    manager: UpdateOwnershipManager,
    tmp_path: Path,
) -> None:
    target = tmp_path / "do-not-persist-this-directory" / "OpenFetch.exe"
    target.parent.mkdir()
    target.write_bytes(b"installed")
    reserve(manager, target)

    path = manager.path_for_target(target)
    serialized = path.read_text(encoding="utf-8")
    payload = json.loads(serialized)

    assert set(payload) == {
        "schema_version",
        "transaction_id",
        "target_identity",
        "target_name",
        "owner_pid",
        "owner_process_created",
        "role",
        "state",
        "created_at",
        "heartbeat_at",
    }
    assert payload["target_name"] == target.name
    assert str(target.parent) not in serialized
    for forbidden in (
        "download_url",
        "cookie",
        "startup_token",
        "command",
        "environment",
        "https://",
    ):
        assert forbidden not in serialized.lower()
    assert not list(path.parent.glob("*.tmp"))
    assert not list(path.parent.glob("*.guard"))


def test_competing_atomic_reservations_have_exactly_one_winner(
    tmp_path: Path,
    target_a: Path,
    identities: IdentityRegistry,
) -> None:
    root = tmp_path / "atomic-updates"
    first_manager = UpdateOwnershipManager(root, identity_provider=identities)
    second_manager = UpdateOwnershipManager(root, identity_provider=identities)
    barrier = threading.Barrier(2)

    def attempt(
        ownership: UpdateOwnershipManager,
        transaction_id: str,
        parent_pid: int,
        parent_identity: str,
    ) -> tuple[str, str]:
        barrier.wait(timeout=5)
        try:
            record = ownership.reserve_handoff(
                transaction_id,
                target_a,
                parent_pid=parent_pid,
                parent_process_created=parent_identity,
            )
        except UpdateError as exc:
            return "error", exc.code
        return "success", record.transaction_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            attempt,
            first_manager,
            TRANSACTION_A,
            PARENT_A_PID,
            PARENT_A_IDENTITY,
        )
        second = executor.submit(
            attempt,
            second_manager,
            TRANSACTION_B,
            PARENT_B_PID,
            PARENT_B_IDENTITY,
        )
        results = [first.result(timeout=10), second.result(timeout=10)]

    assert sum(result[0] == "success" for result in results) == 1
    assert sum(result == ("error", "concurrent_update") for result in results) == 1
    winner = first_manager.read(target_a)
    assert winner is not None
    assert winner.transaction_id in {TRANSACTION_A, TRANSACTION_B}
    assert not list(first_manager.directory.glob("*.guard"))
