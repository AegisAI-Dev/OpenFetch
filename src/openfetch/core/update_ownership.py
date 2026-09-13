"""Target-scoped updater ownership with exact process-lifetime validation.

Updater ownership is deliberately separate from download staging.  A GUI may
reserve a handoff for one normalized installed executable, but only the Python
runtime inside the detached helper may assume installation ownership.  This is
important for PyInstaller one-file builds, where ``Popen.pid`` identifies the
outer bootloader and not necessarily the process executing Python code.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import re
import secrets
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from openfetch.core.process_control import process_creation_identity
from openfetch.core.updater import UpdateError

OWNERSHIP_SCHEMA_VERSION = 1
OWNERSHIP_DIRECTORY = "ownership"
LEGACY_INSTALL_LOCK_FILENAME = "install.lock"
MAX_OWNERSHIP_BYTES = 16 * 1024
GUARD_WAIT_SECONDS = 5.0
GUARD_POLL_SECONDS = 0.05

TRANSACTION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
IDENTITY_PATTERN = re.compile(r"^[a-f0-9]{64}$")
TARGET_IDENTITY_PATTERN = re.compile(r"^[a-f0-9]{64}$")

IdentityProvider = Callable[[int], str | None]
Sleep = Callable[[float], None]
Monotonic = Callable[[], float]
LogCallback = Callable[[str], None]


class TransactionState(str, Enum):
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    VERIFIED = "verified"
    HELPER_PREPARED = "helper_prepared"
    HANDOFF_PENDING = "handoff_pending"
    HANDED_OFF = "handed_off"
    WAITING_FOR_PARENT_EXIT = "waiting_for_parent_exit"
    BACKING_UP = "backing_up"
    REPLACING = "replacing"
    LAUNCHING = "launching"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    CONFIRMED = "confirmed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class OwnershipRole(str, Enum):
    HANDOFF = "handoff"
    INSTALLATION = "installation"
    STARTUP_CONFIRMATION = "startup_confirmation"


class _RecordReadState(str, Enum):
    ABSENT = "absent"
    VALID = "valid"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


class _OwnerLiveness(str, Enum):
    LIVE = "live"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class OwnershipRecord:
    schema_version: int
    transaction_id: str
    target_identity: str
    target_name: str
    owner_pid: int
    owner_process_created: str
    role: str
    state: str
    created_at: str
    heartbeat_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> OwnershipRecord:
        if not isinstance(payload, dict):
            raise ValueError("ownership record must be an object")
        expected = {
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
        if set(payload) != expected or payload.get("schema_version") != OWNERSHIP_SCHEMA_VERSION:
            raise ValueError("unsupported ownership record schema")

        transaction_id = payload.get("transaction_id")
        target_identity = payload.get("target_identity")
        target_name = payload.get("target_name")
        owner_pid = payload.get("owner_pid")
        owner_created = payload.get("owner_process_created")
        role = payload.get("role")
        state = payload.get("state")
        created_at = payload.get("created_at")
        heartbeat_at = payload.get("heartbeat_at")

        if not isinstance(transaction_id, str) or not TRANSACTION_ID_PATTERN.fullmatch(
            transaction_id
        ):
            raise ValueError("invalid transaction ID")
        if not isinstance(target_identity, str) or not TARGET_IDENTITY_PATTERN.fullmatch(
            target_identity
        ):
            raise ValueError("invalid target identity")
        if (
            not isinstance(target_name, str)
            or not target_name
            or len(target_name) > 160
            or target_name != Path(target_name).name
            or "\x00" in target_name
        ):
            raise ValueError("invalid target name")
        if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
            raise ValueError("invalid owner PID")
        if not isinstance(owner_created, str) or not IDENTITY_PATTERN.fullmatch(owner_created):
            raise ValueError("invalid owner process creation identity")
        if role not in {item.value for item in OwnershipRole}:
            raise ValueError("invalid ownership role")
        if state not in {item.value for item in TransactionState}:
            raise ValueError("invalid transaction state")
        _parse_timestamp(created_at, "creation")
        _parse_timestamp(heartbeat_at, "heartbeat")

        return cls(
            schema_version=OWNERSHIP_SCHEMA_VERSION,
            transaction_id=transaction_id,
            target_identity=target_identity,
            target_name=target_name,
            owner_pid=owner_pid,
            owner_process_created=owner_created,
            role=role,
            state=state,
            created_at=created_at,
            heartbeat_at=heartbeat_at,
        )


@dataclass(frozen=True, slots=True)
class RecoveryEvent:
    transaction_id: str
    target_identity: str
    reason: str


def new_transaction_id() -> str:
    return secrets.token_urlsafe(36)


def normalized_target_identity(target_executable: Path) -> str:
    normalized = os.path.normcase(os.path.realpath(os.fspath(Path(target_executable).resolve())))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _parse_timestamp(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"invalid {label} timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"invalid {label} timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"invalid {label} timestamp")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = value
    return result


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_OWNERSHIP_BYTES:
        raise ValueError("ownership record is too large")
    payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(payload, dict):
        raise ValueError("ownership record must be an object")
    return payload


class UpdateOwnershipManager:
    """Serialize ownership changes and validate exact owner process lifetimes."""

    def __init__(
        self,
        updates_root: Path,
        *,
        identity_provider: IdentityProvider = process_creation_identity,
        sleep: Sleep = time.sleep,
        monotonic: Monotonic = time.monotonic,
        log_callback: LogCallback | None = None,
    ) -> None:
        self.root = Path(updates_root).resolve()
        self.directory = self.root / OWNERSHIP_DIRECTORY
        self.directory.mkdir(parents=True, exist_ok=True)
        self.identity_provider = identity_provider
        self.sleep = sleep
        self.monotonic = monotonic
        self.log_callback = log_callback

    def path_for_target(self, target_executable: Path) -> Path:
        return self.directory / f"{normalized_target_identity(target_executable)}.json"

    def read(self, target_executable: Path) -> OwnershipRecord | None:
        path = self.path_for_target(target_executable)
        record, read_state = self._read_record_path(path)
        if read_state == _RecordReadState.UNAVAILABLE:
            raise UpdateError(
                "ownership_unavailable",
                "The updater ownership record could not be read safely.",
            )
        if read_state != _RecordReadState.VALID or record is None:
            return None
        if record.target_identity != normalized_target_identity(target_executable):
            return None
        return record

    def reserve_handoff(
        self,
        transaction_id: str,
        target_executable: Path,
        *,
        parent_pid: int,
        parent_process_created: str,
    ) -> OwnershipRecord:
        self._validate_identity(parent_pid, parent_process_created, "parent")
        legacy_status = self._legacy_lock_status()
        if legacy_status in {"active", "unknown"}:
            raise UpdateError(
                "legacy_ownership_unverifiable",
                "An earlier updater ownership record could not be proven stale.",
            )
        if legacy_status == "stale":
            self.recover_legacy_global_lock()
        target = Path(target_executable).resolve()
        target_identity = normalized_target_identity(target)
        with self._guard(target_identity):
            path = self.path_for_target(target)
            existing, read_state = self._read_record_path(path)
            if read_state == _RecordReadState.UNAVAILABLE:
                self._raise_ownership_unavailable()
            if read_state == _RecordReadState.INVALID:
                self._remove_stale(self.path_for_target(target), "invalid ownership record")
            elif existing is not None:
                liveness = self._owner_liveness(existing)
                self._raise_if_liveness_unavailable(liveness)
                if existing.transaction_id == transaction_id:
                    if (
                        existing.owner_pid == parent_pid
                        and existing.owner_process_created == parent_process_created
                        and liveness == _OwnerLiveness.LIVE
                        and existing.role == OwnershipRole.HANDOFF.value
                    ):
                        return existing
                    if liveness == _OwnerLiveness.LIVE:
                        raise UpdateError(
                            "handoff_validation_failed",
                            "The existing update handoff does not match this transaction.",
                        )
                    self._remove_stale(
                        self.path_for_target(target), "same transaction owner exited"
                    )
                elif liveness == _OwnerLiveness.LIVE:
                    raise UpdateError(
                        "concurrent_update",
                        "Another updater process is active for this installation.",
                    )
                else:
                    self._remove_stale(
                        self.path_for_target(target), "owner exited or PID was reused"
                    )

            timestamp = _now()
            record = OwnershipRecord(
                schema_version=OWNERSHIP_SCHEMA_VERSION,
                transaction_id=transaction_id,
                target_identity=target_identity,
                target_name=target.name,
                owner_pid=parent_pid,
                owner_process_created=parent_process_created,
                role=OwnershipRole.HANDOFF.value,
                state=TransactionState.HANDOFF_PENDING.value,
                created_at=timestamp,
                heartbeat_at=timestamp,
            )
            _atomic_write_json(self.path_for_target(target), record.to_dict())
            return record

    def assume_installation(
        self,
        transaction_id: str,
        target_executable: Path,
        *,
        parent_pid: int,
        parent_process_created: str,
    ) -> OwnershipRecord:
        target = Path(target_executable).resolve()
        target_identity = normalized_target_identity(target)
        helper_pid = os.getpid()
        helper_created = self._identity(helper_pid, "helper")
        path = self.path_for_target(target)

        with self._guard(target_identity):
            existing, read_state = self._read_record_path(path)
            if read_state == _RecordReadState.UNAVAILABLE:
                self._raise_ownership_unavailable()
            if read_state == _RecordReadState.INVALID:
                self._remove_stale(path, "invalid ownership record")
                raise UpdateError(
                    "helper_ownership_acquisition_failed",
                    "The detached updater could not validate the GUI handoff record.",
                )

            if existing is None:
                raise UpdateError(
                    "helper_ownership_acquisition_failed",
                    "The detached updater could not validate the GUI handoff record.",
                )

            if existing.transaction_id != transaction_id:
                liveness = self._owner_liveness(existing)
                self._raise_if_liveness_unavailable(liveness)
                if liveness == _OwnerLiveness.LIVE:
                    raise UpdateError(
                        "concurrent_update",
                        "Another updater process is active for this installation.",
                    )
                self._remove_stale(path, "different transaction owner exited or PID was reused")
                raise UpdateError(
                    "transaction_mismatch",
                    "The updater ownership transaction does not match.",
                )

            if existing.target_identity != target_identity:
                raise UpdateError(
                    "target_mismatch",
                    "The updater ownership target does not match this installation.",
                )
            if existing.role == OwnershipRole.HANDOFF.value:
                parent_matches = (
                    existing.owner_pid == parent_pid
                    and existing.owner_process_created == parent_process_created
                )
                if not parent_matches:
                    raise UpdateError(
                        "handoff_validation_failed",
                        "The GUI-to-helper update handoff could not be validated.",
                    )
                liveness = self._owner_liveness(existing)
                self._raise_if_liveness_unavailable(liveness)
                if liveness == _OwnerLiveness.STALE:
                    self._log("Recovered stale updater ownership from an exited process.")
            elif (
                existing.owner_pid == helper_pid
                and existing.owner_process_created == helper_created
            ):
                return existing
            else:
                liveness = self._owner_liveness(existing)
                self._raise_if_liveness_unavailable(liveness)
                if liveness == _OwnerLiveness.LIVE:
                    raise UpdateError(
                        "duplicate_helper",
                        "This update transaction already has an active helper process.",
                    )
                self._log("Recovered stale updater ownership from an exited process.")

            timestamp = _now()
            record = OwnershipRecord(
                schema_version=OWNERSHIP_SCHEMA_VERSION,
                transaction_id=transaction_id,
                target_identity=target_identity,
                target_name=target.name,
                owner_pid=helper_pid,
                owner_process_created=helper_created,
                role=OwnershipRole.INSTALLATION.value,
                state=TransactionState.WAITING_FOR_PARENT_EXIT.value,
                created_at=existing.created_at if existing is not None else timestamp,
                heartbeat_at=timestamp,
            )
            _atomic_write_json(path, record.to_dict())
            return record

    def update(
        self,
        transaction_id: str,
        target_executable: Path,
        state: TransactionState,
        *,
        role: OwnershipRole = OwnershipRole.INSTALLATION,
    ) -> OwnershipRecord:
        target = Path(target_executable).resolve()
        target_identity = normalized_target_identity(target)
        current_pid = os.getpid()
        current_created = self._identity(current_pid, "updater")
        path = self.path_for_target(target)
        with self._guard(target_identity):
            record, read_state = self._read_record_path(path)
            if read_state == _RecordReadState.UNAVAILABLE:
                self._raise_ownership_unavailable()
            if read_state != _RecordReadState.VALID or record is None:
                raise UpdateError(
                    "helper_ownership_acquisition_failed",
                    "The updater could not confirm installation ownership.",
                )
            if record.transaction_id != transaction_id or record.target_identity != target_identity:
                raise UpdateError(
                    "transaction_mismatch",
                    "The updater ownership transaction does not match.",
                )
            if record.owner_pid != current_pid or record.owner_process_created != current_created:
                liveness = self._owner_liveness(record)
                self._raise_if_liveness_unavailable(liveness)
                if liveness == _OwnerLiveness.LIVE:
                    raise UpdateError(
                        "concurrent_update",
                        "Another updater process is active for this installation.",
                    )
                raise UpdateError(
                    "process_identity_mismatch",
                    "The updater process creation identity changed unexpectedly.",
                )
            updated = OwnershipRecord(
                schema_version=record.schema_version,
                transaction_id=record.transaction_id,
                target_identity=record.target_identity,
                target_name=record.target_name,
                owner_pid=record.owner_pid,
                owner_process_created=record.owner_process_created,
                role=role.value,
                state=state.value,
                created_at=record.created_at,
                heartbeat_at=_now(),
            )
            _atomic_write_json(path, updated.to_dict())
            return updated

    def release(self, transaction_id: str, target_executable: Path) -> bool:
        target = Path(target_executable).resolve()
        target_identity = normalized_target_identity(target)
        path = self.path_for_target(target)
        current_pid = os.getpid()
        current_created = self._identity(current_pid, "ownership release")
        with self._guard(target_identity):
            record, read_state = self._read_record_path(path)
            if read_state == _RecordReadState.UNAVAILABLE:
                self._raise_ownership_unavailable()
            if read_state == _RecordReadState.INVALID:
                self._remove_stale(path, "invalid ownership record")
                return True
            if record is None:
                return True
            if (
                record.transaction_id == transaction_id
                and record.owner_pid == current_pid
                and record.owner_process_created == current_created
            ):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise UpdateError(
                        "ownership_unavailable",
                        "The updater ownership record could not be released safely.",
                    ) from exc
                return True
            liveness = self._owner_liveness(record)
            if liveness in {_OwnerLiveness.LIVE, _OwnerLiveness.UNAVAILABLE}:
                return False
            self._remove_stale(path, "different transaction owner exited or PID was reused")
            return True

    def wait_for_helper_claim(
        self,
        transaction_id: str,
        target_executable: Path,
        *,
        timeout: float,
        helper_exited: Callable[[], bool] | None = None,
    ) -> OwnershipRecord:
        deadline = self.monotonic() + timeout
        while self.monotonic() < deadline:
            record = self.read(target_executable)
            if record is not None:
                liveness = self._owner_liveness(record)
                self._raise_if_liveness_unavailable(liveness)
                if (
                    record.transaction_id == transaction_id
                    and record.role == OwnershipRole.INSTALLATION.value
                    and liveness == _OwnerLiveness.LIVE
                ):
                    return record
            if helper_exited is not None and helper_exited():
                raise UpdateError(
                    "helper_ownership_acquisition_failed",
                    "The detached updater exited before accepting the transaction handoff.",
                )
            self.sleep(GUARD_POLL_SECONDS)
        raise UpdateError(
            "handoff_timeout",
            "The detached updater did not confirm the transaction handoff in time.",
        )

    def recover_stale(self, *, claim_for_recovery: bool = False) -> list[RecoveryEvent]:
        events: list[RecoveryEvent] = []
        for path in self.directory.glob("*.json"):
            target_identity = path.stem
            if not TARGET_IDENTITY_PATTERN.fullmatch(target_identity):
                with contextlib.suppress(OSError):
                    path.unlink()
                continue
            with self._guard(target_identity):
                record, read_state = self._read_record_path(path)
                if read_state == _RecordReadState.UNAVAILABLE:
                    self._log("Updater ownership could not be read safely; record preserved.")
                    continue
                if read_state == _RecordReadState.INVALID:
                    self._remove_stale(path, "invalid ownership record")
                    events.append(
                        RecoveryEvent("unknown", target_identity, "invalid ownership record")
                    )
                    self._log("Recovered stale updater ownership from an invalid record.")
                    continue
                if record is None:
                    continue
                liveness = self._owner_liveness(record)
                if liveness == _OwnerLiveness.UNAVAILABLE:
                    self._log(
                        "Updater owner process identity could not be verified; record preserved."
                    )
                    continue
                if liveness == _OwnerLiveness.LIVE:
                    continue
                if claim_for_recovery:
                    current_pid = os.getpid()
                    current_created = self._identity(current_pid, "updater recovery")
                    recovered_record = OwnershipRecord(
                        schema_version=record.schema_version,
                        transaction_id=record.transaction_id,
                        target_identity=record.target_identity,
                        target_name=record.target_name,
                        owner_pid=current_pid,
                        owner_process_created=current_created,
                        role=OwnershipRole.INSTALLATION.value,
                        state=record.state,
                        created_at=record.created_at,
                        heartbeat_at=_now(),
                    )
                    _atomic_write_json(path, recovered_record.to_dict())
                else:
                    with contextlib.suppress(OSError):
                        path.unlink()
                events.append(
                    RecoveryEvent(
                        record.transaction_id,
                        record.target_identity,
                        "owner exited or process creation identity changed",
                    )
                )
                self._log("Recovered stale updater ownership from an exited process.")
        return events

    def release_identity(self, transaction_id: str, target_identity: str) -> bool:
        if not TARGET_IDENTITY_PATTERN.fullmatch(target_identity):
            return False
        path = self.directory / f"{target_identity}.json"
        current_pid = os.getpid()
        current_created = self._identity(current_pid, "ownership release")
        with self._guard(target_identity):
            record, read_state = self._read_record_path(path)
            if read_state == _RecordReadState.UNAVAILABLE:
                return False
            if read_state == _RecordReadState.INVALID:
                self._remove_stale(path, "invalid ownership record")
                return True
            if record is None:
                return True
            if (
                record.transaction_id == transaction_id
                and record.target_identity == target_identity
                and record.owner_pid == current_pid
                and record.owner_process_created == current_created
            ):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    return False
                return True
            return False

    def claim_recovery(
        self,
        transaction_id: str,
        target_executable: Path,
        state: TransactionState,
    ) -> OwnershipRecord:
        if not TRANSACTION_ID_PATTERN.fullmatch(transaction_id):
            raise UpdateError(
                "invalid_transaction",
                "The updater recovery transaction ID is invalid.",
            )
        target = Path(target_executable).resolve()
        target_identity = normalized_target_identity(target)
        path = self.path_for_target(target)
        current_pid = os.getpid()
        current_created = self._identity(current_pid, "updater recovery")
        with self._guard(target_identity):
            existing, read_state = self._read_record_path(path)
            if read_state == _RecordReadState.UNAVAILABLE:
                self._raise_ownership_unavailable()
            if read_state == _RecordReadState.INVALID:
                self._remove_stale(path, "invalid ownership record")
                existing = None
            if existing is not None:
                liveness = self._owner_liveness(existing)
                self._raise_if_liveness_unavailable(liveness)
                if liveness == _OwnerLiveness.LIVE:
                    raise UpdateError(
                        "concurrent_update",
                        "Another updater process is active for this installation.",
                    )
                self._remove_stale(path, "owner exited or PID was reused")
            timestamp = _now()
            record = OwnershipRecord(
                schema_version=OWNERSHIP_SCHEMA_VERSION,
                transaction_id=transaction_id,
                target_identity=target_identity,
                target_name=target.name,
                owner_pid=current_pid,
                owner_process_created=current_created,
                role=OwnershipRole.INSTALLATION.value,
                state=state.value,
                created_at=timestamp,
                heartbeat_at=timestamp,
            )
            _atomic_write_json(path, record.to_dict())
            return record

    def recover_legacy_global_lock(self) -> bool:
        """Remove a legacy PID-only lock only when its PID is definitely absent."""

        path = self.root / LEGACY_INSTALL_LOCK_FILENAME
        if self._legacy_lock_status() != "stale":
            return False
        with contextlib.suppress(OSError):
            path.unlink()
        if not path.exists():
            self._log("Recovered stale legacy updater ownership without process identity.")
            return True
        return False

    def _legacy_lock_status(self) -> str:
        path = self.root / LEGACY_INSTALL_LOCK_FILENAME
        if not path.exists():
            return "absent"
        try:
            payload = _read_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return "unknown"
        owner_pid = payload.get("owner_pid")
        if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
            return "unknown"
        try:
            current = self.identity_provider(owner_pid)
        except (OSError, PermissionError):
            return "unknown"
        return "stale" if current is None else "active"

    def _read_record_path(
        self, path: Path
    ) -> tuple[OwnershipRecord | None, _RecordReadState]:
        try:
            return OwnershipRecord.from_dict(_read_json(path)), _RecordReadState.VALID
        except FileNotFoundError:
            return None, _RecordReadState.ABSENT
        except (UnicodeError, json.JSONDecodeError, ValueError):
            return None, _RecordReadState.INVALID
        except OSError:
            return None, _RecordReadState.UNAVAILABLE

    def _owner_liveness(self, record: OwnershipRecord) -> _OwnerLiveness:
        try:
            current = self.identity_provider(record.owner_pid)
        except (OSError, PermissionError):
            return _OwnerLiveness.UNAVAILABLE
        if current is not None and current == record.owner_process_created:
            return _OwnerLiveness.LIVE
        return _OwnerLiveness.STALE

    @staticmethod
    def _raise_if_liveness_unavailable(liveness: _OwnerLiveness) -> None:
        if liveness == _OwnerLiveness.UNAVAILABLE:
            raise UpdateError(
                "process_identity_unavailable",
                "The existing updater owner process identity could not be verified safely.",
            )

    @staticmethod
    def _raise_ownership_unavailable() -> None:
        raise UpdateError(
            "ownership_unavailable",
            "The updater ownership record could not be read safely.",
        )

    def _validate_identity(self, pid: int, expected: str, label: str) -> None:
        if not IDENTITY_PATTERN.fullmatch(str(expected or "")):
            raise UpdateError(
                "process_identity_mismatch",
                f"The {label} process creation identity is invalid.",
            )
        try:
            current = self.identity_provider(pid)
        except (OSError, PermissionError) as exc:
            raise UpdateError(
                "process_identity_unavailable",
                f"The {label} process creation identity could not be queried safely.",
            ) from exc
        if current != expected:
            raise UpdateError(
                "process_identity_mismatch",
                f"The {label} process creation identity does not match.",
            )

    def _identity(self, pid: int, label: str) -> str:
        try:
            identity = self.identity_provider(pid)
        except (OSError, PermissionError) as exc:
            raise UpdateError(
                "process_identity_unavailable",
                f"The {label} process identity could not be verified.",
            ) from exc
        if identity is None or not IDENTITY_PATTERN.fullmatch(identity):
            raise UpdateError(
                "process_identity_unavailable",
                f"The {label} process identity could not be verified.",
            )
        return identity

    def _remove_stale(self, path: Path, reason: str) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise UpdateError(
                "ownership_unavailable",
                "The stale updater ownership record could not be removed safely.",
            ) from exc
        self._log(f"Recovered stale updater ownership ({reason}).")

    def _log(self, message: str) -> None:
        if self.log_callback is not None:
            with contextlib.suppress(Exception):
                self.log_callback(message)

    @contextmanager
    def _guard(self, target_identity: str) -> Iterator[None]:
        if sys.platform == "win32":
            with self._windows_mutex_guard(target_identity):
                yield
            return

        with self._posix_file_guard(target_identity):
            yield

    @contextmanager
    def _windows_mutex_guard(self, target_identity: str) -> Iterator[None]:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_mutex = kernel32.CreateMutexW
        create_mutex.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        create_mutex.restype = wintypes.HANDLE
        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_single_object.restype = wintypes.DWORD
        release_mutex = kernel32.ReleaseMutex
        release_mutex.argtypes = [wintypes.HANDLE]
        release_mutex.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        handle = create_mutex(None, False, f"Global\\OpenFetch.Update.{target_identity}")
        if not handle:
            raise UpdateError(
                "helper_ownership_acquisition_failed",
                "The updater could not create the ownership guard.",
            )
        wait_result = wait_for_single_object(handle, int(GUARD_WAIT_SECONDS * 1000))
        acquired = wait_result in {0x00000000, 0x00000080}
        if not acquired:
            close_handle(handle)
            raise UpdateError(
                "helper_ownership_acquisition_failed",
                "The updater could not acquire the ownership guard.",
            )
        try:
            yield
        finally:
            release_mutex(handle)
            close_handle(handle)

    @contextmanager
    def _posix_file_guard(self, target_identity: str) -> Iterator[None]:
        import fcntl

        guard = self.directory / f".{target_identity}.guard"
        handle = guard.open("a+b")
        deadline = self.monotonic() + GUARD_WAIT_SECONDS
        acquired = False
        try:
            while self.monotonic() < deadline:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    self.sleep(GUARD_POLL_SECONDS)
            if not acquired:
                raise UpdateError(
                    "helper_ownership_acquisition_failed",
                    "The updater could not acquire the ownership guard.",
                )
            yield
        finally:
            if acquired:
                with contextlib.suppress(OSError):
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            try:
                handle.close()
            except OSError:
                pass
