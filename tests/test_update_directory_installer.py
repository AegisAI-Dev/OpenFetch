from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from openfetch.core import update_directory_installer as directory_module
from openfetch.core.update_directory_installer import (
    BACKUP_INVENTORY_FILENAME,
    DIRECTORY_MANIFEST_FILENAME,
    DIRECTORY_TRANSACTION_FILENAME,
    ONEFOLDER_EXECUTABLE_NAME,
    QT_COMPONENT_BASELINE_FILENAME,
    DirectoryUpdateApplier,
    DirectoryUpdateManifest,
    DirectoryUpdateTransaction,
    QtReplacementPolicy,
    cleanup_stale_directory_update_state,
    detect_modified_replaceable_files,
    expected_directory_root_name,
    load_directory_update_transaction,
    prepare_and_launch_directory_update,
    recover_stale_directory_updates,
    write_directory_startup_confirmation,
)
from openfetch.core.update_installer import (
    RESULT_FILENAME,
    STARTUP_MARKER_FILENAME,
    _atomic_write_json,
    _read_json,
)
from openfetch.core.update_ownership import (
    OwnershipRole,
    TransactionState,
    UpdateOwnershipManager,
    normalized_target_identity,
)
from openfetch.core.updater import UpdateError

OLD_VERSION = "3.0.4"
NEW_VERSION = "3.0.5"
NEW_ROOT_NAME = expected_directory_root_name(NEW_VERSION)
TOKEN = "A" * 48
OTHER_TOKEN = "B" * 48
CONFIRMATION_TOKEN = "C" * 64
PARENT_PID = 4242
WRAPPER_PID = 515_151
STARTED_WRAPPER_PID = 616_161
STARTED_RUNTIME_PID = 717_171

EXE_PAYLOAD_OLD = b"O" * (1024 * 1024)
EXE_PAYLOAD_NEW = b"N" * (1024 * 1024)

OLD_FILES = {
    ONEFOLDER_EXECUTABLE_NAME: EXE_PAYLOAD_OLD,
    "docs/notes.txt": b"old-notes",
    "PySide6/Qt6Core.dll": b"qt-core-old",
    "shiboken6/shiboken6.abi3.dll": b"shiboken-old",
}
NEW_FILES = {
    ONEFOLDER_EXECUTABLE_NAME: EXE_PAYLOAD_NEW,
    "docs/notes.txt": b"new-notes",
    "PySide6/Qt6Core.dll": b"qt-core-new",
    "shiboken6/shiboken6.abi3.dll": b"shiboken-new",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class IdentityRegistry:
    def __init__(self) -> None:
        self.values: dict[int, str] = {}

    def register(self, pid: int, label: str | None = None) -> str:
        value = identity(label or f"process-{pid}")
        self.values[pid] = value
        return value

    def remove(self, pid: int) -> None:
        self.values.pop(pid, None)

    def __call__(self, pid: int) -> str | None:
        return self.values.get(pid)


class FakeProcess:
    def __init__(self, pid=STARTED_WRAPPER_PID, poll_result=None, on_poll=None):
        self.pid = pid
        self.poll_result = poll_result
        self.on_poll = on_poll
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.on_poll is not None:
            callback, self.on_poll = self.on_poll, None
            callback()
        return self.poll_result

    def terminate(self):
        self.terminated = True
        self.poll_result = 0

    def kill(self):
        self.killed = True
        self.poll_result = -9

    def wait(self, timeout=None):
        return self.poll_result or 0


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        self.value += 0.1
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class SimulatedCrash(BaseException):
    """A process-death fault that deliberately bypasses handled failures."""


@pytest.fixture(autouse=True)
def never_stop_real_processes(monkeypatch):
    """Keep fake PID lifecycle assertions from invoking Windows taskkill."""

    def safe_stop(process, *, expected_identity=None, identity_provider=lambda _pid: None):
        if process.poll() is not None:
            return
        if expected_identity is not None and identity_provider(process.pid) != expected_identity:
            return
        process.terminate()
        process.wait(timeout=10)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    monkeypatch.setattr(directory_module, "_stop_child_process", safe_stop)


def qt_baseline_document(files: dict[str, bytes]) -> bytes:
    records = [
        {
            "path": relative,
            "sha256": sha256(payload),
            "size": len(payload),
        }
        for relative, payload in sorted(files.items())
        if PurePosixPath(relative).parts[0] in ("PySide6", "shiboken6")
    ]
    payload = {"schema_version": 1, "files": records}
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def with_baseline(files: dict[str, bytes]) -> dict[str, bytes]:
    complete = dict(files)
    complete[QT_COMPONENT_BASELINE_FILENAME] = qt_baseline_document(files)
    return complete


def build_tree(root: Path, files: dict[str, bytes]) -> None:
    for relative, payload in files.items():
        absolute = directory_module._long_path(root / Path(PurePosixPath(relative)))
        os.makedirs(os.path.dirname(absolute), exist_ok=True)
        with open(absolute, "wb") as handle:
            handle.write(payload)


def read_tree(root: Path) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    for relative, absolute in directory_module._walk_regular_files(root):
        with open(directory_module._long_path(absolute), "rb") as handle:
            contents[relative] = handle.read()
    return contents


@dataclass
class DirScenario:
    root: Path
    transaction_path: Path
    transaction: DirectoryUpdateTransaction
    manifest: DirectoryUpdateManifest
    target_root: Path
    target: Path
    staged: Path
    backup: Path
    old_root: Path
    new_root: Path
    marker: Path
    identities: IdentityRegistry
    manager: UpdateOwnershipManager
    clock: FakeClock
    old_tree: dict[str, bytes] = field(default_factory=dict)
    new_tree: dict[str, bytes] = field(default_factory=dict)


def write_directory_scenario(
    tmp_path: Path,
    *,
    state: TransactionState = TransactionState.HANDED_OFF,
    transaction_id: str = TOKEN,
    install_parent: Path | None = None,
    install_name: str = "install",
    old_files: dict[str, bytes] | None = None,
    new_files: dict[str, bytes] | None = None,
    preserved_files: dict[str, str] | None = None,
    qt_policy: QtReplacementPolicy | None = None,
    reserve: bool = True,
) -> DirScenario:
    root = (tmp_path / "updates").resolve()
    root.mkdir(parents=True, exist_ok=True)
    old_tree = with_baseline(OLD_FILES) if old_files is None else old_files
    new_tree = with_baseline(NEW_FILES) if new_files is None else new_files

    target_root = Path(
        directory_module._long_path((install_parent or tmp_path) / install_name)
    )
    build_tree(target_root, old_tree)
    target = target_root / ONEFOLDER_EXECUTABLE_NAME

    transaction_dir = root / NEW_VERSION / transaction_id
    staged = transaction_dir / "package" / NEW_ROOT_NAME
    build_tree(staged, new_tree)
    manifest = DirectoryUpdateManifest.for_distribution_root(
        version=NEW_VERSION, root=staged
    )

    backup = target_root.parent / f".{target_root.name}.{transaction_id}.backup"
    old_root = target_root.parent / f".{target_root.name}.{transaction_id}.old"
    new_root = target_root.parent / f".{target_root.name}.{transaction_id}.new"
    marker = transaction_dir / STARTUP_MARKER_FILENAME
    transaction_path = transaction_dir / DIRECTORY_TRANSACTION_FILENAME

    inventory = directory_module._copy_tree_verified(target_root, backup)
    _atomic_write_json(
        transaction_dir / BACKUP_INVENTORY_FILENAME,
        {"schema_version": 1, "transaction_id": transaction_id, "files": inventory},
    )
    inventory_hash = directory_module._hash_file(transaction_dir / BACKUP_INVENTORY_FILENAME)
    _atomic_write_json(
        transaction_dir / DIRECTORY_MANIFEST_FILENAME,
        json.loads(manifest.to_json()),
    )
    manifest_hash = directory_module._hash_file(transaction_dir / DIRECTORY_MANIFEST_FILENAME)

    identities = IdentityRegistry()
    identities.register(os.getpid(), "pytest-helper-runtime")
    parent_created = identities.register(PARENT_PID, "gui-parent")
    clock = FakeClock()
    manager = UpdateOwnershipManager(
        root,
        identity_provider=identities,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )
    if qt_policy is None:
        qt_policy = (
            QtReplacementPolicy.PRESERVE if preserved_files else QtReplacementPolicy.ABORT
        )
    timestamp = datetime(2026, 7, 22, 12, 0, tzinfo=UTC).isoformat()
    transaction = DirectoryUpdateTransaction(
        schema_version=1,
        transaction_id=transaction_id,
        confirmation_token=CONFIRMATION_TOKEN,
        state=state.value,
        expected_version=NEW_VERSION,
        manifest_sha256=manifest_hash,
        backup_inventory_sha256=inventory_hash,
        qt_policy=qt_policy.value,
        preserved_files=dict(preserved_files or {}),
        parent_pid=PARENT_PID,
        parent_process_created=parent_created,
        target_identity=normalized_target_identity(target),
        target_root=str(target_root),
        target_executable=str(target),
        staged_root=str(staged.resolve()),
        backup_root=str(backup),
        old_root=str(old_root),
        new_root=str(new_root),
        startup_marker=str(marker.resolve()),
        created_at=timestamp,
        updated_at=timestamp,
        launched_pid=None,
        launched_process_created=None,
    )
    _atomic_write_json(transaction_path, transaction.to_dict())
    if reserve:
        manager.reserve_handoff(
            transaction_id,
            target,
            parent_pid=PARENT_PID,
            parent_process_created=parent_created,
        )
    return DirScenario(
        root,
        transaction_path,
        transaction,
        manifest,
        target_root,
        target,
        staged,
        backup,
        old_root,
        new_root,
        marker,
        identities,
        manager,
        clock,
        old_tree,
        new_tree,
    )


def write_confirmation_marker(scenario: DirScenario, *, pid=STARTED_RUNTIME_PID, **changes):
    created = scenario.identities.register(pid, f"started-runtime-{pid}")
    payload = {
        "transaction_id": scenario.transaction.transaction_id,
        "confirmation_token": scenario.transaction.confirmation_token,
        "version": scenario.transaction.expected_version,
        "status": "initialized",
        "pid": pid,
        "process_created": created,
    }
    payload.update(changes)
    _atomic_write_json(scenario.marker, payload)


def successful_launcher(scenario: DirScenario, launches: list[list[str]]):
    scenario.identities.register(STARTED_WRAPPER_PID, "new-version-wrapper")

    def launch(arguments):
        launches.append(arguments)
        if "--post-update-transaction" in arguments:
            return FakeProcess(
                pid=STARTED_WRAPPER_PID,
                on_poll=lambda: write_confirmation_marker(scenario),
            )
        return FakeProcess(pid=STARTED_WRAPPER_PID + 1)

    return launch


def make_applier(scenario: DirScenario, launcher, **overrides):
    return DirectoryUpdateApplier(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=scenario.root.parent / "not-the-system-temp",
        process_exists=overrides.pop("process_exists", lambda _pid: False),
        identity_provider=scenario.identities,
        ownership_manager=scenario.manager,
        process_launcher=launcher,
        sleep=scenario.clock.sleep,
        monotonic=scenario.clock.monotonic,
        startup_timeout=overrides.pop("startup_timeout", 2),
        parent_exit_timeout=overrides.pop("parent_exit_timeout", 2),
        **overrides,
    )


def prepare_kwargs(scenario: DirScenario, **overrides):
    values = {
        "parent_pid": PARENT_PID,
        "current_version": OLD_VERSION,
        "transaction_id": OTHER_TOKEN,
        "target_executable": scenario.target,
        "frozen": True,
        "updates_root": scenario.root,
        "temporary_root": scenario.root.parent / "not-the-system-temp",
        "identity_provider": scenario.identities,
        "ownership_manager": scenario.manager,
        "handoff_timeout": 2,
    }
    values.update(overrides)
    return values


def make_fresh_prepare_environment(tmp_path: Path, **scenario_kwargs) -> DirScenario:
    """A scenario without a pre-existing transaction, used for prepare tests."""
    scenario = write_directory_scenario(
        tmp_path, transaction_id=OTHER_TOKEN, reserve=False, **scenario_kwargs
    )
    # Remove the pre-built transaction artifacts so prepare can create its own.
    scenario.transaction_path.unlink()
    (scenario.transaction_path.parent / BACKUP_INVENTORY_FILENAME).unlink()
    (scenario.transaction_path.parent / DIRECTORY_MANIFEST_FILENAME).unlink()
    directory_module._remove_tree(scenario.backup)
    return scenario


def claiming_launcher(scenario: DirScenario, launches: list[list[str]]):
    scenario.identities.register(WRAPPER_PID, "detached-helper-wrapper")

    def launch(arguments):
        launches.append(arguments)
        transaction = load_directory_update_transaction(
            Path(arguments[-1]),
            updates_root=scenario.root,
            temporary_root=scenario.root.parent / "not-the-system-temp",
        )
        scenario.manager.assume_installation(
            transaction.transaction_id,
            scenario.target,
            parent_pid=transaction.parent_pid,
            parent_process_created=transaction.parent_process_created,
        )
        return FakeProcess(pid=WRAPPER_PID)

    return launch


def test_directory_manifest_rejects_unsafe_and_prohibited_paths(tmp_path):
    staged = tmp_path / NEW_ROOT_NAME
    build_tree(staged, with_baseline(NEW_FILES))

    manifest = DirectoryUpdateManifest.for_distribution_root(
        version=NEW_VERSION, root=staged
    )
    payload = json.loads(manifest.to_json())

    for bad_path in (
        "../escape.dll",
        "docs\\windows.txt",
        "CON/notes.txt",
        "docs/trailing.",
        "/absolute.txt",
    ):
        broken = json.loads(manifest.to_json())
        broken["files"][bad_path] = {"sha256": sha256(b"x"), "size": 1}
        broken["total_size"] += 1
        with pytest.raises(UpdateError) as raised:
            DirectoryUpdateManifest.from_json(
                json.dumps(broken), release_version=NEW_VERSION
            )
        assert raised.value.code == "invalid_directory_manifest"

    for prohibited in (
        "PyQt5/QtCore.dll",
        "yt_dlp_plugins/provider.py",
        f"OpenFetch-{NEW_VERSION}-windows-x64.exe",
        "tools/other-tool.exe",
        "sip.pyd",
    ):
        broken = json.loads(manifest.to_json())
        broken["files"][prohibited] = {"sha256": sha256(b"x"), "size": 1}
        broken["total_size"] += 1
        with pytest.raises(UpdateError) as raised:
            DirectoryUpdateManifest.from_json(
                json.dumps(broken), release_version=NEW_VERSION
            )
        assert raised.value.code == "prohibited_artifact"

    duplicate = json.loads(manifest.to_json())
    duplicate["files"]["DOCS/notes.txt"] = duplicate["files"]["docs/notes.txt"]
    duplicate["total_size"] += duplicate["files"]["docs/notes.txt"]["size"]
    with pytest.raises(UpdateError) as raised:
        DirectoryUpdateManifest.from_json(
            json.dumps(duplicate), release_version=NEW_VERSION
        )
    assert raised.value.code == "invalid_directory_manifest"

    outside_family = json.loads(manifest.to_json())
    outside_family["replaceable_paths"] = ["docs/notes.txt"]
    with pytest.raises(UpdateError) as raised:
        DirectoryUpdateManifest.from_json(
            json.dumps(outside_family), release_version=NEW_VERSION
        )
    assert raised.value.code == "invalid_directory_manifest"

    assert payload["executable"] == ONEFOLDER_EXECUTABLE_NAME
    assert "PySide6/Qt6Core.dll" in manifest.replaceable_paths
    with pytest.raises(UpdateError) as raised:
        DirectoryUpdateManifest.from_json(
            manifest.to_json(), release_version=NEW_VERSION, current_version=NEW_VERSION
        )
    assert raised.value.code == "not_newer"


def test_onefolder_update_success_replaces_and_cleans_up(tmp_path):
    scenario = write_directory_scenario(tmp_path)
    launches: list[list[str]] = []
    applier = make_applier(scenario, successful_launcher(scenario, launches))

    assert applier.apply() == 0

    installed = read_tree(scenario.target_root)
    assert installed[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_NEW
    assert installed["docs/notes.txt"] == b"new-notes"
    assert installed["PySide6/Qt6Core.dll"] == b"qt-core-new"
    assert not directory_module._path_exists(scenario.old_root)
    assert not directory_module._path_exists(scenario.new_root)
    assert not directory_module._path_exists(scenario.staged)
    assert not scenario.marker.exists()
    # The helper process runs from the backup copy, so success keeps it for
    # the post-confirmation cleanup pass instead of deleting its own folder.
    assert directory_module._path_exists(scenario.backup)
    result = _read_json(scenario.transaction_path.parent / RESULT_FILENAME)
    assert result["status"] == "success"
    assert scenario.manager.read(scenario.target) is None
    assert any("--post-update-transaction" in launch for launch in launches)


def test_rollback_after_startup_timeout_restores_previous_version(tmp_path):
    scenario = write_directory_scenario(tmp_path)
    launches: list[list[str]] = []
    scenario.identities.register(STARTED_WRAPPER_PID, "new-version-wrapper")

    def never_confirming_launcher(arguments):
        launches.append(arguments)
        return FakeProcess(pid=STARTED_WRAPPER_PID)

    applier = make_applier(scenario, never_confirming_launcher)

    assert applier.apply() == 3

    restored = read_tree(scenario.target_root)
    assert restored[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    assert restored["docs/notes.txt"] == b"old-notes"
    result = _read_json(scenario.transaction_path.parent / RESULT_FILENAME)
    assert result["status"] == "rollback_succeeded"
    final_state = load_directory_update_transaction(
        scenario.transaction_path, updates_root=scenario.root
    ).state
    assert final_state == TransactionState.ROLLED_BACK.value
    assert launches[-1][1] == "--update-rollback-status"
    assert scenario.manager.read(scenario.target) is None
    assert not directory_module._path_exists(scenario.old_root)


def test_interrupted_directory_replacement_is_recovered_at_startup(tmp_path):
    scenario = write_directory_scenario(tmp_path)
    renames: list[tuple[str, str]] = []

    def crashing_rename(source, destination):
        renames.append((str(source), str(destination)))
        if len(renames) == 2:
            raise SimulatedCrash("power loss between directory renames")
        directory_module._rename_path(source, destination)

    applier = make_applier(
        scenario,
        successful_launcher(scenario, []),
        rename_path=crashing_rename,
    )
    with pytest.raises(SimulatedCrash):
        applier.apply()

    # The installation was renamed away and the crash struck before the new
    # tree landed: no target directory remains.
    assert not directory_module._path_exists(scenario.target_root)
    assert directory_module._path_exists(scenario.old_root)

    recovery_identities = IdentityRegistry()
    recovery_identities.register(os.getpid(), "startup-recovery-runtime")
    summary = recover_stale_directory_updates(
        updates_root=scenario.root,
        identity_provider=recovery_identities,
        recorded_process_stopper=lambda _pid, _created: None,
        current_executable=scenario.root / "elsewhere.exe",
    )

    assert summary.recovered_count == 1
    restored = read_tree(scenario.target_root)
    assert restored[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    result = _read_json(scenario.transaction_path.parent / RESULT_FILENAME)
    assert result["status"] == "rollback_succeeded"
    assert not directory_module._path_exists(scenario.old_root)
    assert not directory_module._path_exists(scenario.backup)
    assert scenario.manager.read(scenario.target) is None


def test_rollback_of_byte_identical_update_cleans_the_untouched_old_tree(tmp_path):
    identical_new = dict(with_baseline(OLD_FILES))
    scenario = write_directory_scenario(tmp_path, new_files=identical_new)
    scenario.identities.register(STARTED_WRAPPER_PID, "new-version-wrapper")

    applier = make_applier(
        scenario, lambda arguments: FakeProcess(pid=STARTED_WRAPPER_PID)
    )

    assert applier.apply() == 3
    restored = read_tree(scenario.target_root)
    assert restored[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    assert not directory_module._path_exists(scenario.old_root)
    assert not directory_module._path_exists(scenario.new_root)
    result = _read_json(scenario.transaction_path.parent / RESULT_FILENAME)
    assert result["status"] == "rollback_succeeded"


def test_rollback_from_backup_copy_cleans_redundant_old_tree(tmp_path, monkeypatch):
    scenario = write_directory_scenario(tmp_path)
    scenario.identities.register(STARTED_WRAPPER_PID, "new-version-wrapper")
    real_tree_matches = directory_module._tree_matches

    def old_tree_scan_fails_transiently(root, expected):
        if os.path.normcase(str(root)) == os.path.normcase(str(scenario.old_root)):
            return False
        return real_tree_matches(root, expected)

    monkeypatch.setattr(directory_module, "_tree_matches", old_tree_scan_fails_transiently)

    applier = make_applier(
        scenario, lambda arguments: FakeProcess(pid=STARTED_WRAPPER_PID)
    )

    assert applier.apply() == 3
    restored = read_tree(scenario.target_root)
    assert restored[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    assert not directory_module._path_exists(scenario.old_root)
    result = _read_json(scenario.transaction_path.parent / RESULT_FILENAME)
    assert result["status"] == "rollback_succeeded"


def test_stale_staging_recovery_cleans_terminal_transaction_leftovers(tmp_path):
    scenario = write_directory_scenario(
        tmp_path, state=TransactionState.FAILED, reserve=False
    )
    build_tree(scenario.new_root, scenario.new_tree)

    recovery_identities = IdentityRegistry()
    recovery_identities.register(os.getpid(), "startup-recovery-runtime")
    summary = recover_stale_directory_updates(
        updates_root=scenario.root,
        identity_provider=recovery_identities,
        recorded_process_stopper=lambda _pid, _created: None,
        current_executable=scenario.root / "elsewhere.exe",
    )

    assert summary.recovered_count == 1
    untouched = read_tree(scenario.target_root)
    assert untouched[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    assert not directory_module._path_exists(scenario.new_root)
    assert not directory_module._path_exists(scenario.backup)
    assert not directory_module._path_exists(scenario.staged)


def test_concurrent_directory_update_is_rejected(tmp_path):
    scenario = write_directory_scenario(tmp_path)
    launches: list[list[str]] = []
    fresh_staged = scenario.root / NEW_VERSION / OTHER_TOKEN / "package" / NEW_ROOT_NAME
    build_tree(fresh_staged, scenario.new_tree)

    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            fresh_staged,
            detached_launcher=claiming_launcher(scenario, launches),
            **prepare_kwargs(scenario),
        )

    assert raised.value.code == "concurrent_update"
    assert launches == []
    # The competing attempt must clean its own backup and leave the reserved
    # transaction untouched.
    competing_backup = (
        scenario.target_root.parent / f".{scenario.target_root.name}.{OTHER_TOKEN}.backup"
    )
    assert not directory_module._path_exists(competing_backup)
    record = scenario.manager.read(scenario.target)
    assert record is not None and record.transaction_id == TOKEN


def test_prepare_hands_off_to_helper_from_verified_backup(tmp_path):
    scenario = make_fresh_prepare_environment(tmp_path)
    launches: list[list[str]] = []

    prepared = prepare_and_launch_directory_update(
        scenario.manifest,
        scenario.staged,
        detached_launcher=claiming_launcher(scenario, launches),
        **prepare_kwargs(scenario),
    )

    assert prepared.transaction_id == OTHER_TOKEN
    transaction = load_directory_update_transaction(
        prepared.transaction_path, updates_root=scenario.root
    )
    assert transaction.state == TransactionState.HANDED_OFF.value
    assert transaction.qt_policy == QtReplacementPolicy.ABORT.value
    assert transaction.preserved_files == {}
    backup = Path(transaction.backup_root)
    assert read_tree(backup) == read_tree(scenario.target_root)
    assert launches[0][0] == str(backup / ONEFOLDER_EXECUTABLE_NAME)
    assert launches[0][1] == "--apply-directory-update"
    record = scenario.manager.read(scenario.target)
    assert record is not None and record.role == OwnershipRole.INSTALLATION.value


def test_user_replaced_qt_library_requires_explicit_consent(tmp_path):
    modified_old = with_baseline(OLD_FILES)
    modified_old["PySide6/Qt6Core.dll"] = b"user-custom-qt-library"
    # The baseline still records the original wheel hashes, so the local
    # replacement is detectable.
    modified_old[QT_COMPONENT_BASELINE_FILENAME] = qt_baseline_document(OLD_FILES)
    scenario = make_fresh_prepare_environment(tmp_path, old_files=modified_old)
    before = read_tree(scenario.target_root)

    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            detached_launcher=claiming_launcher(scenario, []),
            **prepare_kwargs(scenario),
        )

    assert raised.value.code == "qt_replacement_consent_required"
    assert "PySide6/Qt6Core.dll" in str(raised.value)
    assert read_tree(scenario.target_root) == before
    assert not directory_module._path_exists(
        scenario.target_root.parent / f".{scenario.target_root.name}.{OTHER_TOKEN}.backup"
    )
    assert not scenario.transaction_path.exists()
    assert scenario.manager.read(scenario.target) is None


def test_preserve_policy_carries_user_replaced_qt_library_forward(tmp_path):
    user_payload = b"user-custom-qt-library"
    modified_old = with_baseline(OLD_FILES)
    modified_old["PySide6/Qt6Core.dll"] = user_payload
    modified_old[QT_COMPONENT_BASELINE_FILENAME] = qt_baseline_document(OLD_FILES)
    scenario = write_directory_scenario(
        tmp_path,
        old_files=modified_old,
        preserved_files={"PySide6/Qt6Core.dll": sha256(user_payload)},
    )

    applier = make_applier(scenario, successful_launcher(scenario, []))

    assert applier.apply() == 0
    installed = read_tree(scenario.target_root)
    assert installed["PySide6/Qt6Core.dll"] == user_payload
    assert installed["shiboken6/shiboken6.abi3.dll"] == b"shiboken-new"
    assert installed[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_NEW


def test_replace_policy_records_explicit_overwrite_consent(tmp_path):
    modified_old = with_baseline(OLD_FILES)
    modified_old["PySide6/Qt6Core.dll"] = b"user-custom-qt-library"
    modified_old[QT_COMPONENT_BASELINE_FILENAME] = qt_baseline_document(OLD_FILES)
    scenario = make_fresh_prepare_environment(tmp_path, old_files=modified_old)

    prepared = prepare_and_launch_directory_update(
        scenario.manifest,
        scenario.staged,
        qt_policy=QtReplacementPolicy.REPLACE,
        detached_launcher=claiming_launcher(scenario, []),
        **prepare_kwargs(scenario),
    )

    transaction = load_directory_update_transaction(
        prepared.transaction_path, updates_root=scenario.root
    )
    assert transaction.qt_policy == QtReplacementPolicy.REPLACE.value
    assert transaction.preserved_files == {}


def test_detect_modified_replaceable_files_uses_recorded_baseline(tmp_path):
    target_root = tmp_path / "install"
    modified = with_baseline(OLD_FILES)
    modified["shiboken6/shiboken6.abi3.dll"] = b"recipient-built-shiboken"
    modified[QT_COMPONENT_BASELINE_FILENAME] = qt_baseline_document(OLD_FILES)
    build_tree(target_root, modified)
    staged = tmp_path / NEW_ROOT_NAME
    build_tree(staged, with_baseline(NEW_FILES))
    manifest = DirectoryUpdateManifest.for_distribution_root(
        version=NEW_VERSION, root=staged
    )

    detected = detect_modified_replaceable_files(target_root, manifest)

    assert detected == {
        "shiboken6/shiboken6.abi3.dll": sha256(b"recipient-built-shiboken")
    }

    # Without a readable baseline every replaceable file needs explicit
    # handling, keeping accidental overwrites impossible.
    (target_root / QT_COMPONENT_BASELINE_FILENAME).unlink()
    fallback = detect_modified_replaceable_files(target_root, manifest)
    assert set(fallback) == {
        "PySide6/Qt6Core.dll",
        "shiboken6/shiboken6.abi3.dll",
    }


def test_unicode_installation_path_updates_successfully(tmp_path):
    unicode_parent = tmp_path / "Ünïcøde 更新 – папка"
    unicode_parent.mkdir()
    scenario = write_directory_scenario(
        tmp_path, install_parent=unicode_parent, install_name="Приложение"
    )

    applier = make_applier(scenario, successful_launcher(scenario, []))

    assert applier.apply() == 0
    installed = read_tree(scenario.target_root)
    assert installed[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_NEW


def test_long_windows_installation_path_updates_successfully(tmp_path):
    deep_parent = tmp_path
    for index in range(4):
        deep_parent = deep_parent / f"deep-directory-level-{index}-{'x' * 60}"
    os.makedirs(directory_module._long_path(deep_parent), exist_ok=True)
    scenario = write_directory_scenario(
        tmp_path, install_parent=deep_parent, install_name="install"
    )
    assert len(str(scenario.target_root)) > 260

    applier = make_applier(scenario, successful_launcher(scenario, []))

    assert applier.apply() == 0
    installed = read_tree(scenario.target_root)
    assert installed[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_NEW
    assert installed["docs/notes.txt"] == b"new-notes"


def test_prepare_rejects_manifest_mismatch_missing_and_extra_files(tmp_path):
    scenario = make_fresh_prepare_environment(tmp_path)

    tampered = scenario.staged / "docs" / "notes.txt"
    tampered.write_bytes(b"tampered-notes")
    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            detached_launcher=claiming_launcher(scenario, []),
            **prepare_kwargs(scenario),
        )
    assert raised.value.code == "checksum_mismatch"
    tampered.write_bytes(b"new-notes")

    missing = scenario.staged / "PySide6" / "Qt6Core.dll"
    missing.unlink()
    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            detached_launcher=claiming_launcher(scenario, []),
            **prepare_kwargs(scenario),
        )
    assert raised.value.code == "update_package_incomplete"
    missing.write_bytes(b"qt-core-new")

    extra = scenario.staged / "extra-payload.bin"
    extra.write_bytes(b"unexpected")
    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            detached_launcher=claiming_launcher(scenario, []),
            **prepare_kwargs(scenario),
        )
    assert raised.value.code == "update_package_unexpected_file"
    extra.unlink()

    untouched = read_tree(scenario.target_root)
    assert untouched[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    assert scenario.manager.read(scenario.target) is None


def test_applier_preserves_original_when_staged_package_is_tampered(tmp_path):
    scenario = write_directory_scenario(tmp_path)
    (scenario.staged / "docs" / "notes.txt").write_bytes(b"tampered-after-handoff")

    applier = make_applier(scenario, successful_launcher(scenario, []))

    assert applier.apply() == 2
    untouched = read_tree(scenario.target_root)
    assert untouched[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    result = _read_json(scenario.transaction_path.parent / RESULT_FILENAME)
    assert result["status"] == "original_preserved"
    final_state = load_directory_update_transaction(
        scenario.transaction_path, updates_root=scenario.root
    ).state
    assert final_state == TransactionState.FAILED.value


def test_reparse_points_in_staged_package_are_rejected(tmp_path, monkeypatch):
    scenario = make_fresh_prepare_environment(tmp_path)
    flagged = scenario.staged / "PySide6" / "Qt6Core.dll"
    real_is_reparse_point = directory_module._is_reparse_point

    def fake_reparse(path):
        if os.path.normcase(os.path.abspath(os.fspath(path)).replace("\\\\?\\", "")) == (
            os.path.normcase(str(flagged))
        ):
            return True
        return real_is_reparse_point(path)

    monkeypatch.setattr(directory_module, "_is_reparse_point", fake_reparse)

    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            detached_launcher=claiming_launcher(scenario, []),
            **prepare_kwargs(scenario),
        )
    assert raised.value.code == "unsafe_path"
    assert read_tree(scenario.target_root)[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point semantics")
def test_real_symlink_in_staged_package_is_rejected_when_creatable(tmp_path):
    scenario = make_fresh_prepare_environment(tmp_path)
    link = scenario.staged / "docs" / "link-to-notes.txt"
    try:
        os.symlink(scenario.staged / "docs" / "notes.txt", link)
    except OSError:
        pytest.skip("symlink creation requires privilege on this system")

    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            detached_launcher=claiming_launcher(scenario, []),
            **prepare_kwargs(scenario),
        )
    assert raised.value.code == "unsafe_path"


def test_cancellation_during_backup_aborts_without_replacement(tmp_path):
    scenario = make_fresh_prepare_environment(tmp_path)
    calls = {"count": 0}

    def cancel_after_verification() -> bool:
        calls["count"] += 1
        return calls["count"] > len(scenario.manifest.files)

    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_directory_update(
            scenario.manifest,
            scenario.staged,
            cancel_callback=cancel_after_verification,
            detached_launcher=claiming_launcher(scenario, []),
            # The reservation is made and released by the calling GUI process.
            **prepare_kwargs(scenario, parent_pid=os.getpid()),
        )

    assert raised.value.code == "cancelled"
    assert read_tree(scenario.target_root)[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD
    assert not directory_module._path_exists(
        scenario.target_root.parent / f".{scenario.target_root.name}.{OTHER_TOKEN}.backup"
    )
    assert scenario.manager.read(scenario.target) is None


def test_startup_confirmation_writes_process_bound_marker(tmp_path):
    scenario = write_directory_scenario(
        tmp_path, state=TransactionState.AWAITING_CONFIRMATION, reserve=False
    )

    write_directory_startup_confirmation(
        scenario.transaction_path,
        version=NEW_VERSION,
        updates_root=scenario.root,
        identity_provider=scenario.identities,
    )

    payload = _read_json(scenario.marker)
    assert payload["transaction_id"] == TOKEN
    assert payload["confirmation_token"] == CONFIRMATION_TOKEN
    assert payload["pid"] == os.getpid()
    assert payload["status"] == "initialized"

    with pytest.raises(UpdateError) as raised:
        write_directory_startup_confirmation(
            scenario.transaction_path,
            version="9.9.9",
            updates_root=scenario.root,
            identity_provider=scenario.identities,
        )
    assert raised.value.code == "transaction_mismatch"


def test_recovery_defers_when_running_from_affected_installation(tmp_path):
    scenario = write_directory_scenario(
        tmp_path, state=TransactionState.REPLACING, reserve=False
    )
    messages: list[str] = []

    summary = recover_stale_directory_updates(
        messages.append,
        updates_root=scenario.root,
        identity_provider=IdentityRegistry(),
        recorded_process_stopper=lambda _pid, _created: None,
        current_executable=scenario.target,
    )

    assert summary.recovered_count == 0
    assert any("runs" in message for message in messages)
    assert read_tree(scenario.target_root)[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD


def test_recovery_skips_transactions_with_a_live_helper(tmp_path):
    scenario = write_directory_scenario(tmp_path, state=TransactionState.REPLACING)

    summary = recover_stale_directory_updates(
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        recorded_process_stopper=lambda _pid, _created: None,
        current_executable=scenario.root / "elsewhere.exe",
    )

    assert summary.recovered_count == 0
    record = scenario.manager.read(scenario.target)
    assert record is not None and record.transaction_id == TOKEN


def test_cleanup_removes_only_old_terminal_transaction_metadata(tmp_path, monkeypatch):
    scenario = write_directory_scenario(
        tmp_path, state=TransactionState.CONFIRMED, reserve=False
    )
    directory_module._remove_tree(scenario.backup)
    directory_module._remove_tree(scenario.staged)
    _atomic_write_json(
        scenario.transaction_path.parent / RESULT_FILENAME,
        {
            "status": "success",
            "message": "done",
            "version": NEW_VERSION,
            "updated_at": "2026-07-01T00:00:00+00:00",
        },
    )
    old_time = 1_500_000_000
    os.utime(scenario.transaction_path.parent / RESULT_FILENAME, (old_time, old_time))

    cleanup_stale_directory_update_state(
        updates_root=scenario.root, successful_retention_days=7
    )

    assert not scenario.transaction_path.exists()
    assert read_tree(scenario.target_root)[ONEFOLDER_EXECUTABLE_NAME] == EXE_PAYLOAD_OLD


def test_transaction_loader_rejects_tampered_paths_and_states(tmp_path):
    scenario = write_directory_scenario(tmp_path, reserve=False)
    payload = _read_json(scenario.transaction_path)

    for field_name, bad_value in (
        ("backup_root", str(tmp_path / "elsewhere-backup")),
        ("new_root", str(tmp_path / "elsewhere-new")),
        ("old_root", str(tmp_path / "elsewhere-old")),
        ("staged_root", str(tmp_path / "elsewhere-package")),
        ("qt_policy", "sneaky"),
        ("state", "not-a-state"),
    ):
        broken = dict(payload)
        broken[field_name] = bad_value
        _atomic_write_json(scenario.transaction_path, broken)
        with pytest.raises(UpdateError):
            load_directory_update_transaction(
                scenario.transaction_path, updates_root=scenario.root
            )

    _atomic_write_json(scenario.transaction_path, payload)
    loaded = load_directory_update_transaction(
        scenario.transaction_path, updates_root=scenario.root
    )
    assert loaded.transaction_id == TOKEN
