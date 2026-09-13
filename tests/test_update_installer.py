from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from openfetch.core import update_installer as installer_module
from openfetch.core.update_installer import (
    RESULT_FILENAME,
    STARTUP_MARKER_FILENAME,
    TRANSACTION_FILENAME,
    InstallationCapability,
    UpdateApplier,
    UpdateTransaction,
    assess_installation_capability,
    load_update_transaction,
    prepare_and_launch_update,
    recover_stale_update_ownership,
    write_transaction_startup_confirmation,
)
from openfetch.core.update_manifest import MIN_UPDATE_SIZE_BYTES, UpdateManifest
from openfetch.core.update_ownership import (
    OwnershipRecord,
    OwnershipRole,
    TransactionState,
    UpdateOwnershipManager,
    normalized_target_identity,
)
from openfetch.core.updater import UpdateError, UpdateInfo

REAL_STOP_CHILD_PROCESS = installer_module._stop_child_process

OLD_BYTES = b"O" * MIN_UPDATE_SIZE_BYTES
NEW_BYTES = b"N" * MIN_UPDATE_SIZE_BYTES
VERSION = "3.0.4"
TOKEN = "A" * 48
OTHER_TOKEN = "B" * 48
CONFIRMATION_TOKEN = "C" * 64
PARENT_PID = 4242
WRAPPER_PID = 515_151
STARTED_WRAPPER_PID = 616_161
STARTED_RUNTIME_PID = 717_171


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


@pytest.mark.skipif(os.name != "nt", reason="Windows taskkill tree semantics")
def test_stop_child_process_force_kills_the_exact_validated_windows_tree(monkeypatch):
    process = FakeProcess(pid=STARTED_WRAPPER_PID)
    identities = IdentityRegistry()
    created = identities.register(process.pid, "packaged-wrapper")
    calls: list[list[str]] = []

    def taskkill(arguments, **_kwargs):
        calls.append(arguments)
        identities.remove(process.pid)
        process.poll_result = 0
        return None

    monkeypatch.setattr(installer_module.subprocess, "run", taskkill)

    REAL_STOP_CHILD_PROCESS(
        process,
        expected_identity=created,
        identity_provider=identities,
    )

    assert len(calls) == 1
    assert calls[0][-5:] == [
        str(
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32"
            / "taskkill.exe"
        ),
        "/PID",
        str(process.pid),
        "/T",
        "/F",
    ]


@dataclass
class Scenario:
    root: Path
    transaction_path: Path
    transaction: UpdateTransaction
    target: Path
    staged: Path
    backup: Path
    marker: Path
    identities: IdentityRegistry
    manager: UpdateOwnershipManager
    clock: FakeClock


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

    monkeypatch.setattr(installer_module, "_stop_child_process", safe_stop)


def make_manifest(version=VERSION, content=NEW_BYTES):
    return UpdateManifest(
        schema_version=1,
        application_name="OpenFetch",
        release_version=version,
        asset_filename=f"OpenFetch-{version}-windows-x64.exe",
        asset_sha256=sha256(content),
        asset_size=len(content),
        platform="windows",
        architecture="x64",
        channel="stable",
        minimum_updater_version="3.0.4",
    )


def make_info(manifest):
    version = manifest.release_version
    base = f"https://github.com/AegisAI-Dev/OpenFetch/releases/download/v{version}"
    return UpdateInfo(
        version=version,
        tag_name=f"v{version}",
        name=f"OpenFetch v{version}",
        html_url=f"https://github.com/AegisAI-Dev/OpenFetch/releases/tag/v{version}",
        download_url=f"{base}/{manifest.asset_filename}",
        manifest_url=f"{base}/OpenFetch-{version}-manifest.json",
        checksum_url="",
        published_at="",
        body="",
        download_size=manifest.asset_size,
        sha256=manifest.asset_sha256,
        manifest=manifest,
    )


def write_transaction(
    tmp_path: Path,
    *,
    staged_bytes=NEW_BYTES,
    target_bytes=OLD_BYTES,
    state: TransactionState = TransactionState.HANDED_OFF,
    transaction_id: str = TOKEN,
    executable_stem: str = "OpenFetch",
) -> Scenario:
    root = (tmp_path / "updates").resolve()
    target = (tmp_path / "install" / f"{executable_stem}.exe").resolve()
    target.parent.mkdir(parents=True)
    target.write_bytes(target_bytes)
    staged = root / VERSION / "package" / f"{executable_stem}-{VERSION}-windows-x64.exe"
    staged.parent.mkdir(parents=True)
    staged.write_bytes(staged_bytes)
    transaction_dir = root / VERSION / transaction_id
    transaction_dir.mkdir(parents=True)
    transaction_path = transaction_dir / TRANSACTION_FILENAME
    marker = transaction_dir / STARTUP_MARKER_FILENAME
    backup = target.parent / f".{target.name}.{transaction_id}.backup"

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
    timestamp = datetime(2026, 7, 15, 12, 0, tzinfo=UTC).isoformat()
    transaction = UpdateTransaction(
        schema_version=2,
        transaction_id=transaction_id,
        confirmation_token=CONFIRMATION_TOKEN,
        state=state.value,
        expected_version=VERSION,
        expected_sha256=sha256(NEW_BYTES),
        expected_size=len(NEW_BYTES),
        original_sha256=sha256(OLD_BYTES),
        parent_pid=PARENT_PID,
        parent_process_created=parent_created,
        target_identity=normalized_target_identity(target),
        target_executable=str(target),
        staged_executable=str(staged),
        backup_executable=str(backup),
        startup_marker=str(marker),
        created_at=timestamp,
        updated_at=timestamp,
        launched_pid=None,
        launched_process_created=None,
    )
    installer_module._atomic_write_json(transaction_path, transaction.to_dict())
    manager.reserve_handoff(
        transaction_id,
        target,
        parent_pid=PARENT_PID,
        parent_process_created=parent_created,
    )
    return Scenario(
        root,
        transaction_path,
        transaction,
        target,
        staged,
        backup,
        marker,
        identities,
        manager,
        clock,
    )


def write_confirmation_marker(scenario: Scenario, *, pid=STARTED_RUNTIME_PID, **changes) -> None:
    transaction = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=scenario.root.parent / "not-the-system-temp",
    )
    created = scenario.identities.register(pid, f"started-runtime-{pid}")
    payload = {
        "transaction_id": transaction.transaction_id,
        "confirmation_token": transaction.confirmation_token,
        "version": transaction.expected_version,
        "status": "initialized",
        "pid": pid,
        "process_created": created,
    }
    payload.update(changes)
    installer_module._atomic_write_json(scenario.marker, payload)


def successful_launcher(scenario: Scenario, launches: list[list[str]], *, immediate=False):
    scenario.identities.register(STARTED_WRAPPER_PID, "new-version-wrapper")
    scenario.identities.register(STARTED_RUNTIME_PID, "new-version-runtime")

    def launch(arguments):
        launches.append(arguments)
        if "--post-update-transaction" in arguments:
            if immediate:
                write_confirmation_marker(scenario)
                return FakeProcess(pid=STARTED_WRAPPER_PID)
            return FakeProcess(
                pid=STARTED_WRAPPER_PID,
                on_poll=lambda: write_confirmation_marker(scenario),
            )
        return FakeProcess(pid=STARTED_WRAPPER_PID + 1)

    return launch


def make_applier(scenario: Scenario, launcher, **overrides):
    return UpdateApplier(
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


def test_source_mode_and_temporary_locations_fall_back_to_manual_install(tmp_path):
    manifest = make_manifest()
    target = tmp_path / "OpenFetch.exe"
    target.write_bytes(OLD_BYTES)

    source = assess_installation_capability(manifest, target_executable=target, frozen=False)
    temporary = assess_installation_capability(
        manifest,
        target_executable=target,
        frozen=True,
        temporary_root=tmp_path,
        updates_root=tmp_path / "updates",
    )

    assert isinstance(source, InstallationCapability)
    assert not source.available
    assert "packaged" in source.reason
    assert not temporary.available
    assert "temporary" in temporary.reason


def test_onefolder_install_requires_manual_consent_and_never_uses_exe_replacement(
    tmp_path, monkeypatch
):
    manifest = make_manifest()
    installation = tmp_path / "install"
    installation.mkdir()
    target = installation / "OpenFetch.exe"
    target.write_bytes(OLD_BYTES)
    monkeypatch.setattr(installer_module.sys, "_MEIPASS", str(installation), raising=False)
    monkeypatch.setattr(installer_module.sys, "platform", "win32")

    capability = assess_installation_capability(
        manifest,
        target_executable=target,
        frozen=True,
        updates_root=tmp_path / "updates",
        temporary_root=tmp_path / "different-temporary-root",
    )

    assert not capability.available
    assert capability.code == "onefolder_manual_install_required"
    assert capability.target_executable == target.resolve()
    assert "explicit consent" in capability.reason


def test_capability_reports_insufficient_disk_space(tmp_path, monkeypatch):
    manifest = make_manifest()
    target = tmp_path / "install" / "OpenFetch.exe"
    target.parent.mkdir()
    target.write_bytes(OLD_BYTES)
    monkeypatch.setattr(
        installer_module.shutil,
        "disk_usage",
        lambda _path: type("DiskUsage", (), {"free": 0})(),
    )

    capability = assess_installation_capability(
        manifest,
        target_executable=target,
        frozen=True,
        updates_root=tmp_path / "updates",
        temporary_root=tmp_path / "not-the-system-temp",
    )

    assert not capability.available
    assert capability.code == "insufficient_disk_space"


def test_capability_combines_same_volume_staging_backup_and_helper_space(tmp_path, monkeypatch):
    manifest = make_manifest()
    target = tmp_path / "install" / "OpenFetch.exe"
    target.parent.mkdir()
    target.write_bytes(OLD_BYTES)
    free_bytes = installer_module.DISK_SPACE_MARGIN_BYTES + 3 * MIN_UPDATE_SIZE_BYTES
    monkeypatch.setattr(
        installer_module.shutil,
        "disk_usage",
        lambda _path: type("DiskUsage", (), {"free": free_bytes})(),
    )

    capability = assess_installation_capability(
        manifest,
        target_executable=target,
        frozen=True,
        updates_root=tmp_path / "updates",
        temporary_root=tmp_path / "not-the-system-temp",
    )

    assert not capability.available
    assert capability.code == "insufficient_disk_space"


def test_prepare_handoff_ack_uses_runtime_identity_not_wrapper_pid(tmp_path):
    manifest = make_manifest()
    info = make_info(manifest)
    root = (tmp_path / "updates").resolve()
    target = (tmp_path / "install" / "OpenFetch.exe").resolve()
    target.parent.mkdir()
    target.write_bytes(OLD_BYTES)
    staged = root / VERSION / "package" / manifest.asset_filename
    staged.parent.mkdir(parents=True)
    staged.write_bytes(NEW_BYTES)
    identities = IdentityRegistry()
    runtime_pid = os.getpid()
    identities.register(runtime_pid, "helper-runtime")
    parent_created = identities.register(PARENT_PID, "gui-parent")
    identities.register(WRAPPER_PID, "pyinstaller-wrapper")
    clock = FakeClock()
    manager = UpdateOwnershipManager(
        root,
        identity_provider=identities,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )
    launches: list[list[str]] = []
    handoff_records: list[OwnershipRecord] = []

    def launch(arguments):
        launches.append(arguments)
        handoff = manager.read(target)
        assert handoff is not None
        handoff_records.append(handoff)
        transaction = load_update_transaction(
            Path(arguments[-1]),
            updates_root=root,
            temporary_root=tmp_path / "not-the-system-temp",
        )
        manager.assume_installation(
            transaction.transaction_id,
            target,
            parent_pid=transaction.parent_pid,
            parent_process_created=transaction.parent_process_created,
        )
        return FakeProcess(pid=WRAPPER_PID)

    prepared = prepare_and_launch_update(
        info,
        staged,
        parent_pid=PARENT_PID,
        transaction_id=TOKEN,
        target_executable=target,
        frozen=True,
        updates_root=root,
        temporary_root=tmp_path / "not-the-system-temp",
        helper_root=tmp_path / "helper",
        detached_launcher=launch,
        identity_provider=identities,
        ownership_manager=manager,
        handoff_timeout=1,
    )

    assert prepared.helper_pid == runtime_pid
    assert prepared.helper_pid != WRAPPER_PID
    assert prepared.transaction_id == TOKEN
    assert handoff_records[0].role == OwnershipRole.HANDOFF.value
    assert handoff_records[0].owner_pid == PARENT_PID
    assert handoff_records[0].owner_process_created == parent_created
    assert launches[0][1:] == ["--apply-update", str(prepared.transaction_path)]
    helper = Path(launches[0][0])
    assert helper.name == "OpenFetch-Updater.exe"
    assert helper.read_bytes() == OLD_BYTES
    transaction = load_update_transaction(
        prepared.transaction_path,
        updates_root=root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert transaction.schema_version == 2
    assert transaction.state == TransactionState.HANDED_OFF.value
    assert transaction.confirmation_token not in " ".join(launches[0])
    ownership = manager.read(target)
    assert ownership is not None
    assert ownership.role == OwnershipRole.INSTALLATION.value
    assert ownership.owner_pid == runtime_pid
    assert not (root / "install.lock").exists()


def test_prepare_handoff_timeout_cleans_reservation_and_stops_wrapper(tmp_path, monkeypatch):
    manifest = make_manifest()
    info = make_info(manifest)
    root = (tmp_path / "updates").resolve()
    target = (tmp_path / "install" / "OpenFetch.exe").resolve()
    target.parent.mkdir()
    target.write_bytes(OLD_BYTES)
    staged = root / VERSION / "package" / manifest.asset_filename
    staged.parent.mkdir(parents=True)
    staged.write_bytes(NEW_BYTES)
    identities = IdentityRegistry()
    gui_pid = os.getpid()
    identities.register(gui_pid, "gui-test-runtime")
    clock = FakeClock()
    manager = UpdateOwnershipManager(
        root,
        identity_provider=identities,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )
    wrapper = FakeProcess(pid=WRAPPER_PID)
    stopped = []
    monkeypatch.setattr(
        installer_module,
        "_stop_child_process",
        lambda process, **_kwargs: (stopped.append(process.pid), process.terminate()),
    )

    with pytest.raises(UpdateError) as raised:
        prepare_and_launch_update(
            info,
            staged,
            parent_pid=gui_pid,
            transaction_id=TOKEN,
            target_executable=target,
            frozen=True,
            updates_root=root,
            temporary_root=tmp_path / "not-the-system-temp",
            helper_root=tmp_path / "helper",
            detached_launcher=lambda _arguments: wrapper,
            identity_provider=identities,
            ownership_manager=manager,
            handoff_timeout=0.3,
        )

    assert raised.value.code == "handoff_timeout"
    assert manager.read(target) is None
    assert stopped == [WRAPPER_PID]
    assert wrapper.terminated
    transaction_path = root / VERSION / TOKEN / TRANSACTION_FILENAME
    transaction = load_update_transaction(
        transaction_path,
        updates_root=root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert transaction.state == TransactionState.FAILED.value


def test_successful_apply_waits_backs_up_replaces_restarts_confirms_and_cleans(tmp_path):
    scenario = write_transaction(tmp_path)
    launches: list[list[str]] = []
    process_checks = iter([True, True, False])
    applier = make_applier(
        scenario,
        successful_launcher(scenario, launches),
        process_exists=lambda _pid: next(process_checks),
    )

    result = applier.apply()

    assert result == 0
    assert scenario.target.read_bytes() == NEW_BYTES
    assert not scenario.backup.exists()
    assert not scenario.staged.exists()
    assert not scenario.marker.exists()
    assert scenario.manager.read(scenario.target) is None
    assert launches[0] == [
        str(scenario.target),
        "--post-update-transaction",
        str(scenario.transaction_path),
    ]
    transaction = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert transaction.state == TransactionState.CONFIRMED.value
    assert transaction.launched_pid == STARTED_RUNTIME_PID
    assert transaction.launched_process_created == scenario.identities(STARTED_RUNTIME_PID)
    payload = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert payload["status"] == "success"


def test_confirmed_update_release_failure_is_deferred_without_rollback(tmp_path, monkeypatch):
    scenario = write_transaction(tmp_path)
    launches: list[list[str]] = []
    applier = make_applier(scenario, successful_launcher(scenario, launches))
    monkeypatch.setattr(
        scenario.manager,
        "release",
        lambda _transaction_id, _target: (_ for _ in ()).throw(
            UpdateError("ownership_unavailable", "controlled release failure")
        ),
    )

    assert applier.apply() == 0
    assert scenario.target.read_bytes() == NEW_BYTES
    transaction = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert transaction.state == TransactionState.CONFIRMED.value
    assert not scenario.backup.exists()
    assert scenario.manager.read(scenario.target) is not None
    result = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert result["status"] == "success"


def test_transaction_startup_confirmation_is_bound_to_transaction_and_process(
    tmp_path, monkeypatch
):
    scenario = write_transaction(tmp_path, state=TransactionState.AWAITING_CONFIRMATION)
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "not-the-system-temp"),
    )

    write_transaction_startup_confirmation(
        scenario.transaction_path,
        version=VERSION,
        updates_root=scenario.root,
        identity_provider=scenario.identities,
    )

    payload = json.loads(scenario.marker.read_text(encoding="utf-8"))
    assert payload == {
        "confirmation_token": CONFIRMATION_TOKEN,
        "pid": os.getpid(),
        "process_created": scenario.identities(os.getpid()),
        "status": "initialized",
        "transaction_id": TOKEN,
        "version": VERSION,
    }
    with pytest.raises(UpdateError) as raised:
        write_transaction_startup_confirmation(
            scenario.transaction_path,
            version="9.9.9",
            updates_root=scenario.root,
            identity_provider=scenario.identities,
        )
    assert raised.value.code == "transaction_mismatch"


def test_success_record_failure_keeps_verified_backup_but_releases_ownership(tmp_path, monkeypatch):
    scenario = write_transaction(tmp_path)
    launches: list[list[str]] = []
    applier = make_applier(scenario, successful_launcher(scenario, launches))
    monkeypatch.setattr(
        applier,
        "_write_result",
        lambda _status, _message: (_ for _ in ()).throw(OSError("result blocked")),
    )

    assert applier.apply() == 0
    assert scenario.target.read_bytes() == NEW_BYTES
    assert scenario.backup.exists()
    assert scenario.manager.read(scenario.target) is None


def test_backup_exists_before_replacement_and_transient_lock_is_retried(tmp_path):
    scenario = write_transaction(tmp_path)
    replace_calls = []

    def replace_with_locks(source, destination):
        replace_calls.append((Path(source), Path(destination)))
        assert scenario.backup.exists()
        assert scenario.backup.read_bytes() == OLD_BYTES
        if len(replace_calls) < 3:
            raise PermissionError("transient antivirus lock")
        os.replace(source, destination)

    launches: list[list[str]] = []
    applier = make_applier(
        scenario,
        successful_launcher(scenario, launches),
        replace_file=replace_with_locks,
    )

    assert applier.apply() == 0
    assert len(replace_calls) == 3
    assert scenario.target.read_bytes() == NEW_BYTES


@pytest.mark.parametrize("failure_mode", ["timeout", "early_exit", "launch_failure"])
def test_startup_failures_restore_restart_previous_version_and_clean_ownership(
    tmp_path, failure_mode
):
    scenario = write_transaction(tmp_path)
    launches: list[list[str]] = []
    started: list[FakeProcess] = []
    scenario.identities.register(STARTED_WRAPPER_PID, "failed-new-wrapper")

    def launcher(arguments):
        launches.append(arguments)
        if "--post-update-transaction" in arguments:
            if failure_mode == "launch_failure":
                raise OSError("launch blocked")
            process = FakeProcess(
                pid=STARTED_WRAPPER_PID,
                poll_result=1 if failure_mode == "early_exit" else None,
            )
            started.append(process)
            return process
        return FakeProcess(pid=STARTED_WRAPPER_PID + 1)

    applier = make_applier(scenario, launcher, startup_timeout=0.5)

    assert applier.apply() == 3
    assert scenario.target.read_bytes() == OLD_BYTES
    assert not scenario.backup.exists()
    assert scenario.manager.read(scenario.target) is None
    assert "--update-rollback-status" in launches[-1]
    payload = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert payload["status"] == "rollback_succeeded"
    transaction = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert transaction.state == TransactionState.ROLLED_BACK.value
    if failure_mode == "timeout":
        assert started[0].terminated


def test_rolled_back_update_release_failure_remains_successful_recovery(
    tmp_path, monkeypatch
):
    scenario = write_transaction(tmp_path)
    scenario.identities.register(STARTED_WRAPPER_PID, "failed-new-wrapper")
    launches: list[list[str]] = []

    def launcher(arguments):
        launches.append(arguments)
        return FakeProcess(pid=STARTED_WRAPPER_PID)

    applier = make_applier(scenario, launcher, startup_timeout=0.5)
    monkeypatch.setattr(
        scenario.manager,
        "release",
        lambda _transaction_id, _target: (_ for _ in ()).throw(
            UpdateError("ownership_unavailable", "controlled release failure")
        ),
    )

    assert applier.apply() == 3
    assert scenario.target.read_bytes() == OLD_BYTES
    transaction = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert transaction.state == TransactionState.ROLLED_BACK.value
    assert scenario.manager.read(scenario.target) is not None
    result = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert result["status"] == "rollback_succeeded"


@pytest.mark.parametrize(
    ("staged_bytes", "expected_code"),
    [
        (b"X" * len(NEW_BYTES), "checksum_mismatch"),
        (NEW_BYTES[:-1], "file_size_mismatch"),
    ],
    ids=["checksum-mismatch", "size-mismatch"],
)
def test_invalid_staged_package_never_replaces_target_and_releases_ownership(
    tmp_path, staged_bytes, expected_code
):
    scenario = write_transaction(tmp_path, staged_bytes=staged_bytes)
    launches: list[list[str]] = []
    applier = make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
    )

    assert applier.apply() == 2
    assert scenario.target.read_bytes() == OLD_BYTES
    assert scenario.manager.read(scenario.target) is None
    assert launches and "--update-rollback-status" in launches[-1]
    result = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert result["status"] == "original_preserved"
    assert expected_code in result["message"]


def test_pre_install_failure_waits_for_closing_parent_then_relaunches_original(tmp_path):
    scenario = write_transaction(tmp_path, staged_bytes=b"X" * len(NEW_BYTES))
    process_checks = iter([True, True, False])
    launches: list[list[str]] = []
    applier = make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
        process_exists=lambda _pid: next(process_checks),
    )

    assert applier.apply() == 2
    assert scenario.target.read_bytes() == OLD_BYTES
    assert launches and "--update-rollback-status" in launches[-1]


def test_backup_failure_preserves_relaunches_original_and_releases_ownership(
    tmp_path, monkeypatch
):
    scenario = write_transaction(tmp_path)
    original_copy = installer_module._copy_file_sync
    launches: list[list[str]] = []

    def fail_backup(source, destination):
        if str(destination).endswith(".backup"):
            raise PermissionError("backup blocked")
        return original_copy(source, destination)

    monkeypatch.setattr(installer_module, "_copy_file_sync", fail_backup)
    applier = make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
    )

    assert applier.apply() == 2
    assert scenario.target.read_bytes() == OLD_BYTES
    assert scenario.manager.read(scenario.target) is None
    assert launches and "--update-rollback-status" in launches[-1]


def test_parent_exit_timeout_does_not_launch_duplicate_original_and_cleans_ownership(tmp_path):
    scenario = write_transaction(tmp_path)
    launches: list[list[str]] = []
    applier = make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
        process_exists=lambda _pid: True,
        parent_exit_timeout=0.5,
    )

    assert applier.apply() == 2
    assert scenario.target.read_bytes() == OLD_BYTES
    assert launches == []
    assert scenario.manager.read(scenario.target) is None


def test_rollback_failure_keeps_backup_reports_recovery_and_releases_ownership(tmp_path):
    scenario = write_transaction(tmp_path)
    messages = []
    scenario.identities.register(STARTED_WRAPPER_PID, "failed-new-wrapper")

    def replace_then_block_rollback(source, destination):
        if str(source).endswith(".rollback"):
            raise PermissionError("rollback locked")
        os.replace(source, destination)

    applier = make_applier(
        scenario,
        lambda _arguments: FakeProcess(pid=STARTED_WRAPPER_PID, poll_result=1),
        replace_file=replace_then_block_rollback,
        message_callback=lambda title, message: messages.append((title, message)),
    )

    assert applier.apply() == 4
    assert scenario.backup.exists()
    assert scenario.target.read_bytes() == NEW_BYTES
    assert messages and str(scenario.backup) in messages[0][1]
    assert scenario.manager.read(scenario.target) is None
    payload = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert payload["status"] == "rollback_failed"


def test_different_live_transaction_same_target_is_rejected_and_preserved(tmp_path):
    scenario = write_transaction(tmp_path)
    scenario.identities.remove(PARENT_PID)
    assert scenario.manager.release(TOKEN, scenario.target)
    competitor_pid = 929_292
    competitor_created = scenario.identities.register(competitor_pid, "live-competitor")
    scenario.manager.reserve_handoff(
        OTHER_TOKEN,
        scenario.target,
        parent_pid=competitor_pid,
        parent_process_created=competitor_created,
    )
    applier = make_applier(scenario, lambda _arguments: FakeProcess())

    with pytest.raises(UpdateError) as raised:
        applier.apply()

    assert raised.value.code == "concurrent_update"
    record = scenario.manager.read(scenario.target)
    assert record is not None
    assert record.transaction_id == OTHER_TOKEN
    assert record.owner_pid == competitor_pid


def test_duplicate_helper_for_same_transaction_is_rejected_and_preserved(tmp_path):
    scenario = write_transaction(tmp_path)
    other_helper_pid = 939_393
    other_identity = scenario.identities.register(other_helper_pid, "live-duplicate-helper")
    timestamp = datetime.now(UTC).isoformat()
    record = OwnershipRecord(
        schema_version=1,
        transaction_id=TOKEN,
        target_identity=normalized_target_identity(scenario.target),
        target_name=scenario.target.name,
        owner_pid=other_helper_pid,
        owner_process_created=other_identity,
        role=OwnershipRole.INSTALLATION.value,
        state=TransactionState.WAITING_FOR_PARENT_EXIT.value,
        created_at=timestamp,
        heartbeat_at=timestamp,
    )
    scenario.manager.path_for_target(scenario.target).write_text(
        json.dumps(record.to_dict()), encoding="utf-8"
    )

    with pytest.raises(UpdateError) as raised:
        make_applier(scenario, lambda _arguments: FakeProcess()).apply()

    assert raised.value.code == "duplicate_helper"
    preserved = scenario.manager.read(scenario.target)
    assert preserved is not None
    assert preserved.owner_pid == other_helper_pid


def test_live_updater_for_different_target_does_not_block_installation(tmp_path):
    scenario = write_transaction(tmp_path)
    other_target = (tmp_path / "second-install" / "OpenFetch.exe").resolve()
    other_target.parent.mkdir()
    other_target.write_bytes(OLD_BYTES)
    other_pid = 949_494
    other_created = scenario.identities.register(other_pid, "other-installation-gui")
    scenario.manager.reserve_handoff(
        OTHER_TOKEN,
        other_target,
        parent_pid=other_pid,
        parent_process_created=other_created,
    )
    launches: list[list[str]] = []

    assert make_applier(scenario, successful_launcher(scenario, launches)).apply() == 0
    other_record = scenario.manager.read(other_target)
    assert other_record is not None
    assert other_record.transaction_id == OTHER_TOKEN


def test_gui_crash_before_helper_launch_is_recovered_by_same_transaction(tmp_path):
    scenario = write_transaction(tmp_path)
    scenario.identities.remove(PARENT_PID)
    launches: list[list[str]] = []

    assert make_applier(scenario, successful_launcher(scenario, launches)).apply() == 0
    assert scenario.target.read_bytes() == NEW_BYTES
    assert scenario.manager.read(scenario.target) is None


@pytest.mark.parametrize(
    ("checkpoint", "backup_exists", "target_bytes"),
    [
        (TransactionState.BACKING_UP.value, False, OLD_BYTES),
        (TransactionState.REPLACING.value, True, OLD_BYTES),
    ],
    ids=["before-backup", "after-backup"],
)
def test_crash_checkpoint_before_replacement_resumes_to_confirmed_success(
    tmp_path, checkpoint, backup_exists, target_bytes
):
    scenario = write_transaction(tmp_path)

    def crash(state):
        if state == checkpoint:
            raise SimulatedCrash(state)

    with pytest.raises(SimulatedCrash):
        make_applier(
            scenario,
            lambda _arguments: FakeProcess(),
            fault_hook=crash,
        ).apply()

    persisted = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert persisted.state == checkpoint
    assert scenario.backup.exists() is backup_exists
    assert scenario.target.read_bytes() == target_bytes
    launches: list[list[str]] = []
    assert make_applier(scenario, successful_launcher(scenario, launches)).apply() == 0
    assert scenario.target.read_bytes() == NEW_BYTES
    assert not scenario.backup.exists()
    assert scenario.manager.read(scenario.target) is None


def test_crash_after_replacement_before_launch_resumes_with_safe_rollback(tmp_path):
    scenario = write_transaction(tmp_path)

    def crash(state):
        if state == TransactionState.LAUNCHING.value:
            raise SimulatedCrash(state)

    with pytest.raises(SimulatedCrash):
        make_applier(scenario, lambda _arguments: FakeProcess(), fault_hook=crash).apply()

    assert scenario.target.read_bytes() == NEW_BYTES
    assert scenario.backup.read_bytes() == OLD_BYTES
    launches: list[list[str]] = []
    assert make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
    ).apply() == 3
    assert scenario.target.read_bytes() == OLD_BYTES
    assert "--update-rollback-status" in launches[-1]
    assert scenario.manager.read(scenario.target) is None


def test_crash_awaiting_confirmation_with_valid_marker_resumes_success(tmp_path):
    scenario = write_transaction(tmp_path)
    launched: list[FakeProcess] = []
    scenario.identities.register(STARTED_WRAPPER_PID, "new-version-wrapper")

    def launcher(_arguments):
        write_confirmation_marker(scenario)
        process = FakeProcess(pid=STARTED_WRAPPER_PID)
        launched.append(process)
        return process

    def crash(state):
        if state == TransactionState.AWAITING_CONFIRMATION.value:
            raise SimulatedCrash(state)

    with pytest.raises(SimulatedCrash):
        make_applier(scenario, launcher, fault_hook=crash).apply()

    assert scenario.target.read_bytes() == NEW_BYTES
    assert scenario.backup.read_bytes() == OLD_BYTES
    assert scenario.marker.exists()
    assert make_applier(scenario, lambda _arguments: FakeProcess()).apply() == 0
    assert scenario.target.read_bytes() == NEW_BYTES
    assert not scenario.backup.exists()
    assert not scenario.marker.exists()
    assert scenario.manager.read(scenario.target) is None


def test_crash_awaiting_confirmation_without_marker_stops_child_and_rolls_back(tmp_path):
    scenario = write_transaction(tmp_path)
    unconfirmed = FakeProcess(pid=STARTED_WRAPPER_PID)
    scenario.identities.register(STARTED_WRAPPER_PID, "unconfirmed-new-wrapper")

    def crash(state):
        if state == TransactionState.AWAITING_CONFIRMATION.value:
            raise SimulatedCrash(state)

    with pytest.raises(SimulatedCrash):
        make_applier(
            scenario,
            lambda _arguments: unconfirmed,
            fault_hook=crash,
        ).apply()

    persisted = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=scenario.root.parent / "not-the-system-temp",
    )
    assert persisted.launched_pid == STARTED_WRAPPER_PID
    assert persisted.launched_process_created == scenario.identities(STARTED_WRAPPER_PID)

    def stop_recorded(pid, created):
        assert pid == STARTED_WRAPPER_PID
        assert created == scenario.identities(STARTED_WRAPPER_PID)
        installer_module._stop_child_process(
            unconfirmed,
            expected_identity=created,
            identity_provider=scenario.identities,
        )

    launches: list[list[str]] = []
    assert make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
        recorded_process_stopper=stop_recorded,
    ).apply() == 3
    assert scenario.target.read_bytes() == OLD_BYTES
    assert unconfirmed.terminated or unconfirmed.killed
    assert scenario.manager.read(scenario.target) is None


def test_stale_confirmation_marker_cannot_satisfy_new_transaction(tmp_path):
    scenario = write_transaction(
        tmp_path,
        target_bytes=NEW_BYTES,
        state=TransactionState.AWAITING_CONFIRMATION,
    )
    scenario.backup.write_bytes(OLD_BYTES)
    write_confirmation_marker(
        scenario,
        transaction_id=OTHER_TOKEN,
        confirmation_token="D" * 64,
    )
    launches: list[list[str]] = []

    assert make_applier(
        scenario,
        lambda arguments: launches.append(arguments) or FakeProcess(),
    ).apply() == 3
    assert scenario.target.read_bytes() == OLD_BYTES
    assert not scenario.marker.exists()
    assert scenario.manager.read(scenario.target) is None


def test_transaction_paths_and_confirmation_reference_cannot_escape_update_root(tmp_path):
    scenario = write_transaction(tmp_path)
    payload = scenario.transaction.to_dict()
    payload["target_executable"] = str(scenario.root / "OpenFetch.exe")
    payload["target_identity"] = normalized_target_identity(scenario.root / "OpenFetch.exe")
    installer_module._atomic_write_json(scenario.transaction_path, payload)

    with pytest.raises(UpdateError):
        load_update_transaction(
            scenario.transaction_path,
            updates_root=scenario.root,
            temporary_root=tmp_path / "not-the-system-temp",
        )
    with pytest.raises(UpdateError):
        write_transaction_startup_confirmation(
            tmp_path / "outside" / TRANSACTION_FILENAME,
            version=VERSION,
            updates_root=scenario.root,
            identity_provider=scenario.identities,
        )


def test_transaction_requires_exact_package_marker_and_target_identity(tmp_path):
    scenario = write_transaction(tmp_path)
    alternate = scenario.root / VERSION / "alternate" / scenario.staged.name
    alternate.parent.mkdir(parents=True)
    alternate.write_bytes(NEW_BYTES)
    payload = scenario.transaction.to_dict()
    payload["staged_executable"] = str(alternate)
    installer_module._atomic_write_json(scenario.transaction_path, payload)

    with pytest.raises(UpdateError):
        load_update_transaction(
            scenario.transaction_path,
            updates_root=scenario.root,
            temporary_root=tmp_path / "not-the-system-temp",
        )

    payload = scenario.transaction.to_dict()
    payload["target_identity"] = "f" * 64
    installer_module._atomic_write_json(scenario.transaction_path, payload)
    with pytest.raises(UpdateError) as raised:
        load_update_transaction(
            scenario.transaction_path,
            updates_root=scenario.root,
            temporary_root=tmp_path / "not-the-system-temp",
        )
    assert raised.value.code == "target_mismatch"


def test_installer_source_has_no_shell_true_uac_external_shells_or_confirmation_secret_args():
    source = Path(installer_module.__file__).read_text(encoding="utf-8")
    lowered = source.lower()

    assert "shell=true" not in lowered
    assert '"runas"' not in lowered
    assert "powershell" not in lowered
    assert "cmd.exe" not in lowered
    assert '"--post-update-token"' not in source
    assert '"--post-update-marker"' not in source


def _write_stale_ownership(
    scenario: Scenario,
    state: TransactionState,
    *,
    owner_pid: int = PARENT_PID,
) -> None:
    owner_identity = scenario.identities(owner_pid)
    assert owner_identity is not None
    timestamp = datetime.now(UTC).isoformat()
    record = OwnershipRecord(
        schema_version=1,
        transaction_id=scenario.transaction.transaction_id,
        target_identity=scenario.transaction.target_identity,
        target_name=scenario.target.name,
        owner_pid=owner_pid,
        owner_process_created=owner_identity,
        role=OwnershipRole.INSTALLATION.value,
        state=state.value,
        created_at=timestamp,
        heartbeat_at=timestamp,
    )
    scenario.manager.path_for_target(scenario.target).write_text(
        json.dumps(record.to_dict()), encoding="utf-8"
    )
    scenario.identities.remove(owner_pid)


def _write_recovery_helper(scenario: Scenario, helper_root: Path) -> Path:
    helper = (
        helper_root
        / scenario.transaction.target_identity
        / scenario.transaction.transaction_id
        / installer_module.UPDATE_HELPER_FILENAME
    )
    helper.parent.mkdir(parents=True)
    helper.write_bytes(OLD_BYTES)
    return helper


def test_stale_post_replacement_rebinds_parent_and_hands_same_transaction_to_helper(
    tmp_path, monkeypatch
):
    scenario = write_transaction(
        tmp_path,
        target_bytes=NEW_BYTES,
        state=TransactionState.REPLACING,
    )
    scenario.backup.write_bytes(OLD_BYTES)
    _write_stale_ownership(scenario, TransactionState.REPLACING)
    helper_root = tmp_path / "helper"
    expected_helper = _write_recovery_helper(scenario, helper_root)
    helper_pid = 818_181
    helper_created = scenario.identities.register(helper_pid, "detached-recovery-helper")
    wrapper_created = scenario.identities.register(WRAPPER_PID, "recovery-wrapper")
    launches: list[list[str]] = []
    monkeypatch.setattr(installer_module, "_append_update_log", lambda _message: None)
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "unrelated-system-temp"),
    )

    def launch(arguments):
        launches.append(arguments)
        rebound = load_update_transaction(
            Path(arguments[-1]),
            updates_root=scenario.root,
            temporary_root=tmp_path / "not-the-system-temp",
        )
        assert rebound.transaction_id == TOKEN
        assert rebound.parent_pid == os.getpid()
        assert rebound.parent_process_created == scenario.identities(os.getpid())
        handoff = scenario.manager.read(scenario.target)
        assert handoff is not None
        assert handoff.transaction_id == TOKEN
        assert handoff.role == OwnershipRole.HANDOFF.value
        claimed = OwnershipRecord(
            schema_version=handoff.schema_version,
            transaction_id=handoff.transaction_id,
            target_identity=handoff.target_identity,
            target_name=handoff.target_name,
            owner_pid=helper_pid,
            owner_process_created=helper_created,
            role=OwnershipRole.INSTALLATION.value,
            state=TransactionState.WAITING_FOR_PARENT_EXIT.value,
            created_at=handoff.created_at,
            heartbeat_at=datetime.now(UTC).isoformat(),
        )
        scenario.manager.path_for_target(scenario.target).write_text(
            json.dumps(claimed.to_dict()), encoding="utf-8"
        )
        return FakeProcess(pid=WRAPPER_PID)

    summary = recover_stale_update_ownership(
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        detached_launcher=launch,
        helper_root=helper_root,
        handoff_timeout=0.5,
    )

    assert summary.recovered_count == 1
    assert summary.shutdown_required is True
    assert launches == [[str(expected_helper.resolve()), "--apply-update", str(scenario.transaction_path)]]
    persisted = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert persisted.transaction_id == TOKEN
    assert persisted.parent_pid == os.getpid()
    assert persisted.parent_process_created == scenario.identities(os.getpid())
    live_helper = scenario.manager.read(scenario.target)
    assert live_helper is not None
    assert live_helper.transaction_id == TOKEN
    assert live_helper.owner_pid == helper_pid
    assert live_helper.owner_process_created == helper_created
    assert live_helper.role == OwnershipRole.INSTALLATION.value
    assert scenario.identities(WRAPPER_PID) == wrapper_created


def test_stale_recovery_launch_failure_preserves_gui_owned_recovery_claim(
    tmp_path, monkeypatch
):
    scenario = write_transaction(
        tmp_path,
        target_bytes=NEW_BYTES,
        state=TransactionState.REPLACING,
    )
    scenario.backup.write_bytes(OLD_BYTES)
    _write_stale_ownership(scenario, TransactionState.REPLACING)
    helper_root = tmp_path / "helper"
    _write_recovery_helper(scenario, helper_root)
    logs: list[str] = []
    monkeypatch.setattr(installer_module, "_append_update_log", lambda _message: None)
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "unrelated-system-temp"),
    )

    def fail_launch(_arguments):
        raise OSError("controlled recovery launch failure")

    summary = recover_stale_update_ownership(
        logs.append,
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        detached_launcher=fail_launch,
        helper_root=helper_root,
        handoff_timeout=0.5,
    )

    assert summary.recovered_count == 1
    assert summary.shutdown_required is False
    recovery_record = scenario.manager.read(scenario.target)
    assert recovery_record is not None
    assert recovery_record.transaction_id == TOKEN
    assert recovery_record.owner_pid == os.getpid()
    assert recovery_record.owner_process_created == scenario.identities(os.getpid())
    assert scenario.backup.read_bytes() == OLD_BYTES
    assert scenario.target.read_bytes() == NEW_BYTES
    persisted = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert persisted.parent_pid == os.getpid()
    assert persisted.parent_process_created == scenario.identities(os.getpid())
    assert any("retained recovery files after OSError" in message for message in logs)


def test_invalid_utf8_stale_transaction_is_bounded_and_preserves_recovery_claim(
    tmp_path, monkeypatch
):
    scenario = write_transaction(
        tmp_path,
        target_bytes=NEW_BYTES,
        state=TransactionState.REPLACING,
    )
    scenario.backup.write_bytes(OLD_BYTES)
    scenario.transaction_path.write_bytes(b"\xffinvalid-transaction")
    _write_stale_ownership(scenario, TransactionState.REPLACING)
    logs: list[str] = []
    monkeypatch.setattr(installer_module, "_append_update_log", lambda _message: None)

    summary = recover_stale_update_ownership(
        logs.append,
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        detached_launcher=lambda _arguments: pytest.fail("invalid transaction must not launch"),
        helper_root=tmp_path / "helper",
    )

    assert summary.recovered_count == 1
    assert summary.shutdown_required is False
    record = scenario.manager.read(scenario.target)
    assert record is not None
    assert record.transaction_id == TOKEN
    assert record.owner_pid == os.getpid()
    assert scenario.transaction_path.read_bytes() == b"\xffinvalid-transaction"
    assert scenario.backup.read_bytes() == OLD_BYTES
    assert scenario.target.read_bytes() == NEW_BYTES
    assert any("retained recovery files after UpdateError" in message for message in logs)


def test_stale_completed_rollback_is_finalized_and_releases_recovery_ownership(
    tmp_path, monkeypatch
):
    scenario = write_transaction(tmp_path, state=TransactionState.ROLLING_BACK)
    scenario.backup.write_bytes(OLD_BYTES)
    scenario.marker.write_text("stale marker", encoding="utf-8")
    _write_stale_ownership(scenario, TransactionState.ROLLING_BACK)
    logs: list[str] = []
    monkeypatch.setattr(installer_module, "_append_update_log", lambda _message: None)
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "unrelated-system-temp"),
    )

    summary = recover_stale_update_ownership(
        logs.append,
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        detached_launcher=lambda _arguments: pytest.fail("rollback finalization must not launch"),
        helper_root=tmp_path / "helper",
    )

    assert summary.recovered_count == 1
    assert summary.shutdown_required is False
    persisted = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert persisted.state == TransactionState.ROLLED_BACK.value
    result = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert result["status"] == "rollback_succeeded"
    assert scenario.target.read_bytes() == OLD_BYTES
    assert not scenario.backup.exists()
    assert not scenario.marker.exists()
    assert scenario.manager.read(scenario.target) is None
    assert any("completed updater rollback" in message for message in logs)


@pytest.mark.parametrize(
    ("state", "target_bytes", "expected_status"),
    [
        (TransactionState.CONFIRMED, NEW_BYTES, "success"),
        (TransactionState.ROLLED_BACK, OLD_BYTES, "rollback_succeeded"),
    ],
    ids=["confirmed", "rolled-back"],
)
def test_terminal_stale_state_finishes_cleanup_and_releases_ownership(
    tmp_path, monkeypatch, state, target_bytes, expected_status
):
    scenario = write_transaction(tmp_path, target_bytes=target_bytes, state=state)
    scenario.backup.write_bytes(OLD_BYTES)
    scenario.marker.write_text("stale marker", encoding="utf-8")
    _write_stale_ownership(scenario, state)
    monkeypatch.setattr(installer_module, "_append_update_log", lambda _message: None)
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "unrelated-system-temp"),
    )

    summary = recover_stale_update_ownership(
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        detached_launcher=lambda _arguments: pytest.fail("terminal cleanup must not launch"),
        helper_root=tmp_path / "helper",
    )

    assert summary.recovered_count == 1
    assert summary.shutdown_required is False
    result = json.loads((scenario.transaction_path.parent / RESULT_FILENAME).read_text())
    assert result["status"] == expected_status
    assert not scenario.backup.exists()
    if state == TransactionState.ROLLED_BACK:
        assert scenario.staged.read_bytes() == NEW_BYTES
    else:
        assert not scenario.staged.exists()
    assert not scenario.marker.exists()
    assert scenario.manager.read(scenario.target) is None


def test_malformed_ownership_binds_to_one_valid_transaction_and_releases_claim(
    tmp_path, monkeypatch
):
    scenario = write_transaction(tmp_path, state=TransactionState.BACKING_UP)
    ownership_path = scenario.manager.path_for_target(scenario.target)
    ownership_path.write_text("{malformed", encoding="utf-8")
    logs: list[str] = []
    monkeypatch.setattr(installer_module, "_append_update_log", lambda _message: None)
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "unrelated-system-temp"),
    )

    summary = recover_stale_update_ownership(
        logs.append,
        updates_root=scenario.root,
        identity_provider=scenario.identities,
        detached_launcher=lambda _arguments: pytest.fail("pre-replacement recovery must not launch"),
        helper_root=tmp_path / "helper",
    )

    assert summary.recovered_count == 1
    assert summary.shutdown_required is False
    persisted = load_update_transaction(
        scenario.transaction_path,
        updates_root=scenario.root,
        temporary_root=tmp_path / "not-the-system-temp",
    )
    assert persisted.transaction_id == TOKEN
    assert persisted.state == TransactionState.FAILED.value
    assert scenario.manager.read(scenario.target) is None
    assert not any("could not be bound" in message for message in logs)
