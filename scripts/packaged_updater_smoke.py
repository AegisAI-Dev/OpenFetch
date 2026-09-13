"""Run controlled Windows smokes against two packaged OpenFetch EXEs.

The script works only inside a unique caller-provided workspace. It never uses
or replaces an installed OpenFetch executable.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from openfetch.config import APP_NAME, GITHUB_REPO, VERSION
from openfetch.core.process_control import process_creation_identity
from openfetch.core.update_installer import (
    RESULT_FILENAME,
    STARTUP_MARKER_FILENAME,
    TRANSACTION_FILENAME,
    UPDATE_HELPER_FILENAME,
    UpdateTransaction,
    prepare_and_launch_update,
)
from openfetch.core.update_manifest import (
    UpdateManifest,
    expected_exe_filename,
    expected_manifest_filename,
    sha256_file,
)
from openfetch.core.update_ownership import (
    OWNERSHIP_SCHEMA_VERSION,
    OwnershipRecord,
    OwnershipRole,
    TransactionState,
    UpdateOwnershipManager,
    new_transaction_id,
    normalized_target_identity,
)
from openfetch.core.updater import UpdateInfo

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class SmokeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Scenario:
    root: Path
    local_app_data: Path
    updates_root: Path
    helper_root: Path
    target: Path
    staged: Path
    transaction_id: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


# Windows CreateProcess resolves lpApplicationName against MAX_PATH unless the
# caller opts into long paths. The detached updater helper is launched by exact
# path, so that path must stay below this limit on an ordinary Windows install
# where long-path policy may well be disabled.
MAX_WINDOWS_PATH = 260
MAX_WINDOWS_COMMAND_LINE = 32767
SHORT_ROOT_LEAF = "neu"
# Preflight models the worst case, so use the longest scenario directory name.
LONGEST_SCENARIO_NAME = "concurrency"
APP_DIRECTORY_NAME = "OpenFetch"
# The CI failure behind the short-root design was measured with the longer
# pre-rename application directory name.
LEGACY_APP_DIRECTORY_NAME = "NeuralExtractorV3"
DRIVE_FIXED = 3


def _fixed_drive_roots() -> list[Path]:
    """Return the fixed (non-removable, non-network) drive roots."""
    if os.name != "nt":
        return [Path("/")]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    mask = kernel32.GetLogicalDrives()
    roots: list[Path] = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(ord('A') + index)}:\\"
        if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == DRIVE_FIXED:
            roots.append(Path(root))
    return roots


def _is_within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except (ValueError, OSError):
        return False
    return True


def _directory_is_writable(path: Path) -> bool:
    probe = path / f".w{uuid.uuid4().hex[:4]}"
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"w")
        probe.unlink()
    except OSError:
        return False
    return True


def select_short_external_root(
    project_root: Path | None = None,
    *,
    temp_root: Path | None = None,
    runner_temp: Path | None = None,
    candidate_roots: list[Path] | None = None,
) -> Path:
    """Pick the shortest writable fixed-drive root for the updater smoke.

    The updater refuses to install a target inside the temporary root, and a
    workspace below the repository checkout pushes the generated helper path
    past MAX_PATH on GitHub's runners. The smoke therefore needs a very short
    root outside the checkout, outside TEMP/TMP and outside RUNNER_TEMP. Fails
    closed when no such root is writable.
    """
    project_root = Path(os.path.abspath(project_root or Path.cwd()))
    temp_root = Path(os.path.abspath(temp_root or Path(tempfile.gettempdir())))
    drives = candidate_roots if candidate_roots is not None else _fixed_drive_roots()
    # Prefer the drive holding the checkout so staging copies stay on one
    # volume, then the remaining fixed drives in a deterministic order.
    ordered = sorted(
        drives,
        key=lambda drive: (
            0 if str(drive)[:1].upper() == str(project_root.drive)[:1].upper() else 1,
            str(drive).upper(),
        ),
    )
    rejected: list[str] = []
    for drive in ordered:
        candidate = Path(os.path.abspath(drive / SHORT_ROOT_LEAF))
        if _is_within(candidate, temp_root):
            rejected.append(f"{candidate} (inside the temporary root)")
            continue
        if runner_temp is not None and _is_within(candidate, runner_temp):
            rejected.append(f"{candidate} (inside RUNNER_TEMP)")
            continue
        if _is_within(candidate, project_root):
            rejected.append(f"{candidate} (inside the repository checkout)")
            continue
        if not _directory_is_writable(candidate):
            rejected.append(f"{candidate} (not writable)")
            continue
        return candidate
    raise SmokeError(
        "No short external updater-smoke root is available; rejected: "
        + ", ".join(rejected or ["<no fixed drive found>"])
    )


def modelled_smoke_paths(workspace: Path,
    app_directory_name: str = APP_DIRECTORY_NAME,
) -> dict[str, Path]:
    """Model the deepest paths the smoke generates, worst case, without I/O.

    Mirrors ``_scenario`` and ``prepare_and_launch_update`` so preflight can
    reject an unusable workspace before a launch fails inside the updater.
    """
    identity = "f" * 64  # normalized_target_identity is a SHA-256 hex digest
    transaction_id = new_transaction_id()
    scenario_root = workspace / LONGEST_SCENARIO_NAME
    local_app_data = scenario_root / "local-app-data"
    updates_root = local_app_data / app_directory_name / "updates"
    helper_root = local_app_data / app_directory_name / "updater-helper"
    target = scenario_root / "install" / "OpenFetch.exe"
    transaction_dir = updates_root / VERSION / transaction_id
    return {
        "detached_helper_executable": (
            helper_root / identity / transaction_id / UPDATE_HELPER_FILENAME
        ),
        "staged_payload": transaction_dir / "package" / expected_exe_filename(VERSION),
        "transaction": transaction_dir / TRANSACTION_FILENAME,
        "startup_marker": transaction_dir / STARTUP_MARKER_FILENAME,
        "result": transaction_dir / RESULT_FILENAME,
        "ownership": updates_root / "ownership" / f"{identity}.json",
        "backup": target.parent / f".{target.name}.{transaction_id}.backup",
        "target": target,
    }


def preflight_workspace(
    workspace: Path,
    *,
    project_root: Path | None = None,
    temp_root: Path | None = None,
    runner_temp: Path | None = None,
) -> dict[str, object]:
    """Validate the workspace and report every path/command-line measurement.

    Raises ``SmokeError`` with an actionable diagnostic rather than letting
    CreateProcess fail with a bare ``WinError 206`` inside the updater.
    """
    project_root = Path(os.path.abspath(project_root or Path.cwd()))
    temp_root = Path(os.path.abspath(temp_root or Path(tempfile.gettempdir())))

    if not workspace.is_absolute():
        raise SmokeError(f"Updater-smoke workspace must be absolute: {workspace}")
    if _is_within(workspace, temp_root):
        raise SmokeError(
            "Updater-smoke workspace must not be below the temporary root "
            f"({temp_root}); the updater rejects an installation target inside it: {workspace}"
        )
    if runner_temp is not None and _is_within(workspace, runner_temp):
        raise SmokeError(
            f"Updater-smoke workspace must not be below RUNNER_TEMP ({runner_temp}): {workspace}"
        )
    if _is_within(workspace, project_root):
        raise SmokeError(
            "Updater-smoke workspace must not be below the repository checkout "
            f"({project_root}); nested transaction paths then exceed MAX_PATH: {workspace}"
        )
    if not _directory_is_writable(workspace):
        raise SmokeError(f"Updater-smoke workspace is not writable: {workspace}")

    paths = modelled_smoke_paths(workspace)
    helper = paths["detached_helper_executable"]
    arguments = [str(helper), "--apply-update", str(paths["transaction"])]
    command_line = subprocess.list2cmdline(arguments)
    longest_argument = max(arguments, key=len)
    deepest_name, deepest_path = max(paths.items(), key=lambda item: len(str(item[1])))

    diagnostics: dict[str, object] = {
        "workspace": str(workspace),
        "workspace_length": len(str(workspace)),
        "cwd": str(project_root),
        "cwd_length": len(str(project_root)),
        "detached_helper_executable": str(helper),
        "detached_helper_executable_length": len(str(helper)),
        "arguments": [{"value": value, "length": len(value)} for value in arguments],
        "longest_argument": longest_argument,
        "longest_argument_length": len(longest_argument),
        "command_line_length": len(command_line),
        "deepest_path": str(deepest_path),
        "deepest_path_name": deepest_name,
        "deepest_path_length": len(str(deepest_path)),
        "modelled_paths": {
            name: {"path": str(value), "length": len(str(value))}
            for name, value in sorted(paths.items(), key=lambda item: -len(str(item[1])))
        },
        "max_windows_path": MAX_WINDOWS_PATH,
        "max_command_line": MAX_WINDOWS_COMMAND_LINE,
    }

    oversized = {
        name: len(str(value))
        for name, value in paths.items()
        if len(str(value)) > MAX_WINDOWS_PATH
    }
    if oversized:
        raise SmokeError(
            "Updater-smoke workspace produces paths beyond the Windows MAX_PATH limit "
            f"({MAX_WINDOWS_PATH}): "
            + ", ".join(f"{name}={length}" for name, length in sorted(oversized.items()))
            + f". Deepest: {deepest_path} ({len(str(deepest_path))} chars). "
            "Use a shorter external workspace root."
        )
    if len(command_line) > MAX_WINDOWS_COMMAND_LINE:
        raise SmokeError(
            "Detached updater command line exceeds the Windows CreateProcess limit "
            f"({MAX_WINDOWS_COMMAND_LINE}): {len(command_line)} characters"
        )
    return diagnostics


def _long_path_smoke_error(helper: Path, arguments: list[str], exc: OSError) -> SmokeError:
    """Turn a raw WinError 206 into an actionable updater-smoke diagnostic."""
    command_line = subprocess.list2cmdline(arguments)
    longest = max(arguments, key=len) if arguments else ""
    return SmokeError(
        "The detached updater helper could not be launched because its path exceeds the "
        f"Windows MAX_PATH limit ({MAX_WINDOWS_PATH}). "
        f"helper={helper} ({len(str(helper))} chars); "
        f"longest argument={longest} ({len(longest)} chars); "
        f"command line={len(command_line)} chars (limit {MAX_WINDOWS_COMMAND_LINE}); "
        f"original error: WinError {getattr(exc, 'winerror', '?')}: {exc.strerror}. "
        "Run the smoke from a short external workspace root such as D:\\neu\\w."
    )


def _environment(
    scenario: Scenario,
    *,
    startup_timeout_seconds: int | None = None,
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(scenario.local_app_data)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment.pop("OPENFETCH_UPDATER_STARTUP_TIMEOUT_SECONDS", None)
    environment.pop("NEURAL_EXTRACTOR_UPDATER_STARTUP_TIMEOUT_SECONDS", None)
    if startup_timeout_seconds is not None:
        environment["OPENFETCH_UPDATER_STARTUP_TIMEOUT_SECONDS"] = str(
            startup_timeout_seconds
        )
    return environment


def _scenario(base: Path, name: str, target_package: Path, staged_package: Path) -> Scenario:
    root = (base / name).resolve()
    local_app_data = root / "local-app-data"
    updates_root = local_app_data / "OpenFetch" / "updates"
    helper_root = local_app_data / "OpenFetch" / "updater-helper"
    target = root / "install" / "OpenFetch.exe"
    transaction_id = new_transaction_id()
    staged = (
        updates_root
        / VERSION
        / transaction_id
        / "package"
        / expected_exe_filename(VERSION)
    )
    target.parent.mkdir(parents=True)
    staged.parent.mkdir(parents=True)
    shutil.copy2(target_package, target)
    shutil.copy2(staged_package, staged)
    return Scenario(
        root,
        local_app_data,
        updates_root,
        helper_root,
        target,
        staged,
        transaction_id,
    )


def _update_info(staged: Path) -> UpdateInfo:
    size = staged.stat().st_size
    digest = sha256_file(staged)
    manifest = UpdateManifest(
        schema_version=1,
        application_name=APP_NAME,
        release_version=VERSION,
        asset_filename=expected_exe_filename(VERSION),
        asset_sha256=digest,
        asset_size=size,
        platform="windows",
        architecture="x64",
        channel="stable",
        minimum_updater_version=VERSION,
    )
    base_url = f"https://github.com/{GITHUB_REPO}/releases/download/v{VERSION}"
    return UpdateInfo(
        version=VERSION,
        tag_name=f"v{VERSION}",
        name=f"{APP_NAME} v{VERSION}",
        html_url=f"https://github.com/{GITHUB_REPO}/releases/tag/v{VERSION}",
        download_url=f"{base_url}/{manifest.asset_filename}",
        manifest_url=f"{base_url}/{expected_manifest_filename(VERSION)}",
        checksum_url="",
        published_at="",
        body="packaged updater smoke",
        download_size=size,
        sha256=digest,
        manifest=manifest,
    )


def _start_parent(environment: dict[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed interpreter and controlled script
        [sys.executable, "-c", "import time; time.sleep(300)"],
        shell=False,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
        env=environment,
    )


def _stop_parent(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _wait_for_state(transaction_path: Path, states: set[str], timeout: float) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    latest: dict[str, object] = {}
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, json.JSONDecodeError):
            latest = _read_json(transaction_path)
            if latest.get("state") in states:
                return latest
        time.sleep(0.2)
    raise SmokeError(
        f"Transaction did not reach {sorted(states)}; last state={latest.get('state')!r}"
    )


def _wait_for_text(path: Path, text: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, UnicodeError):
            if text in path.read_text(encoding="utf-8"):
                return
        time.sleep(0.2)
    raise SmokeError(f"Timed out waiting for {text!r} in {path}")


def _wait_for_path(path: Path, *, exists: bool, timeout: float, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() is exists:
            return
        time.sleep(0.1)
    expectation = "appear" if exists else "be removed"
    raise SmokeError(f"Timed out waiting for {label} to {expectation}: {path}")


def _wait_for_terminal_cleanup(
    scenario: Scenario,
    transaction_path: Path,
    helper_path: Path,
    *,
    state: TransactionState,
    timeout: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    latest: dict[str, object] = {}
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, json.JSONDecodeError):
            latest = _read_json(transaction_path)
            backup = Path(str(latest.get("backup_executable") or ""))
            marker = Path(str(latest.get("startup_marker") or ""))
            ownership = UpdateOwnershipManager(scenario.updates_root).read(scenario.target)
            if (
                latest.get("state") == state.value
                and not backup.exists()
                and not marker.exists()
                and ownership is None
                and not helper_path.exists()
                and (
                    state != TransactionState.CONFIRMED or not scenario.staged.exists()
                )
            ):
                return latest
        time.sleep(0.2)
    raise SmokeError(
        f"Terminal {state.value} cleanup did not finish; "
        f"last state={latest.get('state')!r}"
    )


def _normalize(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _processes_for_executable(executable: Path) -> list[tuple[int, str]]:
    if os.name != "nt":
        return []
    from ctypes import wintypes

    class ProcessEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32)]
    process_next.restype = wintypes.BOOL
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_image.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise SmokeError(f"Windows process enumeration failed with error {error}")
    expected = _normalize(executable)
    matches: list[tuple[int, str]] = []
    try:
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        has_entry = process_first(snapshot, ctypes.byref(entry))
        while has_entry:
            pid = int(entry.th32ProcessID)
            handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    length = wintypes.DWORD(32_768)
                    buffer = ctypes.create_unicode_buffer(length.value)
                    if query_image(handle, 0, buffer, ctypes.byref(length)) and _normalize(
                        buffer.value
                    ) == expected:
                        identity = process_creation_identity(pid)
                        if identity is not None:
                            matches.append((pid, identity))
                finally:
                    close_handle(handle)
            has_entry = process_next(snapshot, ctypes.byref(entry))
        error = ctypes.get_last_error()
        if error not in {0, 18}:  # ERROR_NO_MORE_FILES is the successful end of enumeration.
            raise SmokeError(f"Windows process enumeration ended with error {error}")
    finally:
        close_handle(snapshot)
    return matches


def _terminate_exact_executable(executable: Path) -> None:
    taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
    for pid, expected_identity in _processes_for_executable(executable):
        try:
            current_identity = process_creation_identity(pid)
        except (OSError, PermissionError) as exc:
            raise SmokeError(f"Could not revalidate controlled process {pid}") from exc
        if current_identity != expected_identity:
            continue
        subprocess.run(  # noqa: S603 - exact enumerated PID and fixed system executable
            [str(taskkill), "/PID", str(pid), "/T", "/F"],
            shell=False,
            check=False,
            capture_output=True,
            timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )


def _wait_for_no_process(executable: Path, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _processes_for_executable(executable):
            return
        time.sleep(0.2)
    raise SmokeError(f"Processes remain for controlled executable {executable}")


def _write_stale_ownership(scenario: Scenario) -> None:
    manager = UpdateOwnershipManager(scenario.updates_root)
    timestamp = datetime.now(UTC).isoformat(timespec="milliseconds")
    record = OwnershipRecord(
        schema_version=OWNERSHIP_SCHEMA_VERSION,
        transaction_id=new_transaction_id(),
        target_identity=normalized_target_identity(scenario.target),
        target_name=scenario.target.name,
        owner_pid=2_147_000_000,
        owner_process_created="a" * 64,
        role=OwnershipRole.INSTALLATION.value,
        state=TransactionState.WAITING_FOR_PARENT_EXIT.value,
        created_at=timestamp,
        heartbeat_at=timestamp,
    )
    path = manager.path_for_target(scenario.target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record.to_dict()), encoding="utf-8")
    (scenario.updates_root / "install.lock").write_text(
        json.dumps(
            {
                "token": new_transaction_id(),
                "owner_pid": 2_147_000_001,
                "transaction": "legacy-stale-transaction",
            }
        ),
        encoding="utf-8",
    )


def _run_prepared_update(
    scenario: Scenario,
    *,
    create_stale_state: bool = False,
    startup_timeout_seconds: int | None = None,
) -> tuple[Path, Path]:
    environment = _environment(
        scenario,
        startup_timeout_seconds=startup_timeout_seconds,
    )
    old_environment = os.environ.copy()
    parent: subprocess.Popen[bytes] | None = None
    original_hash = sha256_file(scenario.target)
    try:
        os.environ.clear()
        os.environ.update(environment)
        parent = _start_parent(environment)
        parent_created = process_creation_identity(parent.pid)
        _require(parent_created is not None, "Fake GUI process identity was unavailable")
        if create_stale_state:
            _write_stale_ownership(scenario)
        try:
            prepared = prepare_and_launch_update(
                _update_info(scenario.staged),
                scenario.staged,
                parent_pid=parent.pid,
                transaction_id=scenario.transaction_id,
                target_executable=scenario.target,
                frozen=True,
                updates_root=scenario.updates_root,
                temporary_root=Path(tempfile.gettempdir()),
                helper_root=scenario.helper_root,
                handoff_timeout=45,
            )
        except OSError as exc:
            # CreateProcess reports ERROR_FILENAME_EXCED_RANGE when the helper
            # executable path exceeds MAX_PATH. Report that precisely instead of
            # surfacing a bare traceback from deep inside the updater.
            if getattr(exc, "winerror", None) != 206:
                raise
            expected_helper = (
                scenario.helper_root
                / normalized_target_identity(scenario.target)
                / scenario.transaction_id
                / UPDATE_HELPER_FILENAME
            )
            transaction_path = (
                scenario.updates_root
                / VERSION
                / scenario.transaction_id
                / TRANSACTION_FILENAME
            )
            raise _long_path_smoke_error(
                expected_helper,
                [str(expected_helper), "--apply-update", str(transaction_path)],
                exc,
            ) from exc
        transaction_path = prepared.transaction_path
        helper_path = (
            scenario.helper_root
            / normalized_target_identity(scenario.target)
            / prepared.transaction_id
            / UPDATE_HELPER_FILENAME
        )
        ownership = UpdateOwnershipManager(scenario.updates_root).read(scenario.target)
        _require(ownership is not None, "Packaged helper did not claim ownership")
        _require(ownership.owner_pid == prepared.helper_pid, "GUI did not report inner helper PID")
        _require(
            ownership.role == OwnershipRole.INSTALLATION.value,
            "Packaged helper claim did not become installation ownership",
        )
        transaction = _read_json(transaction_path)
        backup = Path(str(transaction["backup_executable"]))
        time.sleep(1.0)
        _require(parent.poll() is None, "Controlled GUI parent exited unexpectedly")
        _require(
            sha256_file(scenario.target) == original_hash,
            "Packaged helper replaced the target before its parent exited",
        )
        _require(not backup.exists(), "Packaged helper backed up before its parent exited")
        return transaction_path, helper_path
    finally:
        if parent is not None:
            _stop_parent(parent)
        os.environ.clear()
        os.environ.update(old_environment)


def _success_smoke(base: Path, old_package: Path, new_package: Path) -> dict[str, object]:
    scenario = _scenario(base, "success", old_package, new_package)
    old_hash = sha256_file(scenario.target)
    new_hash = sha256_file(scenario.staged)
    _require(old_hash != new_hash, "Two distinct packaged builds are required for replacement smoke")
    transaction_path, helper_path = _run_prepared_update(scenario, create_stale_state=True)
    prepared_transaction = _read_json(transaction_path)
    backup = Path(str(prepared_transaction["backup_executable"]))
    _wait_for_path(backup, exists=True, timeout=30, label="last known-good backup")
    _wait_for_state(
        transaction_path,
        {TransactionState.CONFIRMED.value},
        timeout=120,
    )
    transaction = _wait_for_terminal_cleanup(
        scenario,
        transaction_path,
        helper_path,
        state=TransactionState.CONFIRMED,
        timeout=45,
    )
    _require(sha256_file(scenario.target) == new_hash, "Confirmed update did not replace target")
    _require(not backup.exists(), "Confirmed update retained its backup")
    _require(
        UpdateOwnershipManager(scenario.updates_root).read(scenario.target) is None,
        "Confirmed update retained ownership",
    )
    _require(not helper_path.exists(), "Confirmed update retained the detached helper copy")
    _terminate_exact_executable(scenario.target)
    _wait_for_no_process(scenario.target)
    _wait_for_no_process(helper_path)
    log = scenario.updates_root / "updater.log"
    _require(log.exists(), "Packaged updater diagnostic log was not created")
    text = log.read_text(encoding="utf-8")
    _require("confirmed successfully" in text, "Packaged success was not logged")
    _require("Recovered stale" in text, "Stale updater state recovery was not logged")
    return {
        "state": transaction["state"],
        "target_sha256": new_hash,
        "stale_recovery": "pass",
        "ownership_cleanup": "pass",
        "helper_cleanup": "pass",
    }


def _build_nonconfirming_stage(scenario: Scenario) -> None:
    source = scenario.root / "nonconfirming-update-target.py"
    dist = scenario.root / "nonconfirming-dist"
    work = scenario.root / "nonconfirming-build"
    specs = scenario.root / "nonconfirming-spec"
    specs.mkdir(parents=True)
    source.write_text(
        "import time\n\ntime.sleep(300)\n",
        encoding="utf-8",
    )
    process = subprocess.run(  # noqa: S603 - fixed interpreter and controlled PyInstaller args
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--windowed",
            "--clean",
            "--noconfirm",
            "--name",
            "OpenFetch-NonConfirming",
            "--distpath",
            str(dist),
            "--workpath",
            str(work),
            "--specpath",
            str(specs),
            str(source),
        ],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=240,
        creationflags=CREATE_NO_WINDOW,
    )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout or "")[-1000:]
        raise SmokeError(f"Controlled nonconfirming package build failed: {detail}")
    built = dist / "OpenFetch-NonConfirming.exe"
    _require(built.is_file(), "Controlled nonconfirming package was not produced")
    shutil.copy2(built, scenario.staged)


def _timeout_rollback_smoke(base: Path, old_package: Path) -> dict[str, object]:
    scenario = _scenario(base, "timeout", old_package, old_package)
    _build_nonconfirming_stage(scenario)
    old_hash = sha256_file(scenario.target)
    staged_hash = sha256_file(scenario.staged)
    _require(old_hash != staged_hash, "Timeout stage unexpectedly matches target")
    transaction_path, helper_path = _run_prepared_update(
        scenario,
        startup_timeout_seconds=3,
    )
    prepared_transaction = _read_json(transaction_path)
    backup = Path(str(prepared_transaction["backup_executable"]))
    _wait_for_path(backup, exists=True, timeout=30, label="rollback backup")
    _wait_for_state(
        transaction_path,
        {TransactionState.ROLLED_BACK.value},
        timeout=120,
    )
    transaction = _wait_for_terminal_cleanup(
        scenario,
        transaction_path,
        helper_path,
        state=TransactionState.ROLLED_BACK,
        timeout=45,
    )
    _require(sha256_file(scenario.target) == old_hash, "Rollback did not restore original target")
    result = _read_json(transaction_path.parent / RESULT_FILENAME)
    _require(result.get("status") == "rollback_succeeded", "Rollback result was not successful")
    _require(
        "startup_confirmation_timeout" in str(result.get("message") or ""),
        "Rollback was not caused by the intended startup-confirmation timeout",
    )
    _require(
        UpdateOwnershipManager(scenario.updates_root).read(scenario.target) is None,
        "Rollback retained ownership",
    )
    _terminate_exact_executable(scenario.target)
    _wait_for_no_process(scenario.target)
    _wait_for_no_process(helper_path)
    return {
        "state": transaction["state"],
        "result": result["status"],
        "failure_code": "startup_confirmation_timeout",
        "restored_sha256": old_hash,
        "ownership_cleanup": "pass",
    }


def _manual_transaction(
    scenario: Scenario,
    transaction_id: str,
    parent_pid: int,
    parent_created: str,
) -> Path:
    transaction_dir = scenario.updates_root / VERSION / transaction_id
    transaction_dir.mkdir(parents=True, exist_ok=True)
    transaction_path = transaction_dir / TRANSACTION_FILENAME
    _require(not transaction_path.exists(), "Manual smoke transaction already exists")
    timestamp = datetime.now(UTC).isoformat(timespec="milliseconds")
    transaction = UpdateTransaction(
        schema_version=2,
        transaction_id=transaction_id,
        confirmation_token=new_transaction_id(),
        state=TransactionState.HANDED_OFF.value,
        expected_version=VERSION,
        expected_sha256=sha256_file(scenario.staged),
        expected_size=scenario.staged.stat().st_size,
        original_sha256=sha256_file(scenario.target),
        parent_pid=parent_pid,
        parent_process_created=parent_created,
        target_identity=normalized_target_identity(scenario.target),
        target_executable=str(scenario.target),
        staged_executable=str(scenario.staged),
        backup_executable=str(
            scenario.target.parent / f".{scenario.target.name}.{transaction_id}.backup"
        ),
        startup_marker=str(transaction_dir / STARTUP_MARKER_FILENAME),
        created_at=timestamp,
        updated_at=timestamp,
        launched_pid=None,
        launched_process_created=None,
    )
    transaction_path.write_text(
        json.dumps(transaction.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return transaction_path


def _concurrency_smoke(
    base: Path,
    old_package: Path,
    new_package: Path,
) -> dict[str, object]:
    scenario = _scenario(base, "concurrency", old_package, new_package)
    environment = _environment(scenario)
    competitor = _start_parent(environment)
    other_parent = _start_parent(environment)
    helper = scenario.root / "helper" / UPDATE_HELPER_FILENAME
    helper.parent.mkdir(parents=True)
    shutil.copy2(new_package, helper)
    process: subprocess.Popen[bytes] | None = None
    process_created: str | None = None
    original_hash = sha256_file(scenario.target)
    try:
        competitor_created = process_creation_identity(competitor.pid)
        other_created = process_creation_identity(other_parent.pid)
        _require(competitor_created is not None, "Competitor identity was unavailable")
        _require(other_created is not None, "Second parent identity was unavailable")
        manager = UpdateOwnershipManager(scenario.updates_root)
        competitor_transaction = new_transaction_id()
        live_record = manager.reserve_handoff(
            competitor_transaction,
            scenario.target,
            parent_pid=competitor.pid,
            parent_process_created=competitor_created,
        )
        second_transaction = scenario.transaction_id
        transaction_path = _manual_transaction(
            scenario,
            second_transaction,
            other_parent.pid,
            other_created,
        )
        process = subprocess.Popen(  # noqa: S603 - controlled packaged helper and transaction
            [str(helper), "--apply-update", str(transaction_path)],
            shell=False,
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
            env=environment,
        )
        process_created = process_creation_identity(process.pid)
        _require(process_created is not None, "Concurrent helper identity was unavailable")
        log = scenario.updates_root / "updater.log"
        _wait_for_text(log, "Updater helper rejected transaction: concurrent_update", timeout=45)
        preserved = manager.read(scenario.target)
        _require(preserved == live_record, "Packaged rejection modified the live competitor")
        _require(
            sha256_file(scenario.target) == original_hash,
            "Rejected concurrent helper modified the target",
        )
        return {
            "rejection": "concurrent_update",
            "competitor_preserved": True,
            "target_unchanged": True,
        }
    finally:
        if process is not None and process.poll() is None:
            taskkill = (
                Path(os.environ.get("SystemRoot", r"C:\Windows"))
                / "System32"
                / "taskkill.exe"
            )
            current_created = process_creation_identity(process.pid)
            if current_created is not None and current_created == process_created:
                subprocess.run(  # noqa: S603 - exact revalidated PID and fixed system executable
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    shell=False,
                    check=False,
                    capture_output=True,
                    timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                )
        _stop_parent(competitor)
        _stop_parent(other_parent)
        UpdateOwnershipManager(scenario.updates_root).recover_stale()
        _wait_for_no_process(helper)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-package", type=Path)
    parser.add_argument("--new-package", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument(
        "--scenario",
        choices=("all", "success", "timeout", "concurrency"),
        default="all",
    )
    parser.add_argument(
        "--print-selected-root",
        action="store_true",
        help=(
            "print the short external smoke root chosen for this machine and exit; "
            "the caller stages packages and the workspace below it"
        ),
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if not args.print_selected_root:
        missing = [
            name
            for name, value in (
                ("--old-package", args.old_package),
                ("--new-package", args.new_package),
                ("--workspace", args.workspace),
            )
            if value is None
        ]
        if missing:
            parser.error(f"the following arguments are required: {', '.join(missing)}")
    return args


def main() -> int:
    if os.name != "nt":
        raise SmokeError("Packaged updater smoke requires Windows")
    args = _parse_args()
    runner_temp = Path(os.environ["RUNNER_TEMP"]) if os.environ.get("RUNNER_TEMP") else None
    if args.print_selected_root:
        root = select_short_external_root(
            args.project_root, runner_temp=runner_temp
        )
        print(str(root))
        return 0
    old_package = args.old_package.resolve()
    new_package = args.new_package.resolve()
    workspace = args.workspace.resolve() / f"run-{uuid.uuid4().hex[:8]}"
    _require(old_package.is_file(), f"Old package is missing: {old_package}")
    _require(new_package.is_file(), f"New package is missing: {new_package}")
    _require(
        workspace.parent == args.workspace.resolve() and workspace.name.startswith("run-"),
        "Smoke workspace is invalid",
    )
    # Validate every generated path and the detached command line before any
    # launch, so an unusable workspace fails with an actionable diagnostic
    # rather than a bare WinError 206 from CreateProcess.
    diagnostics = preflight_workspace(
        workspace,
        project_root=args.project_root,
        runner_temp=runner_temp,
    )
    print(
        "updater-smoke preflight: workspace="
        f"{diagnostics['workspace']} ({diagnostics['workspace_length']} chars), "
        f"deepest={diagnostics['deepest_path_name']} "
        f"({diagnostics['deepest_path_length']} chars, limit {MAX_WINDOWS_PATH}), "
        f"detached command line={diagnostics['command_line_length']} chars "
        f"(limit {MAX_WINDOWS_COMMAND_LINE})",
        flush=True,
    )
    # Remove stale smoke-owned state from this exact root so a previous failed
    # run cannot leave a half-created transaction behind.
    for stale in sorted(workspace.parent.glob("run-*")):
        if stale.is_dir():
            for executable in stale.rglob("*.exe"):
                _terminate_exact_executable(executable)
            shutil.rmtree(stale, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    completed = False
    try:
        results: dict[str, object] = {}
        if args.scenario in {"all", "success"}:
            results["same_transaction_handoff"] = _success_smoke(
                workspace,
                old_package,
                new_package,
            )
        if args.scenario in {"all", "timeout"}:
            results["startup_timeout_rollback"] = _timeout_rollback_smoke(
                workspace,
                old_package,
            )
        if args.scenario in {"all", "concurrency"}:
            results["genuine_concurrency"] = _concurrency_smoke(
                workspace,
                old_package,
                new_package,
            )
        results["elapsed_seconds"] = round(time.monotonic() - started, 2)
        results["status"] = "PASS"
        print(json.dumps(results, indent=2, sort_keys=True))
        completed = True
        return 0
    finally:
        controlled_executables = list(workspace.rglob("*.exe"))
        for executable in controlled_executables:
            _terminate_exact_executable(executable)
        for executable in controlled_executables:
            _wait_for_no_process(executable)
        if completed and workspace.exists():
            shutil.rmtree(workspace)
        elif workspace.exists():
            print(f"FAILED_WORKSPACE={workspace}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
