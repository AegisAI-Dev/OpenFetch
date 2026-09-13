"""Exercise the one-folder directory updater against a real packaged build.

The smoke runs entirely inside a caller-provided workspace with a redirected
``LOCALAPPDATA``.  It never touches an installed OpenFetch.  Two
scenarios run against the real packaged EXE:

1. ``success``: a full directory update with backup, swap, real detached
   helper, real startup confirmation from the launched GUI (offscreen), and
   post-confirmation cleanup.
2. ``rollback``: the launched application is forced to fail startup with an
   invalid Qt platform, so the helper must restore and verify the previous
   version from the renamed original tree.

The old and new packages are byte-identical copies of the same audited build;
the updater treats them as an upgrade because the installed version is pinned
below the manifest version for the test.  This keeps the smoke offline and
independent of a second release build.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from openfetch.config import VERSION
from openfetch.core.process_control import process_creation_identity
from openfetch.core.update_directory_installer import (
    DIRECTORY_TRANSACTION_FILENAME,
    ONEFOLDER_EXECUTABLE_NAME,
    DirectoryUpdateManifest,
    expected_directory_root_name,
    load_directory_update_transaction,
    prepare_and_launch_directory_update,
)
from openfetch.core.update_installer import RESULT_FILENAME
from openfetch.core.update_ownership import new_transaction_id
from openfetch.core.updater import UpdateError

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PREVIOUS_VERSION = "3.0.7"


class SmokeError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def _taskkill_tree(pid: int) -> None:
    taskkill = str(
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
    )
    subprocess.run(  # noqa: S603 - exact validated PID, no shell
        [taskkill, "/PID", str(pid), "/T", "/F"],
        shell=False,
        check=False,
        capture_output=True,
        timeout=30,
        creationflags=CREATE_NO_WINDOW,
    )


def _copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination)


def _tree_hashes(root: Path) -> dict[str, str]:
    from openfetch.core.update_directory_installer import (
        _hash_file,
        _walk_regular_files,
    )

    return {relative: _hash_file(path) for relative, path in _walk_regular_files(root)}


def _wait_for_result(
    transaction_dir: Path, *, timeout_seconds: float
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    result_path = transaction_dir / RESULT_FILENAME
    while time.monotonic() < deadline:
        if result_path.is_file():
            with contextlib.suppress(OSError, json.JSONDecodeError):
                return json.loads(result_path.read_text(encoding="utf-8"))
        time.sleep(1.0)
    raise SmokeError(f"No updater result appeared within {timeout_seconds}s")


def _stop_recorded_launch(transaction_path: Path, updates_root: Path) -> None:
    with contextlib.suppress(Exception):
        transaction = load_directory_update_transaction(
            transaction_path, updates_root=updates_root
        )
        pid = transaction.launched_pid
        created = transaction.launched_process_created
        if pid and created and process_creation_identity(pid) == created:
            _taskkill_tree(pid)


def _run_scenario(
    *,
    name: str,
    distribution: Path,
    workspace: Path,
    startup_platform: str,
    startup_timeout: int,
    result_timeout: float,
) -> dict[str, object]:
    scenario_root = workspace / name
    appdata = scenario_root / "appdata"
    install = scenario_root / "install"
    fake_temp = scenario_root / "not-the-system-temp"
    appdata.mkdir(parents=True)
    fake_temp.mkdir(parents=True)
    updates_root = appdata / "OpenFetch" / "updates"
    updates_root.mkdir(parents=True)

    _copy_tree(distribution, install)
    original_hashes = _tree_hashes(install)

    root_name = expected_directory_root_name(VERSION)
    staged = updates_root / VERSION / "package" / root_name
    _copy_tree(distribution, staged)
    # Make the staged release differ from the installed one so the swap and
    # the rollback restore are observable tree transitions, not no-ops.
    build_label = staged / "compliance" / "BUILD-LABEL.txt"
    if build_label.is_file():
        build_label.write_text(
            build_label.read_text(encoding="utf-8")
            + f"Updater-smoke-marker: {name}\n",
            encoding="utf-8",
        )
    manifest = DirectoryUpdateManifest.for_distribution_root(
        version=VERSION, root=staged
    )

    child_env = os.environ.copy()
    child_env.update(
        {
            "LOCALAPPDATA": str(appdata),
            "QT_QPA_PLATFORM": startup_platform,
            "OPENFETCH_UPDATER_STARTUP_TIMEOUT_SECONDS": str(startup_timeout),
        }
    )

    def detached_launcher(arguments: list[str]) -> subprocess.Popen[bytes]:
        return subprocess.Popen(  # noqa: S603 - internally constructed helper command
            arguments,
            shell=False,
            close_fds=True,
            env=child_env,
            creationflags=(
                getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            ),
        )

    parent = subprocess.Popen(  # noqa: S603 - controlled sleeper stand-in for the GUI
        [sys.executable, "-c", "import time; time.sleep(600)"],
        shell=False,
        close_fds=True,
        creationflags=CREATE_NO_WINDOW,
    )
    checks: dict[str, bool] = {}
    transaction_path: Path | None = None
    try:
        prepared = prepare_and_launch_directory_update(
            manifest,
            staged,
            parent_pid=parent.pid,
            current_version=PREVIOUS_VERSION,
            transaction_id=new_transaction_id(),
            target_executable=install / ONEFOLDER_EXECUTABLE_NAME,
            frozen=True,
            updates_root=updates_root,
            temporary_root=fake_temp,
            detached_launcher=detached_launcher,
        )
        transaction_path = prepared.transaction_path
        checks["helper_claimed_ownership"] = True
        _require(
            transaction_path.name == DIRECTORY_TRANSACTION_FILENAME,
            "prepared transaction filename is wrong",
        )

        if name == "success":
            try:
                prepare_and_launch_directory_update(
                    manifest,
                    staged,
                    parent_pid=parent.pid,
                    current_version=PREVIOUS_VERSION,
                    transaction_id=new_transaction_id(),
                    target_executable=install / ONEFOLDER_EXECUTABLE_NAME,
                    frozen=True,
                    updates_root=updates_root,
                    temporary_root=fake_temp,
                    detached_launcher=detached_launcher,
                )
                checks["concurrent_update_rejected"] = False
            except UpdateError as exc:
                checks["concurrent_update_rejected"] = exc.code == "concurrent_update"
    finally:
        with contextlib.suppress(Exception):
            parent.kill()
            parent.wait(timeout=30)

    result = _wait_for_result(transaction_path.parent, timeout_seconds=result_timeout)
    status = str(result.get("status"))
    installed_hashes = _tree_hashes(install)
    expected_new = {
        relative: record.sha256 for relative, record in manifest.files.items()
    }

    if name == "success":
        checks["result_status_success"] = status == "success"
        checks["installed_tree_matches_manifest"] = installed_hashes == expected_new
        _stop_recorded_launch(transaction_path, updates_root)
    else:
        checks["result_status_rollback"] = status == "rollback_succeeded"
        checks["original_tree_restored"] = installed_hashes == original_hashes

    leftovers = [
        path.name
        for path in install.parent.iterdir()
        if path.name.startswith(f".{install.name}.") and not path.name.endswith(".backup")
    ]
    checks["no_partial_swap_leftovers"] = leftovers == []

    return {
        "scenario": name,
        "passed": all(checks.values()),
        "checks": checks,
        "result_status": status,
        "transaction": str(transaction_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--startup-timeout", type=int, default=90)
    parser.add_argument("--result-timeout", type=float, default=900.0)
    args = parser.parse_args()

    distribution = args.distribution.resolve()
    _require(
        (distribution / ONEFOLDER_EXECUTABLE_NAME).is_file(),
        f"distribution does not contain {ONEFOLDER_EXECUTABLE_NAME}: {distribution}",
    )
    workspace = args.workspace.resolve()
    _require(
        not workspace.exists() or not any(workspace.iterdir()),
        f"workspace must be new or empty: {workspace}",
    )
    workspace.mkdir(parents=True, exist_ok=True)
    marker = workspace / f"smoke-{uuid.uuid4().hex}.marker"
    marker.write_text("packaged-directory-updater-smoke\n", encoding="utf-8")

    scenarios = []
    scenarios.append(
        _run_scenario(
            name="success",
            distribution=distribution,
            workspace=workspace,
            startup_platform="offscreen",
            startup_timeout=args.startup_timeout,
            result_timeout=args.result_timeout,
        )
    )
    scenarios.append(
        _run_scenario(
            name="rollback",
            distribution=distribution,
            workspace=workspace,
            startup_platform="openfetch-invalid-platform",
            startup_timeout=max(3, min(args.startup_timeout, 30)),
            result_timeout=args.result_timeout,
        )
    )

    passed = all(bool(entry["passed"]) for entry in scenarios)
    payload = {
        "schema_version": 1,
        "smoke": "packaged-directory-updater",
        "application_version": VERSION,
        "passed": passed,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "distribution": str(distribution),
        "scenarios": scenarios,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": passed, "output": str(args.output)}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SmokeError, UpdateError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
