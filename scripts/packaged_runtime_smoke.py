"""Supervise the packaged runtime smoke with phase-aware, fail-closed handling.

The generic workflow loop launched ``OpenFetch.exe
--internal-runtime-smoke`` through ``Start-Process`` with a single 90-second
``WaitForExit`` and no visibility: on timeout it could not say whether one-file
extraction stalled, a bundled runtime hung, the result JSON already existed, or
the process simply had not finished deleting its extraction directory.

This harness owns the smoke lifecycle instead:

* the packaged EXE is started with ``shell=False`` and the result path is
  passed as a plain ``argv`` element (no manual quote construction anywhere);
* stdout and stderr are captured continuously;
* three separately bounded phases replace the single opaque timeout —
  startup (process spawn until the in-app trace reports
  ``runtime_smoke_entered``, which for a one-file build covers archive
  extraction and imports), checks (until ``result_written``), and exit grace
  (until the parent process exits after writing the result);
* on any timeout, diagnostics are collected BEFORE the process tree is killed:
  the phase trace, result-file state, the EXE pid, and every surviving child
  process with its executable name;
* outcomes are distinguished explicitly: startup timeout, check timeout,
  missing result, invalid JSON, failed runtime check, and the
  result-written-but-process-still-running case, which is a failure — a smoke
  is not successful while its process is still alive;
* temporary smoke files are removed after a successful run and kept for
  inspection otherwise.

Stdlib only, so the workflow can run it without PYTHONPATH.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_STARTUP_TIMEOUT = 240.0
DEFAULT_CHECK_TIMEOUT = 120.0
DEFAULT_EXIT_GRACE = 60.0
POLL_INTERVAL = 0.25
RUNTIME_CHILD_NAMES = {"node.exe", "ffmpeg.exe", "ffprobe.exe"}


@dataclass
class SmokeOutcome:
    kind: str
    message: str
    passed: bool
    details: dict[str, object] = field(default_factory=dict)


def default_argv(executable: Path) -> list[str]:
    """Base command; the harness appends the result path as its own element."""
    return [str(executable), "--internal-runtime-smoke"]


def read_trace(trace_path: Path) -> list[dict[str, object]]:
    if not trace_path.is_file():
        return []
    events: list[dict[str, object]] = []
    try:
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    except OSError:
        return events
    return events


def last_phase(events: list[dict[str, object]]) -> str:
    return str(events[-1].get("phase")) if events else "<no trace events>"


def has_phase(events: list[dict[str, object]], phase: str) -> bool:
    return any(event.get("phase") == phase for event in events)


def list_child_processes(parent_pid: int) -> list[dict[str, object]]:
    """Enumerate direct and transitive children via Toolhelp32 (stdlib only)."""
    if sys.platform != "win32":
        return []

    class ProcessEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.wintypes.ULONG)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.wintypes.LONG),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        return []
    rows: list[tuple[int, int, str]] = []
    try:
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(ProcessEntry32)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                rows.append(
                    (int(entry.th32ProcessID), int(entry.th32ParentProcessID), entry.szExeFile)
                )
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)

    wanted = {parent_pid}
    children: list[dict[str, object]] = []
    # Two passes are enough for the shallow trees this smoke can create.
    for _ in range(2):
        for pid, ppid, name in rows:
            if ppid in wanted and pid not in wanted:
                wanted.add(pid)
                children.append({"pid": pid, "parent_pid": ppid, "name": name})
    return children


def kill_process_tree(pid: int) -> None:
    if sys.platform != "win32":
        return
    taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
    subprocess.run(  # noqa: S603 - fixed system tool, numeric PID argument
        [str(taskkill), "/PID", str(pid), "/T", "/F"],
        shell=False,
        check=False,
        capture_output=True,
        timeout=60,
    )


def collect_diagnostics(
    process: subprocess.Popen[str],
    result_path: Path,
    trace_path: Path,
    stdout_tail: list[str],
    stderr_tail: list[str],
) -> dict[str, object]:
    events = read_trace(trace_path)
    result_exists = result_path.is_file()
    result_payload: object = None
    if result_exists:
        try:
            result_payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result_payload = f"<unreadable: {exc}>"
    children = list_child_processes(process.pid)
    return {
        "exe_pid": process.pid,
        "exit_code": process.poll(),
        "result_exists": result_exists,
        "result_payload": result_payload,
        "trace_events": events,
        "last_phase": last_phase(events),
        "children": children,
        "runtime_children_alive": sorted(
            {str(child["name"]) for child in children if str(child["name"]).casefold() in RUNTIME_CHILD_NAMES}
        ),
        "stdout": "".join(stdout_tail)[-2000:],
        "stderr": "".join(stderr_tail)[-2000:],
    }


def run_smoke(
    argv: list[str],
    *,
    workspace: Path,
    startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
    check_timeout: float = DEFAULT_CHECK_TIMEOUT,
    exit_grace: float = DEFAULT_EXIT_GRACE,
) -> SmokeOutcome:
    workspace.mkdir(parents=True, exist_ok=True)
    result_path = workspace / "r.json"
    trace_path = workspace / "r.json.trace"
    for stale in (result_path, trace_path):
        stale.unlink(missing_ok=True)

    command = [*argv, str(result_path)]
    stdout_tail: list[str] = []
    stderr_tail: list[str] = []
    started = time.monotonic()
    process = subprocess.Popen(  # noqa: S603 - caller-controlled packaged EXE
        command,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    def pump(stream: object, sink: list[str]) -> None:
        try:
            for line in stream:  # type: ignore[union-attr]
                sink.append(line)
        except (OSError, ValueError):
            pass

    threads = [
        threading.Thread(target=pump, args=(process.stdout, stdout_tail), daemon=True),
        threading.Thread(target=pump, args=(process.stderr, stderr_tail), daemon=True),
    ]
    for thread in threads:
        thread.start()

    def elapsed() -> float:
        return time.monotonic() - started

    def fail(kind: str, message: str) -> SmokeOutcome:
        diagnostics = collect_diagnostics(
            process, result_path, trace_path, stdout_tail, stderr_tail
        )
        if process.poll() is None:
            kill_process_tree(process.pid)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                diagnostics["kill_failed"] = True
        diagnostics["elapsed"] = round(elapsed(), 1)
        return SmokeOutcome(kind=kind, message=message, passed=False, details=diagnostics)

    # Phase 1: startup — one-file extraction, interpreter start, app import.
    entered_at: float | None = None
    while True:
        events = read_trace(trace_path)
        if has_phase(events, "runtime_smoke_entered") or result_path.is_file():
            entered_at = elapsed()
            break
        if process.poll() is not None:
            return fail(
                "result_missing",
                f"packaged process exited (rc={process.returncode}) during startup "
                "without entering the runtime smoke",
            )
        if elapsed() > startup_timeout:
            return fail(
                "startup_timeout",
                f"packaged process did not reach runtime_smoke_entered within "
                f"{startup_timeout:.0f}s (one-file extraction/import stall)",
            )
        time.sleep(POLL_INTERVAL)

    # Phase 2: checks — until the result JSON is written.
    while not result_path.is_file():
        if process.poll() is not None:
            return fail(
                "result_missing",
                f"packaged process exited (rc={process.returncode}) before writing "
                "the smoke result",
            )
        if elapsed() - entered_at > check_timeout:
            return fail(
                "check_timeout",
                f"runtime checks did not finish within {check_timeout:.0f}s; "
                f"last completed phase: {last_phase(read_trace(trace_path))}",
            )
        time.sleep(POLL_INTERVAL)
    result_at = elapsed()

    # Phase 3: exit grace — the parent must terminate after writing the result
    # (for a one-file build this includes deleting its extraction directory).
    while process.poll() is None:
        if elapsed() - result_at > exit_grace:
            return fail(
                "no_exit_after_result",
                f"smoke result was written at {result_at:.1f}s but the packaged "
                f"process is still running {exit_grace:.0f}s later; a smoke is "
                "not successful while its process survives",
            )
        time.sleep(POLL_INTERVAL)
    exited_at = elapsed()
    for thread in threads:
        thread.join(timeout=5)

    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail("invalid_result", f"smoke result is not valid JSON: {exc}")
    if not isinstance(payload, dict) or not isinstance(payload.get("checks"), dict):
        return fail("invalid_result", "smoke result JSON has an unexpected shape")

    events = read_trace(trace_path)
    timings = {
        "startup_seconds": round(entered_at, 1),
        "result_seconds": round(result_at, 1),
        "exit_seconds": round(exited_at, 1),
        "exit_lag_seconds": round(exited_at - result_at, 1),
        "trace_events": events,
    }
    failed_checks = sorted(
        name for name, value in payload["checks"].items() if value is not True
    )
    if failed_checks or payload.get("passed") is not True or process.returncode != 0:
        return SmokeOutcome(
            kind="failed_checks",
            message=(
                f"runtime smoke reported failed checks: {failed_checks or '<none>'} "
                f"(passed={payload.get('passed')}, rc={process.returncode})"
            ),
            passed=False,
            details={**timings, "result_payload": payload},
        )

    outcome = SmokeOutcome(
        kind="passed",
        message=(
            f"runtime smoke passed: startup {entered_at:.1f}s, result {result_at:.1f}s, "
            f"exit {exited_at:.1f}s (cleanup lag {exited_at - result_at:.1f}s)"
        ),
        passed=True,
        details={**timings, "result_payload": payload},
    )
    return outcome


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--startup-timeout", type=float, default=DEFAULT_STARTUP_TIMEOUT)
    parser.add_argument("--check-timeout", type=float, default=DEFAULT_CHECK_TIMEOUT)
    parser.add_argument("--exit-grace", type=float, default=DEFAULT_EXIT_GRACE)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="short scratch directory; default is a fresh directory under TEMP",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    executable = args.executable.resolve()
    if not executable.is_file():
        print(f"RUNTIME-SMOKE FAIL: executable does not exist: {executable}")
        return 1
    workspace = args.workspace or Path(tempfile.mkdtemp(prefix="nev3-rt-"))
    outcome = run_smoke(
        default_argv(executable),
        workspace=workspace,
        startup_timeout=args.startup_timeout,
        check_timeout=args.check_timeout,
        exit_grace=args.exit_grace,
    )
    if outcome.passed:
        print(f"RUNTIME-SMOKE PASS: {outcome.message}")
        shutil.rmtree(workspace, ignore_errors=True)
        return 0
    print(f"RUNTIME-SMOKE FAIL [{outcome.kind}]: {outcome.message}")
    print(json.dumps(outcome.details, indent=2, sort_keys=True, default=str))
    print(f"smoke files kept for inspection under: {workspace}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
