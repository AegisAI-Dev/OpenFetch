"""Tests for the dedicated packaged-runtime-smoke harness and its workflow wiring.

Bridge CI failed the runtime smoke with a bare 90-second timeout and zero
diagnostics. These tests drive ``scripts/packaged_runtime_smoke.py`` against
small real subprocess stubs so every distinguished outcome — success, startup
timeout, check timeout, missing/invalid result, failed checks, and
result-written-but-process-still-running — is exercised for real, and pin the
workflow contract around the new harness.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from scripts import packaged_runtime_smoke as harness

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-onefile-release.yml"
PRODUCTION_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-release.yml"
APP_SOURCE = (PROJECT_ROOT / "src" / "openfetch" / "app.py").read_text(
    encoding="utf-8"
)


def _stub(tmp_path: Path, name: str, body: str) -> list[str]:
    """A stub 'packaged EXE': receives the result path as its last argument."""
    script = tmp_path / f"{name}.py"
    script.write_text(
        "import json, os, sys, time\n"
        "result = sys.argv[-1]\n"
        "trace = result + '.trace'\n"
        "def emit(phase, **extra):\n"
        "    event = {'phase': phase, 'elapsed': 0.0}\n"
        "    event.update(extra)\n"
        "    with open(trace, 'a', encoding='utf-8') as fh:\n"
        "        fh.write(json.dumps(event) + '\\n')\n"
        "        fh.flush()\n"
        "        os.fsync(fh.fileno())\n"
        + textwrap.dedent(body),
        encoding="utf-8",
        newline="\n",
    )
    return [sys.executable, str(script)]


GOOD_RESULT = (
    "emit('process_started'); emit('runtime_smoke_entered')\n"
    "emit('ctypes_callback_complete'); emit('libffi_checks_complete')\n"
    "for tool in ('node', 'ffmpeg', 'ffprobe'):\n"
    "    emit(tool + '_started'); emit(tool + '_finished')\n"
    "payload = {'passed': True, 'checks': {'ctypes_callback': True, 'node_runtime': True}}\n"
    "with open(result, 'w', encoding='utf-8') as fh:\n"
    "    json.dump(payload, fh)\n"
    "emit('result_written'); emit('process_exiting')\n"
    "print('stub-stdout-marker')\n"
    "print('stub-stderr-marker', file=sys.stderr)\n"
)


def test_success_with_clean_exit_passes(tmp_path):
    outcome = harness.run_smoke(
        _stub(tmp_path, "good", GOOD_RESULT),
        workspace=tmp_path / "ws",
        startup_timeout=30,
        check_timeout=30,
        exit_grace=30,
    )
    assert outcome.passed and outcome.kind == "passed"
    assert outcome.details["result_payload"]["passed"] is True
    assert outcome.details["exit_lag_seconds"] >= 0


def test_stdout_and_stderr_are_captured_on_failure(tmp_path):
    body = (
        "print('startup-noise-on-stdout'); sys.stdout.flush()\n"
        "print('startup-noise-on-stderr', file=sys.stderr); sys.stderr.flush()\n"
        "time.sleep(60)\n"
    )
    outcome = harness.run_smoke(
        _stub(tmp_path, "noisy-hang", body),
        workspace=tmp_path / "ws",
        startup_timeout=2,
        check_timeout=5,
        exit_grace=5,
    )
    assert outcome.kind == "startup_timeout"
    assert "startup-noise-on-stdout" in str(outcome.details["stdout"])
    assert "startup-noise-on-stderr" in str(outcome.details["stderr"])


def test_startup_timeout_is_distinguished(tmp_path):
    outcome = harness.run_smoke(
        _stub(tmp_path, "startup-hang", "time.sleep(120)\n"),
        workspace=tmp_path / "ws",
        startup_timeout=2,
        check_timeout=5,
        exit_grace=5,
    )
    assert not outcome.passed
    assert outcome.kind == "startup_timeout"
    assert outcome.details["result_exists"] is False


def test_check_timeout_reports_last_completed_phase(tmp_path):
    body = (
        "emit('process_started'); emit('runtime_smoke_entered')\n"
        "emit('ctypes_callback_complete'); emit('libffi_checks_complete')\n"
        "emit('node_started')\n"
        "time.sleep(120)\n"
    )
    outcome = harness.run_smoke(
        _stub(tmp_path, "check-hang", body),
        workspace=tmp_path / "ws",
        startup_timeout=20,
        check_timeout=2,
        exit_grace=5,
    )
    assert outcome.kind == "check_timeout"
    assert outcome.details["last_phase"] == "node_started"
    assert "node_started" in outcome.message


def test_result_written_but_process_alive_is_a_distinct_failure(tmp_path):
    body = (
        "emit('process_started'); emit('runtime_smoke_entered')\n"
        "with open(result, 'w', encoding='utf-8') as fh:\n"
        "    json.dump({'passed': True, 'checks': {'ctypes_callback': True}}, fh)\n"
        "emit('result_written')\n"
        "time.sleep(120)\n"
    )
    outcome = harness.run_smoke(
        _stub(tmp_path, "no-exit", body),
        workspace=tmp_path / "ws",
        startup_timeout=20,
        check_timeout=20,
        exit_grace=2,
    )
    assert not outcome.passed, "a written result with a surviving process must fail"
    assert outcome.kind == "no_exit_after_result"
    assert outcome.details["result_exists"] is True
    assert outcome.details["result_payload"]["passed"] is True


def test_process_tree_is_terminated_on_timeout(tmp_path):
    child_pid_file = tmp_path / "child-pid.txt"
    body = (
        "import subprocess\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])\n"
        f"open(r'{child_pid_file}', 'w').write(str(child.pid))\n"
        "time.sleep(300)\n"
    )
    outcome = harness.run_smoke(
        _stub(tmp_path, "tree", body),
        workspace=tmp_path / "ws",
        startup_timeout=3,
        check_timeout=5,
        exit_grace=5,
    )
    assert outcome.kind == "startup_timeout"
    child_pid = int(child_pid_file.read_text())
    deadline = time.monotonic() + 20
    alive = True
    while time.monotonic() < deadline:
        query = subprocess.run(
            ["tasklist", "/FI", f"PID eq {child_pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
        alive = str(child_pid) in query.stdout
        if not alive:
            break
        time.sleep(0.5)
    assert not alive, f"child process {child_pid} survived the tree kill"


def test_missing_result_when_process_exits_early_fails(tmp_path):
    outcome = harness.run_smoke(
        _stub(tmp_path, "early-exit", "sys.exit(3)\n"),
        workspace=tmp_path / "ws",
        startup_timeout=20,
        check_timeout=20,
        exit_grace=20,
    )
    assert not outcome.passed
    assert outcome.kind == "result_missing"
    assert "rc=3" in outcome.message


def test_invalid_result_json_fails(tmp_path):
    body = (
        "emit('process_started'); emit('runtime_smoke_entered')\n"
        "open(result, 'w', encoding='utf-8').write('{not json')\n"
        "emit('result_written')\n"
    )
    outcome = harness.run_smoke(
        _stub(tmp_path, "bad-json", body),
        workspace=tmp_path / "ws",
        startup_timeout=20,
        check_timeout=20,
        exit_grace=20,
    )
    assert not outcome.passed
    assert outcome.kind == "invalid_result"


def test_failed_runtime_check_fails_with_names(tmp_path):
    body = (
        "emit('process_started'); emit('runtime_smoke_entered')\n"
        "payload = {'passed': False, 'checks': {'ctypes_callback': True, 'ffmpeg_runtime': False}}\n"
        "with open(result, 'w', encoding='utf-8') as fh:\n"
        "    json.dump(payload, fh)\n"
        "emit('result_written')\n"
        "sys.exit(1)\n"
    )
    outcome = harness.run_smoke(
        _stub(tmp_path, "failing-check", body),
        workspace=tmp_path / "ws",
        startup_timeout=20,
        check_timeout=20,
        exit_grace=20,
    )
    assert not outcome.passed
    assert outcome.kind == "failed_checks"
    assert "ffmpeg_runtime" in outcome.message


def test_arguments_are_passed_as_argv_without_quote_construction(tmp_path):
    source = (PROJECT_ROOT / "scripts" / "packaged_runtime_smoke.py").read_text(
        encoding="utf-8"
    )
    assert "shell=False" in source
    assert "[*argv, str(result_path)]" in source
    # No manual quote assembly anywhere in the harness.
    for smell in ('+ "\\""', "'\\\"' +", "`\\\"", "ArgumentList"):
        assert smell not in source
    # A result path containing spaces must survive intact.
    spaced = tmp_path / "with space"
    outcome = harness.run_smoke(
        _stub(tmp_path, "good-spaced", GOOD_RESULT),
        workspace=spaced,
        startup_timeout=30,
        check_timeout=30,
        exit_grace=30,
    )
    assert outcome.passed


def test_app_runtime_smoke_writes_phase_trace_and_runtime_details(tmp_path, monkeypatch):
    """The in-app smoke (unpackaged) must emit the trace and per-runtime data."""
    import tempfile as tempfile_module

    from openfetch import app as app_module

    monkeypatch.setattr(tempfile_module, "gettempdir", lambda: str(tmp_path))
    result = tmp_path / "runtime.json"
    exit_code = app_module.run_runtime_smoke(str(result))

    payload = json.loads(result.read_text(encoding="utf-8"))
    assert set(payload["checks"]) >= {
        "ctypes_callback",
        "cpython_libffi_3_4_2",
        "cpython_ctypes_extension",
        "loaded_libffi_from_bundle_root",
        "node_runtime",
        "ffmpeg_runtime",
        "ffprobe_runtime",
    }
    assert set(payload["runtime_details"]) == {"node", "ffmpeg", "ffprobe"}
    for detail in payload["runtime_details"].values():
        assert "elapsed" in detail and "returncode" in detail and "timed_out" in detail
        assert "stdout_tail" in detail and "stderr_tail" in detail
    # Unpackaged, the bundle-layout checks fail while the real node/ffmpeg/
    # ffprobe checks pass; the exit code must reflect the aggregate.
    assert exit_code == (0 if payload["passed"] else 1)
    assert payload["checks"]["node_runtime"] is True
    assert payload["checks"]["ffmpeg_runtime"] is True
    assert payload["checks"]["ffprobe_runtime"] is True

    events = [
        json.loads(line)
        for line in (tmp_path / "runtime.json.trace")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    phases = [event["phase"] for event in events]
    for required in (
        "process_started",
        "runtime_smoke_entered",
        "ctypes_callback_complete",
        "libffi_checks_complete",
        "node_started",
        "node_finished",
        "ffmpeg_started",
        "ffmpeg_finished",
        "ffprobe_started",
        "ffprobe_finished",
        "result_written",
        "process_exiting",
    ):
        assert required in phases, f"trace is missing phase {required}"
    assert phases.index("node_started") < phases.index("node_finished")
    assert all(isinstance(event["elapsed"], (int, float)) for event in events)


def test_app_smoke_trace_stays_inside_the_temporary_directory():
    from openfetch import app as app_module

    with pytest.raises(ValueError):
        app_module._internal_smoke_trace_path(r"D:\definitely\not\temp\r.json")


def test_runtime_checks_remain_required_in_the_app():
    for required in (
        '"ctypes_callback"',
        '"cpython_libffi_3_4_2"',
        '"cpython_ctypes_extension"',
        '"loaded_libffi_from_bundle_root"',
        'checks[f"{name}_runtime"]',
        '"node-ok"',
        '"ffmpeg version"',
        '"ffprobe version"',
        "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e",
        "6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41",
    ):
        assert required in APP_SOURCE, f"runtime smoke lost required element {required}"
    assert "passed = all(checks.values())" in APP_SOURCE


# --- Workflow contract -----------------------------------------------------


@pytest.fixture(scope="module")
def bridge_workflow() -> str:
    return BRIDGE_WORKFLOW.read_text(encoding="utf-8")


def test_workflow_runs_the_dedicated_runtime_harness_first(bridge_workflow: str):
    names = re.findall(r"^      - name: (.+)$", bridge_workflow, flags=re.MULTILINE)
    assert "Run packaged runtime smoke" in names
    assert "Run packaged GUI, Unicode and provider smokes" in names
    assert names.index("Run packaged runtime smoke") < names.index(
        "Run packaged GUI, Unicode and provider smokes"
    )
    harness_block = bridge_workflow.split("Run packaged runtime smoke", 1)[1].split(
        "- name:", 1
    )[0]
    assert "scripts/packaged_runtime_smoke.py --executable" in harness_block
    assert "--startup-timeout 240" in harness_block
    assert "--check-timeout 120" in harness_block
    assert "--exit-grace 60" in harness_block
    # The generic loop no longer owns the runtime smoke.
    loop_block = bridge_workflow.split(
        "Run packaged GUI, Unicode and provider smokes", 1
    )[1].split("- name:", 1)[0]
    assert "--internal-runtime-smoke" not in loop_block
    for kept in (
        "--internal-gui-startup-smoke",
        "--internal-windows-gui-smoke",
        "--internal-provider-media-smoke",
        "--internal-youtube-connection-smoke",
    ):
        assert kept in loop_block, f"loop lost smoke {kept}"


def test_workflow_keeps_the_complete_pytest_command(bridge_workflow: str):
    assert "-m pytest tests -q" in bridge_workflow
    for workaround in ("-k ", "--ignore", "--deselect", "-m not ", "--maxfail"):
        assert workaround not in bridge_workflow


def test_no_skip_workaround_added_for_the_runtime_smoke():
    """No test may be silenced with a skip/xfail decorator or a runtime skip."""
    decorator = re.compile(r"^\s*@pytest\.mark\.(skip|skipif|xfail)\b", re.MULTILINE)
    runtime_skip = re.compile(r"^\s*pytest\.skip\(", re.MULTILINE)
    for name in (
        "test_packaged_runtime_smoke.py",
        "test_onefile_release.py",
        "test_packaging_contract.py",
    ):
        text = (PROJECT_ROOT / "tests" / name).read_text(encoding="utf-8")
        assert not decorator.search(text), f"{name} gained a skip/xfail decorator"
        assert not runtime_skip.search(text), f"{name} gained a runtime pytest.skip"


def test_release_publishes_exactly_the_openfetch_asset_family(bridge_workflow: str):
    publish = bridge_workflow.split("Publish the stable OpenFetch release", 1)[1]
    assets = re.findall(r"^            dist/(.+)$", publish, flags=re.MULTILINE)
    assert assets == [
        "OpenFetch.exe",
        "OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe",
        "OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe.sha256",
        "OpenFetch-${{ env.RELEASE_VERSION }}-manifest.json",
    ]
    assert "draft: false" in publish
    assert "prerelease: false" in publish


def test_production_workflow_remains_fail_closed():
    production = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert "Licensing audit status is HOLD. Public build/release is blocked." in production
    for gate in (
        "Release-gate-status: PASS",
        "Audit-blocker-count: 0",
        "Qualified-review-status: PASS",
    ):
        assert gate in production
    assert "packaged_runtime_smoke" not in production

def test_internal_smoke_wrapper_reports_errors_instead_of_hanging(capsys):
    """A windowed EXE must never raise into PyInstaller's modal traceback dialog."""
    from openfetch import app as app_module

    def explode() -> int:
        raise ValueError("Internal smoke result must be written below the temporary directory.")

    code = app_module._run_internal_smoke("runtime", explode)
    captured = capsys.readouterr()

    assert code == 3, "a failing internal smoke must exit non-zero, not hang"
    assert "internal runtime smoke failed" in captured.err
    assert "ValueError" in captured.err


def test_internal_smoke_wrapper_passes_through_success():
    from openfetch import app as app_module

    assert app_module._run_internal_smoke("runtime", lambda: 0) == 0
    assert app_module._run_internal_smoke("runtime", lambda: 1) == 1


def test_every_internal_smoke_entry_point_is_wrapped():
    """All five smokes shared the hang defect, so all five must be guarded."""
    dispatch = APP_SOURCE.split("def main(", 1)[1]
    for flag in (
        "internal_youtube_connection_smoke",
        "internal_provider_media_smoke",
        "internal_gui_startup_smoke",
        "internal_windows_gui_smoke",
        "internal_runtime_smoke",
    ):
        section = dispatch.split(f"args.{flag}", 1)[1].split("if args.", 1)[0]
        assert "_run_internal_smoke(" in section, f"{flag} dispatch is not wrapped"


def test_workflow_smoke_results_use_the_process_temp_directory(bridge_workflow: str):
    """RUNNER_TEMP is not the app's temp root; using it made the app hang."""
    loop = bridge_workflow.split("Run packaged GUI, Unicode and provider smokes", 1)[1].split(
        "- name:", 1
    )[0]
    code_lines = [line for line in loop.splitlines() if not line.strip().startswith("#")]
    joined = "\n".join(code_lines)
    assert "[System.IO.Path]::GetTempPath()" in joined
    assert "RUNNER_TEMP" not in joined, "smoke result paths must not use RUNNER_TEMP"
