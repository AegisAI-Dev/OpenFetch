"""Tests for the short external updater-smoke workspace and its preflight.

Bridge CI failed launching the detached update helper with
``FileNotFoundError: [WinError 206]``. With the workspace below the checkout
(``D:\\a\\NeuralExtractor\\NeuralExtractor\\build\\upd-smoke\\run-...``) the
generated helper path reaches 265 characters — a 64-character target identity
plus a 48-character transaction id below
``local-app-data\\NeuralExtractorV3\\updater-helper`` (now ``OpenFetch``) — so CreateProcess rejects
``lpApplicationName`` against MAX_PATH (260). The command line itself was only
~467 characters, far below the 32767 limit, so the cause is the executable path,
not the command line.

These tests pin the short-external-root design, the preflight that rejects an
unusable workspace before any launch, and the WinError 206 translation.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from scripts import packaged_updater_smoke as smoke

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-onefile-release.yml"
PRODUCTION_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-release.yml"
# The exact CI checkout root that produced WinError 206.
CI_CHECKOUT = Path(r"D:\a\NeuralExtractor\NeuralExtractor")


@pytest.fixture(scope="module")
def bridge_workflow() -> str:
    return BRIDGE_WORKFLOW.read_text(encoding="utf-8")


def _updater_step(workflow: str) -> str:
    return workflow.split(
        "Run simulated previous-version updater handoff and rollback smoke", 1
    )[1].split("- name:", 1)[0]


def _code_lines(block: str) -> str:
    return "\n".join(
        line for line in block.splitlines() if not line.strip().startswith("#")
    )


def test_workflow_no_longer_uses_the_checkout_workspace(bridge_workflow: str):
    code = _code_lines(_updater_step(bridge_workflow))
    assert "build\\upd-smoke" not in code
    assert "build\\upd-in" not in code
    assert 'Join-Path $PWD "build' not in code


def test_workflow_never_uses_temp_roots_for_the_updater_workspace(bridge_workflow: str):
    code = _code_lines(_updater_step(bridge_workflow))
    for forbidden in ("RUNNER_TEMP", "env:TEMP", "env:TMP", "GetTempPath"):
        assert forbidden not in code, f"updater workspace must not use {forbidden}"


def test_workflow_selects_a_short_external_root_and_logs_its_length(bridge_workflow: str):
    code = _code_lines(_updater_step(bridge_workflow))
    assert "--print-selected-root" in code
    assert "$root.Length" in code, "the selected root length must be logged"
    assert 'Join-Path $root "w"' in code
    assert 'Join-Path $root "o.exe"' in code
    assert 'Join-Path $root "n.exe"' in code
    assert "--scenario all" in code


def test_selected_root_is_an_absolute_drive_root_outside_checkout_and_temp(tmp_path):
    root = smoke.select_short_external_root(
        PROJECT_ROOT, temp_root=tmp_path, runner_temp=tmp_path / "runner"
    )
    assert root.is_absolute()
    # <drive>:\neu -> exactly one path component below the drive root.
    assert root.parent == Path(root.anchor)
    assert root.name == smoke.SHORT_ROOT_LEAF
    assert len(str(root)) <= 8
    assert not smoke._is_within(root, PROJECT_ROOT)
    assert not smoke._is_within(root, tmp_path)


def test_root_selection_fails_closed_when_no_root_qualifies(tmp_path):
    with pytest.raises(smoke.SmokeError, match="No short external updater-smoke root"):
        smoke.select_short_external_root(
            tmp_path, temp_root=tmp_path, candidate_roots=[tmp_path]
        )


def test_preflight_passes_for_long_checkout_with_short_external_workspace():
    diagnostics = smoke.preflight_workspace(
        Path(r"D:\neu\w\run-1a2b3c4d"), project_root=CI_CHECKOUT
    )
    assert diagnostics["deepest_path_length"] <= smoke.MAX_WINDOWS_PATH
    assert diagnostics["command_line_length"] <= smoke.MAX_WINDOWS_COMMAND_LINE
    assert diagnostics["deepest_path_name"] == "detached_helper_executable"


def test_preflight_rejects_a_workspace_below_the_checkout():
    with pytest.raises(smoke.SmokeError, match="below the repository checkout"):
        smoke.preflight_workspace(
            CI_CHECKOUT / "build" / "upd-smoke" / "run-57672e49",
            project_root=CI_CHECKOUT,
        )


def test_preflight_rejects_a_workspace_below_temp(tmp_path):
    with pytest.raises(smoke.SmokeError, match="below the temporary root"):
        smoke.preflight_workspace(
            tmp_path / "w" / "run-1", project_root=PROJECT_ROOT, temp_root=tmp_path
        )


def test_preflight_rejects_a_workspace_below_runner_temp(tmp_path):
    runner_temp = tmp_path / "runner-temp"
    with pytest.raises(smoke.SmokeError, match="below RUNNER_TEMP"):
        smoke.preflight_workspace(
            runner_temp / "w",
            project_root=PROJECT_ROOT,
            temp_root=tmp_path / "other-temp",
            runner_temp=runner_temp,
        )


def test_preflight_rejects_a_relative_workspace():
    with pytest.raises(smoke.SmokeError, match="must be absolute"):
        smoke.preflight_workspace(Path("build/upd-smoke"), project_root=PROJECT_ROOT)


def test_preflight_rejects_a_workspace_that_exceeds_max_path():
    """A long external root is still rejected: the limit is the path, not the tree."""
    long_root = Path("D:/") / ("p" * 120) / "w"
    with pytest.raises(smoke.SmokeError, match="MAX_PATH"):
        smoke.preflight_workspace(long_root, project_root=PROJECT_ROOT)


def test_preflight_measures_the_command_line_with_list2cmdline():
    workspace = Path(r"D:\neu\w\run-1a2b3c4d")
    diagnostics = smoke.preflight_workspace(workspace, project_root=CI_CHECKOUT)
    arguments = [entry["value"] for entry in diagnostics["arguments"]]
    assert arguments[1] == "--apply-update"
    assert diagnostics["command_line_length"] == len(subprocess.list2cmdline(arguments))
    # Every argument is measured individually, and the longest is identified.
    assert all("length" in entry for entry in diagnostics["arguments"])
    assert diagnostics["longest_argument_length"] == max(len(a) for a in arguments)
    assert diagnostics["longest_argument"] == max(arguments, key=len)


def test_preflight_reports_every_required_path_measurement():
    diagnostics = smoke.preflight_workspace(
        Path(r"D:\neu\w\run-1a2b3c4d"), project_root=CI_CHECKOUT
    )
    modelled = diagnostics["modelled_paths"]
    for required in (
        "detached_helper_executable",
        "transaction",
        "target",
        "staged_payload",
        "backup",
        "ownership",
        "startup_marker",
        "result",
    ):
        assert required in modelled, f"preflight does not measure {required}"
        assert modelled[required]["length"] > 0
    for key in ("workspace_length", "cwd", "cwd_length", "deepest_path_length"):
        assert key in diagnostics


def test_ci_layout_would_have_exceeded_max_path_but_short_root_does_not():
    """Regression guard for the exact measurement behind the CI failure."""
    failing = smoke.modelled_smoke_paths(
        CI_CHECKOUT / "build" / "upd-smoke" / "run-57672e49",
        app_directory_name=smoke.LEGACY_APP_DIRECTORY_NAME,
    )["detached_helper_executable"]
    fixed = smoke.modelled_smoke_paths(Path(r"D:\neu\w\run-1a2b3c4d"))[
        "detached_helper_executable"
    ]
    assert len(str(failing)) > smoke.MAX_WINDOWS_PATH
    assert len(str(fixed)) <= smoke.MAX_WINDOWS_PATH
    # The shorter OpenFetch data directory helps, but the checkout layout still
    # exceeds the limit, so the short external root remains required.
    still_failing = smoke.modelled_smoke_paths(
        CI_CHECKOUT / "build" / "upd-smoke" / "run-57672e49"
    )["detached_helper_executable"]
    assert len(str(still_failing)) > smoke.MAX_WINDOWS_PATH - 20


def test_winerror_206_is_converted_into_an_actionable_smoke_error():
    helper = Path(r"D:\a\NeuralExtractor\NeuralExtractor\build\upd-smoke") / ("h" * 200)
    arguments = [str(helper), "--apply-update", r"D:\a\x\transaction.json"]
    original = OSError(2, "The filename or extension is too long")
    original.winerror = 206
    error = smoke._long_path_smoke_error(helper, arguments, original)

    assert isinstance(error, smoke.SmokeError)
    message = str(error)
    assert "MAX_PATH" in message
    assert "WinError 206" in message
    assert str(len(str(helper))) in message
    assert "longest argument" in message
    assert "command line" in message
    # It must point at the remedy, not just restate the error.
    assert "short external workspace" in message


def test_smoke_translates_winerror_206_at_the_launch_site():
    source = (PROJECT_ROOT / "scripts" / "packaged_updater_smoke.py").read_text(
        encoding="utf-8"
    )
    launch = source.split("def _run_prepared_update", 1)[1]
    assert 'getattr(exc, "winerror", None) != 206' in launch
    assert "_long_path_smoke_error(" in launch


def test_all_scenarios_remain_enabled():
    source = (PROJECT_ROOT / "scripts" / "packaged_updater_smoke.py").read_text(
        encoding="utf-8"
    )
    for scenario in ("_success_smoke", "_timeout_rollback_smoke", "_concurrency_smoke"):
        assert f"{scenario}(" in source, f"{scenario} was removed"
    for assertion in (
        "Confirmed update did not replace target",
        "Rollback did not restore original target",
        "startup_confirmation_timeout",
        "concurrent_update",
        "Recovered stale",
    ):
        assert assertion in source, f"the smoke lost its {assertion!r} assertion"
    assert '"all", "success", "timeout", "concurrency"' in source


def test_smoke_cleans_stale_state_from_the_short_root():
    source = (PROJECT_ROOT / "scripts" / "packaged_updater_smoke.py").read_text(
        encoding="utf-8"
    )
    main = source.split("def main(", 1)[1]
    assert 'glob("run-*")' in main, "stale smoke roots are not reconciled"
    assert "_terminate_exact_executable" in main
    assert "shutil.rmtree" in main


def test_long_path_support_is_not_globally_enabled_and_no_unc_prefix_hack():
    source = (PROJECT_ROOT / "scripts" / "packaged_updater_smoke.py").read_text(
        encoding="utf-8"
    )
    assert "LongPathsEnabled" not in source
    assert "\\\\\\\\?\\\\" not in source


def test_runtime_and_gui_smoke_fixes_remain_intact(bridge_workflow: str):
    names = re.findall(r"^      - name: (.+)$", bridge_workflow, flags=re.MULTILINE)
    assert "Run packaged runtime smoke" in names
    assert "Run packaged GUI, Unicode and provider smokes" in names
    assert names.index("Run packaged runtime smoke") < names.index(
        "Run packaged GUI, Unicode and provider smokes"
    )
    runtime = bridge_workflow.split("Run packaged runtime smoke", 1)[1].split(
        "- name:", 1
    )[0]
    assert "scripts/packaged_runtime_smoke.py --executable" in runtime
    app = (PROJECT_ROOT / "src" / "openfetch" / "app.py").read_text(
        encoding="utf-8"
    )
    assert "_run_internal_smoke" in app, "the windowed-EXE hang fix was lost"
    loop = bridge_workflow.split("Run packaged GUI, Unicode and provider smokes", 1)[
        1
    ].split("- name:", 1)[0]
    assert "[System.IO.Path]::GetTempPath()" in loop


def test_complete_pytest_command_and_no_workaround(bridge_workflow: str):
    assert "-m pytest tests -q" in bridge_workflow
    for workaround in ("-k ", "--ignore", "--deselect", "-m not ", "--maxfail"):
        assert workaround not in bridge_workflow
    decorator = re.compile(r"^\s*@pytest\.mark\.(skip|skipif|xfail)\b", re.MULTILINE)
    for name in ("test_packaged_updater_workspace.py", "test_onefile_release.py"):
        path = PROJECT_ROOT / "tests" / name
        if path.is_file():
            assert not decorator.search(path.read_text(encoding="utf-8"))


def test_exactly_the_openfetch_asset_family_is_published(bridge_workflow: str):
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
    assert "packaged_updater_smoke" not in production
