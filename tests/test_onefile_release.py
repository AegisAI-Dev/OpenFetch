"""Contract tests for the owner-authorized OpenFetch one-file release workflow.

The workflow replaces the V3.0.8-only family bridge workflow, which could not
publish any later version and so left every installed build without a reachable
update. These tests pin the guarantees that keep the generic workflow safe:
exact manual inputs read only from the environment, default-branch and new-tag
requirements, no hardcoded version, a stable release with exactly the OpenFetch
and legacy-compatible updater assets, prohibited-hash and payload-boundary
rejection, both manifests verified against one executable, and the real updater
handoff and rollback smokes.

They also pin that this path does NOT weaken the compliance-gated production
workflow and does not flip any audit status to PASS.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from openfetch.config import VERSION
from openfetch.core.update_manifest import (
    LEGACY_RELEASE,
    OPENFETCH_RELEASE,
    UpdateManifest,
    UpdateValidationError,
    is_newer_version,
)
from openfetch.core.updater import UpdateChecker
from scripts import verify_packaged_licensing as packaged

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ONEFILE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-onefile-release.yml"
PRODUCTION_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-release.yml"
ONEFILE_SPEC = PROJECT_ROOT / "OpenFetch-onefile.spec"
LEGACY_308_SHA256 = "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac"
LEGACY_304_SHA256 = "02fbde8845bcb7b8946a44f320aa1f88a63a70ceac9765f800276ce11bfa6ed7"
# Published in this (canonical) repository.
RELEASE_ASSETS = (
    "OpenFetch.exe",
    "OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe",
    "OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe.sha256",
    "OpenFetch-${{ env.RELEASE_VERSION }}-manifest.json",
)
# Built here from the same executable, published by the owner in the bridge
# repository that keeps the pre-rename name.
BRIDGE_ASSETS = (
    "NeuralExtractorV3-${{ env.RELEASE_VERSION }}-windows-x64.exe",
    "NeuralExtractorV3-${{ env.RELEASE_VERSION }}-windows-x64.exe.sha256",
    "NeuralExtractorV3-${{ env.RELEASE_VERSION }}-manifest.json",
)


@pytest.fixture(scope="module")
def onefile_workflow() -> str:
    return ONEFILE_WORKFLOW.read_text(encoding="utf-8")


def _step(workflow: str, name: str) -> str:
    return workflow.split(name, 1)[1].split("- name:", 1)[0]


def _run_blocks(workflow: str) -> str:
    return "\n".join(
        block.split("\n      - name:", 1)[0] for block in workflow.split("run: |")[1:]
    )


def test_workflow_runs_only_on_manual_dispatch(onefile_workflow: str):
    assert "workflow_dispatch:" in onefile_workflow
    trigger_block = onefile_workflow.split("permissions:", 1)[0]
    assert re.search(r"(?m)^on:\s*$", trigger_block)
    for forbidden in ("push:", "schedule:", "pull_request:", "release:", "tags:"):
        assert forbidden not in trigger_block, f"release workflow must not trigger on {forbidden}"


def test_workflow_requires_version_and_confirmation_inputs(onefile_workflow: str):
    assert "version:" in onefile_workflow
    assert "confirmation:" in onefile_workflow
    assert onefile_workflow.count("required: true") >= 2
    assert "RELEASE_VERSION: ${{ github.event.inputs.version }}" in onefile_workflow
    assert "RELEASE_CONFIRMATION: ${{ github.event.inputs.confirmation }}" in onefile_workflow
    assert 'RELEASE_CONFIRMATION_PREFIX: "PUBLISH-OPENFETCH-"' in onefile_workflow


def test_inputs_are_validated_from_the_environment_and_never_interpolated(
    onefile_workflow: str,
):
    validation = _step(onefile_workflow, "Validate release inputs")
    assert "$version = $env:RELEASE_VERSION" in validation
    assert "$confirmation = $env:RELEASE_CONFIRMATION" in validation
    assert "'^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'" in validation
    assert '$expectedConfirmation = "$($env:RELEASE_CONFIRMATION_PREFIX)$version"' in validation
    assert validation.count("exit 1") >= 3
    # Workflow inputs may only be copied into env, never expanded inside scripts.
    assert "github.event.inputs" not in _run_blocks(onefile_workflow)


def test_no_release_version_is_hardcoded(onefile_workflow: str):
    assert "3.0.8" not in onefile_workflow
    assert "BRIDGE_VERSION" not in onefile_workflow
    assert "PUBLISH-FAMILY-BRIDGE" not in onefile_workflow
    assert "scripts/release_tools.py validate --release-ref $env:RELEASE_TAG" in onefile_workflow


def test_workflow_requires_default_branch(onefile_workflow: str):
    assert "github.event.repository.default_branch" in onefile_workflow
    assert "must run from the repository default branch" in onefile_workflow


def test_workflow_rejects_an_existing_tag(onefile_workflow: str):
    assert "git.getRef" in onefile_workflow
    assert "tags/${tag}" in onefile_workflow
    assert "const tag = process.env.RELEASE_TAG;" in onefile_workflow
    assert "already exists" in onefile_workflow
    assert "core.setFailed" in onefile_workflow
    assert "error.status !== 404" in onefile_workflow


def test_workflow_publishes_only_the_openfetch_family_in_this_repository(
    onefile_workflow: str,
):
    publish_block = onefile_workflow.split("Publish the stable OpenFetch release", 1)[1]
    assets = re.findall(r"^            dist/(.+)$", publish_block, flags=re.MULTILINE)
    assert assets == list(RELEASE_ASSETS)
    # Legacy-named assets must never be published here: installed Neural
    # Extractor updaters cannot reach this repository at all.
    for bridge_asset in BRIDGE_ASSETS:
        assert bridge_asset not in publish_block
    assert "windows-x64.zip" not in publish_block
    assert "corresponding-source" not in publish_block
    assert "build_inputs" not in publish_block
    assert "Compare-Object $expected $actual" in onefile_workflow
    assert "must contain exactly the seven updater assets" in onefile_workflow


def test_workflow_builds_and_hands_over_the_bridge_assets(onefile_workflow: str):
    """The bridge release is published by the owner, never cross-repository."""
    assert 'BRIDGE_REPOSITORY: "AegisAI-Dev/NeuralExtractor"' in onefile_workflow
    artifact_block = _step(onefile_workflow, "Upload workflow artifact")
    for asset in RELEASE_ASSETS + BRIDGE_ASSETS:
        assert f"dist/{asset}" in artifact_block, f"artifact is missing {asset}"
    procedure = _step(onefile_workflow, "Report the legacy bridge release procedure")
    assert "gh release create v$version" in procedure
    assert "--repo $($env:BRIDGE_REPOSITORY)" in procedure
    assert "NeuralExtractorV3-$version-windows-x64.exe" in procedure
    assert "NeuralExtractorV3-$version-manifest.json" in procedure
    # No cross-repository publication may happen automatically.
    assert "--repo" not in onefile_workflow.split("Publish the stable OpenFetch release", 1)[1]


def test_asset_names_match_what_both_updater_families_request():
    assert OPENFETCH_RELEASE.exe_filename(VERSION) == f"OpenFetch-{VERSION}-windows-x64.exe"
    assert OPENFETCH_RELEASE.manifest_filename(VERSION) == f"OpenFetch-{VERSION}-manifest.json"
    assert LEGACY_RELEASE.exe_filename(VERSION) == f"NeuralExtractorV3-{VERSION}-windows-x64.exe"
    assert LEGACY_RELEASE.manifest_filename(VERSION) == f"NeuralExtractorV3-{VERSION}-manifest.json"
    assert LEGACY_RELEASE.checksum_filename(VERSION) == (
        f"NeuralExtractorV3-{VERSION}-windows-x64.exe.sha256"
    )


def test_release_is_stable_not_draft_or_prerelease(onefile_workflow: str):
    publish_block = onefile_workflow.split("Publish the stable OpenFetch release", 1)[1]
    assert "draft: false" in publish_block
    assert "prerelease: false" in publish_block
    assert 'make_latest: "true"' in publish_block
    assert "tag_name: ${{ env.RELEASE_TAG }}" in publish_block
    assert "body_path: docs/release-notes/V${{ env.RELEASE_VERSION }}.md" in publish_block


def test_workflow_validates_before_building_and_publishing(onefile_workflow: str):
    order = [
        "Validate release inputs",
        "Configure byte-stable Git checkout",
        "Checkout default branch",
        "Require a new release tag",
        "Confirm source version matches the requested release",
        "Install locked dependencies",
        "Stage pinned Node, FFmpeg and ffprobe",
        "Reconstruct and verify pinned offline build inputs",
        "Validate source, tests and manifests",
        "Build the one-file OpenFetch EXE",
        "Confirm packaged version",
        "Run packaged runtime smoke",
        "Run packaged GUI, Unicode and provider smokes",
        "Run simulated previous-version updater handoff and rollback smoke",
        "Scan the packaged EXE for PyQt6 and provider payloads",
        "Scan outputs for prohibited legacy hashes",
        "Generate OpenFetch and legacy-compatible updater assets",
        "Verify both manifests against the final EXE",
        "Publish the stable OpenFetch release",
    ]
    positions = [onefile_workflow.index(step) for step in order]
    assert positions == sorted(positions), "release workflow steps are out of order"
    for command in (
        "-m ruff check src tests scripts main.py",
        "-m compileall -q src scripts main.py",
        "-m pytest tests -q",
        "scripts/generate_project_metadata.py --check",
        "scripts/generate_compliance_manifests.py --check",
        "scripts/verify_distribution_boundary.py .",
    ):
        assert command in onefile_workflow, f"release workflow is missing: {command}"


def test_workflow_waits_for_the_windowed_exe_when_checking_version(onefile_workflow: str):
    """PowerShell does not wait for a GUI-subsystem process invoked directly."""
    version_block = _step(onefile_workflow, "Confirm packaged version")
    assert "Start-Process" in version_block
    assert "-Wait" in version_block
    assert "-RedirectStandardOutput" in version_block
    assert "$process.ExitCode -ne 0" in version_block
    assert 'OpenFetch $($env:RELEASE_VERSION)' in version_block
    code_lines = [
        line for line in version_block.splitlines() if not line.strip().startswith("#")
    ]
    assert not any('& "dist\\OpenFetch.exe" --version' in line for line in code_lines)


def test_workflow_rejects_both_prohibited_hashes(onefile_workflow: str):
    assert LEGACY_308_SHA256 in onefile_workflow
    assert LEGACY_304_SHA256 in onefile_workflow
    scan_block = _step(onefile_workflow, "Scan outputs for prohibited legacy hashes")
    assert "$env:PROHIBITED_LEGACY_SHA256_A" in scan_block
    assert "$env:PROHIBITED_LEGACY_SHA256_B" in scan_block
    assert "Prohibited legacy artifact detected" in scan_block
    assert '@("dist", "build")' in scan_block
    assert "-Recurse -File -Force" in scan_block
    assert "exit 1" in scan_block


def test_workflow_builds_clean_from_source_without_local_artifacts(onefile_workflow: str):
    build_block = _step(onefile_workflow, "Build the one-file OpenFetch EXE")
    assert "Remove-Item dist -Recurse -Force" in build_block
    assert "OpenFetch-onefile.spec" in build_block
    assert "--clean --noconfirm" in build_block
    assert "Quarantined Legacy Builds" not in onefile_workflow


def test_workflow_generates_both_manifests_with_their_updater_floors(onefile_workflow: str):
    assert 'OPENFETCH_MINIMUM_UPDATER_VERSION: "3.1.0"' in onefile_workflow
    assert 'LEGACY_MINIMUM_UPDATER_VERSION: "3.0.4"' in onefile_workflow
    generate_block = _step(onefile_workflow, "Generate OpenFetch and legacy-compatible updater assets")
    assert '@{ Naming = "openfetch"; Prefix = "OpenFetch"' in generate_block
    assert '@{ Naming = "legacy"; Prefix = "NeuralExtractorV3"' in generate_block
    assert (
        "scripts/release_tools.py manifest --naming $family.Naming --version $version "
        "--exe $versioned --output $manifest --minimum-updater-version $family.Minimum"
    ) in generate_block
    assert "--bridge-boundary" in generate_block
    verify_block = _step(onefile_workflow, "Verify both manifests against the final EXE")
    for assertion in (
        'Application = "OpenFetch"',
        'Application = "Neural Extractor V3"',
        "versioned EXE differs from dist\\OpenFetch.exe",
        "asset_sha256 -ne $actualHash",
        "asset_size -ne $actualSize",
        "asset_filename -ne",
        'channel -ne "stable"',
        "minimum_updater_version -ne $family.Minimum",
        "docs\\release-notes\\V$version.md",
    ):
        assert assertion in verify_block, f"manifest verification is missing: {assertion}"


def test_workflow_logs_the_hold_warning(onefile_workflow: str):
    warning = "Owner-authorized OpenFetch one-file release. General compliance status remains HOLD."
    assert onefile_workflow.count(warning) >= 2
    assert f"::warning::{warning}" in onefile_workflow


def test_workflow_never_edits_compliance_documents(onefile_workflow: str):
    for forbidden in (
        "Qualified-review-status: PASS",
        "Release-gate-status: PASS",
        "Audit-blocker-count: 0",
        "public_distribution_verdict",
    ):
        assert forbidden not in onefile_workflow, f"release workflow must not write {forbidden}"
    for document in (
        "THIRD_PARTY_NOTICES.md",
        "THIRD_PARTY_LICENSES.txt",
        "docs/DEPENDENCY-SOURCE.md",
        "docs\\DEPENDENCY-SOURCE.md",
        "docs/LGPL-COMPLIANCE.md",
    ):
        assert f"Set-Content {document}" not in onefile_workflow
        assert f"Out-File {document}" not in onefile_workflow


def test_production_workflow_remains_fail_closed_and_separate():
    production = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert "Enforce licensing release gate" in production
    assert "Licensing audit status is HOLD. Public build/release is blocked." in production
    for gate in (
        "Release-gate-status: PASS",
        "Audit-blocker-count: 0",
        "Qualified-review-status: PASS",
    ):
        assert gate in production, f"production gate lost its {gate} requirement"
    assert "OpenFetch.spec" in production
    assert "OpenFetch-onefile.spec" not in production
    assert "PUBLISH-OPENFETCH" not in production
    assert "PUBLISH-FAMILY-BRIDGE" not in production


def test_onefile_spec_builds_one_file_without_pyqt_or_provider_payloads():
    spec = ONEFILE_SPEC.read_text(encoding="utf-8")
    assert "exclude_binaries=True" not in spec
    assert "COLLECT(" not in spec
    assert "a.binaries," in spec and "a.datas," in spec
    for excluded in ("PyQt5", "PyQt6", "yt_dlp_plugins", "bgutil_ytdlp_pot_provider"):
        assert excluded in spec, f"one-file spec must exclude {excluded}"
    for pinned in (
        "39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636",
        "6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e",
        "55a3d20229c2373dade4362215c9bd5a04b59d4e734d0bbb882afd9cea4fb046",
        "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e",
        "6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41",
    ):
        assert pinned in spec
    assert "noarchive=False" in spec
    assert "upx=False" in spec
    assert 'raise SystemExit(\n        "GPL provider sources are present' in spec
    assert "OpenFetch.spec" in spec
    assert "name=EXECUTABLE_STEM," in spec
    assert 'config_constant("VERSION")' in spec
    assert '"OpenFetch.ico"' in spec


def _onefile_archive(monkeypatch):
    """A valid one-file archive plus the bundled runtimes the release EXE must ship."""
    from tests.test_distribution_verifiers import _valid_archive

    archive = _valid_archive(monkeypatch)
    for runtime in packaged.BRIDGE_REQUIRED_RUNTIME_PATHS:
        key = runtime.replace("/", "\\")
        payload = f"runtime:{runtime}".encode()
        archive.payloads[key] = payload
        archive.toc[key] = (0, len(payload), len(payload), 0, "b")
    return archive


def test_boundary_accepts_a_provider_free_onefile_archive(monkeypatch):
    assert packaged.verify_bridge_boundary(_onefile_archive(monkeypatch)) == []


def test_boundary_scan_rejects_pyqt_and_provider_payloads(monkeypatch):
    from tests.test_distribution_verifiers import FakePyz

    for path, expected in (
        ("PyQt6\\QtCore.pyd", "PyQt code or binary"),
        ("vendor\\bgutil-ytdlp-pot-provider\\LICENSE", "in-process provider code"),
        ("payload\\generate_once.js", "raw JavaScript/TypeScript"),
        ("payload\\generate_once.ts.map", "raw JavaScript/TypeScript"),
        ("node_modules\\canvas\\build\\Release\\canvas.node", "canvas native"),
    ):
        tainted = _onefile_archive(monkeypatch)
        tainted.payloads[path] = b"payload"
        tainted.toc[path] = (0, 7, 7, 0, "b")
        errors = packaged.verify_bridge_boundary(tainted)
        assert any(expected in error for error in errors), f"{path} was not rejected"

    for modules, expected in (
        (("PySide6", "PyQt6"), "PyQt module is forbidden"),
        (("PySide6", "getpot_bgutil"), "provider module is forbidden"),
        (("PySide6", "yt_dlp_plugins.extractor.getpot_bgutil"), "provider module is forbidden"),
    ):
        tainted_pyz = _onefile_archive(monkeypatch)
        tainted_pyz.pyz = FakePyz(modules)
        errors = packaged.verify_bridge_boundary(tainted_pyz)
        assert any(expected in error for error in errors), f"{modules} was not rejected"


def test_boundary_requires_bundled_runtimes(monkeypatch):
    for runtime in packaged.BRIDGE_REQUIRED_RUNTIME_PATHS:
        stripped = _onefile_archive(monkeypatch)
        key = runtime.replace("/", "\\")
        del stripped.payloads[key]
        del stripped.toc[key]
        errors = packaged.verify_bridge_boundary(stripped)
        assert any(
            "missing bundled runtime payloads" in error and runtime in error
            for error in errors
        ), f"{runtime} removal was not rejected"


def test_boundary_requires_notices_and_audited_qt_payload(monkeypatch):
    stripped_notice = _onefile_archive(monkeypatch)
    del stripped_notice.payloads["THIRD_PARTY_NOTICES.md"]
    del stripped_notice.toc["THIRD_PARTY_NOTICES.md"]
    assert any(
        "missing required compliance paths" in error and "THIRD_PARTY_NOTICES.md" in error
        for error in packaged.verify_bridge_boundary(stripped_notice)
    )

    unaudited_qt = _onefile_archive(monkeypatch)
    unaudited_qt.payloads["PySide6\\Qt6Pdf.dll"] = b"unaudited"
    unaudited_qt.toc["PySide6\\Qt6Pdf.dll"] = (0, 9, 9, 0, "b")
    assert any(
        "unaudited PySide6/Qt paths" in error
        for error in packaged.verify_bridge_boundary(unaudited_qt)
    )


def test_boundary_cli_rejects_prohibited_legacy_hash(tmp_path, monkeypatch):
    artifact = tmp_path / "legacy.exe"
    artifact.write_bytes(b"legacy payload")
    monkeypatch.setattr(
        packaged,
        "PROHIBITED_LEGACY_SHA256S",
        frozenset({hashlib.sha256(b"legacy payload").hexdigest()}),
    )

    assert packaged.verify_bridge(artifact) == ["artifact is a prohibited legacy one-file EXE"]


def test_installed_neural_extractor_updaters_detect_the_source_release():
    for installed in ("3.0.4", "3.0.5", "3.0.6", "3.0.7", "3.0.8"):
        assert is_newer_version(VERSION, installed)
    assert not is_newer_version(VERSION, VERSION)


def _release_payload(version: str, *, exe_size: int, draft=False, prerelease=False):
    base = f"https://github.com/AegisAI-Dev/OpenFetch/releases/download/v{version}"
    assets = []
    for naming in (OPENFETCH_RELEASE, LEGACY_RELEASE):
        assets.extend(
            [
                {
                    "name": naming.exe_filename(version),
                    "browser_download_url": f"{base}/{naming.exe_filename(version)}",
                    "size": exe_size,
                },
                {
                    "name": naming.manifest_filename(version),
                    "browser_download_url": f"{base}/{naming.manifest_filename(version)}",
                    "size": 512,
                },
                {
                    "name": naming.checksum_filename(version),
                    "browser_download_url": f"{base}/{naming.checksum_filename(version)}",
                    "size": 107,
                },
            ]
        )
    return {
        "tag_name": f"v{version}",
        "name": f"OpenFetch v{version}",
        "draft": draft,
        "prerelease": prerelease,
        "html_url": f"https://github.com/AegisAI-Dev/OpenFetch/releases/tag/v{version}",
        "published_at": "2026-09-13T00:00:00Z",
        "body": "release",
        "assets": assets,
    }


def _manifest(version: str, exe_bytes: bytes, *, minimum: str) -> UpdateManifest:
    return UpdateManifest(
        schema_version=1,
        application_name="OpenFetch",
        release_version=version,
        asset_filename=OPENFETCH_RELEASE.exe_filename(version),
        asset_sha256=hashlib.sha256(exe_bytes).hexdigest(),
        asset_size=len(exe_bytes),
        platform="windows",
        architecture="x64",
        channel="stable",
        minimum_updater_version=minimum,
    )


def test_openfetch_updater_accepts_a_future_release_from_this_workflow():
    exe_bytes = b"release payload" * 100_000
    checker = UpdateChecker()
    candidate = checker.parse_release(
        _release_payload("3.1.1", exe_size=len(exe_bytes)), current_version="3.1.0"
    )
    assert candidate is not None
    assert candidate.exe_url.endswith("/OpenFetch-3.1.1-windows-x64.exe")

    info = checker.bind_manifest(
        candidate, _manifest("3.1.1", exe_bytes, minimum="3.1.0").to_json(), "3.1.0"
    )
    assert info.version == "3.1.1"
    assert info.download_size == len(exe_bytes)


def test_updater_ignores_a_draft_or_prerelease_release():
    """This is why the workflow must publish a stable release."""
    checker = UpdateChecker()
    for flags in ({"draft": True}, {"prerelease": True}):
        assert (
            checker.parse_release(
                _release_payload("3.1.1", exe_size=2_000_000, **flags), current_version="3.1.0"
            )
            is None
        )


def test_openfetch_manifest_floor_above_the_installed_updater_is_rejected():
    exe_bytes = b"release payload" * 100_000
    document = _manifest("3.1.1", exe_bytes, minimum="3.1.1").to_json()
    with pytest.raises(UpdateValidationError) as excinfo:
        UpdateManifest.from_json(document, release_version="3.1.1", current_version="3.1.0")
    assert excinfo.value.code == "updater_too_old"


def test_workflow_drives_the_real_updater_replacement_and_rollback_smokes(
    onefile_workflow: str,
):
    smoke_block = _step(
        onefile_workflow, "Run simulated previous-version updater handoff and rollback smoke"
    )
    assert "scripts/packaged_updater_smoke.py" in smoke_block
    assert "--scenario all" in smoke_block
    assert "simulated-previous-version" in smoke_block
    assert "must differ from the release payload" in smoke_block
    code_lines = [
        line for line in smoke_block.splitlines() if not line.strip().startswith("#")
    ]
    for forbidden in ("RUNNER_TEMP", "env:TEMP", "env:TMP"):
        assert not any(forbidden in line for line in code_lines)
    assert 'Join-Path $PWD "build' not in "\n".join(code_lines)
    assert "--print-selected-root" in smoke_block
    assert 'Join-Path $root "w"' in smoke_block


def test_updater_rejects_an_install_target_inside_the_temporary_root(tmp_path):
    """Locks in why the updater smoke workspace lives outside RUNNER_TEMP."""
    from openfetch.core.update_installer import assess_installation_capability

    exe_bytes = b"release payload" * 100_000
    manifest = _manifest(VERSION, exe_bytes, minimum="3.1.0")
    temporary_root = tmp_path / "temp-root"
    install = temporary_root / "install"
    install.mkdir(parents=True)
    target = install / "OpenFetch.exe"
    target.write_bytes(b"packaged")

    rejected = assess_installation_capability(
        manifest,
        target_executable=target,
        frozen=True,
        updates_root=tmp_path / "updates",
        temporary_root=temporary_root,
    )
    assert not rejected.available
    assert rejected.code == "invalid_install_location"

    outside = tmp_path / "program" / "OpenFetch.exe"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"packaged")
    accepted = assess_installation_capability(
        manifest,
        target_executable=outside,
        frozen=True,
        updates_root=tmp_path / "updates",
        temporary_root=temporary_root,
    )
    assert accepted.code != "invalid_install_location"


def test_packaged_updater_smoke_covers_confirmation_and_rollback_paths():
    smoke = (PROJECT_ROOT / "scripts" / "packaged_updater_smoke.py").read_text(encoding="utf-8")
    assert "_success_smoke" in smoke
    assert "_timeout_rollback_smoke" in smoke
    assert "TransactionState.CONFIRMED" in smoke
    assert "TransactionState.ROLLED_BACK" in smoke
    assert "rollback_succeeded" in smoke
    assert "startup_confirmation_timeout" in smoke
    assert "Confirmed update did not replace target" in smoke
    assert "Rollback did not restore original target" in smoke


def test_release_notes_exist_for_the_source_version():
    assert (PROJECT_ROOT / "docs" / "release-notes" / f"V{VERSION}.md").is_file()


def test_archive_scan_uses_the_pinned_python_module_not_a_path_lookup(onefile_workflow: str):
    """The bare console script is not on the Actions PATH; use the pinned env."""
    block = _step(onefile_workflow, "Scan the packaged EXE for PyQt6 and provider payloads")
    code = "\n".join(line for line in block.splitlines() if not line.strip().startswith("#"))
    assert "pyi-archive_viewer" not in code, "the bare console script is not resolvable"
    assert "pyi-archive-viewer" not in code
    assert "$env:PYTHON_EXE -m PyInstaller.utils.cliutils.archive_viewer" in code
    assert "-l " in code
    assert "$env:PATH" not in code, "PATH must not be mutated for this scan"


def test_archive_scan_fails_closed_on_exit_code_and_empty_output(onefile_workflow: str):
    block = _step(onefile_workflow, "Scan the packaged EXE for PyQt6 and provider payloads")
    assert "$archiveExit = $LASTEXITCODE" in block
    assert "$archiveExit -ne 0" in block
    assert "IsNullOrWhiteSpace($archiveListing)" in block
    assert block.count("exit 1") >= 3


def test_archive_scan_keeps_every_boundary_check(onefile_workflow: str):
    block = _step(onefile_workflow, "Scan the packaged EXE for PyQt6 and provider payloads")
    for runtime in ("bin\\node.exe", "bin\\ffmpeg.exe", "bin\\ffprobe.exe"):
        assert runtime in block, f"required bundled runtime check lost: {runtime}"
    assert "Packaged runtime is missing" in block
    assert "verify_packaged_licensing.py" in block
    assert "--bridge-boundary" in block
    verifier = (PROJECT_ROOT / "scripts" / "verify_packaged_licensing.py").read_text(
        encoding="utf-8"
    )
    assert "def verify_bridge_boundary" in verifier
    assert "_PYQT_TOKEN" in verifier and "_PROVIDER_TOKEN" in verifier
    assert "PROHIBITED_LEGACY_SHA256S" in verifier


def test_prohibited_hash_scan_step_remains(onefile_workflow: str):
    assert "Scan outputs for prohibited legacy hashes" in onefile_workflow
    assert (
        'PROHIBITED_LEGACY_SHA256_A: "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377'
        'd90088eb54537b82ac"'
    ) in onefile_workflow
    assert (
        'PROHIBITED_LEGACY_SHA256_B: "02fbde8845bcb7b8946a44f320aa1f88a63a70ceac9765'
        'f800276ce11bfa6ed7"'
    ) in onefile_workflow
