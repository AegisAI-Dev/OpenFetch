import json
from pathlib import Path

import pytest

from openfetch.core.update_manifest import MIN_UPDATE_SIZE_BYTES, is_newer_version
from scripts.release_tools import (
    generate_manifest,
    render_version_info,
    validate_release_versions,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def write_project_versions(root: Path, config_version: str, *, dynamic: bool = True) -> None:
    config = root / "src" / "openfetch" / "config.py"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        'APP_NAME = "OpenFetch"\nAPP_PUBLISHER = "Brainbyte"\n'
        f'EXECUTABLE_STEM = "OpenFetch"\nVERSION = "{config_version}"\n'
    )
    if dynamic:
        pyproject = (
            '[project]\nname = "openfetch"\ndynamic = ["version"]\n\n'
            '[tool.setuptools.dynamic]\nversion = {attr = "openfetch.config.VERSION"}\n'
        )
    else:
        pyproject = f'[project]\nname = "openfetch"\nversion = "{config_version}"\n'
    (root / "pyproject.toml").write_text(pyproject)
    try:
        (root / "version_info.txt").write_text(render_version_info(root), encoding="utf-8")
    except ValueError:
        (root / "version_info.txt").write_text("", encoding="utf-8")


def test_release_version_validation_requires_tag_and_both_sources_to_match(tmp_path):
    write_project_versions(tmp_path, "3.0.2")

    assert validate_release_versions(tmp_path, "v3.0.2") == "3.0.2"
    assert validate_release_versions(tmp_path, "3.0.2") == "3.0.2"

    with pytest.raises(ValueError, match="Release version mismatch"):
        validate_release_versions(tmp_path, "v3.0.3")


def test_current_source_versions_and_release_ref_are_consistent():
    assert validate_release_versions(PROJECT_ROOT, "v3.1.0") == "3.1.0"


def test_version_info_is_generated_from_the_single_version_source():
    version_info = (PROJECT_ROOT / "version_info.txt").read_text(encoding="utf-8")
    assert version_info == render_version_info(PROJECT_ROOT)
    assert 'StringStruct("ProductName", "OpenFetch")' in version_info
    assert 'StringStruct("OriginalFilename", "OpenFetch.exe")' in version_info
    assert "filevers=(3, 1, 0, 0)" in version_info


def test_v307_release_notes_describe_unicode_hotfix_and_preserved_guarantees():
    notes = (PROJECT_ROOT / "docs" / "release-notes" / "V3.0.7.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(notes.split())

    for statement in (
        "Windows Unicode hotfix",
        "U+FF5C FULLWIDTH VERTICAL LINE",
        "Google Chrome and Firefox authentication were already valid",
        "responsive GUI",
        "startup confirmation",
        "rollback",
        "EXE remains unsigned",
        "not every video is guaranteed to work",
    ):
        assert statement in normalized


def test_v308_release_notes_describe_external_bounded_provider_recovery_and_risks():
    notes = (PROJECT_ROOT / "docs" / "release-notes" / "V3.0.8.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(notes.split())

    for statement in (
        "pyside-provider-free-local-audit",
        "exact browser provider",
        "public attempt",
        "clean public retry",
        "exact recent verified provider once",
        "supported PO Token provider attempt",
        "external helper",
        "separately installed and separately versioned",
        "mweb",
        "automatic/video-bound token fetching",
        "Manual or copied PO Tokens are not accepted",
        "HTTP/listener provider is not bundled or loaded",
        "does not silently download or install",
        "does not guarantee access",
        "account and platform policy risks",
        "GPL-3.0-only",
        "Legal review",
    ):
        assert statement in normalized

    for category in (
        "verified_provider_not_applied",
        "verified_session_media_403",
        "po_token_provider_unavailable",
        "po_token_fetch_failed",
        "po_token_media_403",
        "only_sabr_or_image_formats",
        "media_access_rejected_after_authentication",
    ):
        assert category in normalized


def test_304_is_newer_than_both_affected_updater_versions():
    assert is_newer_version("3.0.4", "3.0.2")
    assert is_newer_version("3.0.4", "3.0.3")
    assert not is_newer_version("3.0.4", "3.0.4")


def test_release_version_validation_rejects_source_disagreement_and_invalid_semver(tmp_path):
    write_project_versions(tmp_path, "3.0.2", dynamic=False)
    with pytest.raises(ValueError, match="static project.version"):
        validate_release_versions(tmp_path, "v3.0.2")

    write_project_versions(tmp_path, "3.0.2")
    (tmp_path / "version_info.txt").write_text("stale", encoding="utf-8")
    with pytest.raises(ValueError, match="version_info.txt"):
        validate_release_versions(tmp_path, "v3.0.2")

    write_project_versions(tmp_path, "3.0.2-beta")
    with pytest.raises(ValueError):
        validate_release_versions(tmp_path, "v3.0.2-beta")


def test_manifest_generator_hashes_exact_versioned_executable(tmp_path):
    executable = tmp_path / "OpenFetch-3.1.0-windows-x64.exe"
    executable.write_bytes(b"E" * MIN_UPDATE_SIZE_BYTES)
    output = tmp_path / "OpenFetch-3.1.0-manifest.json"

    manifest = generate_manifest(
        version="3.1.0",
        executable=executable,
        output=output,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert manifest.asset_size == MIN_UPDATE_SIZE_BYTES
    assert payload["application_name"] == "OpenFetch"
    assert payload["asset_filename"] == executable.name
    assert payload["release_version"] == "3.1.0"
    assert payload["minimum_updater_version"] == "3.1.0"


def test_manifest_generator_writes_the_legacy_compatibility_manifest(tmp_path):
    executable = tmp_path / "NeuralExtractorV3-3.1.0-windows-x64.exe"
    executable.write_bytes(b"E" * MIN_UPDATE_SIZE_BYTES)
    output = tmp_path / "NeuralExtractorV3-3.1.0-manifest.json"

    generate_manifest(version="3.1.0", executable=executable, output=output, naming="legacy")
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["application_name"] == "Neural Extractor V3"
    assert payload["asset_filename"] == "NeuralExtractorV3-3.1.0-windows-x64.exe"
    assert payload["minimum_updater_version"] == "3.0.4"
    with pytest.raises(ValueError, match="Manifest output must be named"):
        generate_manifest(
            version="3.1.0",
            executable=executable,
            output=tmp_path / "OpenFetch-3.1.0-manifest.json",
            naming="legacy",
        )


def test_workflow_contains_mandatory_version_gate_and_manifest_publication():
    workflow = Path(".github/workflows/build-release.yml").read_text(encoding="utf-8")

    assert 'tags:\n      - "v*.*.*"' in workflow
    assert "workflow_dispatch:" in workflow
    assert "scripts/release_tools.py validate" in workflow
    assert "scripts/release_tools.py manifest" in workflow
    assert "--minimum-updater-version 3.0.4" in workflow
    assert "Stage verified bundled runtimes" in workflow
    assert "Pinned FFmpeg archive checksum mismatch" in workflow
    assert 'node-version: "22.17.0"' in workflow
    assert 'foreach ($runtime in @("bin\\\\node.exe", "bin\\\\ffmpeg.exe", "bin\\\\ffprobe.exe"))' in workflow
    assert "Release output does not contain the exact required binary, source" in workflow
    assert "corresponding-source.zip" in workflow
    assert "THIRD_PARTY_LICENSES.txt" in workflow
    assert "body_path: docs/release-notes/V${{ steps.release.outputs.version }}.md" in workflow
    assert "fail_on_unmatched_files: true" in workflow
    assert "NeuralExtractorV3*.exe" not in workflow
    assert "NeuralExtractorV3*.sha256" not in workflow
    assert "NeuralExtractorV3*-manifest.json" not in workflow
    assert "Manual releases must run from the repository default branch." in workflow
    assert "Require a new tag for manual releases" in workflow
    assert "Tag ${tag} already exists" in workflow
    assert "target_commitish: ${{ github.sha }}" in workflow
    assert "release_tag" not in workflow


def test_release_notes_and_packaging_require_all_v304_runtime_and_handoff_guarantees():
    notes = Path("docs/release-notes/V3.0.4.md").read_text(encoding="utf-8")
    spec = Path("OpenFetch.spec").read_text(encoding="utf-8")

    for statement in (
        "Another updater process owns this installation",
        "GUI-to-helper transaction ownership handoff",
        "PID plus process-creation identity",
        "stale updater-state recovery",
        "genuinely concurrent updater processes",
        "SHA-256 and file-size verification",
        "startup confirmation",
        "V3.0.3 YouTube reliability fixes",
        "V3.0.2 and V3.0.3 users may need to install V3.0.4 manually once",
        "Future compatible updates from V3.0.4",
        "unsigned",
        "AegisAI-Dev/NeuralExtractor",
    ):
        assert statement in notes

    assert "A bundled node.exe is required" in spec
    assert "Bundled ffmpeg.exe and ffprobe.exe are required" in spec
    assert '(str(ffmpeg_bin / "ffmpeg.exe"), "bin")' in spec
    assert '(str(ffmpeg_bin / "ffprobe.exe"), "bin")' in spec
    assert '(str(node_runtime), "bin"),' in spec
    assert '(str(python_libffi), "."),' in spec
