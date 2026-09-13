"""Contract tests for the byte-stable checkout and the CI build-input restore.

GitHub Actions run #1 of the bridge workflow failed in "Validate source, tests
and manifests" for two independent reasons:

1. Git converted repository text files to CRLF on the Windows runner, so every
   SHA-256 manifest that records committed bytes (SOURCE-HASHES.sha256, the
   hashed license manifest, PROJECT-METADATA.json) mismatched.
2. A clean checkout has no ``build_inputs/`` payloads, because those pinned
   archives and wheels are intentionally ignored, yet SOURCE-HASHES.sha256
   covers them.

These tests pin the fix for both: one canonical LF representation enforced by
.gitattributes plus pre-checkout Git configuration, and a verified
reconstruction step that runs before pytest.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from scripts import restore_build_inputs as restore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GITATTRIBUTES = PROJECT_ROOT / ".gitattributes"
BRIDGE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-onefile-release.yml"
PRODUCTION_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-release.yml"
SOURCE_HASHES = PROJECT_ROOT / "SOURCE-HASHES.sha256"
LICENSE_MANIFEST = PROJECT_ROOT / "licenses" / "RELEASE-LICENSE-MANIFEST.sha256"
VENDORED_PREFIXES = ("licenses/", "third_party_sources/", "build_inputs/")
CRLF_BY_DESIGN = frozenset({"build.bat", "start.bat"})

LF_EXTENSIONS = (
    "*.py",
    "*.pyi",
    "*.md",
    "*.txt",
    "*.json",
    "*.toml",
    "*.yml",
    "*.yaml",
    "*.spec",
    "*.sha256",
    "*.lock",
    "*.ini",
    "*.cfg",
    "*.ps1",
)
BINARY_EXTENSIONS = (
    "*.exe",
    "*.dll",
    "*.pyd",
    "*.zip",
    "*.gz",
    "*.tar",
    "*.whl",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.ico",
    "*.pdf",
)


def _attribute_lines() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in GITATTRIBUTES.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pattern, _, attributes = stripped.partition(" ")
        rows.append((pattern, attributes.strip()))
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_hash_records() -> dict[str, str]:
    records: dict[str, str] = {}
    for line in SOURCE_HASHES.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match:
            records[match.group(2)] = match.group(1)
    return records


def test_gitattributes_exists_and_is_hash_covered():
    assert GITATTRIBUTES.is_file()
    assert ".gitattributes" in _source_hash_records()


@pytest.mark.parametrize("pattern", LF_EXTENSIONS)
def test_text_extensions_are_pinned_to_lf(pattern: str):
    rows = dict(_attribute_lines())
    assert pattern in rows, f"{pattern} has no .gitattributes rule"
    attributes = rows[pattern]
    assert "text" in attributes.split(), f"{pattern} is not marked text"
    assert "eol=lf" in attributes, f"{pattern} is not pinned to LF"


@pytest.mark.parametrize("pattern", BINARY_EXTENSIONS)
def test_binary_extensions_are_marked_binary(pattern: str):
    rows = dict(_attribute_lines())
    assert pattern in rows, f"{pattern} has no .gitattributes rule"
    attributes = rows[pattern]
    assert attributes == "binary" or "-text" in attributes, (
        f"{pattern} must be binary/non-text, found {attributes!r}"
    )


def test_vendored_trees_are_never_line_ending_converted():
    """Third-party bytes must stay verbatim; normalizing them would modify content."""
    rows = _attribute_lines()
    for tree in ("/licenses/**", "third_party_sources/**", "/build_inputs/**"):
        matches = [attributes for pattern, attributes in rows if pattern == tree]
        assert matches, f"{tree} has no verbatim-bytes rule"
        assert "-text" in matches[-1], f"{tree} must be marked -text"
    # The generated license manifest is project-owned and stays canonical LF,
    # and its rule must come after the licenses/** override to win.
    patterns = [pattern for pattern, _ in rows]
    assert patterns.index("/licenses/RELEASE-LICENSE-MANIFEST.sha256") > patterns.index(
        "/licenses/**"
    )


def test_build_inputs_payloads_stay_binary_by_default():
    """Downloaded archives and wheels must never be line-ending converted."""
    rows = _attribute_lines()
    payload = [attributes for pattern, attributes in rows if pattern == "/build_inputs/**"]
    assert payload, "/build_inputs/** has no rule"
    assert "-text" in payload[-1]
    for pattern in ("*.whl", "*.zip", "*.gz"):
        assert dict(rows)[pattern] == "binary"


def test_preparation_manifest_has_a_later_lf_override():
    """The committed generated manifest is text, unlike the payloads beside it."""
    rows = _attribute_lines()
    patterns = [pattern for pattern, _ in rows]
    override = "/build_inputs/PREPARATION-MANIFEST.json"
    assert override in patterns, "the preparation manifest has no explicit rule"
    # Last match wins in .gitattributes, so the override must follow the broad rule.
    assert patterns.index(override) > patterns.index("/build_inputs/**")
    attributes = dict(rows)[override]
    assert "text" in attributes.split()
    assert "eol=lf" in attributes


def test_preparation_manifest_is_canonical_lf_with_one_trailing_newline():
    raw = (PROJECT_ROOT / "build_inputs" / "PREPARATION-MANIFEST.json").read_bytes()
    assert b"\r\n" not in raw, "the preparation manifest is not canonical LF"
    assert b"\r" not in raw, "the preparation manifest contains a bare CR"
    assert raw.endswith(b"\n"), "the preparation manifest must end with a newline"
    assert not raw.endswith(b"\n\n"), "it must end with exactly one LF"


def test_preparation_manifest_hash_matches_the_source_manifest():
    relative = "build_inputs/PREPARATION-MANIFEST.json"
    recorded = _source_hash_records()[relative]
    raw = (PROJECT_ROOT / relative).read_bytes()
    assert _sha256(PROJECT_ROOT / relative) == recorded
    # Guard against a regression to the CRLF bytes that failed CI run #2.
    assert hashlib.sha256(raw.replace(b"\n", b"\r\n")).hexdigest() != recorded


def test_batch_files_are_pinned_crlf_rather_than_rewritten():
    rows = dict(_attribute_lines())
    assert "eol=crlf" in rows["*.bat"]
    for name in CRLF_BY_DESIGN:
        assert b"\r\n" in (PROJECT_ROOT / name).read_bytes()


def test_maintained_hash_covered_text_files_are_lf_on_disk():
    """The committed bytes must already be the canonical representation."""
    offenders = []
    for relative in _source_hash_records():
        if relative.startswith(VENDORED_PREFIXES) or relative in CRLF_BY_DESIGN:
            continue
        path = PROJECT_ROOT / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if b"\x00" in raw[:8192]:
            continue
        if b"\r\n" in raw:
            offenders.append(relative)
    assert offenders == [], f"maintained text files still contain CRLF: {offenders}"


def test_every_source_hash_record_matches_committed_bytes():
    records = _source_hash_records()
    assert len(records) > 700
    mismatched = [
        relative
        for relative, expected in records.items()
        if (PROJECT_ROOT / relative).is_file()
        and _sha256(PROJECT_ROOT / relative) != expected
    ]
    assert mismatched == [], f"source-hash mismatches: {mismatched[:10]}"


def test_generated_manifests_are_written_with_lf():
    for path in (SOURCE_HASHES, LICENSE_MANIFEST, PROJECT_ROOT / "PROJECT-METADATA.json"):
        assert b"\r\n" not in path.read_bytes(), f"{path.name} is not canonical LF"
    generator = (PROJECT_ROOT / "scripts" / "generate_compliance_manifests.py").read_text(
        encoding="utf-8"
    )
    assert generator.count('newline="\\n"') >= 2
    metadata = (PROJECT_ROOT / "scripts" / "generate_project_metadata.py").read_text(
        encoding="utf-8"
    )
    assert 'newline="\\n"' in metadata
    assert "read_bytes() != expected.encode" in metadata
    preparation = (PROJECT_ROOT / "scripts" / "prepare_offline_inputs.py").read_text(
        encoding="utf-8"
    )
    assert 'newline="\\n"' in preparation


def test_project_metadata_hashes_match_committed_bytes():
    payload = json.loads((PROJECT_ROOT / "PROJECT-METADATA.json").read_text(encoding="utf-8"))

    def rows(node):
        found = []
        if isinstance(node, dict):
            if isinstance(node.get("path"), str) and isinstance(node.get("sha256"), str):
                found.append((node["path"], node["sha256"]))
            for value in node.values():
                found += rows(value)
        elif isinstance(node, list):
            for value in node:
                found += rows(value)
        return found

    inventory = rows(payload)
    assert inventory, "PROJECT-METADATA.json records no hashed files"
    for relative, expected in inventory:
        path = PROJECT_ROOT / relative
        assert path.is_file(), f"inventoried file is missing: {relative}"
        assert _sha256(path) == expected, f"inventory hash mismatch: {relative}"


# --- Bridge workflow contract ---------------------------------------------


@pytest.fixture(scope="module")
def bridge_workflow() -> str:
    return BRIDGE_WORKFLOW.read_text(encoding="utf-8")


def _step_names(workflow: str) -> list[str]:
    return re.findall(r"^      - name: (.+)$", workflow, flags=re.MULTILINE)


def test_workflow_configures_byte_stable_git_before_checkout(bridge_workflow: str):
    names = _step_names(bridge_workflow)
    assert "Configure byte-stable Git checkout" in names
    assert "Checkout default branch" in names
    assert names.index("Configure byte-stable Git checkout") < names.index(
        "Checkout default branch"
    )
    config_block = bridge_workflow.split("Configure byte-stable Git checkout", 1)[1].split(
        "- name:", 1
    )[0]
    assert "git config --global core.autocrlf false" in config_block
    assert "git config --global core.eol lf" in config_block
    # The configuration must be asserted, not merely attempted.
    assert '$autocrlf -ne "false"' in config_block
    assert '$eol -ne "lf"' in config_block


def test_workflow_checkout_stays_clean_and_pinned_to_default_branch(bridge_workflow: str):
    checkout_block = bridge_workflow.split("Checkout default branch", 1)[1].split(
        "- name:", 1
    )[0]
    assert "actions/checkout@v4" in checkout_block
    assert "ref: ${{ github.event.repository.default_branch }}" in checkout_block
    assert "fetch-depth" not in checkout_block
    assert "persist-credentials: true" not in checkout_block


def test_workflow_restores_build_inputs_before_pytest(bridge_workflow: str):
    names = _step_names(bridge_workflow)
    restore_step = "Reconstruct and verify pinned offline build inputs"
    validate_step = "Validate source, tests and manifests"
    assert restore_step in names
    assert names.index(restore_step) < names.index(validate_step)
    block = bridge_workflow.split(restore_step, 1)[1].split("- name:", 1)[0]
    assert "scripts/restore_build_inputs.py --reuse-dir $env:RUNNER_TEMP" in block
    assert "scripts/restore_build_inputs.py --verify-only" in block


def test_workflow_keeps_the_complete_pytest_run_without_exclusions(bridge_workflow: str):
    assert "-m pytest tests -q" in bridge_workflow
    for workaround in ("-k ", "--ignore", "--deselect", "-m not ", "--no-cov"):
        assert workaround not in bridge_workflow, (
            f"bridge workflow must not narrow the test run with {workaround!r}"
        )


def test_no_skip_or_xfail_workaround_was_added_to_the_failing_tests():
    for name in ("test_packaging_contract.py", "test_project_ownership_metadata.py"):
        text = (PROJECT_ROOT / "tests" / name).read_text(encoding="utf-8")
        for workaround in ("skip", "xfail", "skipif"):
            assert workaround not in text, f"{name} gained a {workaround} workaround"


def test_packaging_contract_verifiers_are_not_weakened():
    """The two verifiers behind failures 1 and 2 must still be called strictly."""
    contract = (PROJECT_ROOT / "tests" / "test_packaging_contract.py").read_text(
        encoding="utf-8"
    )
    assert "verify_project(PROJECT_ROOT)" in contract
    assert "verify_license_directory" in contract
    assert "== []" in contract


def test_build_inputs_are_never_published_as_release_assets(bridge_workflow: str):
    publish_block = bridge_workflow.split("Publish the stable OpenFetch release", 1)[1]
    assert "build_inputs" not in publish_block
    artifact_block = bridge_workflow.split("Upload workflow artifact", 1)[1].split(
        "- name:", 1
    )[0]
    assert "build_inputs" not in artifact_block
    assert "build_inputs/*" in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")


def test_release_publishes_only_the_openfetch_asset_family(bridge_workflow: str):
    """Legacy-named assets belong in the bridge repository, not in this one."""
    publish_block = bridge_workflow.split("Publish the stable OpenFetch release", 1)[1]
    for asset in (
        "dist/OpenFetch.exe",
        "dist/OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe",
        "dist/OpenFetch-${{ env.RELEASE_VERSION }}-manifest.json",
    ):
        assert asset in publish_block
    assert "dist/NeuralExtractorV3-" not in publish_block
    assert len(re.findall(r"^            dist/", publish_block, flags=re.MULTILINE)) == 4
    assert "draft: false" in publish_block
    assert "prerelease: false" in publish_block


def test_production_workflow_remains_unchanged_and_fail_closed():
    production = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert "Licensing audit status is HOLD. Public build/release is blocked." in production
    for gate in (
        "Release-gate-status: PASS",
        "Audit-blocker-count: 0",
        "Qualified-review-status: PASS",
    ):
        assert gate in production
    # The bridge fix must not leak into the compliance-gated workflow.
    assert "restore_build_inputs" not in production
    assert "PUBLISH-FAMILY-BRIDGE" not in production
    assert "PUBLISH-OPENFETCH" not in production
    assert "core.autocrlf" not in production


# --- Restore-script behaviour ---------------------------------------------


def _write_pinned_fixture(root: Path, payload: bytes) -> tuple[Path, str]:
    digest = hashlib.sha256(payload).hexdigest()
    (root / "build_inputs").mkdir(parents=True)
    manifest = {
        "schema_version": 1,
        "files": [
            {
                "component": "example",
                "kind": "build-runtime",
                "path": "build_inputs/runtime-archives/example.zip",
                "sha256": digest,
                "size": len(payload),
                "url": "https://example.invalid/example.zip",
                "version": "1.0",
            }
        ],
    }
    (root / "build_inputs" / "PREPARATION-MANIFEST.json").write_text(
        json.dumps(manifest), encoding="utf-8", newline="\n"
    )
    (root / "SOURCE-HASHES.sha256").write_text(
        f"{digest}  build_inputs/runtime-archives/example.zip\n",
        encoding="utf-8",
        newline="\n",
    )
    return root, digest


def test_restore_reuses_a_verified_archive_instead_of_downloading(tmp_path):
    payload = b"pinned archive bytes"
    root, digest = _write_pinned_fixture(tmp_path / "repo", payload)
    reuse = tmp_path / "runner-temp"
    reuse.mkdir()
    (reuse / "example.zip").write_bytes(payload)

    pinned = restore.read_pinned_inputs(root)
    assert len(pinned) == 1
    outcome = restore.restore_input(pinned[0], root, [reuse], verify_only=False)

    assert outcome == "reused"
    restored = root / "build_inputs" / "runtime-archives" / "example.zip"
    assert restored.read_bytes() == payload
    restore.verify_targets(root, restore.read_source_hash_targets(root))


def test_restore_rejects_a_reuse_candidate_with_the_wrong_hash(tmp_path):
    root, _ = _write_pinned_fixture(tmp_path / "repo", b"pinned archive bytes")
    reuse = tmp_path / "runner-temp"
    reuse.mkdir()
    (reuse / "example.zip").write_bytes(b"tampered bytes")

    pinned = restore.read_pinned_inputs(root)
    # A mismatching candidate is ignored, so the restore falls through to the
    # network path; with an unreachable pinned URL that must fail closed.
    with pytest.raises((restore.RestoreError, OSError)):
        restore.restore_input(pinned[0], root, [reuse], verify_only=False)
    assert not (root / "build_inputs" / "runtime-archives" / "example.zip").exists()


def test_restore_verify_only_fails_closed_when_an_input_is_absent(tmp_path):
    root, _ = _write_pinned_fixture(tmp_path / "repo", b"pinned archive bytes")
    pinned = restore.read_pinned_inputs(root)

    with pytest.raises(restore.RestoreError, match="pinned input is missing"):
        restore.restore_input(pinned[0], root, [], verify_only=True)


def test_restore_rejects_credentials_or_runtime_state_under_build_inputs(tmp_path):
    root, _ = _write_pinned_fixture(tmp_path / "repo", b"pinned archive bytes")
    (root / "build_inputs" / "cookies.json").write_text("{}", encoding="utf-8")

    with pytest.raises(restore.RestoreError, match="runtime state or credential"):
        restore.assert_no_runtime_state(root)


def test_restore_rejects_unexpected_payload_types_under_build_inputs(tmp_path):
    root, _ = _write_pinned_fixture(tmp_path / "repo", b"pinned archive bytes")
    (root / "build_inputs" / "stray.exe").write_bytes(b"MZ")

    with pytest.raises(restore.RestoreError, match="unexpected payload type"):
        restore.assert_no_runtime_state(root)


def test_restore_cross_checks_the_lock_against_the_preparation_manifest(tmp_path):
    payload = b"pinned archive bytes"
    root, digest = _write_pinned_fixture(tmp_path / "repo", payload)
    (root / "BUILD-INPUTS.lock").write_text(
        json.dumps(
            {
                "inputs": [
                    {
                        "path": "build_inputs/runtime-archives/example.zip",
                        "sha256": "0" * 64,
                    }
                ]
            }
        ),
        encoding="utf-8",
        newline="\n",
    )

    lock_hashes = restore.read_lock_hashes(root)
    assert lock_hashes["build_inputs/runtime-archives/example.zip"] == "0" * 64
    assert lock_hashes["build_inputs/runtime-archives/example.zip"] != digest


def test_restore_never_rewrites_the_pinned_preparation_manifest():
    """The manifest is a committed, hash-covered pin list: read-only by design."""
    source = (PROJECT_ROOT / "scripts" / "restore_build_inputs.py").read_text(
        encoding="utf-8"
    )
    assert "write_text" not in source
    assert "PREPARATION-MANIFEST.json" in source
    manifest_hash = _source_hash_records()["build_inputs/PREPARATION-MANIFEST.json"]
    assert _sha256(PROJECT_ROOT / "build_inputs" / "PREPARATION-MANIFEST.json") == (
        manifest_hash
    )
    # The restore command must never invoke the regenerating preparation tool.
    assert "prepare_offline_inputs" not in source.replace(
        "scripts/prepare_offline_inputs.py", ""
    ).replace("``prepare_offline_inputs.py``", "")


def test_restore_leaves_the_committed_manifest_byte_identical(tmp_path, monkeypatch):
    """Run the real restore flow and prove the pin list itself is untouched."""
    payload = b"pinned archive bytes"
    root, digest = _write_pinned_fixture(tmp_path / "repo", payload)
    reuse = tmp_path / "runner-temp"
    reuse.mkdir()
    (reuse / "example.zip").write_bytes(payload)
    manifest_path = root / "build_inputs" / "PREPARATION-MANIFEST.json"
    before = manifest_path.read_bytes()
    before_mtime = manifest_path.stat().st_mtime_ns

    pinned = restore.read_pinned_inputs(root)
    restore.restore_input(pinned[0], root, [reuse], verify_only=False)
    targets = restore.read_source_hash_targets(root)
    restore.mirror_wheelhouse(root, targets, verify_only=False)
    restore.assert_no_runtime_state(root)
    restore.verify_targets(root, targets)

    assert manifest_path.read_bytes() == before, "the pin list was rewritten"
    assert manifest_path.stat().st_mtime_ns == before_mtime, "the pin list was replaced"
    assert digest == hashlib.sha256(payload).hexdigest()


def test_bridge_workflow_never_regenerates_the_pin_list():
    """GitHub Actions must not run the manifest-rewriting preparation script."""
    workflow = BRIDGE_WORKFLOW.read_text(encoding="utf-8")
    code_lines = [
        line
        for line in workflow.splitlines()
        if not line.strip().startswith("#")
    ]
    joined = "\n".join(code_lines)
    assert "prepare_offline_inputs.py" not in joined
    assert "restore_build_inputs.py" in joined


def test_clean_checkout_simulation_reconstructs_every_ignored_input(tmp_path):
    """End-to-end: payloads absent, then restored, with zero unsatisfied targets.

    The pinned payloads are staged in a reuse directory (standing in for the
    already-verified RUNNER_TEMP archives) so the simulation performs no network
    access, then every source-hash target under build_inputs/ must be satisfied.
    """
    import shutil

    real_root = PROJECT_ROOT
    targets = restore.read_source_hash_targets(real_root)
    pinned = restore.read_pinned_inputs(real_root)

    clean = tmp_path / "clean-checkout"
    (clean / "build_inputs").mkdir(parents=True)
    # A clean checkout carries the committed manifest and the source manifest,
    # but none of the ignored payloads.
    shutil.copy2(
        real_root / "build_inputs" / "PREPARATION-MANIFEST.json",
        clean / "build_inputs" / "PREPARATION-MANIFEST.json",
    )
    shutil.copy2(real_root / "SOURCE-HASHES.sha256", clean / "SOURCE-HASHES.sha256")
    shutil.copy2(real_root / "BUILD-INPUTS.lock", clean / "BUILD-INPUTS.lock")

    reuse = tmp_path / "reuse"
    reuse.mkdir()
    for item in pinned:
        source = real_root / item.path
        assert source.is_file(), f"local pinned input is missing: {item.path}"
        shutil.copy2(source, reuse / source.name)

    # Nothing but the pin list exists yet, so verification must fail closed.
    with pytest.raises(restore.RestoreError):
        restore.verify_targets(clean, targets)

    for item in pinned:
        assert restore.restore_input(item, clean, [reuse], verify_only=False) == "reused"
    mirrored = restore.mirror_wheelhouse(clean, targets, verify_only=False)
    restore.assert_no_runtime_state(clean)
    restore.verify_targets(clean, targets)

    assert mirrored, "the flat wheel mirror was not reconstructed"
    missing = [r for r in targets if not (clean / r).is_file()]
    mismatched = [
        r for r in targets if (clean / r).is_file() and _sha256(clean / r) != targets[r]
    ]
    assert missing == [] and mismatched == [], (
        f"missing={missing[:5]} mismatched={mismatched[:5]}"
    )
    # The reconstruction must not have altered the committed pin list.
    assert (clean / "build_inputs" / "PREPARATION-MANIFEST.json").read_bytes() == (
        real_root / "build_inputs" / "PREPARATION-MANIFEST.json"
    ).read_bytes()


def test_repository_build_inputs_satisfy_every_covered_target():
    """End-to-end: the real manifest, lock and wheel mirror agree on this machine."""
    pinned = restore.read_pinned_inputs(PROJECT_ROOT)
    assert len(pinned) >= 38
    lock_hashes = restore.read_lock_hashes(PROJECT_ROOT)
    for item in pinned:
        locked = lock_hashes.get(item.path)
        if locked is not None:
            assert locked == item.sha256, f"lock disagrees for {item.path}"
    targets = restore.read_source_hash_targets(PROJECT_ROOT)
    assert len(targets) >= 74
    restore.verify_targets(PROJECT_ROOT, targets)
    restore.assert_no_runtime_state(PROJECT_ROOT)


def test_generated_packaging_metadata_is_never_recorded_as_source():
    """src/<name>.egg-info is build output that uv/setuptools rewrite with CRLF."""
    offenders = [relative for relative in _source_hash_records() if ".egg-info/" in relative]
    assert offenders == [], f"packaging metadata leaked into the source manifest: {offenders}"
