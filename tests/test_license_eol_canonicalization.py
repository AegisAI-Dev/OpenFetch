"""Contract tests for the canonical LF representation of preserved license texts.

GitHub Actions bridge run #3 failed only in
``test_release_license_manifest_covers_every_preserved_license_file``: 27
preserved license files were committed as LF, while the Windows working tree
held CRLF, so ``licenses/RELEASE-LICENSE-MANIFEST.sha256`` recorded CRLF bytes a
clean checkout could never reproduce. The committed bytes were confirmed
one-by-one against the public main branch over read-only HTTPS.

The fix pins exactly those 27 paths to ``text eol=lf`` after the broad
``/licenses/** -text`` rule. Everything else in the tree — notably
``Windows-SDK-10.0.26100.0-third-party-notices.rtf``, whose committed blob
genuinely is CRLF — stays byte-verbatim. These tests lock that arrangement in
and prove the verifier itself was not weakened.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path, PurePosixPath

import pytest

from scripts.verify_release_companion import verify_license_directory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GITATTRIBUTES = PROJECT_ROOT / ".gitattributes"
LICENSE_ROOT = PROJECT_ROOT / "licenses"
LICENSE_MANIFEST = LICENSE_ROOT / "RELEASE-LICENSE-MANIFEST.sha256"
BRIDGE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-onefile-release.yml"
PRODUCTION_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "build-release.yml"

# The exact CI-reported set. Kept literal so a silent drift in the override list
# cannot quietly widen or narrow what this task changed.
LF_PINNED_LICENSES = (
    "CPython-3.12.9-LICENSE.txt",
    "Node.js-22.17.0-LICENSE.txt",
    "microsoft/Visual-Studio-2022-BuildTools-Redist-local.txt",
    "microsoft/Windows-Performance-Toolkit-NOTICE.txt",
    "microsoft/Windows-SDK-10.0.26100.0-license.rtf",
    "python/certifi-2026.7.22/WHEEL-METADATA.txt",
    "python/charset-normalizer-3.4.9/WHEEL-METADATA.txt",
    "python/charset-normalizer-3.4.9/charset_normalizer-3.4.9.dist-info__licenses__LICENSE",
    "python/defusedxml-0.7.1/WHEEL-METADATA.txt",
    "python/idna-3.18/WHEEL-METADATA.txt",
    "python/packaging-26.2/WHEEL-METADATA.txt",
    "python/pillow-12.3.0/WHEEL-METADATA.txt",
    "python/pillow-12.3.0/pillow-12.3.0.dist-info__licenses__LICENSE",
    "python/pyside6-6.11.1/WHEEL-METADATA.txt",
    "python/pyside6-6.11.1/pyside6-6.11.1.dist-info__licenses__LicenseRef-Qt-Commercial.txt",
    "python/pyside6-addons-6.11.1/WHEEL-METADATA.txt",
    "python/pyside6-addons-6.11.1/pyside6_addons-6.11.1.dist-info__licenses__LicenseRef-Qt-Commercial.txt",
    "python/pyside6-essentials-6.11.1/WHEEL-METADATA.txt",
    "python/pyside6-essentials-6.11.1/pyside6_essentials-6.11.1.dist-info__licenses__LicenseRef-Qt-Commercial.txt",
    "python/requests-2.34.2/WHEEL-METADATA.txt",
    "python/setuptools-83.0.0/WHEEL-METADATA.txt",
    "python/shiboken6-6.11.1/WHEEL-METADATA.txt",
    "python/shiboken6-6.11.1/shiboken6-6.11.1.dist-info__licenses__LicenseRef-Qt-Commercial.txt",
    "python/typing-extensions-4.16.0/WHEEL-METADATA.txt",
    "python/urllib3-2.7.0/WHEEL-METADATA.txt",
    "python/youtube-transcript-api-1.2.4/WHEEL-METADATA.txt",
    "python/yt-dlp-2026.7.4/WHEEL-METADATA.txt",
)
# Deliberately excluded: its committed blob is CRLF, so it already matches.
VERBATIM_CRLF_LICENSE = "microsoft/Windows-SDK-10.0.26100.0-third-party-notices.rtf"


def _attribute_rows() -> list[tuple[str, str]]:
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


def _manifest_records() -> dict[str, str]:
    records: dict[str, str] = {}
    for line in LICENSE_MANIFEST.read_text(encoding="utf-8-sig").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+\*?(.+?)\s*", line)
        if match:
            records[match.group(2).replace("\\", "/")] = match.group(1).lower()
    return records


def test_license_tree_remains_verbatim_by_default():
    rows = _attribute_rows()
    matches = [attributes for pattern, attributes in rows if pattern == "/licenses/**"]
    assert matches, "/licenses/** has no verbatim-bytes rule"
    assert "-text" in matches[-1]


@pytest.mark.parametrize("relative", LF_PINNED_LICENSES)
def test_each_pinned_license_has_a_later_lf_override(relative: str):
    rows = _attribute_rows()
    patterns = [pattern for pattern, _ in rows]
    override = f"/licenses/{relative}"
    assert override in patterns, f"missing .gitattributes override for {relative}"
    # Last match wins, so every override must follow the broad tree rule.
    assert patterns.index(override) > patterns.index("/licenses/**")
    attributes = dict(rows)[override]
    assert "text" in attributes.split()
    assert "eol=lf" in attributes


def test_override_list_is_exactly_the_ci_reported_set():
    overrides = {
        pattern[len("/licenses/") :]
        for pattern, attributes in _attribute_rows()
        if pattern.startswith("/licenses/")
        and "eol=lf" in attributes
        and not pattern.endswith("RELEASE-LICENSE-MANIFEST.sha256")
    }
    assert overrides == set(LF_PINNED_LICENSES)
    assert len(overrides) == 27
    assert VERBATIM_CRLF_LICENSE not in overrides


@pytest.mark.parametrize("relative", LF_PINNED_LICENSES)
def test_each_pinned_license_contains_no_crlf(relative: str):
    raw = (LICENSE_ROOT / relative).read_bytes()
    assert b"\r\n" not in raw, f"{relative} still contains CRLF"


@pytest.mark.parametrize("relative", LF_PINNED_LICENSES)
def test_each_pinned_license_hash_matches_the_manifest(relative: str):
    records = _manifest_records()
    assert relative in records, f"{relative} is absent from the license manifest"
    assert _sha256(LICENSE_ROOT / relative) == records[relative]


def test_no_other_license_file_was_rewritten_to_lf():
    """Only the 27 confirmed files changed; the rest stay byte-verbatim."""
    pinned = set(LF_PINNED_LICENSES)
    crlf_remaining = {
        path.relative_to(LICENSE_ROOT).as_posix()
        for path in LICENSE_ROOT.rglob("*")
        if path.is_file()
        and path != LICENSE_MANIFEST
        and path.relative_to(LICENSE_ROOT).as_posix() not in pinned
        and b"\r\n" in path.read_bytes()
    }
    # The one file whose committed blob is genuinely CRLF must still be CRLF.
    assert crlf_remaining == {VERBATIM_CRLF_LICENSE}, (
        f"unexpected CRLF drift in preserved licenses: {sorted(crlf_remaining)}"
    )
    records = _manifest_records()
    verbatim = LICENSE_ROOT / VERBATIM_CRLF_LICENSE
    assert _sha256(verbatim) == records[VERBATIM_CRLF_LICENSE]


def test_license_verifier_still_hashes_exact_bytes_without_canonicalization():
    """The verifier must compare raw bytes; no EOL fixing may hide a mismatch."""
    source = (PROJECT_ROOT / "scripts" / "verify_release_companion.py").read_text(
        encoding="utf-8"
    )
    assert "_sha256_stream" in source
    assert 'path.open("rb")' in source
    for smell in (
        'replace("\\r\\n"',
        "replace(b'\\r\\n'",
        'replace(b"\\r\\n"',
        "splitlines(keepends=False)",
        "universal_newlines",
        "normalize_eol",
    ):
        assert smell not in source, f"verifier appears to canonicalize bytes: {smell}"
    # Coverage and per-file hashing must both still be enforced.
    assert "license manifest coverage mismatch" in source
    assert "license hash mismatch" in source or "hash mismatch" in source


def test_license_verifier_detects_a_reintroduced_crlf_byte(tmp_path):
    """A behavioural check that the verifier is genuinely byte-exact."""
    tree = tmp_path / "licenses"
    tree.mkdir()
    payload = b"Example License\nline two\n"
    (tree / "Example-LICENSE.txt").write_bytes(payload)
    (tree / "RELEASE-LICENSE-MANIFEST.sha256").write_text(
        f"{hashlib.sha256(payload).hexdigest()}  Example-LICENSE.txt\n",
        encoding="utf-8",
        newline="\n",
    )
    assert verify_license_directory(tree) == []

    (tree / "Example-LICENSE.txt").write_bytes(payload.replace(b"\n", b"\r\n"))
    errors = verify_license_directory(tree)
    assert errors, "the verifier accepted CRLF-rewritten bytes"
    assert any("Example-LICENSE.txt" in error for error in errors)


def test_local_license_tree_verifies_clean():
    assert verify_license_directory(LICENSE_ROOT) == []


def test_clean_checkout_license_tree_verifies_clean(tmp_path):
    """Simulate a fresh checkout: canonical bytes plus the regenerated manifest.

    The pinned files are materialized from their canonical LF bytes and every
    other preserved file is copied verbatim, which is exactly what Git produces
    under the current .gitattributes rules. Zero missing, zero extra and zero
    mismatched entries are required.
    """
    clean = tmp_path / "licenses"
    for path in sorted(LICENSE_ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(LICENSE_ROOT).as_posix()
        destination = clean / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_bytes()
        if relative in set(LF_PINNED_LICENSES):
            # A clean checkout of an eol=lf path always yields LF bytes.
            destination.write_bytes(raw.replace(b"\r\n", b"\n"))
        else:
            shutil.copy2(path, destination)

    errors = verify_license_directory(clean)
    assert errors == [], f"clean-checkout license verification failed: {errors[:5]}"

    records = _manifest_records()
    actual = {
        path.relative_to(clean).as_posix()
        for path in clean.rglob("*")
        if path.is_file() and path.name != "RELEASE-LICENSE-MANIFEST.sha256"
    }
    assert set(records) == actual, "coverage drifted in the clean-checkout tree"
    mismatched = [r for r in records if _sha256(clean / r) != records[r]]
    assert mismatched == [], f"clean-checkout hash mismatches: {mismatched[:5]}"
    assert all(
        b"\r\n" not in (clean / relative).read_bytes() for relative in LF_PINNED_LICENSES
    )


def test_workflow_still_runs_the_full_test_suite():
    workflow = BRIDGE_WORKFLOW.read_text(encoding="utf-8")
    assert "-m pytest tests -q" in workflow
    for workaround in ("-k ", "--ignore", "--deselect", "-m not ", "--maxfail"):
        assert workaround not in workflow, f"the test run was narrowed with {workaround!r}"


def test_no_skip_or_xfail_workaround_in_the_affected_tests():
    for name in ("test_packaging_contract.py", "test_release_companion_verifier.py"):
        path = PROJECT_ROOT / "tests" / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for workaround in ("skip", "xfail", "pytest.mark.skipif"):
            assert workaround not in text, f"{name} gained a {workaround} workaround"
    contract = (PROJECT_ROOT / "tests" / "test_packaging_contract.py").read_text(
        encoding="utf-8"
    )
    assert "verify_license_directory" in contract
    assert "== []" in contract


def test_release_publishes_exactly_the_openfetch_asset_family():
    workflow = BRIDGE_WORKFLOW.read_text(encoding="utf-8")
    publish = workflow.split("Publish the stable OpenFetch release", 1)[1]
    assets = re.findall(r"^            dist/(.+)$", publish, flags=re.MULTILINE)
    assert assets == [
        "OpenFetch.exe",
        "OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe",
        "OpenFetch-${{ env.RELEASE_VERSION }}-windows-x64.exe.sha256",
        "OpenFetch-${{ env.RELEASE_VERSION }}-manifest.json",
    ]
    assert "draft: false" in publish
    assert "prerelease: false" in publish
    assert "build_inputs" not in publish
    assert "licenses/" not in publish


def test_build_inputs_are_not_release_assets():
    workflow = BRIDGE_WORKFLOW.read_text(encoding="utf-8")
    artifact = workflow.split("Upload workflow artifact", 1)[1].split("- name:", 1)[0]
    assert "build_inputs" not in artifact
    publish = workflow.split("Publish the stable OpenFetch release", 1)[1]
    assert "build_inputs" not in publish


def test_production_workflow_remains_fail_closed():
    production = PRODUCTION_WORKFLOW.read_text(encoding="utf-8")
    assert "Licensing audit status is HOLD. Public build/release is blocked." in production
    for gate in (
        "Release-gate-status: PASS",
        "Audit-blocker-count: 0",
        "Qualified-review-status: PASS",
    ):
        assert gate in production
    assert "PUBLISH-FAMILY-BRIDGE" not in production
    assert "restore_build_inputs" not in production


def test_license_manifest_is_canonical_lf_and_complete():
    raw = LICENSE_MANIFEST.read_bytes()
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    records = _manifest_records()
    assert len(records) == 352
    actual = {
        PurePosixPath(path.relative_to(LICENSE_ROOT).as_posix()).as_posix()
        for path in LICENSE_ROOT.rglob("*")
        if path.is_file() and path != LICENSE_MANIFEST
    }
    assert set(records) == actual
