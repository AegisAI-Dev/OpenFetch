from pathlib import Path

from scripts.verify_distribution_boundary import verify_project
from scripts.verify_release_companion import verify_license_directory

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_current_tree_satisfies_provider_free_pyside_distribution_boundary():
    assert verify_project(PROJECT_ROOT) == []


def test_release_license_manifest_covers_every_preserved_license_file():
    assert verify_license_directory(PROJECT_ROOT / "licenses") == []


def test_release_workflow_orders_both_distribution_gates_before_publication():
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "build-release.yml").read_text(
        encoding="utf-8"
    )
    prebuild = workflow.index("scripts/verify_distribution_boundary.py")
    build = workflow.index("-m PyInstaller OpenFetch.spec")
    postbuild = workflow.index("scripts/verify_packaged_licensing.py")
    publish = workflow.index("Publish GitHub Release")

    assert prebuild < build < postbuild < publish
    assert "requirements.lock" in workflow
    assert "--require-hashes" in workflow or "uv sync --frozen" in workflow


def test_spec_and_verifier_pin_one_cpython_libffi_and_auditable_pyz():
    spec = (PROJECT_ROOT / "OpenFetch.spec").read_text(encoding="utf-8")
    verifier = (PROJECT_ROOT / "scripts" / "verify_packaged_licensing.py").read_text(
        encoding="utf-8"
    )
    expected_hash = "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e"

    assert expected_hash in spec
    assert expected_hash in verifier
    assert '(str(python_libffi), ".")' in spec
    assert "noarchive=False" in spec
    assert "open_embedded_archive" in verifier
    assert "exactly one libffi DLL at root" in verifier
    assert 'version=str(project_root / "version_info.txt")' in spec


def test_distribution_contract_requires_all_user_facing_compliance_materials():
    spec = (PROJECT_ROOT / "OpenFetch.spec").read_text(encoding="utf-8")
    verifier = (PROJECT_ROOT / "scripts" / "verify_packaged_licensing.py").read_text(
        encoding="utf-8"
    )
    for name in (
        "LICENSE",
        "PROJECT-METADATA.json",
        "THIRD_PARTY_LICENSES.txt",
        "THIRD_PARTY_NOTICES.md",
        "COPYRIGHT-OWNERSHIP-QUESTIONS.md",
        "PROJECT-OWNERSHIP-DECLARATION.md",
        "DEPENDENCY-SOURCE.md",
        "BUILD-REPRODUCIBILITY.md",
        "LGPL-COMPLIANCE.md",
        "QT-REPLACEMENT-GUIDE.md",
        "QT-BUILD-PROVENANCE.md",
        "OPTIONAL-PO-PROVIDER.md",
        "requirements.lock",
        "SOURCE-HASHES.sha256",
        "RELEASE-LICENSE-MANIFEST.sha256",
    ):
        assert name in spec
        assert name in verifier
