import json
import tomllib
from pathlib import Path

from scripts import generate_project_metadata, release_compliance_gate

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_license_is_the_exact_standard_mit_text():
    assert (
        PROJECT_ROOT.joinpath("LICENSE").read_text(encoding="utf-8")
        == generate_project_metadata.STANDARD_MIT_LICENSE
    )


def test_project_metadata_inventory_is_current_and_ownership_gate_passes():
    actual = PROJECT_ROOT.joinpath("PROJECT-METADATA.json").read_text(encoding="utf-8")
    assert actual == generate_project_metadata.render(PROJECT_ROOT)

    checks, failures = release_compliance_gate.ownership_checks(PROJECT_ROOT)
    assert failures == []
    assert len(checks) == 7
    assert all(check["status"] == "PASS" for check in checks)

    payload = json.loads(actual)
    assert payload["public_distribution_verdict"] == "HOLD"
    assert payload["qualified_legal_review_status"] == "HOLD"


def test_project_attribution_is_consistent_across_public_metadata():
    with PROJECT_ROOT.joinpath("pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    assert pyproject["project"]["authors"] == [{"name": "0xRootNull"}]
    assert pyproject["project"]["license"] == {"text": "MIT"}

    declaration = PROJECT_ROOT.joinpath(
        "docs", "PROJECT-OWNERSHIP-DECLARATION.md"
    ).read_text(encoding="utf-8")
    assert "Public author and copyright holder: 0xRootNull" in declaration
    assert "Public brand: Brainbyte" in declaration
    assert "Copyright period: 2025-2026" in declaration
    assert "Registered company or legal entity: None" in declaration
    assert "Employer, client or commissioning party: None" in declaration
    assert "Known other human contributors: None" in declaration
    assert "Qualified legal review: Unresolved" in declaration
    assert "Public distribution verdict: HOLD" in declaration

    version_info = PROJECT_ROOT.joinpath("version_info.txt").read_text(encoding="utf-8")
    assert 'StringStruct("CompanyName", "Brainbyte")' in version_info
    assert '"Copyright (c) 2025-2026 0xRootNull"' in version_info


def test_project_attribution_is_absent_from_third_party_texts():
    text_suffixes = {
        ".cfg",
        ".html",
        ".ini",
        ".json",
        ".md",
        ".py",
        ".rst",
        ".rs",
        ".sh",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
    notice_names = {"authors", "copying", "copyright", "license", "notice"}
    violations = []
    for root_name in ("licenses", "third_party_sources"):
        for path in PROJECT_ROOT.joinpath(root_name).rglob("*"):
            if not path.is_file():
                continue
            if (
                path.suffix.casefold() not in text_suffixes
                and path.name.casefold() not in notice_names
            ):
                continue
            if b"0xRootNull" in path.read_bytes():
                violations.append(path.relative_to(PROJECT_ROOT).as_posix())
    assert violations == []
