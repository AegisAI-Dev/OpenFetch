"""Generate and verify the project-owned public metadata inventory."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "PROJECT-METADATA.json"
PUBLIC_ATTRIBUTION = "0xRootNull"
PROJECT_NAME = "OpenFetch"
FORMER_PROJECT_NAME = "Neural Extractor"
# Brand shown as publisher; it is not a registered company or legal entity.
PUBLIC_BRAND = "Brainbyte"
COPYRIGHT_PERIOD = "2025-2026"

STANDARD_MIT_LICENSE = """MIT License

Copyright (c) 2025-2026 0xRootNull

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

DECLARATION_FIELDS = {
    "Project": PROJECT_NAME,
    "Former project name": FORMER_PROJECT_NAME,
    "Public brand": PUBLIC_BRAND,
    "Public author and copyright holder": PUBLIC_ATTRIBUTION,
    "Public attribution": PUBLIC_ATTRIBUTION,
    "Development started": "2025",
    "Copyright period": COPYRIGHT_PERIOD,
    "Project type": "Personal free and open-source software",
    "Project license": "MIT for project-owned portions",
    "MIT licensing intent": "Explicitly confirmed for project-owned portions",
    "Registered company or legal entity": "None",
    "Company registration number": "None",
    "Employer, client or commissioning party": "None",
    "Known other human contributors": "None",
    "AI-assisted development": "Yes",
    "Legal identity behind pseudonym published": "No",
    "Qualified legal review": "Unresolved",
    "Public distribution verdict": "HOLD",
}

STATUS_FIELDS = {
    "Project-copyright-owner-status": "PASS",
    "Copyright-start-year-status": "PASS",
    "Copyright-year-range-status": "PASS",
    "Public-attribution-status": "PASS",
    "MIT-licensing-intent-status": "PASS",
    "Company-employer-client-claim-status": "PASS",
    "Additional-human-contributor-claim-status": "PASS",
}

SOURCE_PATHS = (
    "LICENSE",
    "README.md",
    "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    "docs/PROJECT-OWNERSHIP-DECLARATION.md",
    "pyproject.toml",
    "version_info.txt",
)


def application_version(root: Path) -> str:
    config_path = root / "src" / "openfetch" / "config.py"
    tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise ValueError("VERSION was not found as a string constant in config.py")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([^:\r\n]+):\s*(.+)", line)
        if match:
            fields[match.group(1)] = match.group(2).strip()
    return fields


def validate_sources(root: Path) -> None:
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    if license_text != STANDARD_MIT_LICENSE:
        raise ValueError("LICENSE is not the exact approved standard MIT text")

    with (root / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    project = pyproject.get("project", {})
    if project.get("authors") != [{"name": PUBLIC_ATTRIBUTION}]:
        raise ValueError("pyproject.toml must name only 0xRootNull as project author")
    if project.get("license") != {"text": "MIT"}:
        raise ValueError("pyproject.toml must declare the MIT project license")

    declaration = (root / "docs" / "PROJECT-OWNERSHIP-DECLARATION.md").read_text(
        encoding="utf-8"
    )
    fields = exact_fields(declaration)
    for key, expected in {**STATUS_FIELDS, **DECLARATION_FIELDS}.items():
        if fields.get(key) != expected:
            raise ValueError(
                f"ownership declaration field differs: {key}={fields.get(key)!r}"
            )

    readme = (root / "README.md").read_text(encoding="utf-8")
    for marker in (
        "Copyright (c) 2025-2026 0xRootNull",
        "Third-party components remain governed by their respective licenses",
    ):
        if marker not in readme:
            raise ValueError(f"README.md lacks required project metadata: {marker}")

    version_info = (root / "version_info.txt").read_text(encoding="utf-8")
    for marker in (
        f'StringStruct("CompanyName", "{PUBLIC_BRAND}")',
        '"Copyright (c) 2025-2026 0xRootNull"',
        f'StringStruct("ProductVersion", "{application_version(root)}")',
    ):
        if marker not in version_info:
            raise ValueError(f"version_info.txt lacks required metadata: {marker}")

    prohibited = ("Neuralshield & " + PUBLIC_ATTRIBUTION, PUBLIC_BRAND + " & " + PUBLIC_ATTRIBUTION)
    for relative in SOURCE_PATHS:
        text = (root / relative).read_text(encoding="utf-8")
        if any(combined in text for combined in prohibited):
            raise ValueError(f"combined brand/copyright attribution remains in {relative}")


def inventory(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    validate_sources(root)
    source_records = [
        {
            "path": relative,
            "sha256": sha256_file(root / relative),
        }
        for relative in SOURCE_PATHS
    ]
    return {
        "schema_version": 1,
        "project": PROJECT_NAME,
        "former_project_name": FORMER_PROJECT_NAME,
        "public_brand": PUBLIC_BRAND,
        "application_version": application_version(root),
        "public_author_and_copyright_holder": PUBLIC_ATTRIBUTION,
        "public_attribution": PUBLIC_ATTRIBUTION,
        "development_started": 2025,
        "copyright_period": COPYRIGHT_PERIOD,
        "project_type": "Personal free and open-source software",
        "project_license": "MIT for project-owned portions",
        "mit_licensing_intent": "explicitly confirmed",
        "registered_company_or_legal_entity": None,
        "company_registration_number": None,
        "employer_client_or_commissioning_party": None,
        "known_other_human_contributors": [],
        "ai_assisted_development": True,
        "legal_identity_behind_pseudonym_published": False,
        "qualified_legal_review_status": "HOLD",
        "public_distribution_verdict": "HOLD",
        "scope": "project-owned portions only",
        "source_records": source_records,
    }


def render(root: Path = PROJECT_ROOT) -> str:
    return json.dumps(inventory(root), indent=2, sort_keys=True) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expected = render()
    output = args.output.resolve()
    if args.check:
        # Compare exact bytes: the inventory records SHA-256 values of tracked
        # files, so a line-ending rewrite of this file must fail the check
        # instead of being hidden by universal-newline decoding.
        if not output.is_file() or output.read_bytes() != expected.encode("utf-8"):
            print(f"HOLD: project metadata inventory differs or is missing: {output}")
            return 1
        print("Project metadata inventory verified.")
        return 0
    # newline="\n" keeps the generated inventory byte-identical across platforms.
    output.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Generated {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
