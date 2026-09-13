"""Verify the provider-free PySide6 source and build boundary before packaging."""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

PYSIDE_VERSION = "6.11.1"
CPYTHON_LIBFFI_SHA256 = (
    "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e"
)
PROVIDER_VENDOR_PATH = Path("vendor/bgutil-ytdlp-pot-provider")
REQUIRED_COMPLIANCE_FILES: tuple[Path, ...] = tuple(
    Path(value)
    for value in (
        "LICENSE",
        "PROJECT-METADATA.json",
        "THIRD_PARTY_LICENSES.txt",
        "THIRD_PARTY_NOTICES.md",
        "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
        "docs/PROJECT-OWNERSHIP-DECLARATION.md",
        "docs/DEPENDENCY-SOURCE.md",
        "docs/BUILD-REPRODUCIBILITY.md",
        "docs/LGPL-COMPLIANCE.md",
        "docs/QT-REPLACEMENT-GUIDE.md",
        "docs/QT-BUILD-PROVENANCE.md",
        "docs/OPTIONAL-PO-PROVIDER.md",
        "requirements.lock",
        "SOURCE-HASHES.sha256",
        "licenses/RELEASE-LICENSE-MANIFEST.sha256",
    )
)

_EXACT_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*"
    r"([^\s;\\]+)(?:\s*;\s*.+)?\s*$"
)
_FORBIDDEN_DISTRIBUTIONS = {
    "bgutil-ytdlp-pot-provider",
    "pyqt",
    "pyqt5",
    "pyqt6",
    "pyqt6-qt6",
    "pyqt6-sip",
}
_REQUIRED_LOCK_PACKAGES = {
    "pyside6": PYSIDE_VERSION,
    "pyside6-addons": PYSIDE_VERSION,
    "pyside6-essentials": PYSIDE_VERSION,
    "shiboken6": PYSIDE_VERSION,
}
_REQUIRED_SPEC_EXCLUDES = {
    "PyQt",
    "PyQt5",
    "PyQt6",
    "yt_dlp_plugins",
    "bgutil_ytdlp_pot_provider",
}
_SPEC_PAYLOAD_KEYWORDS = ("datas", "binaries", "pathex", "hiddenimports")
_RAW_JAVASCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".js.map")
_SOURCE_HASH_LINE = re.compile(r"^([0-9a-f]{64})  ([^\\]+)$")


def _normalize_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_exact_requirement(value: str) -> tuple[str, str] | None:
    match = _EXACT_REQUIREMENT.fullmatch(value.rstrip("\\").strip())
    if match is None:
        return None
    return _normalize_distribution(match.group(1)), match.group(2)


def _forbidden_distribution(name: str) -> bool:
    normalized = _normalize_distribution(name)
    return normalized in _FORBIDDEN_DISTRIBUTIONS or normalized.startswith("bgutil-")


def _forbidden_module(name: str) -> bool:
    normalized = name.casefold().replace("-", "_")
    root = normalized.split(".", 1)[0]
    return (
        root in {"pyqt", "pyqt5", "pyqt6", "bgutil_ytdlp_pot_provider"}
        or normalized == "yt_dlp_plugins"
        or normalized.startswith("yt_dlp_plugins.")
        or root.startswith("getpot_bgutil")
    )


def _iter_dynamic_imports(tree: ast.AST) -> Iterable[tuple[str, int]]:
    import_functions = {"__import__", "find_spec", "import_module"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        function_name = ""
        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr
        if function_name not in import_functions:
            continue
        first_argument = node.args[0]
        if isinstance(first_argument, ast.Constant) and isinstance(first_argument.value, str):
            yield first_argument.value, node.lineno


def _verify_python_sources(project_root: Path) -> list[str]:
    errors: list[str] = []
    source_root = project_root / "src"
    if not source_root.is_dir():
        return [f"application source directory is missing: {source_root}"]

    for path in sorted(source_root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(project_root).as_posix()
        lowered_parts = {part.casefold().replace("-", "_") for part in path.parts}
        if lowered_parts & {"pyqt", "pyqt5", "pyqt6", "yt_dlp_plugins"}:
            errors.append(f"forbidden in-process package path: {relative}")
        if path.name.casefold().endswith(_RAW_JAVASCRIPT_SUFFIXES):
            errors.append(f"raw JavaScript/TypeScript exists in application source: {relative}")
        if path.suffix.casefold() != ".py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            errors.append(f"cannot parse application source {relative}: {exc}")
            continue
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported = [node.module]
            for module in imported:
                if _forbidden_module(module):
                    errors.append(
                        f"forbidden in-process import in {relative}:{node.lineno}: {module}"
                    )
        for module, line_number in _iter_dynamic_imports(tree):
            if _forbidden_module(module):
                errors.append(
                    f"forbidden dynamic import in {relative}:{line_number}: {module}"
                )
    return errors


def _iter_pyproject_requirements(configuration: dict) -> Iterable[tuple[str, str]]:
    project = configuration.get("project", {})
    for value in project.get("dependencies", []):
        yield "project.dependencies", value
    for group, values in project.get("optional-dependencies", {}).items():
        for value in values:
            yield f"project.optional-dependencies.{group}", value
    for value in configuration.get("build-system", {}).get("requires", []):
        yield "build-system.requires", value
    for group, values in configuration.get("dependency-groups", {}).items():
        for value in values:
            if isinstance(value, str):
                yield f"dependency-groups.{group}", value
    for value in configuration.get("tool", {}).get("uv", {}).get("dev-dependencies", []):
        yield "tool.uv.dev-dependencies", value


def _verify_pyproject(path: Path) -> list[str]:
    if not path.is_file():
        return [f"dependency manifest is missing: {path}"]
    try:
        configuration = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot parse dependency manifest {path.name}: {exc}"]

    errors: list[str] = []
    parsed: dict[str, set[str]] = {}
    for group, requirement in _iter_pyproject_requirements(configuration):
        exact = _parse_exact_requirement(requirement)
        if exact is None:
            errors.append(f"dependency is not exactly pinned in {group}: {requirement}")
            continue
        name, version = exact
        parsed.setdefault(name, set()).add(version)
        if _forbidden_distribution(name):
            errors.append(f"forbidden dependency in {group}: {requirement}")

    if parsed.get("pyside6") != {PYSIDE_VERSION}:
        errors.append(f"project must directly pin PySide6=={PYSIDE_VERSION}")
    return errors


def _requirement_records(payload: str) -> list[str]:
    records: list[str] = []
    current: list[str] = []
    for raw_line in payload.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line[:1].isspace():
            if current:
                current.append(raw_line.strip())
            continue
        if current:
            records.append(" ".join(current))
        current = [raw_line.strip()]
    if current:
        records.append(" ".join(current))
    return records


def _verify_requirements_file(path: Path, *, require_hashes: bool) -> list[str]:
    if not path.is_file():
        return [f"dependency manifest is missing: {path}"]
    try:
        records = _requirement_records(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError) as exc:
        return [f"cannot read dependency manifest {path.name}: {exc}"]

    errors: list[str] = []
    parsed: dict[str, set[str]] = {}
    for record in records:
        requirement = record.split(" --hash=", 1)[0].rstrip("\\").strip()
        exact = _parse_exact_requirement(requirement)
        if exact is None:
            errors.append(f"dependency is not exactly pinned in {path.name}: {requirement}")
            continue
        name, version = exact
        parsed.setdefault(name, set()).add(version)
        if _forbidden_distribution(name):
            errors.append(f"forbidden dependency in {path.name}: {requirement}")
        if require_hashes and "--hash=sha256:" not in record:
            errors.append(f"locked dependency has no SHA-256 artifact hash: {requirement}")

    if parsed.get("pyside6") != {PYSIDE_VERSION}:
        errors.append(f"{path.name} must pin PySide6=={PYSIDE_VERSION}")
    if require_hashes:
        for name, version in _REQUIRED_LOCK_PACKAGES.items():
            if parsed.get(name) != {version}:
                errors.append(f"{path.name} must pin {name}=={version}")
    return errors


def _artifact_has_sha256(artifact: object) -> bool:
    return (
        isinstance(artifact, dict)
        and isinstance(artifact.get("hash"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["hash"]) is not None
    )


def _verify_uv_lock(path: Path) -> list[str]:
    if not path.is_file():
        return [f"dependency lock is missing: {path}"]
    try:
        configuration = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot parse dependency lock {path.name}: {exc}"]

    errors: list[str] = []
    versions: dict[str, set[str]] = {}
    packages = configuration.get("package", [])
    if not isinstance(packages, list) or not packages:
        return ["uv.lock has no package records"]
    for package in packages:
        if not isinstance(package, dict):
            errors.append("uv.lock contains a malformed package record")
            continue
        name_value = package.get("name")
        version_value = package.get("version")
        source_record = package.get("source", {})
        if isinstance(source_record, dict) and "editable" in source_record:
            # The project's own editable entry has a dynamic version derived from
            # openfetch.config.VERSION, so uv records no version for it.
            if not isinstance(name_value, str):
                errors.append("uv.lock project record is missing a name")
            continue
        if not isinstance(name_value, str) or not isinstance(version_value, str):
            errors.append("uv.lock package is missing a name or version")
            continue
        name = _normalize_distribution(name_value)
        versions.setdefault(name, set()).add(version_value)
        if _forbidden_distribution(name):
            errors.append(f"forbidden dependency in uv.lock: {name_value}=={version_value}")
        source = package.get("source", {})
        if isinstance(source, dict) and "registry" in source:
            artifacts: list[object] = []
            if "sdist" in package:
                artifacts.append(package["sdist"])
            wheels = package.get("wheels", [])
            if isinstance(wheels, list):
                artifacts.extend(wheels)
            if not artifacts:
                errors.append(f"registry package has no locked artifacts: {name_value}=={version_value}")
            elif not all(_artifact_has_sha256(artifact) for artifact in artifacts):
                errors.append(
                    f"registry package has an artifact without SHA-256: {name_value}=={version_value}"
                )
    for name, version in _REQUIRED_LOCK_PACKAGES.items():
        if versions.get(name) != {version}:
            errors.append(f"uv.lock must pin {name}=={version}")
    return errors


def _verify_source_hashes(project_root: Path) -> list[str]:
    manifest_path = project_root / "SOURCE-HASHES.sha256"
    if not manifest_path.is_file():
        return []  # The common compliance-file check reports the missing file once.
    try:
        lines = manifest_path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        return [f"cannot read SOURCE-HASHES.sha256: {exc}"]

    errors: list[str] = []
    records: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = _SOURCE_HASH_LINE.fullmatch(line)
        if match is None:
            errors.append(
                "invalid SOURCE-HASHES.sha256 line "
                f"{line_number}; expected lowercase '<sha256>  <relative/posix-path>'"
            )
            continue
        relative = match.group(2)
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
            errors.append(f"unsafe/non-POSIX source-hash path: {relative}")
            continue
        if relative in records:
            errors.append(f"duplicate source-hash path: {relative}")
            continue
        records[relative] = match.group(1)
    if not records:
        errors.append("SOURCE-HASHES.sha256 has no valid file records")

    for relative, expected_hash in records.items():
        path = project_root / Path(relative)
        if not path.is_file():
            errors.append(f"source-hash target is missing: {relative}")
            continue
        try:
            size = path.stat().st_size
            actual_hash = _sha256_file(path)
        except OSError as exc:
            errors.append(f"cannot hash source-hash target {relative}: {exc}")
            continue
        if size == 0 and not (
            relative.startswith("third_party_sources/") and actual_hash == expected_hash
        ):
            # Empty project files are placeholders; byte-preserved upstream
            # source copies may legitimately contain empty package markers.
            errors.append(f"source-hash target is empty: {relative}")
        elif actual_hash != expected_hash:
            errors.append(f"source-hash mismatch: {relative}")
    return errors


def _assignment_map(tree: ast.AST) -> dict[str, ast.AST]:
    assignments: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            assignments[node.target.id] = node.value
    return assignments


def _resolved_string_literals(
    expression: ast.AST | None,
    assignments: dict[str, ast.AST],
    seen: frozenset[str] = frozenset(),
) -> set[str]:
    if expression is None:
        return set()
    values = {
        node.value
        for node in ast.walk(expression)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for node in ast.walk(expression):
        if not isinstance(node, ast.Name) or node.id in seen or node.id not in assignments:
            continue
        values.update(
            _resolved_string_literals(
                assignments[node.id], assignments, seen | {node.id}
            )
        )
    return values


def _contains_name(expression: ast.AST, expected: str) -> bool:
    return any(isinstance(node, ast.Name) and node.id == expected for node in ast.walk(expression))


def _spec_forbidden_payload_literal(value: str) -> bool:
    lowered = value.casefold().replace("\\", "/")
    return (
        "pyqt" in lowered
        or "bgutil" in lowered
        or "getpot" in lowered
        or "yt_dlp_plugins" in lowered
        or "yt-dlp-plugins" in lowered
        or "node_modules/canvas" in lowered
    )


def _verify_spec(path: Path) -> list[str]:
    if not path.is_file():
        return [f"PyInstaller spec is missing: {path}"]
    try:
        text = path.read_text(encoding="utf-8-sig")
        tree = ast.parse(text, filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        return [f"cannot parse PyInstaller spec: {exc}"]

    errors: list[str] = []
    assignments = _assignment_map(tree)
    analysis_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Analysis"
    ]
    if len(analysis_calls) != 1:
        return [f"spec must contain exactly one Analysis call, found {len(analysis_calls)}"]
    keywords = {keyword.arg: keyword.value for keyword in analysis_calls[0].keywords if keyword.arg}

    for keyword in _SPEC_PAYLOAD_KEYWORDS:
        values = _resolved_string_literals(keywords.get(keyword), assignments)
        forbidden = sorted(value for value in values if _spec_forbidden_payload_literal(value))
        if forbidden:
            errors.append(f"spec {keyword} references forbidden payloads: {forbidden}")

    excludes = _resolved_string_literals(keywords.get("excludes"), assignments)
    missing_excludes = sorted(_REQUIRED_SPEC_EXCLUDES - excludes)
    if missing_excludes:
        errors.append("spec is missing fail-closed exclusions: " + ", ".join(missing_excludes))
    noarchive = keywords.get("noarchive")
    if not isinstance(noarchive, ast.Constant) or noarchive.value is not False:
        errors.append("spec must set noarchive=False so the embedded PYZ can be audited")

    binary_expression = keywords.get("binaries")
    has_root_libffi = False
    if binary_expression is not None:
        resolved_binary_expression = assignments.get(binary_expression.id) if isinstance(binary_expression, ast.Name) else binary_expression
        if resolved_binary_expression is not None:
            for node in ast.walk(resolved_binary_expression):
                if not isinstance(node, (ast.Tuple, ast.List)):
                    continue
                if _contains_name(node, "python_libffi") and any(
                    isinstance(child, ast.Constant) and child.value == "."
                    for child in ast.walk(node)
                ):
                    has_root_libffi = True
                    break
    if not has_root_libffi:
        errors.append("spec does not place python_libffi at archive root")

    has_exact_libffi_guard = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "require_sha256"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "python_libffi"
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == CPYTHON_LIBFFI_SHA256
        for node in ast.walk(tree)
    )
    if not has_exact_libffi_guard:
        errors.append("spec does not enforce the exact CPython libffi 3.4.2 SHA-256")

    data_literals = _resolved_string_literals(keywords.get("datas"), assignments)
    for required in REQUIRED_COMPLIANCE_FILES:
        if required.name not in data_literals:
            errors.append(f"spec does not bundle required compliance file: {required.as_posix()}")

    if 'project_root / "vendor" / "bgutil-ytdlp-pot-provider"' not in text:
        errors.append("spec has no fail-closed guard against the provider vendor tree")
    return errors


def verify_project(project_root: Path) -> list[str]:
    """Return pre-build distribution-boundary errors for *project_root*."""
    project_root = project_root.resolve()
    errors: list[str] = []
    provider_root = project_root / PROVIDER_VENDOR_PATH
    if provider_root.exists():
        errors.append(f"GPL provider tree is present in application project: {provider_root}")

    errors.extend(_verify_python_sources(project_root))
    errors.extend(_verify_pyproject(project_root / "pyproject.toml"))
    errors.extend(
        _verify_requirements_file(project_root / "requirements.txt", require_hashes=False)
    )
    errors.extend(
        _verify_requirements_file(project_root / "requirements.lock", require_hashes=True)
    )
    errors.extend(_verify_uv_lock(project_root / "uv.lock"))
    errors.extend(_verify_spec(project_root / "OpenFetch.spec"))
    errors.extend(_verify_source_hashes(project_root))

    for relative_path in REQUIRED_COMPLIANCE_FILES:
        path = project_root / relative_path
        if not path.is_file():
            errors.append(f"required compliance file is missing: {relative_path.as_posix()}")
        elif path.stat().st_size == 0:
            errors.append(f"required compliance file is empty: {relative_path.as_posix()}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", nargs="?", type=Path, default=Path(__file__).parents[1])
    args = parser.parse_args()
    errors = verify_project(args.project_root)
    if errors:
        for error in errors:
            print(f"HOLD: {error}")
        return 1
    print("PASS: provider-free PySide6 source, dependency, and spec boundary verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
