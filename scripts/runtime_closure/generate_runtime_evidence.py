"""Generate fail-closed FFmpeg, Python-runtime, Microsoft, and native evidence.

The script is deliberately local-only: it performs no Git operation, network
request, publication, or remote mutation.  `--check` validates generated
evidence.  `--release-gate` additionally fails while any documented closure is
HOLD.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import tarfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
COMPANION = ROOT / "dist" / "pyside-provider-free-final-audit-20260722-2" / "THIRD_PARTY_LICENSES-artifact-companion.txt"
ANALYSIS_TOC = ROOT / "build" / "pyside-provider-free-final-audit-20260722-2" / "NeuralExtractorV3" / "Analysis-00.toc"
FFMPEG_ROOT = ROOT / "third_party_sources" / "ffmpeg"
PYTHON_ROOT = ROOT / "third_party_sources" / "python-runtime"
NATIVE_ROOT = ROOT / "third_party_sources" / "native"
MICROSOFT_ROOT = ROOT / "licenses" / "microsoft"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def parse_native_tables() -> list[dict[str, Any]]:
    text = COMPANION.read_text(encoding="utf-8")
    section_names = (
        "Exact PySide/Qt DLL, PYD, plugin, and translation paths",
        "Exact remaining native DLL, PYD, and EXE paths",
    )
    records: list[dict[str, Any]] = []
    for section in section_names:
        start = text.index(section)
        table_start = text.index("| Archive path |", start)
        table_end = text.find("\n\n", table_start)
        for line in text[table_start:table_end].splitlines()[2:]:
            if not line.startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) != 5 or not cells[1].isdigit() or not re.fullmatch(r"[0-9a-f]{64}", cells[2]):
                continue
            records.append({
                "path": cells[0].replace("\\", "/"),
                "size": int(cells[1]),
                "sha256": cells[2],
                "component": cells[3],
                "pe_file_version": None if cells[4] == "n/a" else cells[4],
            })
    if len(records) != 96 or len({record["path"].casefold() for record in records}) != 96:
        raise ValueError(f"expected 96 unique final native paths, found {len(records)}")
    return sorted(records, key=lambda record: record["path"].casefold())


def walk_toc(value: Any) -> Iterable[tuple[str, str, str]]:
    if isinstance(value, (tuple, list)):
        if len(value) == 3 and all(isinstance(item, str) for item in value) and value[2] in {"BINARY", "EXTENSION"}:
            yield value
        else:
            for item in value:
                yield from walk_toc(item)


def analysis_sources() -> dict[str, str]:
    value = ast.literal_eval(ANALYSIS_TOC.read_text(encoding="utf-8"))
    result: dict[str, str] = {}
    for destination, source, _kind in walk_toc(value):
        result.setdefault(destination.replace("\\", "/").casefold(), source)
    return result


def source_mapping(record: dict[str, Any], analysis: dict[str, str]) -> dict[str, Any]:
    path = record["path"]
    component = record["component"]
    observed_source = analysis.get(path.casefold())
    lower_component = component.casefold()
    if component == "Microsoft runtime":
        if path.startswith("PySide6/"):
            source = "PySide6_Essentials-6.11.1-cp39-abi3-win_amd64.whl"
        elif path.startswith("shiboken6/"):
            source = "shiboken6-6.11.1-cp39-abi3-win_amd64.whl"
        elif path.casefold().startswith("api-ms-") or path.casefold() == "ucrtbase.dll":
            source = "Windows Performance Toolkit installation (Windows Kits 10); exact redistributable installer identity unresolved"
        else:
            source = "python-build-standalone 20250317 stripped install-only asset"
        return {
            "source_set": source,
            "source_location": "licenses/microsoft/MICROSOFT-RUNTIME-INVENTORY.json",
            "build_recipe": "Upstream wheel/PBS/Windows SDK packaging; project did not build these DLLs",
            "notice": "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md and licenses/microsoft/**",
            "observed_build_input_path": observed_source,
            "evidence_status": "HOLD - exact redistribution entitlement is not confirmed",
        }
    if component.startswith("Qt 6.11.1"):
        return {
            "source_set": "QtBase 6.11.1; opengl32sw also uses Qt/ANGLE third-party source",
            "source_location": "third_party_sources/qt and docs/QT-BUILD-PROVENANCE.md",
            "build_recipe": "Official PySide6-Essentials wheel build; exact upstream wheel provenance in Qt package",
            "notice": "licenses/qt/** and docs/LGPL-COMPLIANCE.md",
            "observed_build_input_path": observed_source,
            "evidence_status": "HOLD - Qt package/replacement review is tracked separately",
        }
    if component.startswith("PySide6") or component.startswith("Shiboken6"):
        return {
            "source_set": "pyside-setup-everywhere-src-6.11.1",
            "source_location": "third_party_sources/qt and docs/QT-BUILD-PROVENANCE.md",
            "build_recipe": "Official PySide6/Shiboken6 wheel build",
            "notice": "licenses/pyside/** and docs/LGPL-COMPLIANCE.md",
            "observed_build_input_path": observed_source,
            "evidence_status": "HOLD - Qt package/replacement review is tracked separately",
        }
    if component.startswith("CPython") or any(name in lower_component for name in ("openssl", "sqlite", "bzip2", "xz utils", "mpdecimal", "libffi")):
        return {
            "source_set": component,
            "source_location": "third_party_sources/python-runtime/SOURCE-MANIFEST.json",
            "build_recipe": "python-build-standalone commit 7d8bb5e8cf054d88cbf505645257a25b8f46b286, cpython-windows/build.py",
            "notice": "third_party_sources/python-runtime/licenses/** and docs/PYTHON-RUNTIME-SOURCE.md",
            "observed_build_input_path": observed_source,
            "evidence_status": "HOLD - exact upstream release buildhost/toolchain record is incomplete",
        }
    if component.startswith("FFmpeg"):
        return {
            "source_set": "FFmpeg 9a01c1cb6a4cf87529fe9898b66ec55c5b032639 plus BtbN build scripts 7a83528ea3431e9eca982a712bc3a7cd0789d5d0",
            "source_location": "third_party_sources/ffmpeg/SOURCE-MANIFEST.json",
            "build_recipe": "third_party_sources/ffmpeg/build-scripts/**",
            "notice": "licenses/ffmpeg/**",
            "observed_build_input_path": observed_source,
            "evidence_status": "HOLD - linked-library corresponding source is incomplete",
        }
    if component.startswith("Node.js"):
        return {
            "source_set": "Node.js 22.17.0",
            "source_location": "third_party_sources/node/node-v22.17.0.tar.gz",
            "build_recipe": "Official Node.js Windows x64 release",
            "notice": "licenses/Node.js-22.17.0-LICENSE.txt",
            "observed_build_input_path": observed_source,
            "evidence_status": "MAPPED; root Node source closure tracked separately",
        }
    if component.startswith("charset-normalizer"):
        return {
            "source_set": "charset-normalizer 3.4.9",
            "source_location": "third_party_sources/python-packages and requirements.lock",
            "build_recipe": "Exact locked Windows wheel",
            "notice": "licenses/python/charset_normalizer-3.4.9-LICENSE.txt",
            "observed_build_input_path": observed_source,
            "evidence_status": "MAPPED; Python-package closure tracked separately",
        }
    raise ValueError(f"no source mapping rule for {path}: {component}")


def microsoft_inventory(native: list[dict[str, Any]], analysis: dict[str, str]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for item in native:
        if item["component"] != "Microsoft runtime":
            continue
        source = analysis.get(item["path"].casefold())
        local_match = False
        source_hash = None
        source_size = None
        if source and Path(source).is_file():
            source_path = Path(source)
            source_hash = sha256(source_path)
            source_size = source_path.stat().st_size
            local_match = source_hash == item["sha256"] and source_size == item["size"]
        if item["path"].startswith("PySide6/"):
            source_package = "PySide6_Essentials-6.11.1-cp39-abi3-win_amd64.whl"
            terms = ["Visual-Studio-2022-REDIST-current.txt", "PySide/Qt upstream wheel terms require separate review"]
        elif item["path"].startswith("shiboken6/"):
            source_package = "shiboken6-6.11.1-cp39-abi3-win_amd64.whl"
            terms = ["Visual-Studio-2022-REDIST-current.txt", "PySide/Qt upstream wheel terms require separate review"]
        elif item["path"].casefold().startswith("api-ms-") or item["path"].casefold() == "ucrtbase.dll":
            source_package = "Local Windows Performance Toolkit installation; exact installer/package identity not retained"
            terms = ["Windows-SDK-10.0.26100.0-license.rtf", "Windows-Performance-Toolkit-NOTICE.txt"]
        else:
            source_package = "python-build-standalone 20250317 x86_64-pc-windows-msvc install-only stripped asset"
            terms = ["Visual-Studio-2022-REDIST-current.txt", "python-build-standalone upstream distribution evidence"]
        records.append({
            **item,
            "observed_build_input_path": source,
            "observed_build_input_size": source_size,
            "observed_build_input_sha256": source_hash,
            "observed_input_matches_conveyed_bytes": local_match,
            "source_package": source_package,
            "candidate_terms_evidence": [f"licenses/microsoft/{name}" for name in terms],
            "redistribution_status": "HOLD - candidate terms retained, exact permitted-redistribution proof not confirmed",
        })
    return {
        "schema_version": 1,
        "status": "HOLD",
        "distributed_microsoft_file_count": len(records),
        "all_bytes_mapped_to_observed_build_input": all(record["observed_input_matches_conveyed_bytes"] for record in records),
        "redistribution_rights_confirmed_count": 0,
        "records": records,
        "blockers": [
            "The Windows Performance Toolkit files were taken from a local installed toolkit, not a retained official redistributable installer.",
            "Candidate SDK/Visual Studio terms do not by themselves prove every exact file is permitted for this redistribution.",
            "PySide/Shiboken wheel carriage and PBS carriage do not replace confirmation of the project's own redistribution entitlement.",
            "Qualified legal review is required before changing HOLD.",
        ],
    }


def ffmpeg_version_evidence() -> dict[str, Any]:
    outputs: dict[str, str] = {}
    for name in ("ffmpeg", "ffprobe"):
        binary = ROOT / "bin" / f"{name}.exe"
        process = subprocess.run([str(binary), "-hide_banner", "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        outputs[name] = process.stdout.decode("utf-8", errors="replace").strip()
    first = outputs["ffmpeg"].splitlines()
    configuration = next(line.split("configuration:", 1)[1].strip() for line in first if line.startswith("configuration:"))
    return {
        "reported_version": first[0],
        "compiler": next(line for line in first if line.startswith("built with ")),
        "configure_command": configuration,
        "configure_arguments": configuration.split(),
        "ffmpeg_version_output": outputs["ffmpeg"],
        "ffprobe_version_output": outputs["ffprobe"],
    }


def ffmpeg_dependencies() -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    assignment = re.compile(r"^SCRIPT_(REPO|COMMIT|REV)(\d*)=(?:\"([^\"]*)\"|'([^']*)'|([^\s#]+))", re.MULTILINE)
    for script in sorted((FFMPEG_ROOT / "build-scripts" / "scripts.d").rglob("*.sh"), key=lambda path: path.as_posix().casefold()):
        values: dict[tuple[str, str], str] = {}
        text = script.read_text(encoding="utf-8")
        for match in assignment.finditer(text):
            values[(match.group(1), match.group(2))] = next(value for value in match.groups()[2:] if value is not None)
        suffixes = sorted({suffix for kind, suffix in values if kind == "REPO"}, key=lambda value: (len(value), value))
        for suffix in suffixes:
            repo = values[("REPO", suffix)]
            revision = values.get(("COMMIT", suffix)) or values.get(("REV", suffix))
            literal = bool(revision and "$" not in revision and "`" not in revision)
            if revision and re.fullmatch(r"[0-9a-f]{40}", revision):
                revision_kind = "full Git commit"
                immutable_locator = True
            elif revision and revision.isdecimal():
                revision_kind = "numeric SVN revision"
                immutable_locator = True
            elif literal:
                revision_kind = "tag or other literal"
                immutable_locator = False
            else:
                revision_kind = "missing or dynamic"
                immutable_locator = False
            records.append({
                "build_script": script.relative_to(ROOT).as_posix(),
                "repository": repo,
                "revision": revision,
                "revision_kind": revision_kind,
                "revision_is_literal": literal,
                "revision_is_immutable_locator": immutable_locator,
                "source_archive_retained": False,
                "status": "HOLD - exact linked source archive/submodule closure is not retained",
            })
    return {
        "schema_version": 1,
        "status": "HOLD",
        "build_graph_repository_record_count": len(records),
        "literal_revision_count": sum(record["revision_is_literal"] for record in records),
        "immutable_revision_locator_count": sum(record["revision_is_immutable_locator"] for record in records),
        "tag_or_other_literal_count": sum(record["revision_kind"] == "tag or other literal" for record in records),
        "missing_or_dynamic_revision_count": sum(not record["revision_is_literal"] for record in records),
        "retained_linked_source_archive_count": sum(record["source_archive_retained"] for record in records),
        "records": records,
        "note": "This is the BtbN build-graph source superset. The exact FFmpeg configure command in BINARY-INVENTORY.json identifies enabled libraries. Disabled scripts can still appear here.",
    }


def file_manifest(root: Path, *, excluded_names: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = excluded_names or {"SOURCE-MANIFEST.json"}
    return [
        {"path": path.relative_to(ROOT).as_posix(), "size": path.stat().st_size, "sha256": sha256(path)}
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold())
        if path.is_file() and path.name not in excluded
    ]


def ffmpeg_manifests(native: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    version = ffmpeg_version_evidence()
    binaries = [item for item in native if item["component"].startswith("FFmpeg")]
    binary_inventory = {
        "schema_version": 1,
        "status": "HOLD",
        "release_asset": "autobuild-2026-06-30-13-34/ffmpeg-N-125365-g9a01c1cb6a-win64-gpl.zip",
        "release_asset_sha256": "52c0383c460f0ec1039088f1591921fb82e3b870b32aab8faf2ff1e5ae14bf9d",
        "ffmpeg_commit": "9a01c1cb6a4cf87529fe9898b66ec55c5b032639",
        "btbn_build_scripts_commit": "7a83528ea3431e9eca982a712bc3a7cd0789d5d0",
        "build_date": "2026-06-30",
        "license_route": "GPL-3.0-or-later engineering classification because --enable-gpl and --enable-version3 are present; qualified review required",
        "nonfree_enabled": "--enable-nonfree" in version["configure_arguments"],
        "binaries": binaries,
        **version,
    }
    dependencies = ffmpeg_dependencies()
    files = file_manifest(
        FFMPEG_ROOT,
        excluded_names={"BINARY-INVENTORY.json", "BUILD-DEPENDENCIES.json", "SOURCE-MANIFEST.json"},
    )
    source_manifest = {
        "schema_version": 1,
        "status": "HOLD",
        "ffmpeg_source_retained": any(record["path"].endswith("ffmpeg-9a01c1cb6a4cf87529fe9898b66ec55c5b032639.tar.gz") for record in files),
        "btbn_scripts_retained": any(record["path"].endswith("btbn-ffmpeg-builds-7a83528ea3431e9eca982a712bc3a7cd0789d5d0.tar.gz") for record in files),
        "binary_release_asset_retained": any(record["path"].endswith("ffmpeg-N-125365-g9a01c1cb6a-win64-gpl.zip") for record in files),
        "linked_dependency_sources_complete": False,
        "files": files,
        "blockers": [
            "The BtbN linked-library source archives and nested submodules are not retained.",
            "Some build-graph inputs use tags rather than content-addressed commits, and none of the linked dependency source archives are retained.",
            "The exact container image digest/crosstool source closure and original build log are not retained.",
            "A clean rebuild reproducing the conveyed ffmpeg/ffprobe bytes has not been completed.",
        ],
    }
    return binary_inventory, dependencies, source_manifest


PYTHON_INPUTS = [
    ("Python-3.12.9.tar.xz", "CPython", "3.12.9", "7220835d9f90b37c006e9842a8dff4580aaca4318674f947302b8d28f3f81112", "actual source"),
    ("python-build-standalone-7d8bb5e8cf054d88cbf505645257a25b8f46b286.zip", "python-build-standalone recipes", "7d8bb5e8cf054d88cbf505645257a25b8f46b286", "0f2d76ea433930d72e94541b6edfecbf2a6d26fb811adc681be92f17d07ff4b4", "actual recipes/patches"),
    ("cpython-3.12.9+20250317-x86_64-pc-windows-msvc-install_only_stripped.tar.gz", "python-build-standalone binary input", "20250317", "ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661", "exact runtime asset"),
    ("cpython-source-deps-16fad4855b3d8c03b5910e405ff3a04395b39a98.tar.gz", "libffi source", "commit 16fad4855b3d8c03b5910e405ff3a04395b39a98 / libffi 3.4.2", "f21ae7b0cce58cf9428e01d4d22aac9c3b70722a4e9b2c92b3a97d490a1b401c", "actual libffi source snapshot"),
    ("openssl-3.0.16.tar.gz", "OpenSSL", "3.0.16", "57e03c50feab5d31b152af2b764f10379aecd8ee92f16c985983ce4a99f7ef86", "actual source"),
    ("sqlite-autoconf-3470100.tar.gz", "SQLite", "3.47.1", "416a6f45bf2cacd494b208fdee1beda509abda951d5f47bc4f2792126f01b452", "actual source"),
    ("bzip2-1.0.8.tar.gz", "bzip2", "1.0.8", "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269", "actual source"),
    ("xz-5.2.12-pbs.tar.gz", "XZ/liblzma", "5.2.12", "61bda930767dcb170a5328a895ec74cab0f5aac4558cdda561c83559db582a13", "actual PBS build source"),
    ("zlib-1.3.1.tar.gz", "zlib", "1.3.1", "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23", "actual source"),
    ("UCD-15.0.0.zip", "Unicode UCD", "15.0.0", "5fbde400f3e687d25cc9b0a8d30d7619e76cb2f4c3e85ba9df8ec1312cb6718c", "generator/reference input"),
    ("setuptools-83.0.0.tar.gz", "setuptools", "83.0.0", "025bccbbf0fa05b6192bc64ae1e7b16e001fd6d6d4d5de03c97b1c1ade523bef", "frozen package source; package closure tracked separately"),
    ("strawberry-perl-5.38.2.2-64bit-portable.zip", "Strawberry Perl build tool", "5.38.2.2", "ea451686065d6338d7e4d4a04c9af49f17951d15aa4c2e19ab8cb56fa2373440", "OpenSSL build tool binary"),
    ("nasm-2.11.06-cpython-bin-deps.tar.gz", "NASM build tool", "2.11.06", "8af0ae5ceed63fa8a2ded611d44cc341027a91df22aaaa071efedc81437412a5", "OpenSSL build tool binary"),
    ("jom_1_1_4.zip", "jom build tool", "1.1.4", "d533c1ef49214229681e90196ed2094691e8c4a0a0bef0b2c901debcb562682b", "OpenSSL build tool binary"),
]


PYTHON_SUPPLEMENTAL_FILES = [
    (
        "cpython-3.12.9+20250317-x86_64-pc-windows-msvc-install_only_stripped.tar.gz.sha256",
        "upstream checksum sidecar for the exact runtime asset",
        "7b2d7149b38b8b96f642ad5f024cd0a6eb587f026bc221ec284b2424c02ef159",
    ),
    (
        "python-build-standalone-7d8bb5e8cf054d88cbf505645257a25b8f46b286.tar.gz",
        "alternate archive of the retained recipe commit",
        "6c49ca1c047c2568b6a4d16add1a9982e2c75ece1ef598aa8cb13e85daa1dd85",
    ),
    (
        "expat-2.6.4.tar.xz",
        "supplemental upstream source; the actual runtime copy is vendored in CPython 3.12.9",
        "a695629dae047055b37d50a0ff4776d1d45d0a4c842cf4ccee158441f55ff7ee",
    ),
    (
        "xz-5.2.12.tar.xz",
        "supplemental upstream release; PBS used xz-5.2.12-pbs.tar.gz",
        "f79a92b84101d19d76be833aecc93e68e56065b61ec737610964cd4f6c54ff2e",
    ),
]


def python_manifest(native: list[dict[str, Any]]) -> dict[str, Any]:
    archives = PYTHON_ROOT / "archives"
    records: list[dict[str, Any]] = []
    for filename, component, version, expected, role in PYTHON_INPUTS:
        path = archives / filename
        actual = sha256(path) if path.is_file() else None
        records.append({
            "component": component,
            "version_or_commit": version,
            "role": role,
            "path": path.relative_to(ROOT).as_posix(),
            "size": path.stat().st_size if path.is_file() else None,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "verified": actual == expected,
        })
    supplemental: list[dict[str, Any]] = []
    for filename, role, expected in PYTHON_SUPPLEMENTAL_FILES:
        path = archives / filename
        actual = sha256(path) if path.is_file() else None
        supplemental.append({
            "role": role,
            "path": path.relative_to(ROOT).as_posix(),
            "size": path.stat().st_size if path.is_file() else None,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "verified": actual == expected,
        })
    binary_records = [item for item in native if item["component"].startswith("CPython") or any(name in item["component"] for name in ("OpenSSL", "SQLite", "libffi", "bzip2", "XZ Utils", "mpdecimal"))]
    return {
        "schema_version": 1,
        "status": "HOLD",
        "runtime": "CPython 3.12.9 / python-build-standalone 20250317 / Windows x64",
        "all_declared_archives_present_and_verified": all(
            record["verified"] for record in [*records, *supplemental]
        ),
        "source_and_tool_records": records,
        "supplemental_records": supplemental,
        "retained_file_manifest": file_manifest(
            PYTHON_ROOT,
            excluded_names={"RUNTIME-ASSET-COMPARISON.json", "SOURCE-MANIFEST.json"},
        ),
        "binary_records": binary_records,
        "vendored_in_cpython_source": [
            {"component": "Expat", "version": "2.6.4", "path": "Python-3.12.9/Modules/expat"},
            {"component": "mpdecimal", "version": "2.5.1", "path": "Python-3.12.9/Modules/_decimal/libmpdec"},
            {"component": "HACL*", "version": "bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0", "path": "Python-3.12.9/Modules/_hacl"},
            {"component": "BLAKE2 reference-derived code", "version": "CPython 3.12.9 snapshot", "path": "Python-3.12.9/Modules/_blake2"},
        ],
        "modifications": "Upstream PBS recipe/patch set retained; no project patch to CPython or its native dependencies is declared.",
        "blockers": [
            "The exact Visual Studio 2022 point version, Windows SDK selection, buildhost image and original PBS release build log are not retained.",
            "The libffi archive is a commit snapshot; the upstream recipe used a Git branch checkout and exact repository metadata is not reproduced without Git.",
            "A clean CPython/PBS rebuild matching every conveyed native hash has not been completed.",
            "Microsoft runtime redistribution entitlement remains separately HOLD.",
        ],
    }


def python_runtime_asset_comparison(native: list[dict[str, Any]]) -> dict[str, Any]:
    asset = (
        PYTHON_ROOT
        / "archives"
        / "cpython-3.12.9+20250317-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
    )
    selected = [
        item
        for item in native
        if item["component"].startswith("CPython")
        or any(
            name in item["component"]
            for name in ("OpenSSL", "SQLite", "libffi", "bzip2", "XZ Utils", "mpdecimal")
        )
        or item["path"] in {"VCRUNTIME140.dll", "VCRUNTIME140_1.dll"}
    ]
    records: list[dict[str, Any]] = []
    with tarfile.open(asset, mode="r:gz") as archive:
        for item in selected:
            if item["path"] in {"python3.dll", "python312.dll"}:
                member_name = f"python/{item['path']}"
            elif item["path"] in {"VCRUNTIME140.dll", "VCRUNTIME140_1.dll"}:
                member_name = f"python/{item['path'].lower()}"
            else:
                member_name = f"python/DLLs/{item['path']}"
            member = archive.getmember(member_name)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read runtime-asset member: {member_name}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            member_hash = digest.hexdigest()
            matches = member.size == item["size"] and member_hash == item["sha256"]
            records.append({
                "final_path": item["path"],
                "component": item["component"],
                "final_size": item["size"],
                "final_sha256": item["sha256"],
                "runtime_asset_member": member_name,
                "runtime_asset_member_size": member.size,
                "runtime_asset_member_sha256": member_hash,
                "matches_exact_runtime_asset": matches,
            })
    return {
        "schema_version": 1,
        "status": "HOLD",
        "byte_provenance_status": "MATCH",
        "runtime_asset": asset.relative_to(ROOT).as_posix(),
        "runtime_asset_sha256": sha256(asset),
        "compared_file_count": len(records),
        "all_selected_runtime_bytes_match_exact_asset": all(
            record["matches_exact_runtime_asset"] for record in records
        ),
        "records": records,
        "hold_reason": (
            "Exact artifact-byte provenance does not supply the missing upstream buildhost/toolchain "
            "record, clean rebuild evidence, or Microsoft redistribution-rights confirmation."
        ),
    }


def native_manifest(native: list[dict[str, Any]], analysis: dict[str, str]) -> dict[str, Any]:
    records = [{**item, **source_mapping(item, analysis)} for item in native]
    return {
        "schema_version": 1,
        "status": "HOLD",
        "artifact": COMPANION.relative_to(ROOT).as_posix(),
        "native_file_count": len(records),
        "unmapped_component_count": 0,
        "records": records,
        "note": "Every final DLL/PYD/EXE path has a component/source/build/notice mapping. HOLD records are mapped but not yet legally or reproducibly closed.",
    }


def expected_outputs() -> dict[Path, Any]:
    native = parse_native_tables()
    analysis = analysis_sources()
    binary_inventory, dependencies, ffmpeg_source = ffmpeg_manifests(native)
    return {
        FFMPEG_ROOT / "BINARY-INVENTORY.json": binary_inventory,
        FFMPEG_ROOT / "BUILD-DEPENDENCIES.json": dependencies,
        FFMPEG_ROOT / "SOURCE-MANIFEST.json": ffmpeg_source,
        PYTHON_ROOT / "SOURCE-MANIFEST.json": python_manifest(native),
        PYTHON_ROOT / "RUNTIME-ASSET-COMPARISON.json": python_runtime_asset_comparison(native),
        MICROSOFT_ROOT / "MICROSOFT-RUNTIME-INVENTORY.json": microsoft_inventory(native, analysis),
        NATIVE_ROOT / "NATIVE-COMPONENTS.json": native_manifest(native, analysis),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--release-gate", action="store_true")
    args = parser.parse_args()
    outputs = expected_outputs()
    errors: list[str] = []
    if args.write:
        for path, value in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(json_bytes(value))
    if args.check or not args.write:
        for path, value in outputs.items():
            if not path.is_file():
                errors.append(f"missing generated evidence: {path}")
            elif path.read_bytes() != json_bytes(value):
                errors.append(f"stale generated evidence: {path}")
    statuses = {path.relative_to(ROOT).as_posix(): value["status"] for path, value in outputs.items()}
    print(json.dumps({"outputs": len(outputs), "statuses": statuses, "errors": errors}, indent=2))
    if args.release_gate and any(status != "PASS" for status in statuses.values()):
        errors.append("release gate remains fail-closed because one or more runtime/source/native statuses are not PASS")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
