from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from scripts import verify_distribution_boundary as boundary
from scripts import verify_packaged_licensing as packaged


class FakePyz:
    def __init__(self, modules: tuple[str, ...] = ("PySide6", "PySide6.QtCore")) -> None:
        self.payloads = {module: f"bytecode:{module}".encode() for module in modules}
        self.toc = {
            module: (0, index, len(self.payloads[module]))
            for index, module in enumerate(modules)
        }

    def extract(self, name: str, raw: bool = False) -> bytes:
        assert raw is True
        return self.payloads[name]


class FakeCArchive:
    def __init__(self, payloads: dict[str, bytes], pyz: FakePyz | None = None) -> None:
        self.payloads = payloads
        self.toc = {
            name: (0, len(payload), len(payload), 0, "b")
            for name, payload in payloads.items()
        }
        self.toc["PYZ.pyz"] = (0, 0, 0, 0, "z")
        self.pyz = pyz or FakePyz()

    def extract(self, name: str) -> bytes:
        return self.payloads[name]

    def open_embedded_archive(self, name: str) -> FakePyz:
        assert name == "PYZ.pyz"
        return self.pyz


def _valid_archive(monkeypatch: pytest.MonkeyPatch) -> FakeCArchive:
    ffi = b"audited CPython libffi fixture"
    ctypes_extension = b"audited CPython ctypes fixture"
    monkeypatch.setattr(packaged, "CPYTHON_LIBFFI_SHA256", hashlib.sha256(ffi).hexdigest())
    monkeypatch.setattr(
        packaged,
        "CPYTHON_CTYPES_SHA256",
        hashlib.sha256(ctypes_extension).hexdigest(),
    )
    license_payload = b"Example third-party license text\n"
    license_hash = hashlib.sha256(license_payload).hexdigest()
    manifest = f"{license_hash}  Example-LICENSE.txt\n".encode()
    payloads = {
        path.replace("/", "\\"): b"compliance\n"
        for path in packaged.REQUIRED_COMPLIANCE_PATHS
        if path != packaged.LICENSE_MANIFEST_PATH
    }
    payloads["SOURCE-HASHES.sha256"] = (
        f"{'0' * 64}  corresponding-source-only.txt\n".encode()
    )
    payloads.update(
        {
            packaged.LICENSE_MANIFEST_PATH.replace("/", "\\"): manifest,
            "licenses\\Example-LICENSE.txt": license_payload,
            "libffi-8.dll": ffi,
            "_ctypes.pyd": ctypes_extension,
        }
    )
    for path in packaged.REQUIRED_PYSIDE_PATHS:
        payloads[path.replace("/", "\\")] = f"fixture:{path}".encode()
    archive = FakeCArchive(payloads)
    normalized = {
        name: packaged._normalize_archive_path(name) for name in archive.toc
    }
    fingerprint = packaged._calculate_payload_fingerprint(archive, normalized)
    inventoried_paths = sorted(
        path
        for path in normalized.values()
        if path.casefold().endswith((".dll", ".pyd", ".exe"))
        or path.casefold().startswith(
            ("pyside6/plugins/", "pyside6/translations/")
        )
    )
    inventory_text = "\n".join(
        (
            "Public-distribution verdict: HOLD",
            "Release-gate-status: HOLD",
            "Qualified-review-status: HOLD",
            "Audit-blocker-count: 1",
            f"Audited non-compliance payload fingerprint SHA-256: {fingerprint}",
            "| PyQt code/binary/module | 0 | 0 | 0 |",
            "| bgutil/getpot/yt_dlp_plugins provider code/module | 0 | 0 | 0 |",
            "| Raw JavaScript/TypeScript payload | 0 | 0 | 0 |",
            "| canvas native/module payload | 0 | 0 | 0 |",
            *(f"| {path} | fixture |" for path in inventoried_paths),
            "",
        )
    ).encode()
    inventory_name = "THIRD_PARTY_LICENSES.txt"
    archive.payloads[inventory_name] = inventory_text
    return archive


def test_packaged_verifier_accepts_minimal_provider_free_pyside_archive(monkeypatch):
    archive = _valid_archive(monkeypatch)

    assert packaged.verify_archive(archive) == []


def test_packaged_verifier_accepts_consistent_reviewed_pass_status(monkeypatch):
    archive = _valid_archive(monkeypatch)
    inventory = archive.payloads["THIRD_PARTY_LICENSES.txt"]
    archive.payloads["THIRD_PARTY_LICENSES.txt"] = (
        inventory.replace(b"verdict: HOLD", b"verdict: PASS")
        .replace(b"status: HOLD", b"status: PASS")
        .replace(b"Audit-blocker-count: 1", b"Audit-blocker-count: 0")
    )

    assert packaged.verify_archive(archive) == []


def test_packaged_verifier_rejects_inconsistent_review_status(monkeypatch):
    archive = _valid_archive(monkeypatch)
    archive.payloads["THIRD_PARTY_LICENSES.txt"] = archive.payloads[
        "THIRD_PARTY_LICENSES.txt"
    ].replace(b"Release-gate-status: HOLD", b"Release-gate-status: PASS")

    errors = packaged.verify_archive(archive)

    assert any("inconsistent audit status" in error for error in errors)


@pytest.mark.parametrize(
    ("archive_path", "expected"),
    (
        ("PyQt6\\QtCore.pyd", "PyQt code or binary"),
        ("pyi_rth_pyqt6", "PyQt code or binary"),
        (
            "vendor\\bgutil-ytdlp-pot-provider\\LICENSE",
            "in-process provider code",
        ),
        ("payload\\generate_once.js", "raw JavaScript/TypeScript"),
        ("node_modules\\canvas\\build\\Release\\canvas.node", "canvas native"),
        ("canvas.node", "canvas native"),
        ("nested\\libffi-8.dll", "exactly one libffi DLL"),
        ("PySide6\\Qt6Pdf.dll", "unaudited PySide6/Qt paths"),
        ("PySide6\\plugins\\imageformats\\qpdf.dll", "unaudited PySide6/Qt paths"),
        ("PySide6\\translations\\qtbase_nl.qm", "unaudited PySide6/Qt paths"),
    ),
)
def test_packaged_verifier_rejects_forbidden_carchive_payloads(
    monkeypatch, archive_path, expected
):
    archive = _valid_archive(monkeypatch)
    archive.payloads[archive_path] = b"forbidden"
    archive.toc[archive_path] = (0, 1, 1, 0, "b")

    errors = packaged.verify_archive(archive)

    assert any(expected in error for error in errors)


@pytest.mark.parametrize(
    "module_name",
    (
        "PyQt6",
        "PyQt5.QtCore",
        "yt_dlp_plugins.extractor.getpot_bgutil",
        "getpot_bgutil",
    ),
)
def test_packaged_verifier_rejects_forbidden_pyz_modules(monkeypatch, module_name):
    archive = _valid_archive(monkeypatch)
    archive.pyz.payloads[module_name] = b"forbidden module bytecode"
    archive.pyz.toc[module_name] = (0, 0, len(archive.pyz.payloads[module_name]))

    errors = packaged.verify_archive(archive)

    assert any("forbidden in embedded PYZ" in error for error in errors)


def test_packaged_verifier_allows_yt_dlp_builtin_plugin_framework(monkeypatch):
    archive = _valid_archive(monkeypatch)
    module_name = "yt_dlp.plugins"
    archive.pyz.payloads[module_name] = b"builtin plugin framework bytecode"
    archive.pyz.toc[module_name] = (0, 0, len(archive.pyz.payloads[module_name]))

    normalized = {
        name: packaged._normalize_archive_path(name) for name in archive.toc
    }
    fingerprint = packaged._calculate_payload_fingerprint(archive, normalized)
    inventory_name = "THIRD_PARTY_LICENSES.txt"
    archive.payloads[inventory_name] = re.sub(
        rb"Audited non-compliance payload fingerprint SHA-256: [0-9a-f]{64}",
        f"Audited non-compliance payload fingerprint SHA-256: {fingerprint}".encode(),
        archive.payloads[inventory_name],
    )

    errors = packaged.verify_archive(archive)

    assert not any("provider module is forbidden" in error for error in errors)


def test_packaged_verifier_allows_historical_names_only_in_docs_and_licenses(monkeypatch):
    archive = _valid_archive(monkeypatch)
    notice = b"Historical PyQt6 and bgutil audit notice.\n"
    notice_hash = hashlib.sha256(notice).hexdigest()
    original_manifest_name = packaged.LICENSE_MANIFEST_PATH.replace("/", "\\")
    archive.payloads["licenses\\PyQt6-historical-notice.txt"] = notice
    archive.toc["licenses\\PyQt6-historical-notice.txt"] = (0, 1, 1, 0, "b")
    archive.payloads[original_manifest_name] += (
        f"{notice_hash}  PyQt6-historical-notice.txt\n".encode()
    )
    archive.payloads["docs\\bgutil-historical-audit.md"] = notice
    archive.toc["docs\\bgutil-historical-audit.md"] = (0, 1, 1, 0, "b")

    assert packaged.verify_archive(archive) == []


def test_packaged_verifier_requires_exact_single_root_libffi(monkeypatch):
    archive = _valid_archive(monkeypatch)
    archive.payloads["libffi-8.dll"] = b"wrong"

    errors = packaged.verify_archive(archive)

    assert any("archive hash mismatch for libffi-8.dll" in error for error in errors)


def test_packaged_verifier_requires_complete_hashed_license_manifest(monkeypatch):
    archive = _valid_archive(monkeypatch)
    archive.payloads["licenses\\unlisted.txt"] = b"missing from manifest"
    archive.toc["licenses\\unlisted.txt"] = (0, 1, 1, 0, "b")

    errors = packaged.verify_archive(archive)

    assert any("license manifest coverage mismatch" in error for error in errors)


def _write_valid_project(root: Path) -> None:
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text(
        "from PySide6.QtWidgets import QApplication\n", encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        f"""[project]
name = "fixture"
version = "1.0.0"
dependencies = ["PySide6=={boundary.PYSIDE_VERSION}"]

[project.optional-dependencies]
build = ["pyinstaller==6.21.0"]
dev = ["pytest==9.1.1"]

[build-system]
requires = ["setuptools==83.0.0", "wheel==0.47.0"]
build-backend = "setuptools.build_meta"
""",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text(
        f"PySide6=={boundary.PYSIDE_VERSION}\npyinstaller==6.21.0\n",
        encoding="utf-8",
    )
    locked = "".join(
        f"{name}=={version} --hash=sha256:{'0' * 64}\n"
        for name, version in boundary._REQUIRED_LOCK_PACKAGES.items()
    )
    (root / "requirements.lock").write_text(locked, encoding="utf-8")
    uv_records = "\n".join(
        f"""[[package]]
name = "{name}"
version = "{version}"
source = {{ registry = "https://example.invalid/simple" }}
sdist = {{ url = "https://example.invalid/{name}.tar.gz", hash = "sha256:{'0' * 64}" }}
"""
        for name, version in boundary._REQUIRED_LOCK_PACKAGES.items()
    )
    (root / "uv.lock").write_text(f"version = 1\n{uv_records}", encoding="utf-8")

    compliance_lines = "\n".join(
        f'    project_root / "{path.name}",' for path in boundary.REQUIRED_COMPLIANCE_FILES
    )
    (root / "OpenFetch.spec").write_text(
        f'''project_root = Path.cwd()
python_libffi = Path(sys.base_prefix) / "DLLs" / "libffi-8.dll"
if (project_root / "vendor" / "bgutil-ytdlp-pot-provider").exists():
    raise SystemExit("forbidden")
require_sha256(python_libffi, "{boundary.CPYTHON_LIBFFI_SHA256}")
datas = [
{compliance_lines}
]
binaries = [(str(python_libffi), ".")]
a = Analysis(
    ["main.py"],
    pathex=[str(project_root / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=[],
    excludes=["PyQt", "PyQt5", "PyQt6", "yt_dlp_plugins", "bgutil_ytdlp_pot_provider"],
    noarchive=False,
)
''',
        encoding="utf-8",
    )
    for relative in boundary.REQUIRED_COMPLIANCE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.name in {"SOURCE-HASHES.sha256", "requirements.lock"}:
            continue
        path.write_text(f"fixture compliance: {relative.as_posix()}\n", encoding="utf-8")
    source_payload = (root / "pyproject.toml").read_bytes()
    (root / "SOURCE-HASHES.sha256").write_text(
        f"{hashlib.sha256(source_payload).hexdigest()}  pyproject.toml\n",
        encoding="utf-8",
    )


def test_distribution_boundary_accepts_provider_free_exactly_locked_project(tmp_path):
    _write_valid_project(tmp_path)
    (tmp_path / "docs" / "OPTIONAL-PO-PROVIDER.md").write_text(
        "Historical PyQt6, bgutil, getpot, and yt_dlp_plugins names are documentation.\n",
        encoding="utf-8",
    )

    assert boundary.verify_project(tmp_path) == []


def test_distribution_boundary_rejects_pyqt_import(tmp_path):
    _write_valid_project(tmp_path)
    (tmp_path / "src" / "app.py").write_text(
        "from PyQt6.QtWidgets import QApplication\n", encoding="utf-8"
    )

    assert any("forbidden in-process import" in error for error in boundary.verify_project(tmp_path))


def test_distribution_boundary_rejects_dynamic_provider_import(tmp_path):
    _write_valid_project(tmp_path)
    (tmp_path / "src" / "app.py").write_text(
        'import importlib\nimportlib.import_module("yt_dlp_plugins.extractor.getpot_bgutil")\n',
        encoding="utf-8",
    )

    assert any("forbidden dynamic import" in error for error in boundary.verify_project(tmp_path))


def test_distribution_boundary_rejects_structured_dependency_but_not_comment(tmp_path):
    _write_valid_project(tmp_path)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        requirements.read_text(encoding="utf-8")
        + "# historical bgutil-ytdlp-pot-provider and PyQt6 note\n"
        + "bgutil-ytdlp-pot-provider==1.3.1\n",
        encoding="utf-8",
    )

    errors = boundary.verify_project(tmp_path)

    assert any("forbidden dependency in requirements.txt" in error for error in errors)
    assert sum("forbidden dependency in requirements.txt" in error for error in errors) == 1


def test_distribution_boundary_rejects_provider_tree_and_spec_payload(tmp_path):
    _write_valid_project(tmp_path)
    provider_root = tmp_path / boundary.PROVIDER_VENDOR_PATH
    provider_root.mkdir(parents=True)
    spec = tmp_path / "OpenFetch.spec"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            "hiddenimports=[]", 'hiddenimports=["yt_dlp_plugins.extractor.getpot_bgutil"]'
        ),
        encoding="utf-8",
    )

    errors = boundary.verify_project(tmp_path)

    assert any("GPL provider tree is present" in error for error in errors)
    assert any("spec hiddenimports references forbidden payloads" in error for error in errors)


def test_distribution_boundary_rejects_source_hash_mismatch(tmp_path):
    _write_valid_project(tmp_path)
    (tmp_path / "pyproject.toml").write_text("changed\n", encoding="utf-8")

    errors = boundary.verify_project(tmp_path)

    assert any("source-hash mismatch: pyproject.toml" in error for error in errors)


def _write_onefolder_binary_map(tree: Path) -> None:
    import json as _json

    map_path = tree / "compliance" / "BINARY-TO-SOURCE-MAP.json"
    map_path.parent.mkdir(parents=True, exist_ok=True)
    if not map_path.exists():
        map_path.write_text("{}\n", encoding="utf-8")
    rows = []
    tree_digest = hashlib.sha256()
    files = sorted(
        (item for item in tree.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(tree).as_posix().casefold(),
    )
    for item in files:
        relative = item.relative_to(tree).as_posix()
        self_map = relative.casefold() == "compliance/binary-to-source-map.json"
        digest = hashlib.sha256(item.read_bytes()).hexdigest()
        rows.append(
            {
                "path": relative,
                "size": "SELF-REFERENTIAL" if self_map else item.stat().st_size,
                "sha256": "SELF-REFERENTIAL" if self_map else digest,
                "components": ["project"],
                "mapping_status": "PASS",
            }
        )
        tree_digest.update(relative.encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(b"SELF-REFERENTIAL" if self_map else bytes.fromhex(digest))
        tree_digest.update(b"\0")
    map_path.write_text(
        _json.dumps(
            {
                "files": rows,
                "file_count": len(rows),
                "tree_sha256": tree_digest.hexdigest(),
            }
        ),
        encoding="utf-8",
    )


def _write_onefolder_directory_manifest(tree: Path, manifest_path: Path) -> None:
    import json as _json

    files = {}
    for item in sorted(tree.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(tree).as_posix()
        files[relative] = {
            "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
            "size": item.stat().st_size,
        }
    replaceable = sorted(
        relative
        for relative in files
        if relative.split("/", 1)[0] in ("PySide6", "shiboken6")
    )
    manifest_path.write_text(
        _json.dumps(
            {
                "schema_version": 1,
                "application_name": packaged.APP_NAME,
                "release_version": packaged.APPLICATION_VERSION,
                "platform": "windows",
                "architecture": "x64",
                "channel": "stable",
                "root_name": packaged.ONEFOLDER_ROOT_NAME,
                "executable": packaged.ONEFOLDER_LAUNCHER_PATH,
                "total_size": sum(record["size"] for record in files.values()),
                "files": files,
                "replaceable_paths": replaceable,
            }
        ),
        encoding="utf-8",
    )


def _valid_onefolder_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    import json as _json

    tree = tmp_path / packaged.ONEFOLDER_ROOT_NAME
    tree.mkdir()
    (tree / packaged.ONEFOLDER_LAUNCHER_PATH).write_bytes(b"\x90" * (1024 * 1024 + 64))
    (tree / "bin").mkdir()
    for name in ("node.exe", "ffmpeg.exe", "ffprobe.exe"):
        (tree / "bin" / name).write_bytes(f"tool:{name}".encode())
    monkeypatch.setattr(
        packaged,
        "ONEFOLDER_PINNED_EXECUTABLE_SHA256",
        {
            f"bin/{name}": hashlib.sha256(f"tool:{name}".encode()).hexdigest()
            for name in ("node.exe", "ffmpeg.exe", "ffprobe.exe")
        },
    )
    qt_files = {
        "PySide6/Qt6Core.dll": b"qt-core-fixture",
        "PySide6/plugins/platforms/qwindows.dll": b"qt-platform-fixture",
        "shiboken6/shiboken6.abi3.dll": b"shiboken-fixture",
    }
    for relative, payload in qt_files.items():
        destination = tree / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    qt_manifest = _json.dumps(
        {
            "schema_version": 1,
            "files": [
                {
                    "path": relative,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                for relative, payload in sorted(qt_files.items())
            ],
        }
    ).encode()
    (tree / "QT-PYSIDE-COMPONENTS.json").write_bytes(qt_manifest)
    metadata = b'{"application_version": "3.1.0"}'
    (tree / "PROJECT-METADATA.json").write_bytes(metadata)
    (tree / "README.md").write_text("install instructions", encoding="utf-8")
    (tree / "LICENSE").write_text("MIT", encoding="utf-8")
    (tree / "THIRD_PARTY_LICENSES.txt").write_text("inventory", encoding="utf-8")
    (tree / "THIRD_PARTY_NOTICES.md").write_text("notices", encoding="utf-8")
    (tree / "SOURCE-HASHES.sha256").write_text(
        f"{'0' * 64}  src/main.py\n", encoding="utf-8"
    )
    (tree / "requirements.lock").write_text("package==1.0", encoding="utf-8")
    license_file = tree / "licenses" / "Example-LICENSE.txt"
    license_file.parent.mkdir()
    license_file.write_bytes(b"license text")
    (tree / "licenses" / "RELEASE-LICENSE-MANIFEST.sha256").write_text(
        f"{hashlib.sha256(b'license text').hexdigest()}  Example-LICENSE.txt\n",
        encoding="utf-8",
    )
    (tree / "docs").mkdir()
    for name in (
        "BUILD-REPRODUCIBILITY.md",
        "DEPENDENCY-SOURCE.md",
        "LGPL-COMPLIANCE.md",
        "OPTIONAL-PO-PROVIDER.md",
        "QT-BUILD-PROVENANCE.md",
        "QT-REPLACEMENT-GUIDE.md",
    ):
        (tree / "docs" / name).write_text(f"doc {name}", encoding="utf-8")
    compliance = tree / "compliance"
    compliance.mkdir()
    (compliance / "BUILD-LABEL.txt").write_text(
        "Public-distribution verdict: HOLD\n", encoding="utf-8"
    )
    (compliance / "PROJECT-METADATA.json").write_bytes(metadata)
    (compliance / "QT-PYSIDE-COMPONENTS.json").write_bytes(qt_manifest)
    _write_onefolder_binary_map(tree)
    manifest_path = tmp_path / packaged.ONEFOLDER_DIRECTORY_MANIFEST_NAME
    _write_onefolder_directory_manifest(tree, manifest_path)
    return tree, manifest_path


def _no_launcher_scan(_payload: bytes) -> list[str]:
    return []


def test_onefolder_verifier_accepts_valid_tree(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert errors == []


def test_onefolder_verifier_accepts_valid_zip(tmp_path, monkeypatch):
    import zipfile as _zipfile

    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    archive = tmp_path / f"{packaged.ONEFOLDER_ROOT_NAME}.zip"
    with _zipfile.ZipFile(archive, "w") as handle:
        for item in sorted(tree.rglob("*")):
            if item.is_file():
                arcname = f"{tree.name}/{item.relative_to(tree).as_posix()}"
                handle.writestr(arcname, item.read_bytes())

    errors = packaged.verify_onefolder(archive, manifest, launcher_scan=_no_launcher_scan)

    assert errors == []


def test_onefolder_verifier_rejects_unknown_executable(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    (tree / "bin" / "helper.exe").write_bytes(b"unknown tool")
    _write_onefolder_binary_map(tree)
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert errors == ["unknown executable in one-folder tree: bin/helper.exe"]


def test_onefolder_verifier_rejects_pyqt_and_provider_payloads(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    pyqt = tree / "PyQt6" / "QtCore.pyd"
    pyqt.parent.mkdir()
    pyqt.write_bytes(b"pyqt payload")
    provider = tree / "yt_dlp_plugins" / "getpot_bgutil.py"
    provider.parent.mkdir()
    provider.write_bytes(b"provider payload")
    _write_onefolder_binary_map(tree)
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any("PyQt code or binary is forbidden: PyQt6/QtCore.pyd" in e for e in errors)
    assert any(
        "in-process provider code is forbidden: yt_dlp_plugins/getpot_bgutil.py" in e
        for e in errors
    )


def test_onefolder_verifier_rejects_prohibited_legacy_hash(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    legacy = tree / "extra-archive.zip"
    legacy.write_bytes(b"legacy one-file payload")
    monkeypatch.setattr(
        packaged,
        "PROHIBITED_LEGACY_SHA256S",
        frozenset({hashlib.sha256(b"legacy one-file payload").hexdigest()}),
    )
    _write_onefolder_binary_map(tree)
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert errors == [
        "prohibited legacy artifact hash in one-folder tree: extra-archive.zip"
    ]


def test_onefolder_verifier_rejects_missing_qt_inventory(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    (tree / "QT-PYSIDE-COMPONENTS.json").unlink()
    (tree / "compliance" / "QT-PYSIDE-COMPONENTS.json").unlink()
    _write_onefolder_binary_map(tree)
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any(
        "missing required one-folder paths" in e and "QT-PYSIDE-COMPONENTS.json" in e
        for e in errors
    )


def test_onefolder_verifier_rejects_qt_inventory_hash_mismatch(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    (tree / "PySide6" / "Qt6Core.dll").write_bytes(b"user replaced qt library")
    _write_onefolder_binary_map(tree)
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any(
        "Qt/PySide inventory size mismatch: PySide6/Qt6Core.dll" in e
        or "Qt/PySide inventory hash mismatch: PySide6/Qt6Core.dll" in e
        for e in errors
    )


def test_onefolder_verifier_rejects_unexpected_file(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    (tree / "stray-file.bin").write_bytes(b"not built by the pipeline")

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any("binary-map coverage differs" in e and "stray-file.bin" in e for e in errors)
    assert any("directory-manifest coverage differs" in e for e in errors)


def test_onefolder_verifier_rejects_unresolved_native_mapping(tmp_path, monkeypatch):
    import json as _json

    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    map_path = tree / "compliance" / "BINARY-TO-SOURCE-MAP.json"
    payload = _json.loads(map_path.read_text(encoding="utf-8"))
    for row in payload["files"]:
        if row["path"] == "bin/node.exe":
            row["mapping_status"] = "HOLD"
            row["components"] = []
    map_path.write_text(_json.dumps(payload), encoding="utf-8")
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any(
        "unresolved native/source mapping in binary map: bin/node.exe" in e
        for e in errors
    )


def test_onefolder_verifier_requires_directory_manifest(tmp_path, monkeypatch):
    tree, _manifest = _valid_onefolder_tree(tmp_path, monkeypatch)

    errors = packaged.verify_onefolder(tree, None, launcher_scan=_no_launcher_scan)

    assert any("directory update manifest is required" in e for e in errors)


def test_onefolder_verifier_rejects_directory_manifest_hash_mismatch(
    tmp_path, monkeypatch
):
    import json as _json

    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    payload = _json.loads(manifest.read_text(encoding="utf-8"))
    payload["files"]["README.md"]["sha256"] = "0" * 64
    manifest.write_text(_json.dumps(payload), encoding="utf-8")

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any("directory-manifest hash mismatch: README.md" in e for e in errors)


def test_onefolder_verifier_rejects_runtime_state(tmp_path, monkeypatch):
    tree, manifest = _valid_onefolder_tree(tmp_path, monkeypatch)
    (tree / "debug.log").write_bytes(b"log line")
    (tree / "cookies.txt").write_bytes(b"cookie jar")
    _write_onefolder_binary_map(tree)
    _write_onefolder_directory_manifest(tree, manifest)

    errors = packaged.verify_onefolder(tree, manifest, launcher_scan=_no_launcher_scan)

    assert any(
        "runtime state must not ship in the release tree: debug.log" in e for e in errors
    )
    assert any(
        "runtime state must not ship in the release tree: cookies.txt" in e
        for e in errors
    )


def test_boundary_accepts_the_projects_dynamic_version_lock_entry(tmp_path):
    """The project's own uv.lock entry has no version: it comes from config.py."""
    _write_valid_project(tmp_path)
    lock = tmp_path / "uv.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8")
        + '\n[[package]]\nname = "openfetch"\nsource = { editable = "." }\n',
        encoding="utf-8",
    )

    errors = boundary.verify_project(tmp_path)

    assert not any("missing a name or version" in error for error in errors)


def test_boundary_still_rejects_a_registry_package_without_a_version(tmp_path):
    _write_valid_project(tmp_path)
    lock = tmp_path / "uv.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8")
        + '\n[[package]]\nname = "mystery"\nsource = { registry = "https://example.invalid/simple" }\n',
        encoding="utf-8",
    )

    errors = boundary.verify_project(tmp_path)

    assert any("missing a name or version" in error for error in errors)
