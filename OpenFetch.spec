# -*- mode: python ; coding: utf-8 -*-

"""Fail-closed PyInstaller one-folder recipe for the provider-free application.

The public-compliance candidate deliberately keeps PySide6, Shiboken6, and Qt
shared libraries outside the executable.  A recipient can therefore replace a
compatible library without rewriting or unpacking ``OpenFetch.exe``.
The historical one-file artifact remains a non-public audit input only.
"""

import ast
import hashlib
import sys
from pathlib import Path, PurePath


project_root = Path.cwd()
assets = project_root / "assets"
license_root = project_root / "licenses"
node_runtime = project_root / "bin" / "node.exe"
ffmpeg_bin = project_root / "bin"
python_libffi = Path(sys.base_prefix) / "DLLs" / "libffi-8.dll"
python_ctypes = Path(sys.base_prefix) / "DLLs" / "_ctypes.pyd"


def config_constant(name):
    """Read a string constant from src/openfetch/config.py, the single identity source."""
    config_path = project_root / "src" / "openfetch" / "config.py"
    tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise SystemExit(f"{name} is missing from src/openfetch/config.py")


APPLICATION_VERSION = config_constant("VERSION")
EXECUTABLE_STEM = config_constant("EXECUTABLE_STEM")

compliance_files = [
    project_root / "LICENSE",
    project_root / "PROJECT-METADATA.json",
    project_root / "THIRD_PARTY_LICENSES.txt",
    project_root / "THIRD_PARTY_NOTICES.md",
    project_root / "docs" / "COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    project_root / "docs" / "PROJECT-OWNERSHIP-DECLARATION.md",
    project_root / "docs" / "DEPENDENCY-SOURCE.md",
    project_root / "docs" / "BUILD-REPRODUCIBILITY.md",
    project_root / "docs" / "LGPL-COMPLIANCE.md",
    project_root / "docs" / "QT-REPLACEMENT-GUIDE.md",
    project_root / "docs" / "QT-BUILD-PROVENANCE.md",
    project_root / "docs" / "OPTIONAL-PO-PROVIDER.md",
    project_root / "requirements.lock",
    project_root / "SOURCE-HASHES.sha256",
    license_root / "RELEASE-LICENSE-MANIFEST.sha256",
]


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha256(path, expected):
    if not path.is_file():
        raise SystemExit(f"Required audited build input is missing: {path}")
    actual = file_sha256(path)
    if actual != expected:
        raise SystemExit(
            f"Audited build input changed: {path} (expected {expected}, got {actual})"
        )


if (project_root / "vendor" / "bgutil-ytdlp-pot-provider").exists():
    raise SystemExit(
        "GPL provider sources are present in the OpenFetch project; "
        "move the complete provider distribution outside the application tree."
    )
if not node_runtime.is_file():
    raise SystemExit("A bundled node.exe is required.")
if not (ffmpeg_bin / "ffmpeg.exe").is_file() or not (
    ffmpeg_bin / "ffprobe.exe"
).is_file():
    raise SystemExit("Bundled ffmpeg.exe and ffprobe.exe are required.")

require_sha256(
    node_runtime,
    "39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636",
)
require_sha256(
    ffmpeg_bin / "ffmpeg.exe",
    "6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e",
)
require_sha256(
    ffmpeg_bin / "ffprobe.exe",
    "55a3d20229c2373dade4362215c9bd5a04b59d4e734d0bbb882afd9cea4fb046",
)

# This _ctypes.pyd comes from python-build-standalone 20250317 and was built
# against its own x64 libffi 3.4.2. Pin that exact DLL at archive root. No
# canvas/MSYS2 runtime is allowed in this application distribution.
require_sha256(
    python_libffi,
    "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e",
)
require_sha256(
    python_ctypes,
    "6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41",
)

missing_compliance_files = [path for path in compliance_files if not path.is_file()]
if missing_compliance_files:
    raise SystemExit(
        "Required licensing/compliance files are missing: "
        + ", ".join(str(path) for path in missing_compliance_files)
    )
if not license_root.is_dir():
    raise SystemExit("The reviewed third-party license-text directory is required.")
if not (license_root / "RELEASE-LICENSE-MANIFEST.sha256").is_file():
    raise SystemExit("The release license-text manifest is required.")

license_manifest = license_root / "RELEASE-LICENSE-MANIFEST.sha256"
license_datas = [
    (
        str(path),
        str(Path("licenses") / path.relative_to(license_root).parent),
    )
    for path in sorted(license_root.rglob("*"))
    if path.is_file() and path != license_manifest
]

datas = [
    (str(assets / "OpenFetch.ico"), "assets"),
    (str(assets / "OpenFetchIcon.png"), "assets"),
    (str(assets / "background.png"), "assets"),
    (str(assets / "backgroundrightpanel.png"), "assets"),
    (str(assets / "chevron-down.png"), "assets"),
    (str(assets / "chevron-down-disabled.png"), "assets"),
    (str(ffmpeg_bin / "ffmpeg.exe"), "bin"),
    (str(ffmpeg_bin / "ffprobe.exe"), "bin"),
    (str(project_root / "LICENSE"), "."),
    (str(project_root / "PROJECT-METADATA.json"), "."),
    (str(project_root / "THIRD_PARTY_LICENSES.txt"), "."),
    (str(project_root / "THIRD_PARTY_NOTICES.md"), "."),
    (
        str(project_root / "docs" / "COPYRIGHT-OWNERSHIP-QUESTIONS.md"),
        "docs",
    ),
    (
        str(project_root / "docs" / "PROJECT-OWNERSHIP-DECLARATION.md"),
        "docs",
    ),
    (str(project_root / "docs" / "DEPENDENCY-SOURCE.md"), "docs"),
    (str(project_root / "docs" / "BUILD-REPRODUCIBILITY.md"), "docs"),
    (str(project_root / "docs" / "LGPL-COMPLIANCE.md"), "docs"),
    (str(project_root / "docs" / "QT-REPLACEMENT-GUIDE.md"), "docs"),
    (str(project_root / "docs" / "QT-BUILD-PROVENANCE.md"), "docs"),
    (str(project_root / "docs" / "OPTIONAL-PO-PROVIDER.md"), "docs"),
    (str(project_root / "requirements.lock"), "."),
    (str(project_root / "SOURCE-HASHES.sha256"), "."),
    (str(license_root / "RELEASE-LICENSE-MANIFEST.sha256"), "licenses"),
    *license_datas,
]

binaries = [
    (str(node_runtime), "bin"),
    (str(python_libffi), "."),
]

# Only QtCore/QtGui/QtWidgets are imported by the application. These explicit
# exclusions make accidental collection of optional PySide add-on modules a
# build-contract failure surface instead of silently growing the artifact.
unused_pyside_modules = [
    "PySide6.Qt3DAnimation",
    "PySide6.Qt3DCore",
    "PySide6.Qt3DExtras",
    "PySide6.Qt3DInput",
    "PySide6.Qt3DLogic",
    "PySide6.Qt3DRender",
    "PySide6.QtBluetooth",
    "PySide6.QtAxContainer",
    "PySide6.QtCanvasPainter",
    "PySide6.QtCharts",
    "PySide6.QtConcurrent",
    "PySide6.QtDataVisualization",
    "PySide6.QtDBus",
    "PySide6.QtDesigner",
    "PySide6.QtGraphs",
    "PySide6.QtGraphsWidgets",
    "PySide6.QtHelp",
    "PySide6.QtHttpServer",
    "PySide6.QtLocation",
    "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets",
    "PySide6.QtNetwork",
    "PySide6.QtNetworkAuth",
    "PySide6.QtNfc",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf",
    "PySide6.QtPdfWidgets",
    "PySide6.QtPositioning",
    "PySide6.QtPrintSupport",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuick3D",
    "PySide6.QtQuickControls2",
    "PySide6.QtQuickTest",
    "PySide6.QtQuickWidgets",
    "PySide6.QtRemoteObjects",
    "PySide6.QtScxml",
    "PySide6.QtSensors",
    "PySide6.QtSerialBus",
    "PySide6.QtSerialPort",
    "PySide6.QtSpatialAudio",
    "PySide6.QtSql",
    "PySide6.QtStateMachine",
    "PySide6.QtSvg",
    "PySide6.QtSvgWidgets",
    "PySide6.QtTest",
    "PySide6.QtTextToSpeech",
    "PySide6.QtUiTools",
    "PySide6.QtWebChannel",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebSockets",
    "PySide6.QtWebView",
    "PySide6.QtXml",
]

a = Analysis(
    ["main.py"],
    pathex=[str(project_root / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PyQt",
        "PyQt5",
        "PyQt5.QtCore",
        "PyQt5.QtGui",
        "PyQt5.QtWidgets",
        "PyQt6",
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        "yt_dlp_plugins",
        "bgutil_ytdlp_pot_provider",
        *unused_pyside_modules,
    ],
    noarchive=False,
    optimize=0,
)

# PyInstaller's generic PySide hooks intentionally collect plugins and
# translations for broad application compatibility. OpenFetch has a
# narrower audited surface: QtCore/QtGui/QtWidgets, the native Windows and
# offscreen platforms, ICO loading, and the Windows style plugin. PNG support
# is built into QtGui; media thumbnails are handled by yt-dlp/FFmpeg/Pillow.
allowed_pyside_root_native = {
    "pyside6/msvcp140.dll",
    "pyside6/msvcp140_1.dll",
    "pyside6/msvcp140_2.dll",
    "pyside6/opengl32sw.dll",
    "pyside6/pyside6.abi3.dll",
    "pyside6/qt6core.dll",
    "pyside6/qt6gui.dll",
    "pyside6/qt6widgets.dll",
    "pyside6/qtcore.pyd",
    "pyside6/qtgui.pyd",
    "pyside6/qtwidgets.pyd",
    "pyside6/vcruntime140.dll",
    "pyside6/vcruntime140_1.dll",
}
allowed_qt_plugins = {
    "pyside6/plugins/imageformats/qico.dll",
    "pyside6/plugins/platforms/qoffscreen.dll",
    "pyside6/plugins/platforms/qwindows.dll",
    "pyside6/plugins/styles/qmodernwindowsstyle.dll",
}


def normalized_toc_name(entry):
    return str(entry[0]).replace("\\", "/").casefold()


def keep_audited_qt_entry(entry):
    path = normalized_toc_name(entry)
    if path.startswith("pyside6/translations/"):
        return False
    if path.startswith("pyside6/plugins/"):
        return path in allowed_qt_plugins
    parts = PurePath(path).parts
    if len(parts) == 2 and parts[0] == "pyside6" and path.endswith((".dll", ".pyd")):
        return path in allowed_pyside_root_native
    return True


a.binaries = [entry for entry in a.binaries if keep_audited_qt_entry(entry)]
a.datas = [entry for entry in a.datas if keep_audited_qt_entry(entry)]

collected_paths = {
    normalized_toc_name(entry) for entry in (*a.binaries, *a.datas)
}
required_qt_paths = allowed_pyside_root_native | allowed_qt_plugins | {
    "shiboken6/shiboken.pyd",
    "shiboken6/shiboken6.abi3.dll",
}
missing_qt_paths = sorted(required_qt_paths - collected_paths)
if missing_qt_paths:
    raise SystemExit(
        "Audited PySide6/Qt payload is incomplete: " + ", ".join(missing_qt_paths)
    )
unexpected_qt_paths = sorted(
    path
    for path in collected_paths
    if (
        path.startswith(("pyside6/plugins/", "pyside6/translations/"))
        or (
            len(PurePath(path).parts) == 2
            and path.startswith("pyside6/")
            and path.endswith((".dll", ".pyd"))
        )
    )
    and path not in allowed_pyside_root_native
    and path not in allowed_qt_plugins
)
if unexpected_qt_paths:
    raise SystemExit(
        "Unaudited PySide6/Qt payload survived filtering: "
        + ", ".join(unexpected_qt_paths)
    )

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=EXECUTABLE_STEM,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(assets / "OpenFetch.ico"),
    version=str(project_root / "version_info.txt"),
    # PyInstaller's legacy one-folder layout keeps the external libraries and
    # compliance material at stable, recipient-visible paths.  Do not switch
    # this to one-file or an opaque contents archive for a public candidate.
    contents_directory=".",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=f"{EXECUTABLE_STEM}-{APPLICATION_VERSION}-windows-x64",
)
