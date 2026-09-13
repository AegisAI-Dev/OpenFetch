"""Generate the evidence-based third-party inventory for the frozen Windows build.

This script deliberately does not guess missing licenses or source provenance. A
missing value is written as ``UNRESOLVED`` so that it remains a release blocker.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata as metadata
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = PROJECT_ROOT / "vendor" / "bgutil-ytdlp-pot-provider" / "server"
NODE_MODULES = SERVER_ROOT / "node_modules"
PYZ_TOC = PROJECT_ROOT / "build" / "NeuralExtractorV3" / "PYZ-00.toc"
ANALYSIS_TOC = PROJECT_ROOT / "build" / "NeuralExtractorV3" / "Analysis-00.toc"
PKG_TOC = PROJECT_ROOT / "build" / "NeuralExtractorV3" / "PKG-00.toc"
ARTIFACT = PROJECT_ROOT / "dist" / "NeuralExtractorV3-3.0.8-windows-x64.exe"
OUTPUT = PROJECT_ROOT / "THIRD_PARTY_LICENSES.txt"
LICENSE_ROOT = PROJECT_ROOT / "licenses"
AUDIT_DATE = "2026-07-22"
BTBN_RELEASE = "autobuild-2026-06-30-13-34"
BTBN_BUILD_SCRIPTS_COMMIT = "7a83528ea3431e9eca982a712bc3a7cd0789d5d0"
BTBN_ASSET = "ffmpeg-N-125365-g9a01c1cb6a-win64-gpl.zip"
BTBN_ASSET_SHA256 = "52c0383c460f0ec1039088f1591921fb82e3b870b32aab8faf2ff1e5ae14bf9d"
CANVAS_PREBUILD_URL = (
    "https://github.com/Automattic/node-canvas/releases/download/v3.2.1/"
    "canvas-v3.2.1-napi-v7-win32-x64.tar.gz"
)
CANVAS_PREBUILD_SHA256 = "b9c21d5338bcecfb36149694fc0d0e46668c9a6188c6cd6ceb660bd6fa86b672"
PYTHON_BUILD_STANDALONE_ASSET = (
    "cpython-3.12.9+20250317-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
)
PYTHON_BUILD_STANDALONE_ASSET_SHA256 = (
    "ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661"
)
PYTHON_BUILD_STANDALONE_COMMIT = "7d8bb5e8cf054d88cbf505645257a25b8f46b286"
CPYTHON_SOURCE_SHA256 = "7220835d9f90b37c006e9842a8dff4580aaca4318674f947302b8d28f3f81112"
CPYTHON_LIBFFI_342_SHA256 = (
    "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e"
)
CANVAS_LIBFFI_352_SHA256 = (
    "ccd1c21178c2e239eaa6c904a25c7f26efdfadb0faf344e62b1bbb39a30241d5"
)

_CPYTHON_ACTION = (
    "ship the exact CPython license; retain exact source and build configuration "
    "for combined-work source review"
)
_CPYTHON_COMPONENT_ACTION = (
    "ship the component's exact copyright/license notice; retain exact source and "
    "build inputs for combined-work source review"
)

# (size, SHA-256, component, version, license/status, required action). These are
# the 23 non-Microsoft CPython/python-build-standalone paths in the audited PKG.
CPYTHON_RUNTIME_EXPECTED: dict[str, tuple[int, str, str, str, str, str]] = {
    "_asyncio.pyd": (
        59392,
        "50bd131291858692d51935caa3fdd3849931cd794e84850dc5d017855766143e",
        "CPython _asyncio extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "_bz2.pyd": (
        73216,
        "c464b6c94e123e3ec32b893093d162ef4edc3ee1dcecdb28e73c84b5a30c9d7d",
        "CPython _bz2 plus statically linked bzip2",
        "3.12.9 / bzip2 1.0.8",
        "Python-2.0 plus historical terms; plus bzip2 license",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "_ctypes.pyd": (
        116224,
        "6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41",
        "CPython _ctypes; built for libffi 3.4.2, currently loads 3.5.2",
        "3.12.9 / 3.4.2 build / 3.5.2 runtime",
        "Python-2.0 plus historical terms; plus libffi MIT",
        "HOLD: package CPython libffi 3.4.2 at archive root, retain canvas 3.5.2 "
        "only in its vendor path, test both and ship both MIT notices/sources",
    ),
    "_decimal.pyd": (
        244736,
        "3f5057579bc3c859bd07d237c2f86248092cfda3eb044b4ba2625530146def2a",
        "CPython _decimal plus static mpdecimal",
        "3.12.9 / mpdecimal 2.5.1",
        "Python-2.0 plus historical terms; plus BSD-2-Clause",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "_elementtree.pyd": (
        121856,
        "cd0d716a10545c22b0fc4757ca6bbe1fb3d9a916d9b7a23b61727d0286c7dde7",
        "CPython _elementtree extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "_hashlib.pyd": (
        54272,
        "20286c64126a874a57968c8cfd483bedd907b9133bac56d9c64fa2407892c2df",
        "CPython _hashlib plus dynamic OpenSSL",
        "3.12.9 / OpenSSL 3.0.16",
        "Python-2.0 plus historical terms; plus Apache-2.0",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "_lzma.pyd": (
        147968,
        "e335d7f6c588524dd92069c9d2554ae45cb0e6da5f1a0458c6f42bd7a0c44dfc",
        "CPython _lzma plus static liblzma",
        "3.12.9 / liblzma 5.2.12",
        "Python-2.0 plus historical terms; plus source-exact public-domain notices",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "_multiprocessing.pyd": (
        24064,
        "5aedf510e8a5dd3756e09407eecf801e6ea1d454a51a9ad3b0af18e44ffa7fe4",
        "CPython _multiprocessing extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "_overlapped.pyd": (
        44032,
        "475577388258fd9e96b7c7da0176785e69a06bcabd1ae198b9ab684da57e4865",
        "CPython _overlapped extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "_queue.pyd": (
        20992,
        "ae122b8a31257116e2fe93a7e8f21b5b7a68fa66e7a5620abf0ec27669f4ee6d",
        "CPython _queue extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "_socket.pyd": (
        71680,
        "a4fe6b67451a47d65333060bf24654a2371819cff0c558b99dad95a9ed33d4b8",
        "CPython _socket extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "_sqlite3.pyd": (
        112128,
        "a15942f2af97b987b6b64de80828362b27344648d2a53a4739e1baf6f20e3df9",
        "CPython _sqlite3 plus dynamic SQLite",
        "3.12.9 / SQLite 3.47.1",
        "Python-2.0 plus historical terms; plus SQLite public-domain dedication",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "_ssl.pyd": (
        166400,
        "f6ccf5deb18e5046f553fb167281e509f536faa5c6b019c7d4019ef0514358c3",
        "CPython _ssl plus dynamic OpenSSL",
        "3.12.9 / OpenSSL 3.0.16",
        "Python-2.0 plus historical terms; plus Apache-2.0",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "_uuid.pyd": (
        13824,
        "c219a8ccfefc5b3ccf402c1d6800c2cf46203e97bf744602f3bf57684fa1858c",
        "CPython _uuid extension using Windows rpcrt4",
        "3.12.9",
        "Python-2.0 plus historical terms; no bundled libuuid",
        _CPYTHON_ACTION,
    ),
    "_wmi.pyd": (
        26112,
        "7e6da91e0445ee7f2c98bbc5a2aec4b9ad568231f07381e49e5ea87ff26d3919",
        "CPython _wmi extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "libcrypto-3-x64.dll": (
        5932032,
        "1d54af6f7434a9e3be42acc1f192b0c66926582fb07ef7bb6b41226df7e73acd",
        "OpenSSL libcrypto",
        "3.0.16",
        "Apache-2.0",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "libssl-3-x64.dll": (
        936448,
        "4cde268f01a6f81c989de12f2b20b3548deee452674123ad00da0aa0e31ecbd0",
        "OpenSSL libssl",
        "3.0.16",
        "Apache-2.0",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "pyexpat.pyd": (
        190464,
        "9d09acbd76537a9842b4f10acdd897fcdeb333505d4f104a8180fa74963a588a",
        "CPython pyexpat plus static Expat",
        "3.12.9 / Expat 2.6.4",
        "Python-2.0 plus historical terms; plus MIT",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "python3.dll": (
        56320,
        "37b361cee2f40e922801986d7f750169b5ae95c9a2cf37ad899a690b4788754d",
        "CPython stable-ABI shim",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "python312.dll": (
        6954496,
        "3cad6885f126d08ce38b2999fb127292a0399a3fa69bba65ca0bc2964c6c6168",
        "CPython core plus zlib, HACL* and BLAKE2 code",
        "3.12.9 / zlib 1.3.1 / pinned vendor snapshots",
        "Python-2.0 plus historical terms; plus Zlib, MIT and CC0/public-domain terms",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "select.pyd": (
        18944,
        "5a28b7d60be8f64f7b8af6e68d6d465671a3f9fc4a672ebb5809d57766566fe0",
        "CPython select extension",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        _CPYTHON_ACTION,
    ),
    "sqlite3.dll": (
        1558528,
        "f62eb83c9dfcfb17fc2e58534fcc0b7536affb40b269ab46d6cb5cd67c6ba9f5",
        "SQLite",
        "3.47.1",
        "public-domain dedication",
        _CPYTHON_COMPONENT_ACTION,
    ),
    "unicodedata.pyd": (
        1126400,
        "f96337dd3f56a0ab4f904e31452a5c05fb0119632463f107fe57d4867f620067",
        "CPython unicodedata plus Unicode Character Database",
        "3.12.9 / UCD 15.0.0",
        "Python-2.0 plus historical terms; Unicode UCD 15.0.0 terms pending exact text",
        _CPYTHON_COMPONENT_ACTION,
    ),
}

CPYTHON_EMBEDDED_COMPONENTS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "CPython",
        "3.12.9",
        "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms",
        "https://www.python.org/ftp/python/3.12.9/Python-3.12.9.tar.xz "
        f"(SHA-256 {CPYTHON_SOURCE_SHA256})",
        "ship the complete CPython license, source and exact build configuration",
    ),
    (
        "python-build-standalone build recipes",
        "20250317",
        "MPL-2.0",
        "https://github.com/astral-sh/python-build-standalone/tree/"
        f"{PYTHON_BUILD_STANDALONE_COMMIT}",
        "ship MPL-2.0 and retain the exact Windows build scripts/configuration",
    ),
    (
        "OpenSSL",
        "3.0.16",
        "Apache-2.0",
        "https://www.openssl.org/source/openssl-3.0.16.tar.gz",
        "ship Apache-2.0 and source-exact copyright/ACKNOWLEDGEMENTS; retain source/build inputs",
    ),
    (
        "SQLite",
        "3.47.1",
        "public-domain dedication",
        "https://www.sqlite.org/2024/sqlite-autoconf-3470100.tar.gz",
        "ship the public-domain dedication and exact provenance",
    ),
    (
        "bzip2",
        "1.0.8",
        "custom permissive bzip2 license",
        "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz",
        "ship the exact 1.0.8 copyright, conditions and disclaimer",
    ),
    (
        "liblzma / XZ Utils",
        "5.2.12",
        "source-exact public-domain notices",
        "https://github.com/tukaani-project/xz/tree/v5.2.12",
        "retain the exact source and reproduce every notice applicable to the selected files",
    ),
    (
        "zlib",
        "1.3.1",
        "Zlib",
        "https://github.com/madler/zlib/releases/tag/v1.3.1",
        "ship the exact zlib 1.3.1 notice and retain source/build inputs",
    ),
    (
        "Expat",
        "2.6.4",
        "MIT",
        "https://github.com/libexpat/libexpat/tree/R_2_6_4",
        "ship the exact MIT copyright/permission notice and retain source",
    ),
    (
        "mpdecimal",
        "2.5.1",
        "BSD-2-Clause",
        "CPython 3.12.9 Modules/_decimal/libmpdec",
        "ship the exact BSD-2-Clause notice and retain the covered source",
    ),
    (
        "libffi build input",
        "3.4.2",
        "MIT",
        "https://github.com/python/cpython-source-deps/tree/"
        "16fad4855b3d8c03b5910e405ff3a04395b39a98",
        "ship the exact MIT notice/source and CPython build steps; package its DLL at root",
    ),
    (
        "HACL* vendor code",
        "CPython snapshot bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0",
        "MIT",
        "CPython 3.12.9 Modules/_hacl and refresh.sh provenance",
        "preserve MIT headers, exact vendor source and transformation steps",
    ),
    (
        "Unicode Character Database",
        "15.0.0",
        "Unicode data license; exact UCD 15.0.0 text not locally retained",
        "https://www.unicode.org/Public/15.0.0/ucd/",
        "HOLD: obtain and reproduce the exact UCD 15.0.0 permission notice; retain provenance",
    ),
    (
        "BLAKE2 reference-derived code",
        "CPython 3.12.9 snapshot",
        "CC0/public-domain dedication",
        "CPython 3.12.9 Modules/_blake2",
        "preserve the exact dedication/provenance and transformation record",
    ),
)
FFMPEG_RECIPE_TRANSITIVE_COMPONENTS: tuple[str, ...] = (
    "Brotli",
    "GCC runtime / libgomp",
    "gnulib",
    "Highway (libjxl submodule)",
    "libdvdcss",
    "libpng",
    "Little CMS",
    "LV2 lilv",
    "LV2 serd",
    "LV2 sord",
    "LV2 sratom",
    "LV2 zix",
    "mbedTLS",
    "MinGW-w64 runtime",
    "OpenCL Headers",
    "OpenCL ICD Loader",
    "shaderc synchronized dependency tree",
    "SPIRV-Cross",
    "SPIRV-Headers",
    "Vulkan Headers",
    "Vulkan Shim Loader (BtbN)",
    "Windows libva",
)


QT_STATIC_DEPENDENCIES: tuple[tuple[str, str, str, str], ...] = (
    ("Qt6Core.dll", "PCRE2", "10.47", "BSD-3-Clause; JIT also BSD-2-Clause"),
    ("Qt6Core.dll", "zlib", "1.3.2", "Zlib"),
    (
        "Qt6Gui.dll",
        "FreeType",
        "2.14.3",
        "FTL selected (alternative GPL-2.0-or-later)",
    ),
    ("Qt6Gui.dll", "HarfBuzz", "14.2.0", "MIT"),
    ("Qt6Gui.dll", "libpng", "1.6.58", "Libpng"),
    ("Qt6Gui.dll", "D3D12 Memory Allocator", "UNRESOLVED", "MIT expected"),
    ("Qt6Gui.dll", "Vulkan Memory Allocator", "3.2.1", "MIT"),
    ("Qt6Gui.dll", "sRGB ICC profile", "UNRESOLVED", "ICC profile license"),
    ("qjpeg.dll", "libjpeg-turbo", "3.1.4", "IJG AND BSD-3-Clause AND Zlib"),
    ("qtiff.dll", "libtiff", "4.7.1", "libtiff license"),
    ("qtiff.dll", "zlib", "UNRESOLVED in plugin", "Zlib expected"),
    ("qwebp.dll", "libwebp", "UNRESOLVED; likely 1.6.0", "BSD-3-Clause expected"),
    ("Qt6Pdf.dll / qpdf.dll", "Abseil", "UNRESOLVED", "Apache-2.0"),
    ("Qt6Pdf.dll / qpdf.dll", "FreeType", "UNRESOLVED", "FTL"),
    ("Qt6Pdf.dll / qpdf.dll", "PDFium", "UNRESOLVED commit", "BSD"),
    ("Qt6Pdf.dll / qpdf.dll", "Chromium code", "UNRESOLVED", "BSD-3-Clause"),
    ("Qt6Pdf.dll / qpdf.dll", "fast_float", "UNRESOLVED", "MIT"),
    ("Qt6Pdf.dll / qpdf.dll", "ICU and data", "UNRESOLVED", "Unicode/ICU terms"),
    (
        "Qt6Pdf.dll / qpdf.dll",
        "libjpeg-turbo",
        "UNRESOLVED",
        "IJG AND BSD-3-Clause AND Zlib",
    ),
    ("Qt6Pdf.dll / qpdf.dll", "libpng", "UNRESOLVED", "Libpng"),
    ("Qt6Pdf.dll / qpdf.dll", "zlib", "UNRESOLVED", "Zlib"),
    ("Qt6Pdf.dll", "OpenJPEG code", "UNRESOLVED", "exact terms/source unresolved"),
    ("opengl32sw.dll", "Mesa llvmpipe/Gallium", "11.2.2", "MIT/Boost family"),
    ("opengl32sw.dll", "LLVM", "3.6.2", "UIUC/NCSA plus embedded notices"),
)


QT_UNRESOLVED_EMBEDDED_COMPONENTS: tuple[str, ...] = (
    "BLAKE2/Keccak implementation",
    "double-conversion",
    "MD4C",
    "Public Suffix List / libpsl",
    "TinyCBOR",
    "Unicode/CLDR data",
    "XSVG",
)


@dataclass(slots=True)
class PackageRecord:
    name: str
    version: str
    license_expression: str
    source: str
    locations: list[str] = field(default_factory=list)
    license_files: list[Path] = field(default_factory=list)


SETUPTOOLS_LICENSE_SUFFIXES: tuple[str, ...] = (
    "setuptools-83.0.0.dist-info/licenses/LICENSE",
    "setuptools/_vendor/backports.tarfile-1.2.0.dist-info/LICENSE",
    "setuptools/_vendor/jaraco.text-4.0.0.dist-info/LICENSE",
    "setuptools/_vendor/jaraco_context-6.1.0.dist-info/licenses/LICENSE",
    "setuptools/_vendor/jaraco_functools-4.4.0.dist-info/licenses/LICENSE",
    "setuptools/_vendor/more_itertools-10.8.0.dist-info/licenses/LICENSE",
    "setuptools/_vendor/packaging-26.0.dist-info/licenses/LICENSE",
    "setuptools/_vendor/packaging-26.0.dist-info/licenses/LICENSE.APACHE",
    "setuptools/_vendor/packaging-26.0.dist-info/licenses/LICENSE.BSD",
    "setuptools/_vendor/tomli-2.4.0.dist-info/licenses/LICENSE",
    "setuptools/_vendor/wheel-0.46.3.dist-info/licenses/LICENSE.txt",
    "setuptools/config/NOTICE",
    "setuptools/config/_validate_pyproject/NOTICE",
)


SETUPTOOLS_PYZ_COMPONENTS: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "backports.tarfile",
        "backports; backports.tarfile; compat; compat.py38",
        "1.2.0",
        "MIT",
        "https://github.com/jaraco/backports.tarfile/tree/v1.2.0",
        "ship exact MIT text and preserve the Lars Gustaebel copyright/header",
    ),
    (
        "jaraco.context",
        "jaraco.context",
        "6.1.0",
        "MIT",
        "https://github.com/jaraco/jaraco.context/tree/v6.1.0",
        "ship exact upstream MIT file",
    ),
    (
        "jaraco.functools",
        "jaraco.functools",
        "4.4.0",
        "MIT",
        "https://github.com/jaraco/jaraco.functools/tree/v4.4.0",
        "ship exact upstream MIT file",
    ),
    (
        "jaraco.text",
        "jaraco.text",
        "4.0.0",
        "MIT",
        "https://github.com/jaraco/jaraco.text/tree/v4.0.0",
        "ship exact MIT text without changing its literal placeholders",
    ),
    (
        "more-itertools",
        "more_itertools; more; recipes",
        "10.8.0",
        "MIT",
        "https://github.com/more-itertools/more-itertools/tree/v10.8.0",
        "ship MIT text and Erik Rose copyright",
    ),
    (
        "packaging (setuptools-vendored)",
        "package plus 12 observed submodules",
        "26.0",
        "Apache-2.0 OR BSD-2-Clause; BSD-2-Clause selected",
        "https://github.com/pypa/packaging/tree/26.0",
        "ship LICENSE, LICENSE.APACHE and LICENSE.BSD; no upstream NOTICE exists",
    ),
    (
        "tomli",
        "tomli; _parser; _re; _types",
        "2.4.0",
        "MIT",
        "https://github.com/hukkin/tomli/tree/2.4.0",
        "ship MIT text and retain SPDX/copyright headers",
    ),
    (
        "wheel (setuptools-vendored)",
        "wheel; macosx_libfile; wheelfile",
        "0.46.3",
        "MIT",
        "https://github.com/pypa/wheel/tree/0.46.3",
        "ship MIT text and Daniel Holth/contributors copyright",
    ),
    (
        "validate-pyproject-derived code",
        "__init__; error_reporting; extra_validations; formats; generated schema code",
        "0.25-derived",
        "MPL-2.0 portions",
        "https://github.com/abravalheri/validate-pyproject/tree/v0.25",
        "ship unmodified setuptools notices/MPL text; make exact covered source and generator inputs available",
    ),
    (
        "fastjsonschema-derived code",
        "fastjsonschema_exceptions; fastjsonschema_validations; conservatively mixed generated __init__",
        "2.21.2-derived",
        "BSD-3-Clause portions",
        "https://github.com/horejsek/python-fastjsonschema/tree/v2.21.2",
        "reproduce exact BSD copyright, conditions and disclaimer; retain full setuptools notice",
    ),
)


NATIVE_CANVAS_COMPONENTS: tuple[tuple[str, str, str], ...] = (
    ("canvas.node", "3.2.1", "MIT; linked native libraries listed below"),
    ("libbrotlicommon.dll", "1.2.0", "MIT"),
    ("libbrotlidec.dll", "1.2.0", "MIT"),
    ("libbz2-1.dll", "1.0.8", "custom bzip2 license"),
    ("libcairo-2.dll", "1.18.4", "LGPL-2.1-or-later OR MPL-1.1"),
    (
        "libcairo-gobject-2.dll",
        "1.18.4 (component inference)",
        "LGPL-2.1-or-later OR MPL-1.1 expected",
    ),
    ("libdatrie-1.dll", "0.2.14", "LGPL; version unspecified in package metadata"),
    ("libdeflate.dll", "1.25", "MIT"),
    ("libexpat-1.dll", "2.7.3", "MIT"),
    ("libffi-8.dll", "3.5.2", "MIT"),
    ("libfontconfig-1.dll", "2.17.1", "custom fontconfig license"),
    (
        "libfreetype-6.dll",
        "2.14.1",
        "FTL selected (alternative GPL-2.0-or-later)",
    ),
    ("libfribidi-0.dll", "1.0.16", "LGPL-2.1-or-later"),
    ("libgcc_s_seh-1.dll", "15.2.0", "GPL-3.0-or-later WITH GCC-exception-3.1"),
    ("libgdk_pixbuf-2.0-0.dll", "2.44.4", "LGPL-2.1-or-later"),
    ("libgif-7.dll", "5.2.2", "MIT"),
    ("libgio-2.0-0.dll", "2.86.3", "LGPL-2.1-or-later"),
    ("libglib-2.0-0.dll", "2.86.3", "LGPL-2.1-or-later"),
    ("libgmodule-2.0-0.dll", "2.86.3", "LGPL-2.1-or-later"),
    ("libgobject-2.0-0.dll", "2.86.3", "LGPL-2.1-or-later"),
    ("libgraphite2.dll", "1.3.14", "LGPL-2.1-or-later"),
    ("libharfbuzz-0.dll", "12.3.0", "MIT"),
    ("libiconv-2.dll", "1.18", "LGPL-2.1-or-later"),
    ("libintl-8.dll", "0.26", "GPL-3.0-or-later AND LGPL-2.1-or-later"),
    ("libjbig-0.dll", "2.1", "GPL-2.0-or-later from exact source header"),
    ("libjpeg-8.dll", "3.1.3", "custom BSD-like AND IJG AND Zlib"),
    ("liblerc.dll", "4.0.0", "Apache-2.0"),
    ("liblzma-5.dll", "5.8.2", "0BSD/LGPL/GPL file mix; verify exact terms"),
    ("libpango-1.0-0.dll", "1.56.4", "LGPL-2.1"),
    ("libpangocairo-1.0-0.dll", "1.56.4", "LGPL-2.1"),
    ("libpangoft2-1.0-0.dll", "1.56.4", "LGPL-2.1"),
    ("libpangowin32-1.0-0.dll", "1.56.4", "LGPL-2.1"),
    ("libpcre2-8-0.dll", "10.47", "BSD-3-Clause"),
    ("libpixman-1-0.dll", "0.46.4", "MIT"),
    ("libpng16-16.dll", "1.6.53", "Libpng-2.0"),
    ("librsvg-2-2.dll", "2.61.3", "LGPL-2.1-or-later plus embedded Rust crates"),
    ("libsharpyuv-0.dll", "0.4.2", "BSD-3-Clause"),
    ("libstdc++-6.dll", "15.2.0", "GPL-3.0-or-later WITH GCC-exception-3.1"),
    ("libthai-0.dll", "0.1.29", "LGPL; version unspecified in package metadata"),
    ("libtiff-6.dll", "4.7.1", "MIT"),
    ("libwebp-7.dll", "1.6.0", "BSD-3-Clause"),
    (
        "libwinpthread-1.dll",
        "13.0.0.r391.g848cce552",
        "MIT AND BSD-3-Clause-Clear",
    ),
    ("libxml2-16.dll", "2.15.1", "MIT"),
    (
        "libzstd.dll",
        "1.5.7",
        "BSD-3-Clause selected (alternative GPL-2.0-or-later)",
    ),
    ("zlib1.dll", "1.3.1", "Zlib"),
)


# Every one of the 44 DLLs in the node-canvas prebuild was byte-matched to the
# exact official historical MSYS2 binary package below. ``source_stem`` is the
# exact filename stem used in repo.msys2.org/mingw/sources/.
CANVAS_MSYS2_PACKAGES: tuple[tuple[str, str, str, str, str], ...] = (
    ("brotli", "1.2.0-1", "libbrotlicommon.dll; libbrotlidec.dll", "MIT", "brotli"),
    ("bzip2", "1.0.8-3", "libbz2-1.dll", "custom bzip2", "bzip2"),
    (
        "cairo",
        "1.18.4-4",
        "libcairo-2.dll; libcairo-gobject-2.dll",
        "LGPL-2.1-or-later OR MPL-1.1",
        "cairo",
    ),
    ("libdatrie", "0.2.14-1", "libdatrie-1.dll", "LGPL; version unspecified", "libdatrie"),
    ("libdeflate", "1.25-1", "libdeflate.dll", "MIT", "libdeflate"),
    ("expat", "2.7.3-1", "libexpat-1.dll", "MIT", "expat"),
    ("libffi", "3.5.2-1", "libffi-8.dll", "MIT", "libffi"),
    ("fontconfig", "2.17.1-1", "libfontconfig-1.dll", "custom fontconfig", "fontconfig"),
    (
        "freetype",
        "2.14.1-2",
        "libfreetype-6.dll",
        "FTL selected (alternative GPL-2.0-or-later)",
        "freetype",
    ),
    ("fribidi", "1.0.16-1", "libfribidi-0.dll", "LGPL-2.1-or-later", "fribidi"),
    (
        "gcc-libs",
        "15.2.0-9",
        "libgcc_s_seh-1.dll; libstdc++-6.dll",
        "GPL-3.0-or-later WITH GCC-exception-3.1 AND LGPL-2.1-or-later",
        "gcc",
    ),
    (
        "gdk-pixbuf2",
        "2.44.4-1",
        "libgdk_pixbuf-2.0-0.dll",
        "LGPL-2.1-or-later",
        "gdk-pixbuf2",
    ),
    ("giflib", "5.2.2-1", "libgif-7.dll", "MIT", "giflib"),
    (
        "glib2",
        "2.86.3-1",
        "libgio-2.0-0.dll; libglib-2.0-0.dll; libgmodule-2.0-0.dll; libgobject-2.0-0.dll",
        "LGPL-2.1-or-later",
        "glib2",
    ),
    ("graphite2", "1.3.14-3", "libgraphite2.dll", "LGPL-2.1-or-later", "graphite2"),
    ("harfbuzz", "12.3.0-1", "libharfbuzz-0.dll", "MIT", "harfbuzz"),
    (
        "libiconv",
        "1.18-1",
        "libiconv-2.dll",
        "LGPL-2.1-or-later; package docs also GPL-3.0-or-later",
        "libiconv",
    ),
    (
        "gettext-runtime",
        "0.26-2",
        "libintl-8.dll",
        "GPL-3.0-or-later AND LGPL-2.1-or-later",
        "gettext",
    ),
    ("jbigkit", "2.1-5", "libjbig-0.dll", "GPL-2.0-or-later from source header", "jbigkit"),
    (
        "libjpeg-turbo",
        "3.1.3-1",
        "libjpeg-8.dll",
        "custom BSD-like / IJG / Zlib",
        "libjpeg-turbo",
    ),
    ("lerc", "4.0.0-1", "liblerc.dll", "Apache-2.0", "lerc"),
    (
        "xz",
        "5.8.2-1",
        "liblzma-5.dll",
        "0BSD AND LGPL-2.1-or-later AND GPL-2.0-or-later package mix",
        "xz",
    ),
    (
        "pango",
        "1.56.4-3",
        "libpango-1.0-0.dll; libpangocairo-1.0-0.dll; libpangoft2-1.0-0.dll; libpangowin32-1.0-0.dll",
        "LGPL-2.1",
        "pango",
    ),
    ("pcre2", "10.47-1", "libpcre2-8-0.dll", "BSD-3-Clause", "pcre2"),
    ("pixman", "0.46.4-1", "libpixman-1-0.dll", "MIT", "pixman"),
    ("libpng", "1.6.53-1", "libpng16-16.dll", "custom libpng", "libpng"),
    ("librsvg", "2.61.3-1", "librsvg-2-2.dll", "LGPL-2.1-or-later", "librsvg"),
    (
        "libwebp",
        "1.6.0-1",
        "libwebp-7.dll; libsharpyuv-0.dll",
        "BSD-3-Clause",
        "libwebp",
    ),
    (
        "libwinpthread",
        "13.0.0.r391.g848cce552-1",
        "libwinpthread-1.dll",
        "MIT AND BSD-3-Clause-Clear",
        "winpthreads",
    ),
    ("libthai", "0.1.29-3", "libthai-0.dll", "LGPL; version unspecified", "libthai"),
    ("libtiff", "4.7.1-1", "libtiff-6.dll", "MIT", "libtiff"),
    ("libxml2", "2.15.1-3", "libxml2-16.dll", "MIT", "libxml2"),
    (
        "zstd",
        "1.5.7-1",
        "libzstd.dll",
        "BSD-3-Clause selected (alternative GPL-2.0-or-later)",
        "zstd",
    ),
    ("zlib", "1.3.1-1", "zlib1.dll", "Zlib", "zlib"),
)


# These crate name/version pairs are recoverable from crates.io source paths in
# librsvg-2-2.dll. Optimisation can remove such paths, so this is evidence of a
# minimum dependency set, not a complete Cargo SBOM.
LIBRSVG_DETECTED_RUST_CRATES: tuple[str, ...] = (
    "aho-corasick-1.1.4",
    "bytemuck-1.24.0",
    "byteorder-1.5.0",
    "byteorder-lite-0.1.0",
    "cairo-rs-0.21.2",
    "color_quant-1.1.0",
    "crossbeam-deque-0.8.6",
    "crossbeam-epoch-0.9.18",
    "crossbeam-utils-0.8.21",
    "cssparser-0.35.0",
    "data-url-0.3.2",
    "dtoa-short-0.3.5",
    "encoding_rs-0.8.35",
    "fdeflate-0.3.7",
    "flate2-1.1.5",
    "form_urlencoded-1.2.2",
    "futures-channel-0.3.31",
    "futures-core-0.3.31",
    "futures-executor-0.3.31",
    "futures-util-0.3.31",
    "gdk-pixbuf-0.21.2",
    "gif-0.13.3",
    "gio-0.21.4",
    "glib-0.21.4",
    "icu_collections-2.1.1",
    "icu_locale_core-2.1.1",
    "icu_normalizer-2.1.1",
    "icu_provider-2.1.1",
    "idna-1.1.0",
    "image-0.25.8",
    "image-webp-0.2.4",
    "itertools-0.14.0",
    "language-tags-0.3.2",
    "lazy_static-1.5.0",
    "locale_config-0.3.0",
    "log-0.4.28",
    "markup5ever-0.35.0",
    "memchr-2.7.6",
    "miniz_oxide-0.8.9",
    "moxcms-0.7.9",
    "nalgebra-0.33.2",
    "num-integer-0.1.46",
    "num-rational-0.4.2",
    "num-traits-0.2.19",
    "pango-0.21.3",
    "pangocairo-0.21.2",
    "parking_lot-0.12.5",
    "parking_lot_core-0.9.12",
    "percent-encoding-2.3.2",
    "phf-0.11.3",
    "phf_shared-0.11.3",
    "phf_shared-0.13.1",
    "png-0.18.0",
    "pxfm-0.1.25",
    "rayon-1.11.0",
    "rayon-core-1.13.0",
    "rctree-0.6.0",
    "regex-1.12.2",
    "regex-automata-0.4.13",
    "regex-syntax-0.8.8",
    "selectors-0.31.0",
    "serde-1.0.228",
    "serde_core-1.0.228",
    "servo_arc-0.4.1",
    "smallvec-1.15.1",
    "string_cache-0.8.9",
    "string_cache-0.9.0",
    "tendril-0.4.3",
    "tinyvec-1.10.0",
    "url-2.5.7",
    "utf-8-0.7.6",
    "weezl-0.1.10",
    "windows-sys-0.59.0",
    "xml5ever-0.35.0",
    "zerotrie-0.2.3",
    "zerovec-0.11.5",
    "zune-core-0.4.12",
    "zune-jpeg-0.4.21",
)


NODE_LICENSES = {
    "acorn": "MIT",
    "ada": "MIT",
    "amaro": "MIT",
    "ares": "MIT",
    "brotli": "MIT",
    "cjs_module_lexer": "MIT",
    "cldr": "Unicode-3.0",
    "icu": "ICU",
    "llhttp": "MIT",
    "nbytes": "MIT",
    "ncrypto": "MIT",
    "nghttp2": "MIT",
    "openssl": "Apache-2.0",
    "simdjson": "Apache-2.0",
    "simdutf": "Apache-2.0 OR MIT",
    "sqlite": "blessing/public-domain",
    "tz": "public-domain/IANA notices",
    "undici": "MIT",
    "unicode": "Unicode-3.0",
    "uv": "MIT",
    "uvwasi": "MIT",
    "v8": "BSD-3-Clause",
    "zlib": "Zlib",
    "zstd": "BSD-3-Clause selected (alternative GPL-2.0-only)",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_text(path: Path) -> str:
    payload = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeError(f"Could not decode license text: {path}")


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _action(license_expression: str) -> str:
    value = license_expression.upper()
    if "UNRESOLVED" in value or "UNKNOWN" in value:
        return "HOLD: establish exact license, provenance and required source"
    if value == "(APACHE-2.0 AND BSD-3-CLAUSE)":
        return (
            "ship both the Apache-2.0 text/change attribution and the exact "
            "BSD-3-Clause copyright notice; include upstream NOTICE if present"
        )
    if value == "APACHE-2.0 OR BSD-2-CLAUSE":
        return (
            "selected BSD-2-Clause route: retain and ship its exact copyright, "
            "conditions and disclaimer"
        )
    if value == "(BSD-2-CLAUSE OR MIT OR APACHE-2.0)":
        return (
            "selected MIT route: retain and ship its exact copyright and license notice"
        )
    if value == "(MIT OR WTFPL)":
        return (
            "selected MIT route: retain and ship its exact copyright and license notice"
        )
    if value.startswith("FTL SELECTED"):
        return (
            "selected FTL route: ship the exact FTL text, copyright and required "
            "acknowledgement; no FreeType GPL source obligation is selected"
        )
    if value.startswith("BSD-3-CLAUSE SELECTED"):
        return (
            "selected BSD-3-Clause route: retain and ship its copyright, conditions "
            "and disclaimer; no zstd GPL source obligation is selected"
        )
    if "LGPL" in value:
        return "license/notices + exact covered source, relink/install information and modification notices"
    if "GPL" in value:
        return "GPL text/notices + exact Corresponding Source, build scripts and valid source delivery"
    if "MPL" in value:
        return "license/notices + source for covered files and modifications"
    if "APACHE" in value:
        return "Apache-2.0 text, copyright/attribution, changes, and upstream NOTICE if present"
    return "retain and ship the exact copyright and license notice"


def _license_candidates(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    matches: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if "node_modules" in relative.parts:
            continue
        name = path.name.lower()
        if re.match(r"^(licen[cs]e|copying|notice|copyright)([._-].*)?$", name):
            matches.append(path)
    return sorted(set(matches), key=lambda item: item.as_posix().lower())


def _python_packages() -> list[PackageRecord]:
    if not PYZ_TOC.is_file():
        raise FileNotFoundError(f"PyInstaller PYZ TOC is missing: {PYZ_TOC}")
    toc = ast.literal_eval(PYZ_TOC.read_text(encoding="utf-8"))
    top_levels = {entry[0].split(".", 1)[0] for entry in toc[1]}
    package_map = metadata.packages_distributions()
    distribution_names = {
        distribution
        for top_level in top_levels
        for distribution in package_map.get(top_level, ())
    }
    records: list[PackageRecord] = []
    for distribution_name in sorted(distribution_names, key=str.lower):
        distribution = metadata.distribution(distribution_name)
        name = distribution.metadata.get("Name", distribution_name)
        if name.lower() in {"neural-extractor-v3", "openfetch"}:
            continue
        expression = (
            distribution.metadata.get("License-Expression")
            or distribution.metadata.get("License")
            or "UNRESOLVED"
        )
        if name.lower() == "bgutil-ytdlp-pot-provider":
            expression = "GPL-3.0-only"
        project_urls = distribution.metadata.get_all("Project-URL") or []
        source = next(
            (
                item.split(",", 1)[1].strip()
                for item in project_urls
                if "," in item
                and item.split(",", 1)[0].strip().lower()
                in {"source", "repository", "code", "home"}
            ),
            f"https://pypi.org/project/{name}/{distribution.version}/",
        )
        license_files = []
        for item in distribution.files or ():
            candidate = Path(distribution.locate_file(item))
            lowered = candidate.name.lower()
            if re.match(r"^(licen[cs]e|copying|notice|copyright)([._-].*)?$", lowered):
                license_files.append(candidate)
        if name.lower() == "bgutil-ytdlp-pot-provider":
            provider_license = (
                PROJECT_ROOT / "vendor" / "bgutil-ytdlp-pot-provider" / "LICENSE"
            )
            if provider_license.is_file():
                license_files.append(provider_license)
        if name.lower() == "setuptools":
            license_files = [
                path
                for path in license_files
                if any(
                    path.as_posix().endswith(suffix)
                    for suffix in SETUPTOOLS_LICENSE_SUFFIXES
                )
            ]
            if len(set(license_files)) != len(SETUPTOOLS_LICENSE_SUFFIXES):
                raise RuntimeError(
                    "Setuptools bundled-license selection changed: "
                    f"expected {len(SETUPTOOLS_LICENSE_SUFFIXES)}, "
                    f"got {len(set(license_files))}"
                )
        records.append(
            PackageRecord(
                name=name,
                version=distribution.version,
                license_expression=expression,
                source=source,
                locations=["PyInstaller PYZ"],
                license_files=sorted(set(license_files), key=str),
            )
        )
    return records


def _setuptools_pyz_modules() -> list[str]:
    toc = ast.literal_eval(PYZ_TOC.read_text(encoding="utf-8"))
    modules = sorted(
        entry[0]
        for entry in toc[1]
        if entry[0] == "setuptools._vendor"
        or entry[0].startswith("setuptools._vendor.")
        or entry[0].startswith("setuptools.config._validate_pyproject")
    )
    if len(modules) != 38:
        raise RuntimeError(f"Setuptools embedded module set changed: got {len(modules)}")
    excluded_prefixes = (
        "setuptools._vendor.autocommand",
        "setuptools._vendor.importlib_metadata",
        "setuptools._vendor.platformdirs",
        "setuptools._vendor.zipp",
    )
    if any(module.startswith(excluded_prefixes) for module in modules):
        raise RuntimeError("An excluded setuptools build-environment vendor is now bundled")
    return modules


def _repository(package: dict[str, Any]) -> str:
    value = package.get("repository")
    if isinstance(value, dict):
        return str(value.get("url") or "")
    return str(value or "")


def _npm_packages() -> list[PackageRecord]:
    hidden_lock = NODE_MODULES / ".package-lock.json"
    lock = json.loads(hidden_lock.read_text(encoding="utf-8"))
    records: dict[tuple[str, str], PackageRecord] = {}
    for relative, locked in lock["packages"].items():
        if not relative:
            continue
        package_root = SERVER_ROOT / Path(relative)
        package = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
        key = (str(package["name"]), str(package["version"]))
        record = records.get(key)
        if record is None:
            resolved = str(locked.get("resolved") or _repository(package) or "UNRESOLVED")
            record = PackageRecord(
                name=key[0],
                version=key[1],
                license_expression=str(package.get("license") or locked.get("license") or "UNRESOLVED"),
                source=resolved,
            )
            records[key] = record
        record.locations.append(relative.replace("\\", "/"))
        record.license_files.extend(_license_candidates(package_root))
        if (not record.license_files or record.name == "canvas") and record.name in {
            "agent-base",
            "canvas",
            "degenerator",
            "https-proxy-agent",
            "netmask",
        }:
            readme = package_root / "README.md"
            if readme.is_file():
                record.license_files.append(readme)
        if record.name == "@bufbuild/protobuf" and record.version == "2.11.0":
            record.license_files.extend(
                [
                    LICENSE_ROOT / "npm" / "bufbuild-protobuf-2.11.0-APACHE-2.0.txt",
                    LICENSE_ROOT
                    / "npm"
                    / "bufbuild-protobuf-2.11.0-GOOGLE-VARINT-NOTICE.txt",
                ]
            )
        if record.name == "saxes" and record.version == "6.0.0":
            record.license_files.append(
                LICENSE_ROOT / "npm" / "saxes-6.0.0-LICENSE.txt"
            )
    for record in records.values():
        record.locations = sorted(set(record.locations), key=str.lower)
        record.license_files = sorted(set(record.license_files), key=str)
    return sorted(records.values(), key=lambda item: (item.name.lower(), item.version))


def _node_versions() -> dict[str, str]:
    node = PROJECT_ROOT / "bin" / "node.exe"
    completed = subprocess.run(  # noqa: S603 - fixed, bundled executable
        [str(node), "-p", "JSON.stringify(process.versions)"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def _qt_payload() -> list[tuple[str, str, str, str, str, str, str]]:
    if not ANALYSIS_TOC.is_file():
        raise FileNotFoundError(f"PyInstaller analysis TOC is missing: {ANALYSIS_TOC}")
    toc = ast.literal_eval(ANALYSIS_TOC.read_text(encoding="utf-8"))
    records: dict[tuple[str, str], tuple[str, str, str, str, str, str, str]] = {}
    for collection in toc:
        if not isinstance(collection, list):
            continue
        for entry in collection:
            if not isinstance(entry, tuple) or len(entry) != 3:
                continue
            destination, _source, kind = entry
            normalized = str(destination).replace("\\", "/")
            if not normalized.startswith("PyQt6/") or kind not in {
                "BINARY",
                "DATA",
                "EXTENSION",
            }:
                continue
            filename = normalized.rsplit("/", 1)[-1].lower()
            if kind == "EXTENSION" and filename.startswith("sip."):
                component = "PyQt6_sip"
                version = "distribution 13.11.1; embedded SIP runtime 6.15.2"
                expression = "BSD-2-Clause"
                source = "PyQt6_sip 13.11.1 wheel"
                action = "retain exact BSD copyright and license notice"
            elif kind == "EXTENSION":
                component = "PyQt6"
                version = "6.11.0"
                expression = "GPL-3.0-only"
                source = "PyQt6 6.11.0 wheel"
                action = "resolve commercial rights or GPLv3 combined-source obligations"
            elif filename.startswith(("msvcp140", "vcruntime140")):
                component = "Microsoft Visual C++ runtime"
                version = "14.44.35211.0"
                expression = "Microsoft redistributable terms"
                source = "PyQt6-Qt6 6.11.1 wheel"
                action = "verify exact redistributable-list coverage and retain terms"
            elif filename == "opengl32sw.dll":
                component = "Mesa llvmpipe/Gallium plus LLVM"
                version = "Mesa 11.2.2; LLVM 3.6.2"
                expression = "MIT/Boost and UIUC/NCSA; embedded notices required"
                source = "PyQt6-Qt6 6.11.1 wheel"
                action = "ship exact Mesa/LLVM source, copyright and embedded notices"
            else:
                component = "Qt"
                version = "6.11.1.0 (translations: wheel 6.11.1)"
                expression = "LGPLv3 distribution; embedded third-party terms unresolved"
                source = "PyQt6-Qt6 6.11.1 wheel"
                action = "ship exact source/notices and practical relink/install information"
            records[(normalized, str(kind))] = (
                normalized,
                str(kind),
                component,
                version,
                expression,
                source,
                action,
            )
    result = [records[key] for key in sorted(records, key=lambda item: item[0].lower())]
    binary_count = sum(row[1] in {"BINARY", "EXTENSION"} for row in result)
    data_count = sum(row[1] == "DATA" for row in result)
    if (len(result), binary_count, data_count) != (128, 32, 96):
        raise RuntimeError(
            "Qt payload changed: "
            f"total={len(result)}, binaries/extensions={binary_count}, data={data_count}"
        )
    return result


def _microsoft_runtime_payload() -> list[tuple[str, str, str, str, str]]:
    if not PKG_TOC.is_file():
        raise FileNotFoundError(f"PyInstaller package TOC is missing: {PKG_TOC}")
    toc = ast.literal_eval(PKG_TOC.read_text(encoding="utf-8"))
    records: list[tuple[str, str, str, str, str]] = []
    for entry in toc[2]:
        if not isinstance(entry, tuple) or len(entry) != 3:
            continue
        destination, _source_path, kind = entry
        if kind != "BINARY":
            continue
        normalized = str(destination).replace("\\", "/")
        filename = normalized.rsplit("/", 1)[-1]
        lowered = filename.lower()
        if not lowered.startswith(("api-ms-win-", "vcruntime140", "msvcp140", "ucrtbase")):
            continue
        if normalized.startswith("PyQt6/"):
            version = "14.44.35211.0"
            source = "PyQt6-Qt6 6.11.1 wheel"
        elif lowered.startswith("vcruntime140"):
            version = "14.42.34438.0"
            source = "python-build-standalone CPython 3.12.9 runtime"
        elif lowered in {"api-ms-win-core-file-l2-1-0.dll", "ucrtbase.dll"}:
            version = "10.0.22000.194"
            source = "Windows Performance Toolkit (unexpected harvested path)"
        else:
            version = "10.0.26100.8249"
            source = "Windows Performance Toolkit (unexpected harvested path)"
        records.append(
            (
                normalized,
                version,
                "Microsoft redistributable terms; entitlement unresolved",
                source,
                "HOLD: use a coherent official redist source, verify REDIST rights and retain terms",
            )
        )
    records.sort(key=lambda row: row[0].lower())
    if len(records) != 49:
        raise RuntimeError(f"Microsoft runtime payload changed: expected 49, got {len(records)}")
    return records


def _cpython_runtime_payload() -> list[tuple[object, ...]]:
    if not PKG_TOC.is_file():
        raise FileNotFoundError(f"PyInstaller package TOC is missing: {PKG_TOC}")
    toc = ast.literal_eval(PKG_TOC.read_text(encoding="utf-8"))
    entries: dict[str, tuple[Path, str]] = {}
    root_libffi_source: Path | None = None
    for entry in toc[2]:
        if not isinstance(entry, tuple) or len(entry) != 3:
            continue
        destination, source_path, kind = entry
        normalized = str(destination).replace("\\", "/")
        if normalized in CPYTHON_RUNTIME_EXPECTED:
            entries[normalized] = (Path(source_path), str(kind))
        elif normalized == "libffi-8.dll":
            root_libffi_source = Path(source_path)

    expected_paths = set(CPYTHON_RUNTIME_EXPECTED)
    actual_paths = set(entries)
    if actual_paths != expected_paths:
        missing = sorted(expected_paths - actual_paths)
        unexpected = sorted(actual_paths - expected_paths)
        raise RuntimeError(
            f"CPython runtime payload changed: missing={missing}, unexpected={unexpected}"
        )
    if root_libffi_source is None or not root_libffi_source.is_file():
        raise RuntimeError("Audited root libffi-8.dll is missing")
    root_libffi_hash = _sha256(root_libffi_source)
    if root_libffi_hash != CANVAS_LIBFFI_352_SHA256:
        raise RuntimeError(
            "Audited root libffi collision changed: "
            f"expected {CANVAS_LIBFFI_352_SHA256}, got {root_libffi_hash}"
        )

    rows: list[tuple[object, ...]] = []
    source_label = (
        f"python-build-standalone 20250317 {PYTHON_BUILD_STANDALONE_ASSET}"
    )
    for archive_path in sorted(entries, key=str.lower):
        source_path, kind = entries[archive_path]
        if not source_path.is_file():
            raise FileNotFoundError(f"CPython runtime source is missing: {source_path}")
        expected = CPYTHON_RUNTIME_EXPECTED[archive_path]
        expected_size, expected_hash, component, version, license_status, action = expected
        actual_size = source_path.stat().st_size
        actual_hash = _sha256(source_path)
        if (actual_size, actual_hash) != (expected_size, expected_hash):
            raise RuntimeError(
                f"CPython runtime file changed: {archive_path}; expected "
                f"{expected_size}/{expected_hash}, got {actual_size}/{actual_hash}"
            )
        rows.append(
            (
                archive_path,
                kind,
                actual_size,
                actual_hash,
                component,
                version,
                license_status,
                source_label,
                action,
            )
        )
    if len(rows) != 23:
        raise RuntimeError(f"Expected 23 CPython runtime paths, got {len(rows)}")
    return rows


def _binary_extension_payload() -> list[tuple[str, str, str]]:
    if not PKG_TOC.is_file():
        raise FileNotFoundError(f"PyInstaller package TOC is missing: {PKG_TOC}")
    toc = ast.literal_eval(PKG_TOC.read_text(encoding="utf-8"))
    native_names = {filename.lower() for filename, _version, _license in NATIVE_CANVAS_COMPONENTS}
    provider_native_prefix = (
        "vendor/bgutil-ytdlp-pot-provider/server/node_modules/canvas/build/Release/"
    )
    records: list[tuple[str, str, str]] = []
    for entry in toc[2]:
        if not isinstance(entry, tuple) or len(entry) != 3:
            continue
        destination, _source_path, kind = entry
        if kind not in {"BINARY", "EXTENSION"}:
            continue
        normalized = str(destination).replace("\\", "/")
        filename = normalized.rsplit("/", 1)[-1]
        lowered = filename.lower()
        if normalized.startswith(provider_native_prefix):
            category = "canvas native payload in provider tree (see E)"
        elif "/" not in normalized and lowered in native_names - {"canvas.node"}:
            category = "second/root copy of canvas native DLL (see E)"
        elif normalized.startswith("PyQt6/"):
            category = "PyQt6/Qt/Microsoft Qt-wheel payload (see B2)"
        elif lowered.startswith(("api-ms-win-", "vcruntime140", "msvcp140", "ucrtbase")):
            category = "Microsoft runtime payload (see B3)"
        elif normalized == "bin/node.exe":
            category = "Node.js runtime (see A and C)"
        elif normalized in {"bin/ffmpeg.exe", "bin/ffprobe.exe"}:
            category = "FFmpeg GPL static executable (see A and G)"
        elif normalized.startswith("charset_normalizer/") or lowered.startswith(
            "ada92cb5d92a588d1b93__mypyc."
        ):
            category = "charset-normalizer 3.4.9 native extension (see B)"
        else:
            category = "CPython/python-build-standalone runtime (see A and B1a)"
        records.append((normalized, str(kind), category))
    records.sort(key=lambda row: row[0].lower())
    counts = Counter(row[1] for row in records)
    categories = Counter(row[2] for row in records)
    if len(records) != 194 or counts != Counter({"BINARY": 169, "EXTENSION": 25}):
        raise RuntimeError(
            f"Binary/extension payload changed: total={len(records)}, counts={counts}"
        )
    if categories["canvas native payload in provider tree (see E)"] != 45:
        raise RuntimeError("Expected exactly 45 provider-tree canvas native paths")
    if categories["second/root copy of canvas native DLL (see E)"] != 44:
        raise RuntimeError("Expected exactly 44 root-level canvas DLL copies")
    return records


def _ffmpeg_flags() -> tuple[str, list[str]]:
    ffmpeg = PROJECT_ROOT / "bin" / "ffmpeg.exe"
    completed = subprocess.run(  # noqa: S603 - fixed, bundled executable
        [str(ffmpeg), "-version"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines = completed.stdout.splitlines()
    version = lines[0].removeprefix("ffmpeg version ").split(" Copyright", 1)[0]
    configuration = next(line for line in lines if line.startswith("configuration:"))
    flags = []
    for token in configuration.split()[1:]:
        if token.startswith("--enable-"):
            name = token.removeprefix("--enable-")
            if name not in {"gpl", "pthreads", "version3"}:
                flags.append(name)
    return version, sorted(set(flags))


def _table(lines: list[str], headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    lines.append("")


def generate(*, output: Path, node_license: Path | None) -> None:
    python_packages = _python_packages()
    setuptools_pyz_modules = _setuptools_pyz_modules()
    npm_packages = _npm_packages()
    qt_payload = _qt_payload()
    microsoft_runtime_payload = _microsoft_runtime_payload()
    cpython_runtime_payload = _cpython_runtime_payload()
    binary_extension_payload = _binary_extension_payload()
    node_versions = _node_versions()
    ffmpeg_version, ffmpeg_dependencies = _ffmpeg_flags()
    artifact_hash = _sha256(ARTIFACT) if ARTIFACT.is_file() else "ARTIFACT MISSING"

    lines = [
        "NEURAL EXTRACTOR V3.0.8 - THIRD-PARTY LICENSE AND DISTRIBUTION INVENTORY",
        "=" * 78,
        "",
        f"Audit date: {AUDIT_DATE}",
        f"Audited artifact SHA-256: {artifact_hash}",
        "Public-distribution verdict: HOLD",
        "Release-gate-status: HOLD",
        "Audit-HOLD-marker-count: __CALCULATED__",
        "Audit-MISSING-marker-count: __CALCULATED__",
        "Audit-UNRESOLVED-marker-count: __CALCULATED__",
        "",
        "This is an engineering licensing audit, not legal advice. UNRESOLVED or",
        "MISSING entries are release blockers and must not be interpreted as permission",
        "to distribute. License conclusions require confirmation by qualified counsel.",
        "",
        "0. Audited PyInstaller archive facts",
        "-" * 37,
        "",
        "The frozen archive contains 5,751 entries under",
        "vendor/bgutil-ytdlp-pot-provider/: 20 provider/metadata files and 5,731",
        "node_modules files. It also contains two raw yt_dlp_plugins Python sources and",
        "two compiled PYZ modules, for 5,755 provider-namespace/plugin-code entries.",
        "Separately, PyInstaller collected a second root-level copy of each of canvas's",
        "44 native DLL dependencies plus bin/node.exe. Those paths are not included in",
        "the 5,755 count and are enumerated below.",
        "",
        "Exact GPL-3.0-only provider Python sources included:",
        "- vendor/bgutil-ytdlp-pot-provider/python/yt_dlp_plugins/extractor/getpot_bgutil.py",
        "- vendor/bgutil-ytdlp-pot-provider/python/yt_dlp_plugins/extractor/getpot_bgutil_script.py",
        "",
        "Each is also represented by a vendor .pyc, a raw yt_dlp_plugins/extractor/*.py",
        "entry, and a compiled PYZ module. The provider's GPL JavaScript object code is:",
        "- vendor/bgutil-ytdlp-pot-provider/server/build/generate_once.js",
        "- vendor/bgutil-ytdlp-pot-provider/server/build/session_manager.js",
        "- vendor/bgutil-ytdlp-pot-provider/server/build/utils.js",
        "",
        "Their .js.map files and matching TypeScript sources are present. The HTTP provider",
        "getpot_bgutil_http.py and server main.js/main.ts are not present. The Python plugin",
        "is imported into the internal yt-dlp worker interpreter; only its Node.js script",
        "runtime is launched as a separate subprocess. This technical fact creates a strong",
        "combined-work risk but is not stated here as a legal conclusion.",
        "",
        "The audited EXE predates the root LICENSE, this generated inventory and",
        "docs/DEPENDENCY-SOURCE.md; those files are not inside the audited artifact.",
        "",
        "A. Core executable and toolchain components",
        "-" * 45,
        "",
    ]
    core_rows = [
        (
            "Neural Extractor project-authored code",
            "3.0.8",
            "MIT for project-owned portions",
            "0xRootNull; Copyright (c) 2025-2026",
            "ship the standard MIT LICENSE and ownership declaration; if treated as "
            "one GPL work, provide complete source/build scripts under GPLv3-compatible terms",
        ),
        (
            "CPython",
            "3.12.9 (python-build-standalone 20250317)",
            "Python-2.0 plus historical CNRI, BeOpen.com and CWI terms; plus bundled notices",
            "https://github.com/astral-sh/python-build-standalone/releases/tag/20250317 "
            f"asset {PYTHON_BUILD_STANDALONE_ASSET} "
            f"(SHA-256 {PYTHON_BUILD_STANDALONE_ASSET_SHA256})",
            "HOLD: correct the root libffi collision; ship exact CPython/embedded-component "
            "notices and retain exact source/build provenance",
        ),
        (
            "PyInstaller bootloader/loader",
            "6.21.0",
            "GPL-2.0-or-later with Bootloader Exception; runtime hooks Apache-2.0",
            "https://github.com/pyinstaller/pyinstaller/tree/v6.21.0",
            "no PyInstaller notice is required for the generated executable under the exception; retain COPYING as audit evidence; dependency licenses still apply",
        ),
        (
            "Node.js Windows x64",
            node_versions["node"],
            "MIT plus Node's bundled third-party terms",
            f"https://nodejs.org/dist/v{node_versions['node']}/",
            "ship the unmodified Node LICENSE and all embedded third-party notices",
        ),
        (
            "FFmpeg/ffprobe BtbN GPL static build",
            ffmpeg_version,
            "GPL-3.0-or-later configuration; exact dependency terms unresolved",
            f"https://github.com/BtbN/FFmpeg-Builds/releases/tag/{BTBN_RELEASE}",
            "HOLD: provide exact build commit, all Corresponding Source, scripts, notices and GPL text",
        ),
        (
            "Microsoft UCRT/Visual C++ runtime",
            "versions from Windows SDK, CPython and Qt wheels",
            "Microsoft redistributable terms",
            "local Windows SDK / CPython / PyQt wheel provenance",
            "HOLD: verify every DLL is on the applicable Microsoft redistributable list and retain terms",
        ),
    ]
    _table(lines, ("Component", "Version", "License", "Source", "Required action"), core_rows)
    lines.extend(
        [
            "A1. Exact binary and extension archive paths",
            "-" * 44,
            "",
            "The final PyInstaller package TOC contains 194 binary/extension paths:",
            "169 BINARY and 25 EXTENSION entries. Every path follows. Category tables",
            "below supply its version, license, source location and required action.",
            "",
        ]
    )
    _table(lines, ("Archive path", "Kind", "Inventory category"), binary_extension_payload)

    lines.extend(["B. Python distributions present in the PYZ", "-" * 43, ""])
    python_rows = [
        (
            package.name,
            package.version,
            package.license_expression,
            package.source,
            ", ".join(_relative(path) for path in package.license_files) or "MISSING",
            _action(package.license_expression),
        )
        for package in python_packages
    ]
    _table(
        lines,
        ("Package", "Version", "License", "Source", "License text", "Required action"),
        python_rows,
    )

    lines.extend(
        [
            "B1a. Exact CPython/python-build-standalone native runtime closure",
            "-" * 66,
            "",
            "The PKG contains exactly 23 non-Microsoft native paths from the official",
            f"{PYTHON_BUILD_STANDALONE_ASSET} asset, whose SHA-256 is",
            f"{PYTHON_BUILD_STANDALONE_ASSET_SHA256}. Each original runtime file was",
            "byte-matched to that asset. The two Microsoft VC runtime files are listed in",
            "section B3. The current EXE contains none of the CPython/OpenSSL/SQLite/libffi/",
            "mpdecimal/Expat/zlib component license files.",
            "",
            "Critical collision: _ctypes.pyd was built against python-build-standalone's",
            "libffi 3.4.2 (expected root DLL SHA-256",
            f"{CPYTHON_LIBFFI_342_SHA256}), but the final PKG root libffi-8.dll is the",
            "canvas/MSYS2 libffi 3.5.2 DLL (SHA-256",
            f"{CANVAS_LIBFFI_352_SHA256}). The imported symbols exist, but this is an",
            "uncontrolled ABI/build-toolchain substitution. A future build must put 3.4.2",
            "at archive root and keep the separate 3.5.2 copy only in the canvas vendor path.",
            "Both require their own MIT notice, source provenance and test record.",
            "",
        ]
    )
    _table(
        lines,
        (
            "Archive path",
            "Kind",
            "Bytes",
            "SHA-256",
            "Component",
            "Version",
            "License/status",
            "Exact binary source",
            "Required action",
        ),
        cpython_runtime_payload,
    )
    _table(
        lines,
        ("Component/build input", "Version", "License", "Exact source", "Required action"),
        list(CPYTHON_EMBEDDED_COMPONENTS),
    )

    lines.extend(
        [
            "B1b. Third-party code embedded by setuptools 83.0.0",
            "-" * 55,
            "",
            f"The PYZ contains {len(setuptools_pyz_modules)} relevant setuptools vendor/",
            "generated entries (36 source modules and two virtual namespaces). The ten",
            "actual components follow. Their dist-info licenses and both setuptools NOTICE",
            "files are absent from the audited EXE. The exact enclosing source archive is",
            "setuptools-83.0.0.tar.gz, SHA-256",
            "025bccbbf0fa05b6192bc64ae1e7b16e001fd6d6d4d5de03c97b1c1ade523bef.",
            "",
        ]
    )
    _table(
        lines,
        (
            "Component",
            "Bundled modules",
            "Version",
            "License",
            "Exact source",
            "Required action",
        ),
        list(SETUPTOOLS_PYZ_COMPONENTS),
    )
    lines.extend(
        [
            "Installed under setuptools/_vendor but absent from the PYZ: autocommand",
            "2.2.2, importlib_metadata 8.7.1, platformdirs 4.4.0 and zipp 3.23.0.",
            "Their original files/notices were not altered; they are excluded from the",
            "bundled matrix. Treat generated __init__.py/fastjsonschema_validations.py",
            "conservatively under both MPL-2.0 source and BSD-3-Clause notice duties.",
            "",
        ]
    )

    lines.extend(
        [
            "B2. Exact PyQt6/Qt6 archive payload",
            "-" * 37,
            "",
            "The current EXE has exactly 128 PyQt6 paths: 32 binaries/extensions and",
            "96 Qt translation files. No PyQt/Qt license, source, SBOM, third-party notice",
            "or relink/install document is present in the audited EXE. Every path follows.",
            "",
        ]
    )
    _table(
        lines,
        (
            "Archive path",
            "Type",
            "Component",
            "Version",
            "License/status",
            "Source",
            "Required action",
        ),
        qt_payload,
    )
    lines.extend(
        [
            "Static/embedded Qt dependencies evidenced by exports, strings, PDB paths or",
            "official Qt PDF 6.11.1 licensing documentation follow. UNRESOLVED means the",
            "artifact does not establish the exact selected revision or complete notice set.",
            "",
        ]
    )
    qt_static_rows = [
        (
            container,
            component,
            version,
            expression,
            "Qt 6.11.1 source/SBOM and exact wheel build provenance required",
            "ship exact source, copyright/license text, notices and applicable relink info",
        )
        for container, component, version, expression in QT_STATIC_DEPENDENCIES
    ]
    _table(
        lines,
        ("Container", "Embedded component", "Version", "License/status", "Source", "Action"),
        qt_static_rows,
    )
    _table(
        lines,
        ("Unresolved possible embedded component", "Version", "License", "Required action"),
        [
            (
                component,
                "UNRESOLVED",
                "UNRESOLVED",
                "HOLD: verify actual inclusion from exact Qt SBOM/source and retain terms",
            )
            for component in QT_UNRESOLVED_EMBEDDED_COMPONENTS
        ],
    )
    lines.extend(
        [
            "B3. Exact Microsoft/UCRT archive payload",
            "-" * 42,
            "",
            "The EXE has 49 Microsoft runtime-like DLL paths: 42 root UCRT DLLs, two",
            "root Python VC runtime DLLs, and five Qt-scoped VC runtime DLLs. The root",
            "UCRT files were unexpectedly harvested from Windows Performance Toolkit, not",
            "the documented UCRT redist directory; WPT NOTICE.txt is not in the EXE.",
            "",
        ]
    )
    _table(
        lines,
        ("Archive path", "File version", "License/status", "Observed source", "Action"),
        microsoft_runtime_payload,
    )

    lines.extend(["C. Node.js embedded dependency versions", "-" * 39, ""])
    node_rows = [
        (
            name,
            version,
            NODE_LICENSES.get(name, "see Node LICENSE; exact expression requires review"),
            f"Node.js {node_versions['node']} source tree",
            "ship exact Node LICENSE",
        )
        for name, version in sorted(node_versions.items())
        if name not in {"node", "modules", "napi"}
    ]
    _table(lines, ("Component", "Version", "License", "Source", "Required action"), node_rows)

    lines.extend(
        [
            "D. npm production packages physically present in node_modules",
            "-" * 60,
            "",
            f"Physical package directories: {sum(len(item.locations) for item in npm_packages)}",
            f"Unique name/version records: {len(npm_packages)}",
            "",
        ]
    )
    npm_license_counts = Counter(package.license_expression for package in npm_packages)
    _table(
        lines,
        ("Declared npm license expression", "Unique name/version records"),
        [
            (expression, count)
            for expression, count in sorted(
                npm_license_counts.items(), key=lambda item: (-item[1], item[0])
            )
        ],
    )
    npm_rows = [
        (
            package.name,
            package.version,
            package.license_expression,
            package.source,
            "<br>".join(package.locations),
            ", ".join(_relative(path) for path in package.license_files) or "MISSING",
            _action(package.license_expression),
        )
        for package in npm_packages
    ]
    _table(
        lines,
        (
            "Package",
            "Version",
            "License",
            "Exact tarball/source",
            "Bundled location",
            "License text",
            "Required action",
        ),
        npm_rows,
    )

    lines.extend(
        [
            "E. canvas 3.2.1 native payload",
            "-" * 33,
            "",
            "Versions are detected from exports, PE metadata, import chains or embedded",
            "strings; parenthetical inferences are marked. License expressions are expected",
            "upstream terms, not proof that the exact license/provenance was conveyed in this",
            "prebuild. The prebuild contains no native SBOM or native license bundle.",
            "",
            f"Exact prebuild: {CANVAS_PREBUILD_URL}",
            f"Prebuild SHA-256: {CANVAS_PREBUILD_SHA256}",
            "All 49 archive members (45 native artifacts plus four build files) match the",
            "installed payload. The archive contains no license, notice, SBOM, manifest or",
            "source. Provenance is established; native license/source compliance is not.",
            "",
        ]
    )
    native_root = NODE_MODULES / "canvas" / "build" / "Release"
    actual_native = {path.name for path in native_root.iterdir() if path.is_file()}
    expected_native = {item[0] for item in NATIVE_CANVAS_COMPONENTS}
    if actual_native != expected_native:
        raise RuntimeError(
            f"Native canvas inventory changed: missing={expected_native - actual_native}, "
            f"extra={actual_native - expected_native}"
        )
    native_rows = [
        (
            filename,
            version,
            expression,
            _relative(native_root / filename),
            "retain exact notices and provenance; apply the selected-license and relink action in the exact MSYS2 package table below",
        )
        for filename, version, expression in NATIVE_CANVAS_COMPONENTS
    ]
    _table(
        lines,
        (
            "Artifact",
            "Detected version",
            "Expected upstream license / local status",
            "Bundled location",
            "Required action",
        ),
        native_rows,
    )
    package_dlls = {
        filename
        for _package, _version, filenames, _expression, _source_stem in CANVAS_MSYS2_PACKAGES
        for filename in filenames.split("; ")
    }
    if package_dlls != actual_native - {"canvas.node"}:
        raise RuntimeError(
            "MSYS2 native package mapping changed: "
            f"missing={actual_native - {'canvas.node'} - package_dlls}, "
            f"extra={package_dlls - actual_native}"
        )
    lines.extend(
        [
            "All 44 DLLs were byte-for-byte matched to these 34 official historical MSYS2",
            "packages. This establishes exact binary/source-package locations. The package",
            "license files and source archives still are not conveyed by the Neural EXE.",
            "",
        ]
    )
    msys2_rows = []
    for package, version, filenames, expression, source_stem in CANVAS_MSYS2_PACKAGES:
        binary_url = (
            "https://repo.msys2.org/mingw/ucrt64/"
            f"mingw-w64-ucrt-x86_64-{package}-{version}-any.pkg.tar.zst"
        )
        source_url = (
            "https://repo.msys2.org/mingw/sources/"
            f"mingw-w64-{source_stem}-{version}.src.tar.zst"
        )
        msys2_rows.append(
            (
                package,
                version,
                filenames,
                expression,
                binary_url,
                source_url,
                _action(expression),
            )
        )
    _table(
        lines,
        (
            "MSYS2 package",
            "Package version",
            "Matched DLLs",
            "Exact package license metadata",
            "Binary package",
            "Source package",
            "Required action",
        ),
        msys2_rows,
    )
    lines.extend(
        [
            "F. Minimum Rust dependency set detected in librsvg-2-2.dll",
            "-" * 61,
            "",
            "These rows come from crates.io source-path strings embedded in the DLL. They",
            "prove that at least these crates contributed to the binary, but do not prove a",
            "complete dependency graph. Their exact license expressions and texts have not",
            "been recovered from the current payload. Cargo.lock and checksums are absent.",
            "",
        ]
    )
    rust_rows = []
    for item in LIBRSVG_DETECTED_RUST_CRATES:
        name, version = item.rsplit("-", 1)
        rust_rows.append(
            (
                name,
                version,
                "UNRESOLVED locally",
                f"https://crates.io/crates/{name}/{version}",
                "HOLD: obtain Cargo.lock, checksum, exact source, license and notice text",
            )
        )
    for library in ("Rust alloc", "Rust core", "Rust std"):
        rust_rows.append(
            (
                library,
                "1.91.0",
                "UNRESOLVED locally",
                "exact Rust 1.91.0 toolchain/library source required",
                "HOLD: obtain exact source, toolchain provenance, license and notice text",
            )
        )
    _table(lines, ("Detected component", "Version", "License", "Source", "Required action"), rust_rows)
    lines.extend(
        [
            "Optimisation can remove crate paths, and proc-macro/build dependencies need not",
            "appear in the DLL. Therefore this minimum set is not a complete SBOM and public",
            "distribution remains on HOLD.",
            "",
            "G. FFmpeg external/static build flags",
            "-" * 38,
            "",
            "Every external integration enabled in the audited FFmpeg configuration is listed",
            "below. A build flag alone does not reveal whether code is statically linked, loaded",
            "from Windows, header-only, or merely enabled; exact build provenance is required.",
            "",
            f"Exact BtbN asset: {BTBN_ASSET}",
            f"Asset SHA-256: {BTBN_ASSET_SHA256}",
            f"BtbN build-scripts tag commit: {BTBN_BUILD_SCRIPTS_COMMIT}",
            "The archive's ffmpeg.exe and ffprobe.exe hashes exactly match the local files.",
            "This proves binary provenance, not completeness of Corresponding Source.",
            "",
        ]
    )
    ffmpeg_rows = [
        (
            dependency,
            "UNRESOLVED",
            "UNRESOLVED from current binary alone",
            "BtbN build scripts.d plus exact retained source archive required",
            "HOLD: obtain exact version, license text and Corresponding Source",
        )
        for dependency in ffmpeg_dependencies
    ]
    _table(lines, ("Build dependency", "Version", "License", "Source", "Required action"), ffmpeg_rows)

    lines.extend(
        [
            "Additional components found in the exact BtbN build recipes or their transitive",
            "build steps are listed below. They are not all named by `ffmpeg -version`; exact",
            "versions, actually linked objects, licenses and source snapshots remain unresolved.",
            "",
        ]
    )
    ffmpeg_transitive_rows = [
        (
            component,
            "UNRESOLVED",
            "UNRESOLVED",
            f"BtbN scripts commit {BTBN_BUILD_SCRIPTS_COMMIT} and retained build cache required",
            "HOLD: identify exact source revision, license/notices and linkage",
        )
        for component in FFMPEG_RECIPE_TRANSITIVE_COMPONENTS
    ]
    _table(
        lines,
        ("Recipe/transitive component", "Version", "License", "Evidence", "Required action"),
        ffmpeg_transitive_rows,
    )

    lines.extend(
        [
            "H. Preserved local license and copyright texts",
            "-" * 47,
            "",
            "The texts below are copied without intentional alteration from the indicated",
            "local files. Their presence does not cure missing source/provenance obligations.",
            "",
        ]
    )
    text_sources: list[tuple[str, Path]] = [
        (
            "bgutil-ytdlp-pot-provider 1.3.1",
            PROJECT_ROOT / "vendor" / "bgutil-ytdlp-pot-provider" / "LICENSE",
        ),
        (
            "CPython 3.12.9",
            LICENSE_ROOT / "CPython-3.12.9-LICENSE.txt",
        ),
        (
            "PyInstaller 6.21.0",
            LICENSE_ROOT / "PyInstaller-6.21.0-COPYING.txt",
        ),
        (
            "FFmpeg BtbN win64-gpl archive GPL-3.0 text",
            LICENSE_ROOT / "FFmpeg-BtbN-win64-gpl-LICENSE.txt",
        ),
    ]
    if node_license is None:
        bundled_node_license = LICENSE_ROOT / "Node.js-22.17.0-LICENSE.txt"
        if bundled_node_license.is_file():
            node_license = bundled_node_license
    if node_license is not None:
        text_sources.append(
            (f"Node.js {node_versions['node']} and embedded third parties", node_license)
        )
    else:
        lines.extend(
            [
                "MISSING: exact Node.js 22.17.0 LICENSE was not supplied to the generator.",
                "This is a release blocker.",
                "",
            ]
        )
    for package in python_packages + npm_packages:
        for license_file in package.license_files:
            text_sources.append((f"{package.name} {package.version}", license_file))

    seen: set[tuple[str, str]] = set()
    for label, source in text_sources:
        key = (label, str(source.resolve()))
        if key in seen:
            continue
        seen.add(key)
        if not source.is_file():
            lines.extend([f"MISSING LICENSE TEXT: {label}: {source}", ""])
            continue
        lines.extend(
            [
                "=" * 78,
                f"COMPONENT: {label}",
                f"SOURCE FILE: {_relative(source)}",
                f"SOURCE SHA-256: {_sha256(source)}",
                "=" * 78,
                _read_text(source).rstrip(),
                "",
            ]
        )

    audit_start = lines.index("0. Audited PyInstaller archive facts")
    audit_end = lines.index("H. Preserved local license and copyright texts")
    audit_lines = lines[audit_start:audit_end]
    for marker in ("HOLD", "MISSING", "UNRESOLVED"):
        placeholder = f"Audit-{marker}-marker-count: __CALCULATED__"
        count = sum(line.count(marker) for line in audit_lines)
        lines[lines.index(placeholder)] = f"Audit-{marker}-marker-count: {count}"

    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8", newline="\n")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--node-license", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    generate(
        output=args.output.resolve(),
        node_license=args.node_license.resolve() if args.node_license else None,
    )
    print(f"Generated {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
