"""Generate a deterministic, artifact-derived Windows distribution inventory.

The report deliberately remains a HOLD record.  It inventories the bytes in a
PyInstaller one-file executable; it does not decide copyright ownership,
license compatibility, source completeness, or legal sufficiency.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import tempfile
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from PyInstaller.archive.readers import CArchiveReader

try:
    from scripts.project_identity import APP_NAME, APPLICATION_VERSION
except ModuleNotFoundError:  # executed directly as scripts/generate_distribution_inventory.py
    from project_identity import APP_NAME, APPLICATION_VERSION  # type: ignore[no-redef]

REPORT_SCHEMA = f"{APP_NAME} distribution inventory v1"
EXPECTED_LIBFFI_SHA256 = "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e"
ROOT_LIBFFI_PATH = "libffi-8.dll"

COMPLIANCE_PATHS: tuple[str, ...] = (
    "LICENSE",
    "PROJECT-METADATA.json",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    "docs/PROJECT-OWNERSHIP-DECLARATION.md",
    "docs/DEPENDENCY-SOURCE.md",
    "docs/BUILD-REPRODUCIBILITY.md",
    "docs/LGPL-COMPLIANCE.md",
    "docs/OPTIONAL-PO-PROVIDER.md",
    "requirements.lock",
    "SOURCE-HASHES.sha256",
    "licenses/RELEASE-LICENSE-MANIFEST.sha256",
)

# Embedding a newly rendered inventory changes both the inventory bytes and the
# source manifest that hashes those bytes.  An embedded report therefore cannot
# truthfully predict these two hashes from its seed artifact.  The post-build
# sidecar inventories the final bytes and is the only report allowed to state
# their exact values.
EMBEDDED_DYNAMIC_COMPLIANCE_PATHS: frozenset[str] = frozenset(
    {
        "THIRD_PARTY_LICENSES.txt",
        "SOURCE-HASHES.sha256",
    }
)

_NATIVE_SUFFIXES = (".dll", ".pyd", ".exe")
_RAW_JAVASCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".js.map")
_PYQT_TOKEN = re.compile(r"(?:^|[./_\\-])pyqt(?:5|6)?(?:$|[./_\\-])", re.I)
_PROVIDER_TOKEN = re.compile(
    r"(?:^|[./_\\-])(?:bgutil|getpot)(?:$|[./_\\-])"
    r"|(?:^|[./\\])(?:yt_dlp_plugins|yt-dlp-plugins)(?:$|[./\\])",
    re.I,
)
_LOCK_RECORD = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^;\\\s]+)(?:\s|;|\\|$)")
_LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})(?:\s|\\|$)")


class InventoryError(RuntimeError):
    """Raised when an executable cannot be inventoried unambiguously."""


class _EmbeddedArchive(Protocol):
    toc: dict[str, object]

    def extract(self, name: str, raw: bool = False) -> bytes | None: ...


class _CArchive(Protocol):
    toc: dict[str, tuple[object, ...]]

    def extract(self, name: str) -> bytes: ...

    def open_embedded_archive(self, name: str) -> _EmbeddedArchive: ...


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    component: str


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    license: str
    copyright_holder: str
    location: str
    upstream: str
    modifications: str
    action: str
    boundary: str = "MAIN EXE"
    lock_name: str | None = None


@dataclass(frozen=True)
class LockRecord:
    name: str
    version: str
    hashes: tuple[str, ...]


def _components(
    microsoft_version: str,
    module_roots: set[str],
    archive_paths: set[str],
) -> tuple[Component, ...]:
    pillow_included = "PIL" in module_roots or any(
        path.casefold().startswith("pil/") for path in archive_paths
    )
    defusedxml_included = "defusedxml" in module_roots
    transcript_api_included = "youtube_transcript_api" in module_roots
    python_lock = (
        "Exact PyPI artifact hashes are in the embedded requirements.lock and "
        "the locked-hash table below; source URL/hash retention is governed by "
        "uv.lock and docs/DEPENDENCY-SOURCE.md in the corresponding-source set."
    )
    permissive_action = (
        "Ship the exact copyright/license text and notices; retain the exact "
        "upstream source/archive and build provenance named in the source companion."
    )
    qt_action = (
        "Ship prominent LGPL/Qt/PySide notices and complete applicable license and "
        "third-party texts; provide exact corresponding source and project build "
        "scripts for covered modifications; preserve reverse-engineering rights and "
        "a tested DLL replacement/relink procedure. Qualified review must approve it."
    )
    return (
        Component(
            APP_NAME,
            APPLICATION_VERSION,
            "MIT for project-owned portions",
            "0xRootNull; Copyright (c) 2025-2026",
            "Frozen application modules in the embedded PYZ plus entry-point script",
            "Project corresponding source; embedded SOURCE-HASHES.sha256 records inputs",
            "Project-maintainer declaration records no known other human contributor claim; "
            "AI-assisted development used under maintainer direction and approval",
            "Ship the standard MIT LICENSE, PROJECT-METADATA.json, ownership declaration, "
            "and corresponding build/source inputs. Third-party terms remain separate.",
        ),
        Component(
            "CPython / python-build-standalone",
            "CPython 3.12.9; python-build-standalone 20250317",
            "Python-2.0 plus historical and bundled-component terms; build recipes MPL-2.0",
            "Python Software Foundation and historical licensors; standalone-build and "
            "bundled-component per-file holders (exact closure in notices)",
            "python312.dll, python3.dll, stdlib/PYZ modules, and CPython extension modules",
            "https://www.python.org/ftp/python/3.12.9/Python-3.12.9.tar.xz "
            "(SHA-256 7220835d9f90b37c006e9842a8dff4580aaca4318674f947302b8d28f3f81112); "
            "https://github.com/astral-sh/python-build-standalone/releases/tag/20250317 "
            "install-only asset SHA-256 "
            "ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661",
            "Upstream standalone build/patch set; no project source patch declared; exact "
            "upstream build transformation must accompany source provenance",
            "Ship CPython, standalone-build, and all selected bundled-component notices; "
            "retain exact source, patches, recipes, toolchain, and reconstruction steps.",
        ),
        Component(
            "libffi",
            "3.4.2",
            "MIT",
            "Anthony Green, Red Hat, and libffi contributors (exact per-file holders in license)",
            ROOT_LIBFFI_PATH,
            "python/cpython-source-deps commit "
            "16fad4855b3d8c03b5910e405ff3a04395b39a98; exact binary hash is in the "
            "boundary section",
            "Built by the audited CPython standalone runtime; no project source patch declared",
            permissive_action + " Keep exactly one audited root DLL; do not shadow it.",
        ),
        Component(
            "OpenSSL",
            "3.0.16",
            "Apache-2.0",
            "The OpenSSL Project Authors and individual contributors",
            "libcrypto-3-x64.dll, libssl-3-x64.dll, _hashlib.pyd and _ssl.pyd",
            "https://www.openssl.org/source/openssl-3.0.16.tar.gz; exact source-archive "
            "hash is not yet recorded (HOLD)",
            "Built into the pinned python-build-standalone runtime; no project patch declared",
            "Ship Apache-2.0 and source-exact acknowledgements/copyright material; retain "
            "the exact source archive hash and standalone-build recipe before release.",
        ),
        Component(
            "SQLite",
            "3.47.1",
            "Public-domain dedication",
            "D. Richard Hipp and SQLite contributors",
            "sqlite3.dll and _sqlite3.pyd",
            "https://www.sqlite.org/2024/sqlite-autoconf-3470100.tar.gz; exact "
            "source-archive hash is not yet recorded (HOLD)",
            "Built into the pinned python-build-standalone runtime; no project patch declared",
            "Retain the public-domain dedication, exact source/archive hash, and build provenance.",
        ),
        Component(
            "bzip2",
            "1.0.8",
            "bzip2 permissive license",
            "Julian Seward",
            "statically linked into _bz2.pyd",
            "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz; exact source-archive "
            "hash is not yet recorded (HOLD)",
            "Built into the pinned python-build-standalone runtime; no project patch declared",
            "Ship the exact copyright, conditions and disclaimer; retain exact source/build inputs.",
        ),
        Component(
            "XZ Utils / liblzma",
            "5.2.12",
            "Source-exact public-domain notices",
            "Lasse Collin, Igor Pavlov, and XZ contributors as identified per source file",
            "statically linked into _lzma.pyd",
            "https://github.com/tukaani-project/xz/tree/v5.2.12; exact source-archive "
            "hash is not yet recorded (HOLD)",
            "Built into the pinned python-build-standalone runtime; no project patch declared",
            "Retain exact source and every notice applicable to the selected files.",
        ),
        Component(
            "zlib",
            "1.3.1",
            "Zlib",
            "Jean-loup Gailly and Mark Adler",
            "CPython runtime compression paths, including python312.dll",
            "https://github.com/madler/zlib/releases/tag/v1.3.1; exact source-archive "
            "hash is not yet recorded (HOLD)",
            "Built into the pinned python-build-standalone runtime; no project patch declared",
            "Ship the exact zlib notice and retain exact source/build inputs.",
        ),
        Component(
            "Expat",
            "2.6.4",
            "MIT",
            "Expat maintainers and contributors",
            "statically linked into pyexpat.pyd",
            "https://github.com/libexpat/libexpat/tree/R_2_6_4; exact source-archive "
            "hash is not yet recorded (HOLD)",
            "Built into the pinned python-build-standalone runtime; no project patch declared",
            "Ship the exact MIT notice and retain exact source/build inputs.",
        ),
        Component(
            "mpdecimal",
            "2.5.1",
            "BSD-2-Clause",
            "Stefan Krah and mpdecimal contributors",
            "statically linked into _decimal.pyd",
            "CPython 3.12.9 Modules/_decimal/libmpdec; covered by the pinned CPython source hash",
            "Built into CPython; no project patch declared",
            "Ship the exact BSD-2-Clause notice and retain the covered CPython source.",
        ),
        Component(
            "HACL* vendor code",
            "CPython snapshot bb3d0dc8d9d15a5cd51094d5b69e70aa09005ff0",
            "MIT",
            "HACL*/EverCrypt contributors as identified by CPython source headers",
            "CPython hashing/runtime code in python312.dll",
            "CPython 3.12.9 Modules/_hacl and refresh.sh; covered by the pinned CPython source hash",
            "Vendored/transformed by upstream CPython; no project patch declared",
            "Preserve MIT headers, the exact vendor source, and upstream transformation steps.",
        ),
        Component(
            "Unicode Character Database",
            "15.0.0",
            "Unicode data files and software license",
            "Unicode, Inc.",
            "generated Unicode tables in CPython runtime",
            "https://www.unicode.org/Public/15.0.0/ucd/; exact source/archive and license "
            "hash are not yet retained (HOLD)",
            "Generated by upstream CPython; no project modification declared",
            "Obtain and ship the exact UCD 15.0.0 permission notice and retain generator inputs.",
        ),
        Component(
            "BLAKE2 reference-derived code",
            "CPython 3.12.9 snapshot",
            "CC0-1.0 / public-domain dedication",
            "BLAKE2 reference authors and CPython contributors",
            "CPython BLAKE2 implementation in the runtime",
            "CPython 3.12.9 Modules/_blake2; covered by the pinned CPython source hash",
            "Vendored/adapted upstream by CPython; no project patch declared",
            "Preserve the exact dedication, source provenance, and transformation record.",
        ),
        Component(
            "PyInstaller",
            "6.21.0",
            "GPL-2.0-or-later with PyInstaller bootloader exception; selected files Apache-2.0",
            "Gordon McMillan, the PyInstaller Development Team, and per-file contributors",
            "Outer bootloader/generated CArchive and frozen PyInstaller runtime hooks",
            "https://github.com/pyinstaller/pyinstaller/tree/v6.21.0; " + python_lock,
            "Build-time freezing only; no local PyInstaller source patch declared",
            "Retain the exact COPYING/exception and relevant per-file notices as audit evidence; "
            "retain exact build scripts and source even though the bootloader exception permits "
            "distribution of the generated application.",
            lock_name="pyinstaller",
        ),
        Component(
            "setuptools",
            "83.0.0",
            "MIT plus licenses of selected vendored/generated components",
            "Python Packaging Authority and per-vendor contributors",
            "setuptools PYZ root (119 entries in the audited candidate)",
            "https://files.pythonhosted.org/packages/source/s/setuptools/setuptools-83.0.0.tar.gz "
            "SHA-256 025bccbbf0fa05b6192bc64ae1e7b16e001fd6d6d4d5de03c97b1c1ade523bef; "
            + python_lock,
            "Collected by the PyInstaller setuptools runtime hook; no project source patch declared",
            "Ship setuptools MIT plus every selected vendor/generated notice below; make MPL-2.0 "
            "Source Code Form and generator/schema inputs available.",
            lock_name="setuptools",
        ),
        Component(
            "packaging",
            "26.2",
            "Apache-2.0 OR BSD-2-Clause",
            "Donald Stufft and packaging contributors",
            "top-level packaging PYZ root",
            "https://github.com/pypa/packaging/tree/26.2; " + python_lock,
            "Frozen without project source modification",
            "Ship LICENSE, LICENSE.APACHE and LICENSE.BSD; retain exact source/wheel hashes.",
            lock_name="packaging",
        ),
        Component(
            "typing_extensions",
            "4.16.0",
            "PSF-2.0",
            "Python Software Foundation and typing_extensions contributors",
            "typing_extensions PYZ module",
            "https://github.com/python/typing_extensions/tree/4.16.0; " + python_lock,
            "Frozen without project source modification",
            permissive_action,
            lock_name="typing-extensions",
        ),
        Component(
            "backports.tarfile (setuptools-vendored)",
            "1.2.0",
            "MIT",
            "Jason R. Coombs, Lars Gustäbel, and contributors",
            "setuptools._vendor.backports.tarfile PYZ modules",
            "https://github.com/jaraco/backports.tarfile/tree/v1.2.0",
            "Vendored by setuptools; no project patch declared",
            permissive_action,
        ),
        Component(
            "jaraco.context / jaraco.functools / jaraco.text (setuptools-vendored)",
            "6.1.0 / 4.4.0 / 4.0.0",
            "MIT",
            "Jason R. Coombs and per-project contributors",
            "selected setuptools._vendor.jaraco PYZ modules",
            "https://github.com/jaraco/jaraco.context/tree/v6.1.0; "
            "https://github.com/jaraco/jaraco.functools/tree/v4.4.0; "
            "https://github.com/jaraco/jaraco.text/tree/v4.0.0",
            "Vendored by setuptools; no project patch declared",
            permissive_action,
        ),
        Component(
            "more-itertools (setuptools-vendored)",
            "10.8.0",
            "MIT",
            "Erik Rose and more-itertools contributors",
            "setuptools._vendor.more_itertools PYZ modules",
            "https://github.com/more-itertools/more-itertools/tree/10.8.0",
            "Vendored by setuptools; no project patch declared",
            permissive_action,
        ),
        Component(
            "packaging (setuptools-vendored)",
            "26.0",
            "Apache-2.0 OR BSD-2-Clause",
            "Donald Stufft and packaging contributors",
            "setuptools._vendor.packaging PYZ modules",
            "https://github.com/pypa/packaging/tree/26.0",
            "Vendored by setuptools; no project patch declared",
            "Ship LICENSE, LICENSE.APACHE and LICENSE.BSD; retain exact source provenance.",
        ),
        Component(
            "tomli (setuptools-vendored)",
            "2.4.0",
            "MIT",
            "Taneli Hukkinen and contributors",
            "setuptools._vendor.tomli PYZ modules",
            "https://github.com/hukkin/tomli/tree/2.4.0",
            "Vendored by setuptools; no project patch declared",
            permissive_action,
        ),
        Component(
            "wheel (setuptools-vendored)",
            "0.46.3",
            "MIT",
            "Daniel Holth and wheel contributors",
            "setuptools._vendor.wheel PYZ modules",
            "https://github.com/pypa/wheel/tree/0.46.3",
            "Vendored by setuptools; no project patch declared",
            permissive_action,
        ),
        Component(
            "validate-pyproject-derived setuptools code",
            "0.25-derived",
            "MPL-2.0 portions",
            "Anderson Bravalheri and validate-pyproject contributors",
            "setuptools.config._validate_pyproject PYZ modules and generated schemas",
            "https://github.com/abravalheri/validate-pyproject/tree/v0.25",
            "Vendored/generated by upstream setuptools; no project patch declared",
            "Ship unmodified setuptools notices/MPL-2.0 and make exact covered source plus "
            "generator/schema inputs available.",
        ),
        Component(
            "fastjsonschema-derived setuptools code",
            "2.21.2-derived",
            "BSD-3-Clause portions",
            "Peter Tröger and fastjsonschema contributors",
            "generated validation modules under setuptools.config._validate_pyproject",
            "https://github.com/horejsek/python-fastjsonschema/tree/v2.21.2",
            "Generated/vendored by upstream setuptools; no project patch declared",
            "Reproduce the exact BSD copyright, conditions and disclaimer; retain full "
            "setuptools notices and generator provenance.",
        ),
        Component(
            "PySide6",
            "6.11.1",
            "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
            "The Qt Company Ltd. and PySide contributors; exact per-file holder list UNRESOLVED",
            "PySide6 PYZ root and selected PySide6 native table paths",
            "pyside-setup-everywhere-src-6.11.1.tar.xz SHA-256 "
            "6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2; "
            "https://pypi.org/project/PySide6/6.11.1/; " + python_lock,
            "No project source patch declared; frozen/collected into a one-file executable",
            qt_action,
            lock_name="pyside6",
        ),
        Component(
            "PySide6-Essentials",
            "6.11.1",
            "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
            "The Qt Company Ltd. and PySide contributors; exact per-file holder list UNRESOLVED",
            "QtCore/QtGui/QtWidgets bindings and selected PySide/Qt native paths",
            "pyside-setup-everywhere-src-6.11.1.tar.xz SHA-256 "
            "6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2; "
            "https://pypi.org/project/PySide6-Essentials/6.11.1/; " + python_lock,
            "No project source patch declared; selected files frozen/collected",
            qt_action,
            lock_name="pyside6-essentials",
        ),
        Component(
            "PySide6-Addons",
            "6.11.1",
            "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
            "The Qt Company Ltd. and PySide contributors; exact per-file holder list UNRESOLVED",
            "Locked build input; optional add-on modules are intended to be excluded; exact "
            "PySide/Qt table is authoritative for bytes actually conveyed",
            "https://pypi.org/project/PySide6-Addons/6.11.1/; " + python_lock,
            "No project source patch declared; runtime inclusion, if any, is path-inventoried below",
            qt_action,
            boundary="LOCKED BUILD INPUT / ADD-ON MODULES NOT INCLUDED",
            lock_name="pyside6-addons",
        ),
        Component(
            "Shiboken6",
            "6.11.1",
            "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
            "The Qt Company Ltd. and Shiboken contributors; exact per-file holder list UNRESOLVED",
            "shiboken6 PYZ/native paths and PySide support DLLs",
            "pyside-setup-everywhere-src-6.11.1.tar.xz SHA-256 "
            "6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2; "
            "https://pypi.org/project/shiboken6/6.11.1/; " + python_lock,
            "No project source patch declared; frozen/collected into a one-file executable",
            qt_action,
            lock_name="shiboken6",
        ),
        Component(
            "Qt",
            "6.11.1",
            "LGPL-3.0-only for selected Qt modules, plus applicable Qt third-party terms; "
            "GPL/commercial alternatives are not asserted here",
            "The Qt Company Ltd., Qt contributors, and third-party per-file holders; exact "
            "payload-to-attribution closure UNRESOLVED",
            "Selected PySide6/Qt DLLs and four plugins listed byte-for-byte below; no Qt "
            "translation catalogs or add-on modules are included",
            "qtbase-everywhere-src-6.11.1.tar.xz SHA-256 "
            "d9594a31228aa23ad6b531719a29b45f0f3989fe6c136d45767ea179f233c1ac; "
            "https://download.qt.io/official_releases/qt/6.11/6.11.1/submodules/",
            "No project Qt source patch declared; upstream wheel binaries are repackaged in one-file form",
            qt_action,
        ),
        Component(
            "yt-dlp",
            "2026.7.4",
            "Unlicense",
            "yt-dlp contributors; individual per-file holder list UNRESOLVED",
            "yt_dlp PYZ root",
            "https://github.com/yt-dlp/yt-dlp/tree/2026.07.04; " + python_lock,
            "No project source patch declared; Python modules byte-compiled/frozen",
            permissive_action,
            lock_name="yt-dlp",
        ),
        Component(
            "Pillow",
            "12.3.0",
            "MIT-CMU",
            "Secret Labs AB, Fredrik Lundh, and Pillow contributors",
            (
                "PIL PYZ root and PIL native extension paths"
                if pillow_included
                else "Locked dependency and preserved notice text; no PIL code/native path "
                "in the audited artifact"
            ),
            "https://github.com/python-pillow/Pillow/tree/12.3.0; " + python_lock,
            (
                "No project source patch declared; modules/native wheel content frozen"
                if pillow_included
                else "Package code is not frozen; its unmodified license evidence is retained"
            ),
            permissive_action,
            boundary=(
                "MAIN EXE"
                if pillow_included
                else "LOCKED INPUT / PACKAGE CODE NOT INCLUDED; NOTICE TEXT INCLUDED"
            ),
            lock_name="pillow",
        ),
        Component(
            "requests",
            "2.34.2",
            "Apache-2.0",
            "Kenneth Reitz and Requests contributors",
            "requests PYZ root",
            "https://github.com/psf/requests/tree/v2.34.2; " + python_lock,
            "No project source patch declared; Python modules byte-compiled/frozen",
            "Ship Apache-2.0, retained copyright/NOTICE material, and exact source provenance.",
            lock_name="requests",
        ),
        Component(
            "certifi",
            "2026.7.22",
            "MPL-2.0",
            "Kenneth Reitz and certifi contributors; Mozilla CA certificate holders are separate",
            "certifi PYZ/data paths",
            "https://github.com/certifi/python-certifi; " + python_lock,
            "No project source patch declared; package/data frozen",
            "Ship MPL-2.0 and notices; make the exact Source Code Form for conveyed MPL-covered "
            "files and any modifications available, with source provenance retained.",
            lock_name="certifi",
        ),
        Component(
            "charset-normalizer",
            "3.4.9",
            "MIT",
            "Ahmed Tahri and charset-normalizer contributors",
            "charset_normalizer PYZ/native paths",
            "https://github.com/jawah/charset_normalizer/tree/3.4.9; " + python_lock,
            "No project source patch declared; modules/native wheel content frozen",
            permissive_action,
            lock_name="charset-normalizer",
        ),
        Component(
            "idna",
            "3.18",
            "BSD-3-Clause",
            "Kim Davies",
            "idna PYZ root",
            "https://github.com/kjd/idna/tree/v3.18; " + python_lock,
            "No project source patch declared; Python modules byte-compiled/frozen",
            permissive_action,
            lock_name="idna",
        ),
        Component(
            "urllib3",
            "2.7.0",
            "MIT",
            "Andrey Petrov and urllib3 contributors",
            "urllib3 PYZ root",
            "https://github.com/urllib3/urllib3/tree/2.7.0; " + python_lock,
            "No project source patch declared; Python modules byte-compiled/frozen",
            permissive_action,
            lock_name="urllib3",
        ),
        Component(
            "defusedxml",
            "0.7.1",
            "PSF-2.0",
            "Christian Heimes",
            (
                "defusedxml PYZ root"
                if defusedxml_included
                else "Locked transitive dependency and preserved notice text; no defusedxml "
                "module in the audited artifact"
            ),
            "https://github.com/tiran/defusedxml/tree/v0.7.1; " + python_lock,
            (
                "No project source patch declared; Python modules byte-compiled/frozen"
                if defusedxml_included
                else "Package code is not frozen; its unmodified license evidence is retained"
            ),
            permissive_action,
            boundary=(
                "MAIN EXE"
                if defusedxml_included
                else "LOCKED INPUT / PACKAGE CODE NOT INCLUDED; NOTICE TEXT INCLUDED"
            ),
            lock_name="defusedxml",
        ),
        Component(
            "youtube-transcript-api",
            "1.2.4",
            "MIT",
            "Jonas Depoix and youtube-transcript-api contributors",
            (
                "youtube_transcript_api PYZ root"
                if transcript_api_included
                else "Locked dependency and preserved notice text; no youtube_transcript_api "
                "module in the audited artifact"
            ),
            "https://github.com/jdepoix/youtube-transcript-api/tree/v1.2.4; " + python_lock,
            (
                "No project source patch declared; Python modules byte-compiled/frozen"
                if transcript_api_included
                else "Package code is not frozen; its unmodified license evidence is retained"
            ),
            permissive_action,
            boundary=(
                "MAIN EXE"
                if transcript_api_included
                else "LOCKED INPUT / PACKAGE CODE NOT INCLUDED; NOTICE TEXT INCLUDED"
            ),
            lock_name="youtube-transcript-api",
        ),
        Component(
            "Node.js",
            "22.17.0",
            "MIT plus bundled third-party licenses/notices",
            "Node.js contributors and bundled third-party holders named in the Node license file",
            "bin/node.exe",
            "https://nodejs.org/download/release/v22.17.0/node-v22.17.0-win-x64.zip; "
            "source node-v22.17.0.tar.gz SHA-256 "
            "f8bf095ff559033edf04108fb1f14f72e2be337c609d4f83e8af1e299af7f4b4; "
            "exact executable SHA-256 is in the native table",
            "Official Windows binary redistributed without declared project modification",
            "Ship the complete Node.js license and its bundled third-party notices; retain the "
            "exact source archive and build provenance.",
        ),
        Component(
            "FFmpeg / ffprobe (BtbN GPL build)",
            "N-125365-g9a01c1cb6a-20260630",
            "GPL-3.0-or-later distribution route (configured --enable-gpl --enable-version3); "
            "bundled libraries retain their terms",
            "FFmpeg developers plus bundled-library copyright holders; exact native closure UNRESOLVED",
            "bin/ffmpeg.exe and bin/ffprobe.exe",
            "https://github.com/BtbN/FFmpeg-Builds; commit 9a01c1cb6a and build date "
            "20260630; exact executable hashes are in the native table",
            "Upstream BtbN compiled build redistributed without declared project binary modification",
            "Ship GPLv3 and all notices. Convey complete machine-readable Corresponding Source, "
            "configuration, patches, and build/install scripts by a GPLv3 section 6 method, or a "
            "qualified-review-approved valid written offer where legally applicable. Upstream links "
            "alone are not treated as the distributor's source delivery.",
        ),
        Component(
            "Microsoft Visual C++ / Universal CRT runtime",
            microsoft_version,
            "Microsoft redistributable/proprietary terms",
            "Microsoft Corporation",
            "Microsoft runtime paths in the native-file table",
            "Official Microsoft toolchain/runtime redistribution; exact bytes are identified by "
            "path, file version where readable, size, and SHA-256",
            "Runtime DLLs redistributed without declared project modification",
            "Confirm each exact file is redistributable under the applicable Visual Studio/Windows "
            "SDK terms; preserve Microsoft notices and do not imply an open-source source offer.",
        ),
        Component(
            "bgutil-ytdlp-pot-provider optional helper",
            "1.3.1 compatibility target; installed helper version is independently verified",
            "GPL-3.0-only (external package; exact dependency terms remain with that distribution)",
            "Provider contributors; exact external-package copyright chain UNRESOLVED here",
            "The external helper package is NOT PRESENT as such; it is separately installed/"
            "versioned only. Any nonzero provider count below is a forbidden legacy payload, "
            "not part of this helper row.",
            "https://github.com/Brainicism/bgutil-ytdlp-pot-provider/tree/1.3.1; no provider "
            "archive/source hash is asserted as part of this EXE inventory",
            "No helper/provider bytes are modified or conveyed by this main-EXE report",
            "Do not bundle or silently install it. If separately conveyed, audit that package and "
            "its npm/native closure independently and satisfy its GPL/source/notice obligations.",
            boundary="EXTERNAL / NOT INCLUDED",
        ),
    )


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint_payload_identity(path: str, payload: bytes) -> tuple[bytes, int, bytes]:
    """Return a stable content identity for a CArchive payload.

    PyInstaller's base_library.zip can contain identical entries in a different
    ZIP order between otherwise equivalent builds.  Its canonical identity
    binds every sorted member path and byte sequence while ignoring only that
    container ordering.  The final outer EXE hash still covers the original ZIP
    bytes and metadata.
    """
    if path.casefold() != "base_library.zip":
        return b"RAW", len(payload), hashlib.sha256(payload).digest()

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            names = [member.filename.replace("\\", "/") for member in members]
            folded = [name.casefold() for name in names]
            if len(folded) != len(set(folded)):
                raise InventoryError("base_library.zip contains duplicate member paths")
            records = []
            for member, name in zip(members, names, strict=True):
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise InventoryError(
                        f"base_library.zip contains unsafe member path: {name}"
                    )
                records.append((name, archive.read(member)))
    except (OSError, zipfile.BadZipFile) as exc:
        raise InventoryError(f"cannot inspect base_library.zip: {exc}") from exc

    digest = hashlib.sha256()
    total_size = 0
    for name, data in sorted(records, key=lambda item: (item[0].casefold(), item[0])):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
        total_size += len(data)
    return b"CANONICAL-ZIP-CONTENT-V1", total_size, digest.digest()


def _normalize_archive_path(value: str) -> str:
    normalized = value.replace("\\", "/").removeprefix("./")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise InventoryError(f"unsafe CArchive path: {value!r}")
    return path.as_posix()


def _entry_type(entry: tuple[object, ...]) -> str:
    return str(entry[-1]) if entry else ""


def _is_documentation_path(path: str) -> bool:
    lowered = path.casefold()
    return lowered.startswith(("docs/", "licenses/")) or lowered in {
        "license",
        "third_party_licenses.txt",
        "third_party_notices.md",
    }


def _is_pyside_qt_path(path: str) -> bool:
    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    is_binding_binary = lowered.startswith(("pyside6/", "shiboken6/")) and name.endswith(
        (".dll", ".pyd")
    )
    is_qt_binary = name.startswith("qt6") and name.endswith((".dll", ".pyd"))
    is_plugin_or_translation = lowered.startswith(
        ("pyside6/plugins/", "pyside6/translations/")
    ) or any(marker in lowered for marker in ("/qt/plugins/", "/qt/translations/"))
    return is_binding_binary or is_qt_binary or is_plugin_or_translation


def _native_component(path: str) -> str:
    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    if _is_microsoft_runtime(path):
        return "Microsoft runtime"
    if (
        lowered.startswith(
            (
                "pyside6/qt/",
                "pyside6/plugins/",
                "pyside6/translations/",
                "pyside6/resources/",
            )
        )
        or name.startswith("qt6")
        or (lowered.startswith("pyside6/") and name.endswith(".dll") and "pyside" not in name)
    ):
        return "Qt 6.11.1"
    if lowered.startswith("pyside6/"):
        return "PySide6 / Essentials 6.11.1"
    if lowered.startswith("shiboken6/") or "shiboken" in name:
        return "Shiboken6 6.11.1"
    if lowered.startswith("pil/"):
        return "Pillow 12.3.0"
    if lowered.startswith("charset_normalizer/"):
        return "charset-normalizer 3.4.9"
    if "__mypyc" in name:
        # charset-normalizer is the only locked/runtime component in this
        # distribution that supplies a mypyc aggregate extension.
        return "charset-normalizer 3.4.9"
    if lowered == "bin/node.exe":
        return "Node.js 22.17.0"
    if lowered in {"bin/ffmpeg.exe", "bin/ffprobe.exe"}:
        return "FFmpeg GPL build N-125365-g9a01c1cb6a-20260630"
    if name.startswith("libffi") and name.endswith(".dll"):
        return "libffi 3.4.2"
    if name in {"libcrypto-3-x64.dll", "libssl-3-x64.dll"}:
        return "OpenSSL 3.0.16 (CPython standalone runtime)"
    if name == "sqlite3.dll":
        return "SQLite 3.47.1 (CPython standalone runtime)"
    if name == "pyexpat.pyd":
        return "CPython 3.12.9 + Expat 2.6.4"
    if name == "_bz2.pyd":
        return "CPython 3.12.9 + bzip2 1.0.8"
    if name == "_lzma.pyd":
        return "CPython 3.12.9 + XZ Utils/liblzma 5.2.12"
    if name == "_decimal.pyd":
        return "CPython 3.12.9 + mpdecimal 2.5.1"
    if name in {"_hashlib.pyd", "_ssl.pyd"}:
        return "CPython 3.12.9 + OpenSSL 3.0.16"
    if name == "_sqlite3.pyd":
        return "CPython 3.12.9 + SQLite 3.47.1"
    if name == "python312.dll":
        return "CPython 3.12.9 + zlib/HACL*/BLAKE2 runtime code"
    if (
        name.startswith("python")
        or name.startswith("_")
        or name
        in {
            "select.pyd",
            "unicodedata.pyd",
            "winsound.pyd",
        }
    ):
        return "CPython 3.12.9"
    return "UNRESOLVED component mapping - qualified audit required"


def _is_microsoft_runtime(path: str) -> bool:
    name = PurePosixPath(path.casefold()).name
    return name == "ucrtbase.dll" or name.startswith(
        ("api-ms-win-", "concrt", "msvcp", "vccorlib", "vcomp", "vcruntime")
    )


def _pe_file_version(payload: bytes) -> str | None:
    """Return the numeric PE fixed-file version when one is present."""
    try:
        import pefile

        pe = pefile.PE(data=payload, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        if not getattr(pe, "VS_FIXEDFILEINFO", None):
            return None
        info = pe.VS_FIXEDFILEINFO[0]
        return ".".join(
            str(value)
            for value in (
                info.FileVersionMS >> 16,
                info.FileVersionMS & 0xFFFF,
                info.FileVersionLS >> 16,
                info.FileVersionLS & 0xFFFF,
            )
        )
    except Exception:
        return None


def _parse_requirements_lock(payload: bytes | None) -> dict[str, LockRecord]:
    if payload is None:
        return {}
    try:
        lines = payload.decode("utf-8-sig").splitlines()
    except UnicodeError as exc:
        raise InventoryError(f"embedded requirements.lock is not UTF-8: {exc}") from exc

    result: dict[str, LockRecord] = {}
    current_name: str | None = None
    current_version = ""
    hashes: list[str] = []

    def finish() -> None:
        nonlocal current_name, current_version, hashes
        if current_name is None:
            return
        if current_name in result:
            raise InventoryError(f"duplicate requirements.lock record: {current_name}")
        result[current_name] = LockRecord(current_name, current_version, tuple(sorted(set(hashes))))
        current_name = None
        current_version = ""
        hashes = []

    for line in lines:
        match = _LOCK_RECORD.match(line)
        if match is not None:
            finish()
            current_name = re.sub(r"[-_.]+", "-", match.group(1)).casefold()
            current_version = match.group(2)
        if current_name is not None:
            hashes.extend(item.casefold() for item in _LOCK_HASH.findall(line))
    finish()
    return result


def _markdown(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> list[str]:
    lines = [
        "| " + " | ".join(_markdown(item) for item in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(_markdown(item) for item in row) + " |" for row in rows)
    return lines


def _microsoft_version(
    native_payloads: list[tuple[str, bytes]],
) -> tuple[str, dict[str, str]]:
    versions: dict[str, str] = {}
    for path, payload in native_payloads:
        if _is_microsoft_runtime(path):
            versions[path] = _pe_file_version(payload) or "UNRESOLVED (no readable PE version)"
    if not versions:
        return "UNRESOLVED - no Microsoft runtime path detected", versions
    summary = "; ".join(f"{path} {versions[path]}" for path in sorted(versions, key=str.casefold))
    return summary, versions


def render_inventory(
    executable: Path, archive: _CArchive, *, include_outer_identity: bool = True
) -> str:
    """Render the deterministic inventory for an already-open CArchive."""
    executable = executable.resolve()
    if not executable.is_file():
        raise InventoryError(f"executable does not exist: {executable}")

    normalized: dict[str, str] = {}
    folded: dict[str, str] = {}
    for archive_name in archive.toc:
        path = _normalize_archive_path(str(archive_name))
        collision = folded.get(path.casefold())
        if collision is not None:
            raise InventoryError(f"case-insensitive CArchive collision: {collision!r} and {path!r}")
        normalized[str(archive_name)] = path
        folded[path.casefold()] = str(archive_name)

    pyz_names = [name for name, entry in archive.toc.items() if _entry_type(entry) == "z"]
    if len(pyz_names) != 1:
        raise InventoryError(f"expected exactly one embedded PYZ archive, found {len(pyz_names)}")
    try:
        pyz = archive.open_embedded_archive(pyz_names[0])
    except Exception as exc:
        raise InventoryError(f"cannot inspect embedded PYZ archive: {exc}") from exc
    module_names = sorted((str(name) for name in pyz.toc), key=lambda item: (item.casefold(), item))
    module_roots = Counter(name.split(".", 1)[0].split("/", 1)[0] for name in module_names)

    payload_cache: dict[str, bytes] = {}

    def payload(archive_name: str) -> bytes:
        if archive_name not in payload_cache:
            extracted = archive.extract(archive_name)
            if not isinstance(extracted, bytes):
                raise InventoryError(
                    f"CArchive extraction did not return bytes: {normalized[archive_name]}"
                )
            payload_cache[archive_name] = extracted
        return payload_cache[archive_name]

    native_names = [
        name for name, path in normalized.items() if path.casefold().endswith(_NATIVE_SUFFIXES)
    ]
    native_names.sort(key=lambda name: (normalized[name].casefold(), normalized[name]))
    native_payloads = [(normalized[name], payload(name)) for name in native_names]
    microsoft_version, microsoft_versions = _microsoft_version(native_payloads)

    all_native_records = [
        FileRecord(path, len(data), _sha256_bytes(data), _native_component(path))
        for path, data in native_payloads
    ]
    pyside_paths = {path for path in normalized.values() if _is_pyside_qt_path(path)}
    # Plugins and translations can include non-native resources (for example .qm
    # catalogs or metadata), so hash those in addition to the native partition.
    pyside_names = [name for name, path in normalized.items() if path in pyside_paths]
    pyside_names.sort(key=lambda name: (normalized[name].casefold(), normalized[name]))
    pyside_records = [
        FileRecord(
            normalized[name],
            len(payload(name)),
            _sha256_bytes(payload(name)),
            _native_component(normalized[name]),
        )
        for name in pyside_names
    ]
    other_native_records = [
        record for record in all_native_records if record.path not in pyside_paths
    ]

    compliance_rows: list[tuple[object, ...]] = []
    compliance_payloads: dict[str, bytes] = {}
    for expected in COMPLIANCE_PATHS:
        archive_name = folded.get(expected.casefold())
        if archive_name is None:
            compliance_rows.append((expected, "NO", "MISSING", "MISSING"))
            continue
        data = payload(archive_name)
        compliance_payloads[expected] = data
        if not include_outer_identity:
            dependency = (
                "SELF-REFERENTIAL"
                if expected in EMBEDDED_DYNAMIC_COMPLIANCE_PATHS
                else "FINAL-BUILD-DEPENDENT"
            )
            compliance_rows.append((expected, "YES", dependency, "SEE POST-BUILD SIDECAR"))
        else:
            compliance_rows.append((expected, "YES", len(data), _sha256_bytes(data)))

    lock_records = _parse_requirements_lock(compliance_payloads.get("requirements.lock"))

    carchive_code_paths = [path for path in normalized.values() if not _is_documentation_path(path)]
    pyqt_carchive = [path for path in carchive_code_paths if _PYQT_TOKEN.search(path)]
    pyqt_pyz = [name for name in module_names if _PYQT_TOKEN.search(name)]
    provider_carchive = [path for path in carchive_code_paths if _PROVIDER_TOKEN.search(path)]
    provider_pyz = [name for name in module_names if _PROVIDER_TOKEN.search(name)]
    raw_javascript = [
        path for path in normalized.values() if path.casefold().endswith(_RAW_JAVASCRIPT_SUFFIXES)
    ]
    canvas_carchive = [
        path
        for path in carchive_code_paths
        if "node_modules/canvas/" in path.casefold()
        or PurePosixPath(path.casefold()).name == "canvas.node"
    ]
    canvas_pyz = [
        name
        for name in module_names
        if name.casefold() == "canvas" or name.casefold().startswith("canvas.")
    ]

    libffi_records = [
        record
        for record in all_native_records
        if PurePosixPath(record.path.casefold()).name.startswith("libffi")
        and PurePosixPath(record.path.casefold()).suffix == ".dll"
    ]
    root_libffi = [
        record for record in libffi_records if record.path.casefold() == ROOT_LIBFFI_PATH
    ]
    root_libffi_hash = root_libffi[0].sha256 if len(root_libffi) == 1 else "UNRESOLVED"
    root_libffi_match = (
        "YES" if len(root_libffi) == 1 and root_libffi_hash == EXPECTED_LIBFFI_SHA256 else "NO"
    )

    type_counts = Counter(_entry_type(entry) for entry in archive.toc.values())
    components = _components(
        microsoft_version,
        set(module_roots),
        set(normalized.values()),
    )

    compliance_folded = {path.casefold() for path in COMPLIANCE_PATHS}
    fingerprint = hashlib.sha256()
    for archive_name, path in sorted(
        normalized.items(), key=lambda item: (item[1].casefold(), item[1])
    ):
        if (
            _entry_type(archive.toc[archive_name]) == "z"
            or path.casefold() in compliance_folded
            or _is_documentation_path(path)
        ):
            continue
        data = payload(archive_name)
        identity_kind, identity_size, identity_digest = _fingerprint_payload_identity(
            path, data
        )
        fingerprint.update(path.encode("utf-8"))
        fingerprint.update(b"\0")
        fingerprint.update(_entry_type(archive.toc[archive_name]).encode("ascii", "replace"))
        fingerprint.update(b"\0")
        fingerprint.update(identity_kind)
        fingerprint.update(b"\0")
        fingerprint.update(str(identity_size).encode("ascii"))
        fingerprint.update(b"\0")
        fingerprint.update(identity_digest)
    for module_name in module_names:
        try:
            raw_module = pyz.extract(module_name, raw=True)
        except Exception as exc:
            raise InventoryError(
                f"cannot extract embedded PYZ module {module_name!r}: {exc}"
            ) from exc
        if raw_module is None:
            raw_module = b""
        if not isinstance(raw_module, bytes):
            raise InventoryError(
                f"embedded PYZ extraction did not return bytes: {module_name}"
            )
        entry = pyz.toc[module_name]
        entry_type = entry[0] if isinstance(entry, (tuple, list)) and entry else "UNKNOWN"
        fingerprint.update(b"PYZ\0")
        fingerprint.update(module_name.encode("utf-8"))
        fingerprint.update(b"\0")
        fingerprint.update(str(entry_type).encode("ascii", "replace"))
        fingerprint.update(b"\0")
        fingerprint.update(str(len(raw_module)).encode("ascii"))
        fingerprint.update(b"\0")
        fingerprint.update(hashlib.sha256(raw_module).digest())
    payload_fingerprint = fingerprint.hexdigest()

    if include_outer_identity:
        outer_size = str(executable.stat().st_size)
        outer_hash = _sha256_file(executable)
    else:
        outer_size = "OMITTED FROM EMBEDDED REPORT (see post-build sidecar/final audit)"
        outer_hash = "OMITTED FROM EMBEDDED REPORT (self-reference avoidance)"

    lines: list[str] = [
        f"{APP_NAME.upper()} - DETERMINISTIC DISTRIBUTION INVENTORY",
        "=" * 62,
        "",
        "Status: HOLD - NOT APPROVED FOR PUBLIC DISTRIBUTION",
        "Public-distribution verdict: HOLD",
        "Release-gate-status: HOLD",
        "Qualified-review-status: HOLD",
        "Audit-blocker-count: 6",
        f"Report schema: {REPORT_SCHEMA}",
        "",
        "This is an artifact-derived engineering record, not legal advice or a claim of",
        "license compliance. UNRESOLVED means qualified legal or provenance review is still",
        "required. The report records uncompressed CArchive payload bytes; the outer-artifact",
        "hash covers the bootloader, compressed archive, and all other executable bytes.",
        "",
        "Artifact identity",
        "-----------------",
        "",
        f"Artifact file: {executable.name}",
        f"Artifact size: {outer_size}",
        f"Artifact SHA-256: {outer_hash}",
        f"Audited non-compliance payload fingerprint SHA-256: {payload_fingerprint}",
        f"CArchive entries: {len(archive.toc)}",
        f"Embedded PYZ entries: {len(module_names)}",
        "",
        "Component, license, source, and distribution-action inventory",
        "-------------------------------------------------------------",
        "",
    ]
    lines.extend(
        _table(
            (
                "Component",
                "Version",
                "License",
                "Copyright holder",
                "Distribution location/evidence",
                "Upstream/source/hash provenance",
                "Modifications",
                "Required notice/source/relink action",
                "Boundary",
            ),
            [
                (
                    item.name,
                    item.version,
                    item.license,
                    item.copyright_holder,
                    item.location,
                    item.upstream,
                    item.modifications,
                    item.action,
                    item.boundary,
                )
                for item in components
            ],
        )
    )

    lines.extend(
        [
            "",
            "Locked Python source-artifact hashes",
            "------------------------------------",
            "",
            "These are every SHA-256 selector recorded by the embedded requirements.lock for",
            "the Python components named above. A lock hash is acquisition evidence, not proof",
            "that the corresponding wheel's every file is present in the frozen PYZ.",
            "",
        ]
    )
    lock_rows: list[tuple[object, ...]] = []
    for item in components:
        if item.lock_name is None:
            continue
        normalized_name = re.sub(r"[-_.]+", "-", item.lock_name).casefold()
        locked = lock_records.get(normalized_name)
        if locked is None:
            lock_rows.append((item.lock_name, "UNRESOLVED", "MISSING FROM EMBEDDED LOCK"))
        elif not locked.hashes:
            lock_rows.append((locked.name, locked.version, "UNRESOLVED - NO HASH"))
        else:
            lock_rows.extend((locked.name, locked.version, value) for value in locked.hashes)
    lines.extend(_table(("Package", "Version", "SHA-256"), lock_rows))

    lines.extend(
        [
            "",
            "Distribution-boundary zero counts and libffi singleton",
            "--------------------------------------------------------",
            "",
        ]
    )
    boundary_rows = [
        (
            "PyQt code/binary/module",
            len(pyqt_carchive),
            len(pyqt_pyz),
            len(pyqt_carchive) + len(pyqt_pyz),
        ),
        (
            "bgutil/getpot/yt_dlp_plugins provider code/module",
            len(provider_carchive),
            len(provider_pyz),
            len(provider_carchive) + len(provider_pyz),
        ),
        ("Raw JavaScript/TypeScript payload", len(raw_javascript), 0, len(raw_javascript)),
        (
            "canvas native/module payload",
            len(canvas_carchive),
            len(canvas_pyz),
            len(canvas_carchive) + len(canvas_pyz),
        ),
    ]
    lines.extend(_table(("Forbidden class", "CArchive", "PYZ", "Total"), boundary_rows))
    lines.extend(
        [
            "",
            f"libffi DLL count: {len(libffi_records)}",
            f"Root {ROOT_LIBFFI_PATH} count: {len(root_libffi)}",
            f"Root {ROOT_LIBFFI_PATH} SHA-256: {root_libffi_hash}",
            f"Expected CPython libffi 3.4.2 SHA-256: {EXPECTED_LIBFFI_SHA256}",
            f"Root hash matches expected CPython runtime: {root_libffi_match}",
            "",
        ]
    )
    lines.extend(
        _table(
            ("libffi archive path", "Size", "SHA-256", "Component"),
            [(r.path, r.size, r.sha256, r.component) for r in libffi_records]
            or [("NONE", 0, "MISSING", "UNRESOLVED")],
        )
    )

    lines.extend(
        ["", "Required packaged compliance paths", "----------------------------------", ""]
    )
    if not include_outer_identity:
        lines.extend(
            [
                "Embedded compliance rows are intentionally marked FINAL-BUILD-DEPENDENT;",
                "the report and SOURCE-HASHES rows are additionally SELF-REFERENTIAL because",
                "embedding the report changes both files. The final post-build sidecar records",
                "all exact compliance sizes and SHA-256 values.",
                "",
            ]
        )
    lines.extend(_table(("Path", "Present", "Size", "SHA-256"), compliance_rows))

    lines.extend(["", "CArchive entry-type counts", "--------------------------", ""])
    lines.extend(
        _table(
            ("PyInstaller type code", "Count"),
            [(code or "<empty>", count) for code, count in sorted(type_counts.items())],
        )
    )

    lines.extend(
        ["", "Embedded PYZ top-level module roots", "-----------------------------------", ""]
    )
    lines.extend(
        _table(
            ("Top-level root", "PYZ entry count"),
            [(root, module_roots[root]) for root in sorted(module_roots, key=str.casefold)],
        )
    )

    lines.extend(
        [
            "",
            "Exact PySide/Qt DLL, PYD, plugin, and translation paths",
            "------------------------------------------------------",
            "",
            f"Path count: {len(pyside_records)}",
            "",
        ]
    )
    pyside_rows: list[tuple[object, ...]] = []
    for record in pyside_records:
        version = microsoft_versions.get(record.path, "n/a")
        pyside_rows.append((record.path, record.size, record.sha256, record.component, version))
    lines.extend(
        _table(
            ("Archive path", "Size", "SHA-256", "Component", "PE file version"),
            pyside_rows or [("NONE", 0, "MISSING", "UNRESOLVED", "n/a")],
        )
    )

    lines.extend(
        [
            "",
            "Exact remaining native DLL, PYD, and EXE paths",
            "------------------------------------------------",
            "",
            f"Path count: {len(other_native_records)}",
            "",
        ]
    )
    other_rows = [
        (
            record.path,
            record.size,
            record.sha256,
            record.component,
            microsoft_versions.get(record.path, "n/a"),
        )
        for record in other_native_records
    ]
    lines.extend(
        _table(
            ("Archive path", "Size", "SHA-256", "Component", "PE file version"),
            other_rows or [("NONE", 0, "MISSING", "UNRESOLVED", "n/a")],
        )
    )

    unresolved_native = [
        record for record in all_native_records if record.component.startswith("UNRESOLVED")
    ]
    lines.extend(
        [
            "",
            "Inventory closure notes",
            "-----------------------",
            "",
            f"All native .dll/.pyd/.exe paths: {len(all_native_records)}",
            f"PySide/Qt table native/resource paths: {len(pyside_records)}",
            f"Remaining native paths: {len(other_native_records)}",
            f"Native paths with UNRESOLVED component mapping: {len(unresolved_native)}",
            "The PySide/Qt table and remaining-native table partition every native DLL/PYD/EXE",
            "path; the former can additionally contain non-native plugin/translation resources.",
            "Standard-library module roots are covered by the CPython component row. Every other",
            "PYZ root is disclosed above; a root is not by itself proof of a separately licensed",
            "distribution. Any unmapped or unexpected root/native path remains a HOLD item.",
            "The optional bgutil-ytdlp-pot-provider helper is external and not included. Its own",
            "Python, JavaScript, npm, canvas, and native dependencies are outside this EXE report",
            "and require a separate inventory if that helper is ever conveyed.",
            "Because an embedded report cannot contain a fixed-point hash of the outer EXE that",
            "contains it, this post-build report is the artifact companion of the identified EXE.",
            "If the report is changed and then embedded by rebuilding, regenerate a new companion",
            "for that new artifact and never claim the prior artifact hash applies to the rebuild.",
            "",
            "Open audit blockers (6)",
            "-----------------------",
            "",
            "1. The one-file LGPL replacement/relink procedure is not yet independently tested.",
            "2. Complete FFmpeg Corresponding Source and a distributor-controlled delivery method are absent.",
            "3. The CPython/python-build-standalone transitive source and recipe closure needs final review.",
            "4. Microsoft runtime redistribution coverage for every inventoried DLL is unconfirmed.",
            "5. Qt/PySide notice, attribution, source, and software-render fallback closure needs final review.",
            "6. Qualified legal review has not approved the distribution or external-helper classification.",
            "",
            "Final verdict: HOLD FOR PUBLIC DISTRIBUTION.",
            "This status must not be changed merely because zero-count or hash checks pass. It",
            "requires complete source/notice/relink closure, reproducibility evidence, and",
            "qualified legal review.",
            "",
        ]
    )
    return "\n".join(lines)


def generate(
    executable: Path,
    output: Path,
    *,
    archive_factory: Callable[[str], _CArchive] = CArchiveReader,
    include_outer_identity: bool = True,
) -> str:
    """Generate *output* atomically and return its rendered text."""
    executable = executable.resolve()
    output = output.resolve()
    if executable == output:
        raise InventoryError("input executable and output report must be different files")
    if not executable.is_file():
        raise InventoryError(f"executable does not exist: {executable}")
    try:
        archive = archive_factory(str(executable))
    except Exception as exc:
        raise InventoryError(f"cannot read PyInstaller CArchive: {exc}") from exc
    rendered = render_inventory(
        executable, archive, include_outer_identity=include_outer_identity
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            stream.write(rendered)
            temporary_name = stream.name
        os.replace(temporary_name, output)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path, help="PyInstaller one-file Windows executable")
    parser.add_argument(
        "output", type=Path, help="inventory output (normally THIRD_PARTY_LICENSES.txt)"
    )
    parser.add_argument(
        "--embeddable",
        action="store_true",
        help="omit the self-referential outer EXE size/hash while retaining the payload fingerprint",
    )
    args = parser.parse_args()
    try:
        rendered = generate(
            args.executable,
            args.output,
            include_outer_identity=not args.embeddable,
        )
    except InventoryError as exc:
        parser.exit(1, f"HOLD: {exc}\n")
    print(
        f"Wrote HOLD inventory to {args.output.resolve()} ({len(rendered.encode('utf-8'))} bytes)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
