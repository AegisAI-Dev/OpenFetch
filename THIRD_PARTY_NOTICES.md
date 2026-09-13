# Neural Extractor V3.0.8 third-party notices

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Public-distribution verdict: HOLD
Release-gate-status: HOLD
Qualified-review-status: HOLD
Audit-blocker-count: 6

Audit date: 2026-07-22  
Target: Windows x64, PyInstaller one-file  
Application version: 3.0.8

This is an engineering distribution record, not legal advice or a declaration
of compliance. Public distribution remains blocked. A qualified reviewer must
approve the legal conclusions and the completed source, notice, replacement,
and redistribution package before these status fields may be changed to PASS.

## Artifact basis

The first provider-free/PySide6 filtered candidate retained as historical audit
evidence is:

- `dist/pyside-provider-free-audit-20260722-2/NeuralExtractorV3.exe`
- size: 189,351,131 bytes
- SHA-256: `528a7c693825ef8efd1adfe4f7b65afb4a1642ece39fd530c8c69abf436bafee`
- CArchive entries: 308
- embedded PYZ entries: 1,535

That candidate is superseded audit evidence, not an approved release. The
current embedded fingerprint is stated only in `THIRD_PARTY_LICENSES.txt`; the
final clean candidate must reproduce it and have a post-build companion that
states the final outer EXE size and SHA-256. The embedded inventory
intentionally omits its enclosing EXE hash to avoid a fixed-point/self-reference
claim.

`THIRD_PARTY_LICENSES.txt` is the authoritative artifact-derived register. It
lists every observed component, version, license expression, copyright-holder
record, source location and hash status, modification status, required action,
boundary, CArchive path, native path, and PYZ root. `SOURCE-HASHES.sha256`,
`requirements.lock`, `uv.lock`, and
`licenses/RELEASE-LICENSE-MANIFEST.sha256` bind the local source, Python input,
and notice sets.

## OpenFetch license and ownership

The project maintainer explicitly confirmed the public attribution, copyright
period, and MIT licensing intent for project-owned portions. The root
`LICENSE` contains the standard MIT notice:

`Copyright (c) 2025-2026 0xRootNull`

`PROJECT-METADATA.json` and
`docs/PROJECT-OWNERSHIP-DECLARATION.md` record the resolved project-owned
findings. The public identity is the pseudonym `0xRootNull`; the identity
behind it is intentionally not published. The MIT grant applies only to
OpenFetch-owned material and does not relicense third-party material.
Qualified legal review remains unresolved.

## Main-EXE boundary findings

The filtered candidate contains direct PySide6 imports and no compatibility
shim. Its archive and embedded PYZ have verified zero counts for:

- PyQt5/PyQt6 modules, binaries, hooks, and distributions;
- `bgutil-ytdlp-pot-provider`, `getpot_bgutil`, and `yt_dlp_plugins` provider
  source or bytecode;
- provider JavaScript, TypeScript, source maps, npm trees, and canvas native
  payloads.

The built-in yt-dlp namespace `yt_dlp.plugins` is not the forbidden external
namespace `yt_dlp_plugins`. The main worker clears external plugin registries,
sets `YTDLP_NO_PLUGINS=1`, and uses only first-party adapter code to communicate
with a separately installed helper process.

The main EXE contains no npm package tree. It does contain the official Node.js
22.17.0 executable, whose complete license and bundled third-party notices are
preserved separately. npm-specific redistribution review applies only to the
separate optional helper if that package is conveyed.

## PySide6 and Qt payload

The candidate uses PySide6, PySide6-Essentials, and Shiboken6 6.11.1 with Qt
6.11.1. PySide6-Addons 6.11.1 is a locked build input, but no Addons Qt module
is included. Exactly these 22 PySide/Qt/Shiboken native or plugin paths are
present:

1. `PySide6/MSVCP140.dll`
2. `PySide6/MSVCP140_1.dll`
3. `PySide6/MSVCP140_2.dll`
4. `PySide6/opengl32sw.dll`
5. `PySide6/plugins/imageformats/qico.dll`
6. `PySide6/plugins/platforms/qoffscreen.dll`
7. `PySide6/plugins/platforms/qwindows.dll`
8. `PySide6/plugins/styles/qmodernwindowsstyle.dll`
9. `PySide6/pyside6.abi3.dll`
10. `PySide6/Qt6Core.dll`
11. `PySide6/Qt6Gui.dll`
12. `PySide6/Qt6Widgets.dll`
13. `PySide6/QtCore.pyd`
14. `PySide6/QtGui.pyd`
15. `PySide6/QtWidgets.pyd`
16. `PySide6/VCRUNTIME140.dll`
17. `PySide6/VCRUNTIME140_1.dll`
18. `shiboken6/MSVCP140.dll`
19. `shiboken6/Shiboken.pyd`
20. `shiboken6/shiboken6.abi3.dll`
21. `shiboken6/VCRUNTIME140.dll`
22. `shiboken6/VCRUNTIME140_1.dll`

No Qt translation catalogs, QtNetwork, QtPdf, QML, Quick, SVG, WebEngine,
VirtualKeyboard, TLS, multimedia, or other Addons module is included. Exact
sizes and SHA-256 values are in `THIRD_PARTY_LICENSES.txt`.

PySide6 and the selected Qt libraries offer LGPLv3/GPL alternatives; this
project records the intended LGPLv3 route without asserting that merely using
PySide6 satisfies it. Preserve all Qt/PySide/Shiboken copyright and license
texts, provide the exact applicable source and build information, do not
restrict reverse engineering for debugging modifications, and provide a
practical, independently tested replacement/relink route. That last route has
not been demonstrated for this one-file layout, so the LGPL distribution item
remains HOLD.

## Component/action summary

The full table is in `THIRD_PARTY_LICENSES.txt`. The following rows identify
the principal distribution actions and do not replace the full register or the
unmodified license texts under `licenses/`.

| Component | Version | Recorded license route | Required distribution action |
|---|---:|---|---|
| OpenFetch | 3.0.8 | MIT for project-owned portions; `Copyright (c) 2025-2026 0xRootNull` | Ship `LICENSE`, `PROJECT-METADATA.json`, the ownership declaration, application source, build scripts, locks, and manifests. |
| CPython / python-build-standalone | 3.12.9 / 20250317 | Python-2.0 plus historical terms; recipes MPL-2.0 | Ship all selected notices; retain exact CPython and recipe source, patches, toolchain, and transitive source closure. |
| libffi | 3.4.2 | MIT | Preserve notice/source/provenance and exactly one validated root `libffi-8.dll`. |
| OpenSSL | 3.0.16 | Apache-2.0 | Preserve license/acknowledgements and retain exact source hash and standalone-build recipe. |
| SQLite | 3.47.1 | public-domain dedication | Preserve dedication and exact source/build provenance. |
| bzip2 | 1.0.8 | bzip2 permissive | Preserve copyright/conditions/disclaimer and exact source/build inputs. |
| XZ/liblzma | 5.2.12 | source-exact public-domain notices | Retain exact selected source and notices. |
| zlib | 1.3.1 | Zlib | Preserve notice and exact source/build inputs. |
| Expat | 2.6.4 | MIT | Preserve notice and exact source/build inputs. |
| mpdecimal | 2.5.1 | BSD-2-Clause | Preserve notice; covered source is in the pinned CPython tree. |
| HACL* snapshot | CPython snapshot | MIT | Preserve headers, exact vendor source, and transformation record. |
| Unicode data | 15.0.0 | Unicode terms | Preserve permission notice and exact generator inputs. |
| BLAKE2-derived code | CPython snapshot | CC0/public-domain dedication | Preserve dedication and exact source/transformation record. |
| PyInstaller | 6.21.0 | GPL-2.0-or-later with bootloader exception; selected Apache-2.0 files | Retain the exact exception/notices and build source/scripts. |
| setuptools and selected vendors | 83.0.0 | MIT, BSD, Apache/BSD, MPL-2.0 portions | Preserve all selected vendor/generated notices and make MPL-covered source/generator inputs available. |
| packaging / typing_extensions | 26.2 / 4.16.0 | Apache-2.0 OR BSD-2-Clause / PSF-2.0 | Preserve all selected terms and exact source/wheel provenance. |
| PySide6 / Qt / Shiboken6 | 6.11.1 | intended LGPLv3 route plus third-party terms | Ship complete notices and exact source; preserve recipient rights and prove replacement/relink mechanics. |
| yt-dlp | 2026.7.4 | Unlicense | Preserve the dedication and exact source provenance. |
| Pillow | 12.3.0 | MIT-CMU; locked input, package code absent | Preserve license/copyright and exact wheel/source provenance for the retained notice evidence. |
| Requests | 2.34.2 | Apache-2.0 | Preserve license, retained notice material, and source provenance. |
| certifi | 2026.7.22 | MPL-2.0 | Preserve MPL notice and make exact Source Code Form available. |
| charset-normalizer / idna / urllib3 | 3.4.9 / 3.18 / 2.7.0 | MIT / BSD-3-Clause / MIT | Preserve exact notices and source/wheel provenance. |
| defusedxml | 0.7.1 | PSF-2.0; locked input, package code absent | Preserve notice and exact source provenance for the retained notice evidence. |
| youtube-transcript-api | 1.2.4 | MIT; locked input, package code absent | Preserve notice and exact source provenance for the retained notice evidence. |
| Node.js | 22.17.0 | MIT plus bundled third-party terms | Ship the complete Node license/notices and retain exact source/binary provenance. |
| FFmpeg / ffprobe BtbN build | N-125365-g9a01c1cb6a-20260630 | GPL-3.0-or-later distribution route | Ship GPLv3/notices and complete Corresponding Source, patches, configuration, linked-library source, and build/install scripts through a valid delivery method. |
| Microsoft VC/UCRT files | inventoried per file | Microsoft redistributable terms | Confirm redistribution entitlement for every exact DLL and preserve applicable Microsoft terms. |

The generated inventory additionally enumerates the exact versions and license
actions for the setuptools-vendored `backports.tarfile`, `jaraco.context`,
`jaraco.functools`, `jaraco.text`, `more-itertools`, `packaging`, `tomli`, and
`wheel`, plus validate-pyproject- and fastjsonschema-derived code. Their
individual copyright notices have not been removed.

## GPLv3 compatibility assessment

No known license expression in the filtered main payload has been identified
by this engineering audit as necessarily incompatible with a GPLv3-compatible
distribution route. That is not a PASS finding. The legal characterization of
the PyInstaller one-file package, the relationship between the MIT application
and the separately executed GPL FFmpeg tools, the selected Qt/PySide route,
and the adequacy of the source/relink delivery all require qualified review.

The current distribution is therefore **not proven GPLv3-compatible for public
conveyance** and remains HOLD. In particular, the FFmpeg Corresponding Source
set and delivery method are incomplete, and an upstream hyperlink alone is not
treated as source delivery by this audit.

## Optional external PO helper

The GPL-3.0-only `bgutil-ytdlp-pot-provider` 1.3.1 integration is no longer
linked, imported, frozen, or copied into the main EXE. It is a separately
installed, separately versioned Node process outside the application root. The
main process exchanges only bounded versioned JSON over standard input/output;
no Python objects, provider imports, shared memory, command-line secrets, or
provider files cross the boundary.

This is materially stronger technical process separation and removes the
provider's Python/JavaScript/npm/canvas/Rust closure from the main distribution.
It does not establish as a matter of law that the programs are separate works.
That classification remains unconfirmed pending qualified review.

The current external helper closure has 184 npm package records. All records
have version, declared license, registry tarball/integrity, and notice paths;
the packages report permissive expressions, with additional retained texts for
`@bufbuild/protobuf`, Google varint-derived code, `saxes`, README-carried MIT
grants, and `canvas/src/bmp/LICENSE.md`. Those npm records and 44 canvas/MSYS2
native DLLs are **not in the main EXE**. If the helper is separately conveyed,
its own GPLv3 source/notices and its complete native canvas, librsvg/Rust,
MSYS2, source, build, and relink closure must accompany it. That helper's public
distribution is independently HOLD.

The application neither silently downloads nor silently installs the helper.
Absence is a normal UI/runtime state and normal downloads remain available.

## Required accompanying material

Before any Windows binary is public, the distribution set must include or make
available through a qualified-review-approved method, as applicable:

- root `LICENSE`, this notice, `THIRD_PARTY_LICENSES.txt`, and all unmodified
  applicable texts under `licenses/`;
- `docs/DEPENDENCY-SOURCE.md`, `docs/BUILD-REPRODUCIBILITY.md`, and
  `docs/LGPL-COMPLIANCE.md`;
- complete OpenFetch source corresponding to the binary, the PyInstaller
  spec, build/release scripts, dependency locks, exact source/binary hashes, and
  local modifications;
- complete applicable Qt/PySide/Shiboken source, notices, attribution material,
  and a tested replacement/relink procedure;
- complete FFmpeg/BtbN and linked-library Corresponding Source, configuration,
  patches, toolchain/build/install scripts, and a valid delivery method;
- CPython/python-build-standalone source, recipe/patch/toolchain closure and all
  embedded-component source/notices;
- Node.js source and complete bundled notices;
- exact Python source artifacts and notices for every frozen distribution and
  selected vendored/generated component; and
- applicable Microsoft runtime terms after redistribution entitlement has been
  confirmed.

No complete corresponding-source companion is currently present. No written
source offer has been approved or issued. Do not describe the current upstream
links as a written offer. If an offer route is later chosen where the relevant
license permits it, qualified counsel must approve its scope, duration, cost,
recipient rights, and delivery mechanics before it accompanies any binary.

## Open blockers

1. The one-file LGPL replacement/relink procedure is not independently tested.
2. Complete FFmpeg Corresponding Source and a distributor-controlled delivery
   method are absent.
3. The CPython/python-build-standalone transitive source and recipe closure
   needs final review and missing exact source hashes.
4. Microsoft runtime redistribution coverage for every inventoried DLL is
   unconfirmed.
5. Qt/PySide notice, attribution, source, and software-render fallback closure
   needs final review.
6. Qualified legal review has not approved the distribution or external-helper
   classification.

## Existing 3.0.8 release artifact

The legacy file `dist/NeuralExtractorV3-3.0.8-windows-x64.exe` (234,709,652
bytes; SHA-256
`0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac`)
contains PyQt6, in-process GPL provider Python, provider JavaScript/npm/canvas
payloads, and the wrong root libffi selection. Do not publish or relabel it.
If it has been exposed anywhere, the engineering recommendation is to withdraw
it pending qualified review and replace it only with a newly audited build.
