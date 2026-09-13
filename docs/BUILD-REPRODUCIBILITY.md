# Neural Extractor V3.0.8 build reproducibility

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: HOLD

Qualified-review-status: HOLD

This document defines the controlled Windows x64 build for OpenFetch
V3.0.8. It records engineering controls and evidence requirements; it does not
authorize publication and does not provide legal certainty. Public distribution
remains on **HOLD** until every source, notice, replacement/relink, ownership,
and qualified-review blocker is closed.

## Frozen architecture

The target artifact is a PyInstaller 6.21.0 **one-file** Windows executable
built from `NeuralExtractorV3.spec` with:

- CPython 3.12.9 from python-build-standalone release `20250317`;
- PySide6, PySide6-Essentials, PySide6-Addons, and Shiboken6 6.11.1 as the
  installed wheel family, but only the audited paths below retained in the EXE;
- only the application imports `PySide6.QtCore`, `PySide6.QtGui`, and
  `PySide6.QtWidgets`;
- `upx=False`, so UPX may not rewrite Node, CPython, Qt, Shiboken, or other
  native payload bytes;
- one root `libffi-8.dll` from the pinned CPython runtime; and
- the optional `bgutil-ytdlp-pot-provider` helper entirely outside the project
  tree and outside this EXE.

The EXE must contain no PyQt, provider Python or JavaScript, npm tree,
`canvas.node`, helper-native closure, Qt translation catalog, or unapproved Qt
module/plugin. A successful executable launch does not waive these boundaries.

## Exact PySide6/Qt/Shiboken payload

The final archive inventory must contain exactly these 22 PySide6, Qt,
Shiboken, and colocated Microsoft-runtime paths:

| # | Required archive path | Purpose |
|---:|---|---|
| 1 | `PySide6/MSVCP140.dll` | PySide C++ runtime |
| 2 | `PySide6/MSVCP140_1.dll` | PySide C++ runtime |
| 3 | `PySide6/MSVCP140_2.dll` | PySide C++ runtime |
| 4 | `PySide6/opengl32sw.dll` | Audited software-render fallback |
| 5 | `PySide6/plugins/imageformats/qico.dll` | Runtime ICO loading |
| 6 | `PySide6/plugins/platforms/qoffscreen.dll` | Deterministic offscreen GUI smoke |
| 7 | `PySide6/plugins/platforms/qwindows.dll` | Production Windows platform |
| 8 | `PySide6/plugins/styles/qmodernwindowsstyle.dll` | Windows widget style |
| 9 | `PySide6/pyside6.abi3.dll` | PySide binding runtime |
| 10 | `PySide6/Qt6Core.dll` | QtCore shared library |
| 11 | `PySide6/Qt6Gui.dll` | QtGui shared library |
| 12 | `PySide6/Qt6Widgets.dll` | QtWidgets shared library |
| 13 | `PySide6/QtCore.pyd` | QtCore Python extension |
| 14 | `PySide6/QtGui.pyd` | QtGui Python extension |
| 15 | `PySide6/QtWidgets.pyd` | QtWidgets Python extension |
| 16 | `PySide6/VCRUNTIME140.dll` | PySide VC runtime |
| 17 | `PySide6/VCRUNTIME140_1.dll` | PySide VC runtime |
| 18 | `shiboken6/MSVCP140.dll` | Shiboken C++ runtime |
| 19 | `shiboken6/Shiboken.pyd` | Shiboken Python extension |
| 20 | `shiboken6/shiboken6.abi3.dll` | Shiboken binding runtime |
| 21 | `shiboken6/VCRUNTIME140.dll` | Shiboken VC runtime |
| 22 | `shiboken6/VCRUNTIME140_1.dll` | Shiboken VC runtime |

`THIRD_PARTY_LICENSES.txt` is authoritative for the size, SHA-256, component
mapping, and PE version of each retained path. Its current table must report
`Path count: 22`. The specification filters the PyInstaller hook output after
`Analysis` and fails if a required path is absent or an unaudited PySide root
DLL/PYD, plugin, or translation survives.

No `PySide6/translations/*` file is permitted. In particular, the artifact may
not contain QtNetwork, QtPdf, QtSvg, QtVirtualKeyboard, QtQml, QtQuick,
QtOpenGL, their Python bindings, their transitive DLLs, or their plugins. PNG
support is supplied by QtGui; `qico.dll` remains for the runtime ICO asset.
`qoffscreen.dll` is retained only for the offscreen smoke, while
`qwindows.dll` is exercised separately as the actual production platform.

## Pinned build inputs

| Input | Required identity | Required verification |
|---|---|---|
| Platform | Windows x64 | Reject another OS or architecture |
| CPython | 3.12.9 x64, python-build-standalone `20250317` | Verify the exact install-only asset hash recorded in `docs/DEPENDENCY-SOURCE.md`; assert version and AMD64 |
| Resolver | uv 0.11.31 | Record `uv --version`; require unchanged `uv.lock` and hash-locked export |
| PyInstaller | 6.21.0 | Install only its locked wheel; require `upx=False` in the spec |
| PySide wheel family | 6.11.1 | Install only locked Windows x64 wheels, then enforce the 22-path archive allowlist |
| `_ctypes.pyd` | CPython 3.12.9 standalone runtime | SHA-256 `6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41` |
| `libffi-8.dll` | libffi 3.4.2 at archive root | SHA-256 `d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e` |
| Node.js | 22.17.0 x64 | `bin/node.exe` SHA-256 `39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636` |
| FFmpeg | BtbN GPL build `N-125365-g9a01c1cb6a-20260630` | `bin/ffmpeg.exe` SHA-256 `6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e` |
| ffprobe | Same FFmpeg build | `bin/ffprobe.exe` SHA-256 `55a3d20229c2373dade4362215c9bd5a04b59d4e734d0bbb882afd9cea4fb046` |

`uv.lock` records the resolved graph and artifact selectors.
`requirements.lock` is the `--require-hashes` installation view. Before a
candidate build, `uv lock --check` must pass and a fresh export must be
byte-identical to the committed lock. A changed lock, wheel, source archive,
binary hash, PyInstaller hook result, or 22-path inventory starts a new review.

## Clean build preconditions

Use the exact pinned CPython asset in a new staging directory. Do not substitute
whatever `python`, `py`, or `uv python install 3.12.9` happens to resolve on the
machine. Install with:

```powershell
& $python -m ensurepip
& $python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
& $python -m pip check
```

Then require all of the following before PyInstaller runs:

```powershell
uv --version
uv lock --check
& $python -c "import platform,sys; assert sys.version_info[:3] == (3,12,9); assert platform.machine().upper() == 'AMD64'"
& $python -m ruff check src tests scripts main.py
& $python -m compileall -q src scripts main.py
$env:PYTHONPATH = "$PWD\src"
& $python -m pytest tests -q
& $python scripts\generate_compliance_manifests.py --check
& $python scripts\verify_distribution_boundary.py .
```

Use new work and dist directories or a clean staging copy. Do not infer a clean
build merely from PyInstaller `--clean` over a previously used environment.
`NeuralExtractorV3.spec` itself must reject changed Node/FFmpeg/ffprobe,
`_ctypes.pyd`, or libffi hashes; a provider vendor tree; missing compliance
material; missing required Qt paths; and surviving unaudited Qt paths.

## Two-phase inventory and fingerprint flow

The inventory embedded in a one-file EXE cannot contain that same EXE's final
outer SHA-256: changing the embedded report changes the outer EXE. The release
process therefore uses two distinct identities and must not conflate them:

- the **audited non-compliance payload fingerprint** covers sorted non-document,
  non-compliance CArchive payload records plus each sorted embedded PYZ module's
  name, entry type, raw byte length, and raw-byte SHA-256, as implemented by the
  inventory generator and verifier. `base_library.zip` is bound to its sorted
  member paths and raw member hashes so irrelevant ZIP entry order cannot hide
  or invent a content difference; and
- the **outer EXE SHA-256** covers the bootloader, compressed archive, embedded
  inventory, and every other final executable byte.

Phase 1 creates the embeddable inventory:

1. Build an isolated candidate with the current compliance documents.
2. Run the boundary scanner and all packaged smokes against that candidate.
3. Generate `THIRD_PARTY_LICENSES.txt` from the candidate with `--embeddable`.
   This intentionally omits outer size/hash but records the payload fingerprint,
   exact native paths, hashes, versions, zero-count boundaries, and HOLD fields.
   Compliance rows are marked `FINAL-BUILD-DEPENDENT`; its own row and the
   `SOURCE-HASHES.sha256` row are additionally `SELF-REFERENTIAL`. Only the
   final post-build sidecar may give their exact sizes and hashes.
4. Regenerate `SOURCE-HASHES.sha256` and
   `licenses/RELEASE-LICENSE-MANIFEST.sha256` after the inventory and documents
   are final for embedding.

```powershell
& $python scripts\generate_distribution_inventory.py `
  dist\phase1\NeuralExtractorV3.exe THIRD_PARTY_LICENSES.txt --embeddable
& $python scripts\generate_compliance_manifests.py
```

Phase 2 creates and verifies the final artifact:

1. Build again from a new PyInstaller work/dist directory.
2. Run `verify_packaged_licensing.py`. It must recalculate the payload
   fingerprint, match it to the embedded inventory, require the exact Qt
   allowlist, verify native/inventory coverage, and recheck the license and
   source manifests.
3. Run every packaged smoke, then generate a separate post-build inventory or
   checksum sidecar **without** `--embeddable` to record the final outer size and
   SHA-256. Do not embed that outer identity and rebuild again.
4. Treat any payload-fingerprint difference between phases as a new candidate;
   regenerate the embeddable inventory and repeat both phases.

Set `PYTHONHASHSEED=0` and `SOURCE_DATE_EPOCH=0` before every release build to
stabilize hash-dependent collection order and the Windows PE build timestamp.
The outer hash still remains the authoritative identity of each exact EXE.

```powershell
& $python scripts\verify_packaged_licensing.py dist\phase2\NeuralExtractorV3.exe
& $python scripts\generate_distribution_inventory.py `
  dist\phase2\NeuralExtractorV3.exe `
  dist\NeuralExtractorV3-3.0.8-windows-x64-inventory.txt
Get-FileHash dist\phase2\NeuralExtractorV3.exe -Algorithm SHA256
```

The external inventory and checksum identify the final EXE. The embedded
inventory identifies the audited payload without claiming an impossible
self-referential outer hash.

## Mandatory packaged smokes

Each smoke must write a result below the isolated temporary directory, exit
successfully, report `passed: true`, and complete within the workflow timeout.
A timeout must terminate the complete process tree.

1. `--internal-runtime-smoke` must:
   - create and invoke a `ctypes.CFUNCTYPE` callback (`35 + 7 == 42`);
   - hash the actually imported `_ctypes.pyd` and require the pinned hash above;
   - require `_ctypes.pyd` to reside at the extracted bundle root;
   - hash the sole root `libffi-8.dll` and require the pinned hash above;
   - use `GetModuleHandleW` and `GetModuleFileNameW` to prove the loaded
     `libffi-8.dll` resolves to that extracted root file; and
   - launch the bundled Node, FFmpeg, and ffprobe paths with `shell=False`.
2. `--internal-gui-startup-smoke` must force the `offscreen` platform, load the
   PNG and ICO assets, exercise responsive layout, and prove
   `app.platformName() == "offscreen"`.
3. `--internal-windows-gui-smoke` must perform the same startup and asset checks
   with `app.platformName() == "windows"`, proving `qwindows.dll` works rather
   than relying only on the test plugin.
4. The provider-boundary and YouTube-connection smokes must remain offline and
   must not install, download, or import the external helper.

Both GUI smokes use isolated QSettings paths, callback exception handling, an
internal watchdog, and forced platform selection. Passing the offscreen smoke
does not substitute for passing the Windows smoke.

## Reproducibility comparison

Build the final phase twice in independent absolute paths with the same pinned
inputs and controlled environment. Compare:

- outer EXE SHA-256 and size;
- audited payload fingerprint;
- complete CArchive path/type/size/hash inventory;
- PYZ module-name inventory and raw-byte-bound fingerprint;
- exact 22-path PySide/Qt/Shiboken table; and
- packaged smoke results.

If outer hashes differ while payload fingerprints match, inspect bootloader and
PE metadata, archive ordering, compression, timestamps, and signing separately.
Do not call the process byte-reproducible until every difference is explained
and bounded. `upx=False` is mandatory in both builds.

## Hold conditions

Public distribution remains on HOLD for any missing source or notice, changed
input hash, unexpected archive path, failed fingerprint comparison, failed
offscreen or Windows GUI smoke, failed `_ctypes`/libffi loaded-path proof,
unexplained build difference, unresolved application ownership/year, or
unproven LGPL replacement/relink route. Qualified legal review remains required;
these engineering controls do not establish legal compliance by themselves.
