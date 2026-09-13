# PySide6 and Qt LGPL compliance plan

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: HOLD

Qualified-review-status: HOLD

Distribution-format-status: ONE-FOLDER TECHNICAL CANDIDATE

This is an engineering compliance plan, not legal advice. It does not select a
license on behalf of a rightsholder or establish that every requirement of an
applicable license has been met.

Neural Extractor V3.0.8 uses PySide6, PySide6-Essentials, Shiboken6, and Qt
6.11.1. The intended open-source route is reviewed against the license choices
and notices shipped by those upstream packages. Qt also contains third-party
code under its authors' own terms. The exact component-by-component selection
still requires qualified legal review.

## Selected distribution architecture

The primary compliance candidate is a PyInstaller 6.21.0 **one-folder**
distribution named `NeuralExtractorV3-3.0.8-windows-x64`. The executable and
shared libraries are separate files:

```text
NeuralExtractorV3-3.0.8-windows-x64/
  NeuralExtractorV3.exe
  PySide6/
    Qt6Core.dll
    Qt6Gui.dll
    Qt6Widgets.dll
    QtCore.pyd
    QtGui.pyd
    QtWidgets.pyd
    plugins/...
  shiboken6/...
  licenses/...
  docs/...
  QT-PYSIDE-COMPONENTS.json
```

`NeuralExtractorV3.spec` uses `exclude_binaries=True`, `COLLECT`, `upx=False`,
and `contents_directory="."`. Qt and PySide binaries are not stored inside the
EXE. A recipient can copy a compatible replacement into the documented path
without unpacking, patching, resigning, or recompressing the application EXE.
Application startup does not hash, restore, delete, or reject those external
files.

The historical one-file V3.0.8 artifacts are not public candidates. Rebuilding
a one-file EXE is not treated as the primary replacement mechanism, and the
one-file LGPL route remains **HOLD**.

## Exact retained family

The candidate retains exactly these 22 PySide6, Qt, Shiboken, and colocated
Microsoft-runtime paths:

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

This family list is not a statement that Microsoft runtime files are covered
by the LGPL. Their redistribution evidence is a separate release blocker.
`opengl32sw.dll` also needs its exact software-rendering source and notice
closure.

The application imports QtCore, QtGui, and QtWidgets. It retains `qwindows.dll`
for Windows execution, `qoffscreen.dll` for deterministic GUI testing,
`qico.dll` for ICO loading, and `qmodernwindowsstyle.dll` for the selected
Windows style. It excludes QtNetwork, QtPdf, QtSvg, QtQml, QtQuick, WebEngine,
multimedia, VirtualKeyboard, translations, and unused plugins. Their appearance
is a release blocker.

## Source and notice set

The locally retained official source baselines are:

- `third_party_sources/qt-pyside/pyside-setup-everywhere-src-6.11.1.tar.xz`,
  SHA-256
  `6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2`;
- `third_party_sources/qt-pyside/qtbase-everywhere-src-6.11.1.tar.xz`, SHA-256
  `d9594a31228aa23ad6b531719a29b45f0f3989fe6c136d45767ea179f233c1ac`.

The structured, byte-preserving notice copies are under
`licenses/pyside/6.11.1` and `licenses/qt/6.11.1`. The older flat locations are
retained as audit evidence; nothing was removed or rewritten. Exact archive and
wheel provenance is in `docs/QT-BUILD-PROVENANCE.md`.

These two source archives do not yet prove complete Corresponding Source for
every byte. The exact Qt wheel configure command, upstream binary patches,
MSVC/SDK toolchain, generated inputs, and complete `opengl32sw.dll` closure are
not independently recovered. There is also no reviewed distributor-controlled
source-delivery offer. This keeps the gate at HOLD.

## Replacement and relink test

`scripts/qt_onefolder_compliance.py replacement-smoke` performs the following
local test:

1. verifies the 22-path baseline manifest;
2. backs up every retained Qt/PySide/Shiboken-family path;
3. verifies every selected source-wheel file against its wheel `RECORD`, then
   installs the pinned Windows x64 PySide6-Essentials/Shiboken6 6.11.1 files as
   one coherent compatible set;
4. appends benign PE overlay markers to the replacement `qoffscreen.dll` and
   `qwindows.dll`, so both exercised plugins have deliberately different
   SHA-256 values without changing their ABI;
5. starts the packaged GUI through both modified platform plugins and checks
   widgets, dialogs, PNG/ICO loading, platform selection, Python extension
   paths, and actual Windows loaded-module paths;
6. confirms startup neither rejects nor rewrites any of the 22 replacement
   files;
7. restores all original files atomically and verifies every original hash; and
8. starts the GUI again after rollback.

This is an **external-library integrity-policy and rollback smoke**, not an LGPL
replacement/relink proof. The overlay does not represent a source-code change
or independent rebuild. A source-built modified implementation remains required
before any LGPL PASS decision. Exact recipient steps are in
`docs/QT-REPLACEMENT-GUIDE.md`.

Local result on 2026-07-22 for audit candidate
`pyside-onefolder-compliance-candidate-20260722-1`: **external integrity-policy
smoke PASS**. The modified `qoffscreen.dll` had SHA-256
`4f8077fd59f10e2d5fc9cacd24e3c66cb1cbef5a78b611e3bcda51d058b81726`;
the external plugin path was confirmed, all widget/asset checks passed, no
startup integrity block rewrote it, all 22 originals were restored byte for
byte, and both `offscreen` and `windows` GUI starts passed after rollback. The
machine-readable result is `qt-replacement-smoke.json`, SHA-256
`aa2f807acd068667c77cf86169fe67ea296f9dc0a571e627e27b1efef6123ac5`.
This preliminary PASS is deliberately narrower than replacement/relink proof
and the release gate, which both remain HOLD.

## Updater behavior

The legacy automatic updater transaction replaces one EXE and is not allowed to
run against this one-folder layout. `assess_installation_capability` detects a
one-folder runtime and returns `onefolder_manual_install_required`. This
fail-closed behavior prevents the one-file transaction from leaving a mixed
runtime or silently overwriting recipient-replaced Qt/PySide files.

A directory-wide transaction is now implemented in
`src/openfetch/core/update_directory_installer.py` and locally
tested. It verifies every file of the staged one-folder release against a
strict per-file SHA-256 directory manifest, rejects symlinks/reparse points,
unexpected or missing files, and prohibited legacy artifacts, creates a
byte-verified backup of the whole installation, swaps directories with
recoverable renames, requires process-bound startup confirmation, and rolls
back to the verified backup on failure, interruption, or timeout. Stale-state
recovery and concurrent-update rejection reuse the target-scoped ownership
records of the legacy updater.

Recipient-replaced Qt/PySide libraries are detected against the installed
`QT-PYSIDE-COMPONENTS.json` baseline and are never overwritten silently: the
transaction requires an explicit `QtReplacementPolicy` (`abort` by default,
`preserve` to carry the local library forward, `replace` only as recorded,
explicit consent). A missing baseline treats every replaceable file as
potentially recipient-modified, which keeps overwrite decisions explicit.

The GUI update dialog still directs one-folder recipients to the manual flow:
wiring the directory transaction into the GUI requires a reviewed consent
dialog for the replacement policy and a published one-folder release asset
format, both of which remain owner-scope work. The legacy one-file updater is
retained only as a non-public compatibility mode for existing installations.

## Recipient rights and terms

No project EULA or runtime control may prohibit reverse engineering to the
extent needed to debug recipient modifications to LGPL-covered components. The
engineering candidate introduces no signature or integrity requirement for the
external Qt/PySide files. Qualified review must still confirm that the final
application terms, distribution channel, updater wording, and selected license
route preserve all required rights. The project-owned author/year/MIT record
is resolved separately and does not establish LGPL compliance.

## Remaining HOLD conditions

Do not change this document or any release gate to PASS until all of the
following are complete:

- an independent source-built, ABI-compatible replacement/relink exercise;
- exact upstream build configuration, patches, generated inputs, and toolchain;
- complete Qt/PySide/Shiboken/software-render source and notice closure;
- a valid, operational source-delivery method for every distribution channel;
- Microsoft runtime redistribution evidence;
- qualified legal review of the exact final artifact and distribution method.

Public-distribution verdict: **HOLD**.
