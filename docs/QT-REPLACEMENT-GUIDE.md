# Qt/PySide6 compatible replacement and rollback guide

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Release-gate-status: HOLD

This guide documents a practical engineering replacement route for the Windows
x64 one-folder candidate. It is not legal advice and does not certify that a
particular replacement is license- or ABI-compatible.

## Supported candidate

- OpenFetch: 3.0.8
- layout: PyInstaller one-folder with `contents_directory="."`
- architecture: Windows x64
- PySide6/PySide6-Essentials: 6.11.1
- Shiboken6: 6.11.1
- Qt: 6.11.1
- Python ABI used by the candidate: CPython 3.12 x64 with PySide `abi3`

The exact baseline paths and hashes are in the candidate's
`QT-PYSIDE-COMPONENTS.json`. Do not use this guide for a one-file EXE: its
libraries are embedded and are not persistently replaceable beside the EXE.
The external verifier intentionally reports a hash difference while a recipient
replacement is installed; that is an audit signal, not a runtime prohibition.
The application itself does not consult the baseline manifest at startup.

## Compatibility constraints

A replacement test set must meet all of these constraints:

1. Windows x64 release binaries; no ARM64, debug, or Unix binaries.
2. Qt `6.11.1` throughout. Qt does not promise private ABI compatibility across
   arbitrary patch/build combinations, so use one coherent Qt build.
3. PySide6, PySide6-Essentials, and Shiboken6 `6.11.1`, built together against
   the replacement Qt set and a compatible CPython limited ABI.
4. Plugins built against that same Qt set. In particular, do not mix
   `qwindows.dll`, `qoffscreen.dll`, or `qico.dll` from another Qt build unless
   the complete ABI relationship has been validated.
5. Required dependent runtimes must remain resolvable. Microsoft runtime files
   have separate terms and must not be assumed to be LGPL components.
6. Preserve every license and copyright notice supplied with both the original
   and replacement set.

An arbitrary same-named DLL is not an approved replacement.

## Safe recipient replacement

Close every OpenFetch process first. Work on a copy of the entire
distribution directory, not the only installed copy.

1. Verify the original layout:

   ```powershell
   .\.venv\Scripts\python.exe scripts\qt_onefolder_compliance.py verify `
     D:\path\to\NeuralExtractorV3-3.0.8-windows-x64
   ```

2. Copy the whole installation directory to a rollback directory. Preserve
   permissions, timestamps, `QT-PYSIDE-COMPONENTS.json`, licenses, and docs.
3. Copy a coherent replacement set to the same relative paths under `PySide6/`
   and `shiboken6/`. Use a temporary filename in the destination directory and
   `Move-Item`/`os.replace` only after the copy is complete.
4. Do not edit `NeuralExtractorV3.exe`. No signing key is required for external
   library replacement.
5. Start the GUI and exercise the main window, connection dialogs, managed
   browser dialog, format controls, PNG/ICO loading, and both the `windows` and
   `offscreen` platform plugins.
6. Record replacement hashes, loaded plugin paths, commands, output, and the
   exact source/build inputs used.

The project smoke automates the pinned-wheel variant:

```powershell
.\.venv\Scripts\python.exe scripts\qt_onefolder_compliance.py replacement-smoke `
  D:\path\to\NeuralExtractorV3-3.0.8-windows-x64 `
  --output D:\path\to\qt-replacement-smoke.json
```

It deliberately changes the SHA-256 of `qoffscreen.dll` and `qwindows.dll` with
inert PE overlays, starts the GUI through both plugins, verifies actual binding
and loaded-DLL paths, confirms no application integrity mechanism restores any
of the 22 files, and then performs a byte-exact rollback. Its JSON deliberately
records `lgpl_relink_proven: false`. This is an external-library
integrity-policy smoke; it does not prove a source-built modified Qt
implementation or LGPL relink route.
All loaded paths in the saved result are validated against the real
distribution first and then normalized to distribution-relative paths, so the
evidence does not embed the builder's absolute workspace location.

## Rollback

If startup or a widget/plugin check fails:

1. terminate the new process tree;
2. move the failed test directory aside rather than deleting evidence;
3. restore the complete backed-up directory;
4. verify every baseline hash against `QT-PYSIDE-COMPONENTS.json`; and
5. rerun the offscreen and Windows GUI smokes.

Do not roll back only one core DLL after replacing a coherent Qt/PySide build.
That can create an unsupported mixed ABI.

## Rebuild/relink from source

The local source baselines are:

```text
third_party_sources/qt-pyside/
  qtbase-everywhere-src-6.11.1.tar.xz
  pyside-setup-everywhere-src-6.11.1.tar.xz
  SHA256SUMS
```

For an independent source-built exercise:

1. verify both archives with `SHA256SUMS` before extraction;
2. prepare an isolated Windows x64 build environment with a supported MSVC
   toolset, Windows SDK, CMake, Ninja, Perl, and CPython 3.12 x64;
3. build QtBase 6.11.1 as shared release libraries into a separate prefix;
4. make the intended benign source change and record it as a patch;
5. build Shiboken6 and PySide6 6.11.1 from the PySide source archive against
   that exact Qt prefix and Python interpreter;
6. collect QtCore, QtGui, QtWidgets and only the documented plugins into a copy
   of the candidate layout;
7. rebuild OpenFetch with `NeuralExtractorV3.spec`, or replace the
   external compatible files directly;
8. run the replacement smoke, Windows GUI smoke, libffi runtime smoke, and full
   test suite; and
9. retain configure commands, environment, compiler/SDK versions, patches,
   build logs, and output hashes.

The exact configure command and toolchain used to produce the upstream PyPI
wheel binaries have not been recovered. Therefore an independent build must not
be represented as bit-identical to those wheels, and the current LGPL gate
remains HOLD.

## Update policy

The 3.0.8 automatic updater is intentionally fail-closed for a one-folder
runtime. Install a newer directory beside the old one and explicitly decide
whether locally modified Qt/PySide files should be retained or replaced. No
automatic updater may overwrite such files without clear consent.

## Reverse engineering for debugging

The application candidate adds no technical restriction against inspecting or
debugging the interaction between OpenFetch and a recipient-modified
LGPL component. The final EULA, installer, signing policy, and support terms
must be reviewed to ensure they do not contradict any rights required by the
selected license route.

## Source delivery status

The two official source archives are retained locally, but no public source
bundle or reviewed written source offer has been issued. Upstream URLs alone
are not treated as the distributor's source delivery. Public distribution
therefore remains **HOLD**.
