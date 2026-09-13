# OpenFetch — One-Folder Distribution (3.0.8)

> OpenFetch is the renamed Neural Extractor V3. Version-specific evidence in this
> document was recorded for the audited Neural Extractor V3.0.8 candidate; artifact
> and path names that begin with `NeuralExtractorV3` refer to that audited build and
> must be regenerated for an OpenFetch public candidate.


Status: NON-PUBLIC TECHNICAL RELEASE CANDIDATE. Public-distribution verdict: HOLD.
This build must not be published or redistributed until the release gate and
qualified legal review record PASS.

## What this is

OpenFetch packaged as a Windows x64 one-folder application. All
shared libraries, the Qt/PySide GUI runtime, and the bundled tools live as
plain files beside the launcher so recipients can inspect and — for the
LGPL-licensed Qt/PySide libraries — replace them (see
`docs/QT-REPLACEMENT-GUIDE.md`).

## Installation

1. Extract the release archive `NeuralExtractorV3-3.0.8-windows-x64.zip`.
   It contains a single directory: `NeuralExtractorV3-3.0.8-windows-x64\`.
2. Place that directory anywhere you control (for example
   `C:\Program Files\NeuralExtractorV3-3.0.8-windows-x64` or a per-user
   location). No installer runs and no system state is modified.
3. Start `NeuralExtractorV3.exe` inside the directory.

Requirements: Windows 10/11 x64. Everything else (Python runtime, Qt/PySide,
FFmpeg, ffprobe, Node.js) ships inside this directory.

## Layout

- `NeuralExtractorV3.exe` — application launcher (no embedded native libraries).
- `PySide6\`, `shiboken6\` — Qt/PySide runtime; every file is enumerated with
  its SHA-256 in `QT-PYSIDE-COMPONENTS.json` and is user-replaceable per the
  LGPL-3.0 route described in `docs\QT-REPLACEMENT-GUIDE.md`.
- `bin\` — `ffmpeg.exe`, `ffprobe.exe`, `node.exe` (pinned audited builds).
- `licenses\` — third-party license texts with a hashed manifest
  (`licenses\RELEASE-LICENSE-MANIFEST.sha256`).
- `docs\` — compliance and replacement documentation.
- `compliance\` — the audited compliance snapshot for this build, including
  `BINARY-TO-SOURCE-MAP.json` (per-file source/provenance inventory),
  `NATIVE-COMPONENTS.json`, `SOURCE-BUNDLE-MANIFEST.json`,
  `PROJECT-METADATA.json`, and `BUILD-LABEL.txt` (build verdict).
- `LICENSE`, `THIRD_PARTY_LICENSES.txt`, `THIRD_PARTY_NOTICES.md`,
  `PROJECT-METADATA.json`, `SOURCE-HASHES.sha256`, `requirements.lock`.

## Updates

Directory-based updates are described by the sibling release asset
`NeuralExtractorV3-3.0.8-windows-x64-directory-manifest.json` (it is not
inside this directory: the updater verifies the staged tree exactly against
the manifest, so the manifest travels next to the archive).

The automatic updater is intentionally fail-closed for this layout: if any
Qt/PySide library in `PySide6\` or `shiboken6\` differs from the recorded
baseline in `QT-PYSIDE-COMPONENTS.json`, an update requires your explicit
decision — abort (default), preserve your replaced libraries, or replace them
with the release versions. Until the graphical consent dialog ships, perform
directory updates manually: install the new directory beside the old one and
decide explicitly whether locally modified Qt/PySide files are retained.
No update path overwrites replaced Qt/PySide libraries silently.

## Licensing

The project-owned portions are MIT licensed (see `LICENSE`). Third-party
components remain under their own licenses; see `THIRD_PARTY_LICENSES.txt`,
`THIRD_PARTY_NOTICES.md`, and the `licenses\` directory. Qt/PySide is used
under LGPL-3.0; the replacement procedure and source availability are
documented in `docs\QT-REPLACEMENT-GUIDE.md` and `docs\QT-BUILD-PROVENANCE.md`.
