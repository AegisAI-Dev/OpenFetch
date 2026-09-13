# OpenFetch

**OpenFetch by Brainbyte** — open-source media downloader & toolkit.

OpenFetch (formerly Neural Extractor V3) downloads single videos, full
playlists, YouTube Mixes, batches of links, MP3/M4A audio, SRT subtitles,
thumbnails, and optional metadata sidecars. Upgrading from Neural Extractor keeps
your settings; see [docs/OPENFETCH-MIGRATION.md](docs/OPENFETCH-MIGRATION.md).

## Features

- Video downloads as MP4 with selectable quality up to best available.
- Audio downloads as MP3 or M4A with bitrate presets.
- Full playlist and Mix support, plus current-video-only mode.
- Batch queue: paste one URL per line and process them in order.
- Subtitles saved as `.srt`, including auto-generated subtitles when needed.
- Thumbnail download as JPG, with optional embedding for audio files.
- Guided `YouTube verbinden` flow using an isolated OpenFetch browser profile.
- Optional `cookies.txt` support retained as an advanced compatibility fallback.
- Optional metadata JSON output.
- CLI mode for scripted downloads.
- PySide6 desktop interface with progress, queue status, and logs.
- Optional PO-token support only through a separately installed, hash-verified
  external helper; ordinary downloads do not require it.

## Start

From this folder:

```powershell
python -m pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python main.py
```

Or run:

```powershell
start.bat
```

## CLI Examples

Download a video with Dutch SRT subtitles and thumbnail:

```powershell
$env:PYTHONPATH = "$PWD\src"
python main.py --url "https://www.youtube.com/watch?v=VIDEO_ID" --mode video --subs nl
```

Download a full playlist as MP3:

```powershell
$env:PYTHONPATH = "$PWD\src"
python main.py --url "https://www.youtube.com/playlist?list=PLAYLIST_ID" --mode audio_mp3 --playlist full
```

Download subtitles only:

```powershell
$env:PYTHONPATH = "$PWD\src"
python main.py --url "https://youtu.be/VIDEO_ID" --mode subtitles_only --subs nl
```

## Build Windows EXE

The self-updating one-file executable:

```powershell
pyinstaller OpenFetch-onefile.spec --clean --noconfirm
```

It is written to `dist\OpenFetch.exe`.

The compliance-friendly one-folder candidate (`build.bat`) uses
`OpenFetch.spec` and is written to `dist\OpenFetch-<version>-windows-x64\`. It
is not published and does not update itself automatically.

## Versioning

`src/openfetch/config.py` `VERSION` is the single authoritative version.
`pyproject.toml` derives its version from it, and `version_info.txt` is
generated from it:

```powershell
python scripts/release_tools.py version-info
python scripts/release_tools.py validate --release-ref v3.1.0
```

## GitHub Release Pipeline

`.github/workflows/build-onefile-release.yml` is a manually dispatched,
owner-confirmed workflow. It requires the exact source version and the phrase
`PUBLISH-OPENFETCH-<version>`, runs Ruff, compileall, the full test suite and
manifest checks, builds `OpenFetch-onefile.spec`, runs packaged runtime, GUI,
provider and updater smokes, publishes the OpenFetch assets in this repository,
and hands the legacy-named bridge assets to the owner as a workflow artifact.

`.github/workflows/build-release.yml` is the compliance-gated one-folder
workflow and stays fail-closed while the licensing verdict is HOLD. See
[docs/UPDATE_ARCHITECTURE.md](docs/UPDATE_ARCHITECTURE.md).

## App Updates

On startup, the desktop app silently checks the latest stable GitHub Release. The
`Check Updates` button runs the same check manually. A newer release is
downloaded only after a clear user action, validated against its strict
manifest, size, and SHA-256, installed through a detached helper, restarted,
confirmed, and rolled back to the verified backup when startup fails.

Neural Extractor 3.0.4 and later update to OpenFetch in place. Source-mode,
one-folder, or non-writable installs keep the manual release-page fallback.

The canonical release repository is:

```text
AegisAI-Dev/OpenFetch
```

The automatic update source is intentionally pinned and is not configurable at
runtime; redirects are never followed. Installed Neural Extractor V3 builds are
pinned to the pre-rename slug and are served once, for the 3.1.0 migration, by
the owner-controlled bridge repository `AegisAI-Dev/NeuralExtractor`; OpenFetch
itself never reads it. See
[docs/OPENFETCH-MIGRATION.md](docs/OPENFETCH-MIGRATION.md). The EXE is SHA-256
verified but is not Authenticode publisher-signed.

## Notes

- FFmpeg is required for merging video/audio, MP3 conversion, thumbnail embedding, and SRT conversion. If a local `bin` folder exists, OpenFetch will use it automatically.
- When YouTube requests sign-in or human verification, use `YouTube verbinden`.
  OpenFetch opens a separate browser profile and never receives the password.
- `cookies.txt` is an optional advanced fallback, not the normal authentication workflow.
- Respect YouTube terms, creator rights, and local law.

See [docs/V3.0.5-YOUTUBE-CONNECTION.md](docs/V3.0.5-YOUTUBE-CONNECTION.md)
for the profile architecture, privacy model, PO Token provider decision, known
limitations, renewal/disconnect behavior, and owner field-test plan.

## License and ownership

OpenFetch-owned portions are free and open-source software under the
MIT License:

`Copyright (c) 2025-2026 0xRootNull`

The public author and copyright-holder attribution is the pseudonym
`0xRootNull`; the identity behind the pseudonym is intentionally not
published. `Brainbyte` is the brand under which OpenFetch is presented, not a
registered company or legal entity. Third-party components remain governed by their respective licenses
and are not relicensed under MIT. See
[docs/PROJECT-OWNERSHIP-DECLARATION.md](docs/PROJECT-OWNERSHIP-DECLARATION.md)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
