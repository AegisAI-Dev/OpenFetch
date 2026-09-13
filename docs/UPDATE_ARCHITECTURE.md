# OpenFetch Update Architecture

## Release 3.1.0: rename, release-path repair, and legacy upgrade path

OpenFetch 3.1.0 is the renamed Neural Extractor V3. The self-updater itself
(check, verified download, detached helper, startup confirmation, rollback) was
intact; three structural faults prevented it from delivering updates:

1. **No release could reach installed builds.** The compliance-gated workflow
   `build-release.yml` stops at the licensing HOLD gate, and the only publishing
   path, the family bridge workflow, accepted exactly version 3.0.8. Every
   installed 3.0.4–3.0.8 build therefore reported "no update" indefinitely.
   Repair: `build-onefile-release.yml` is an owner-confirmed one-file release
   workflow for any version equal to the source version (confirmation
   `PUBLISH-OPENFETCH-<version>`), keeping every smoke, boundary scan, and
   manifest check of the bridge workflow. The compliance gate is unchanged.
2. **The default build could not self-update.** `build.bat` builds the
   compliance one-folder layout, which the one-file transaction refuses
   (`onefolder_manual_install_required`). The directory transaction still needs
   the reviewed Qt replacement consent dialog, so this stays fail-closed and is
   documented; the updatable distribution is `OpenFetch-onefile.spec`.
3. **The repository rename cut off every installed build.** The repository is
   now `AegisAI-Dev/OpenFetch`, and the pre-rename API URL answers
   `301 Moved Permanently`. Installed builds call it with
   `allow_redirects=False`; `raise_for_status()` does not raise for 3xx, so they
   parse the redirect body, find no `tag_name`, and report
   *"The latest release has an invalid version."* (code `invalid_version`).
   Measured against live GitHub for 3.0.4, 3.0.7 and 3.0.8.
   Repair: a two-repository bridge (below). OpenFetch trusts only the canonical
   repository; a separate owner-controlled bridge repository keeps the exact
   pre-rename name and serves those clients. A 3xx answer is now classified as
   `release_source_moved` and a missing feed as `release_source_unavailable`,
   instead of being parsed as release metadata. Redirects are still never
   followed.

See [OPENFETCH-MIGRATION.md](OPENFETCH-MIGRATION.md) for the upgrade sequence,
repository-rename order, and user-data migration.

## Release 3.0.4 transaction-handoff repair

Version 3.0.4 repairs the detached updater transaction used by 3.0.2 and
3.0.3. Those versions recorded the PID returned by launching a PyInstaller
one-file helper. That PID belongs to the outer bootloader, while Python helper
mode can run in its child process. The child therefore rejected its own
transaction as if a competing updater owned the installation.

Because the defective code is already installed in 3.0.2 and 3.0.3, neither is
a supported automatic path to 3.0.4. Install 3.0.4 manually once from the
official GitHub Release. The 3.0.4 manifest deliberately declares
`minimum_updater_version` 3.0.4. Releases after 3.0.4 can then use the repaired
automatic updater when their manifests keep a compatible minimum.

V3.0.4 creates a transaction before staging, uses target-scoped ownership keyed
by the normalized installed EXE, and stores both PID and process-creation
identity. The GUI reserves only a same-transaction handoff. The Python runtime
inside the helper atomically assumes installation ownership itself and writes a
readiness acknowledgement before the GUI exits. A live different transaction
for the same target remains blocked; a different installation path does not.

## Release 3.0.2

Version 3.0.2 is the bootstrap release for the Windows self-updater. Version
3.0.1 can discover a release but cannot replace itself, so users of 3.0.1 must
install 3.0.2 manually once. Although 3.0.2 introduced the complete confirmed
update design, its packaged one-file GUI-to-helper PID handoff is defective.
3.0.2 and 3.0.3 may fail before replacement and must not be described as a
reliable automatic path to 3.0.4.

The existing YouTube HTTP 403 retry hardening is included in 3.0.2. Update work
does not alter download naming, Mix/RDMM normalization, queueing, cancellation,
subtitles, thumbnails, cookies, browser-cookie fallback, Node, EJS, or ffmpeg
behavior.

## Previous Limitation

The earlier updater checked the latest GitHub Release and opened a browser. It
did not download, verify, install, restart, confirm startup, or roll back an
update. Asset selection could also accept an ambiguous EXE name.

## Trust Model

The automatic source is pinned in code (`openfetch.config.GITHUB_REPO`) to the
canonical repository:

```text
AegisAI-Dev/OpenFetch
```

Installed Neural Extractor V3 updaters are pinned to the pre-rename slug and
cannot be repointed, so they are served by a separate bridge repository with
that exact name, owned by the same account:

```text
AegisAI-Dev/NeuralExtractor   (migration bridge, legacy asset family only)
```

OpenFetch never reads the bridge, and the updater refuses any other source:
constructing `UpdateChecker` with a different API or releases URL raises.

Only the latest non-draft, non-prerelease GitHub Release is considered. The
updater accepts only HTTPS URLs matching exact release-asset URLs in that
repository. It never uses a repository or local target supplied by release
metadata, command-line users, or environment variables.

The strict manifest and the package are obtained through TLS with certificate
verification, explicit timeouts, and bounded streaming. SHA-256 protects the
package against corruption and a package/manifest mismatch. It does not protect
against compromise of the official GitHub repository, release credentials, or
the build pipeline because the manifest is not independently signed.

There is currently no Authenticode signing certificate or signature-validation
step. Do not describe the EXE as publisher-signed.

## Release Assets

In `AegisAI-Dev/OpenFetch`, OpenFetch automatic installation requires exactly:

```text
OpenFetch-X.Y.Z-windows-x64.exe
OpenFetch-X.Y.Z-manifest.json
```

plus the human-verification sidecar `OpenFetch-X.Y.Z-windows-x64.exe.sha256`
and the convenience download `OpenFetch.exe`, which the updater never selects.

In the bridge repository `AegisAI-Dev/NeuralExtractor`, the one migration
release `v3.1.0` carries exactly what installed 3.0.4-3.0.8 clients request,
built from the same executable:

```text
NeuralExtractorV3-3.1.0-windows-x64.exe
NeuralExtractorV3-3.1.0-manifest.json          application_name "Neural Extractor V3"
NeuralExtractorV3-3.1.0-windows-x64.exe.sha256
```

## Manifest Format

Schema version 1 contains exactly these required fields plus one optional field:

```json
{
  "application_name": "OpenFetch",
  "architecture": "x64",
  "asset_filename": "OpenFetch-3.0.2-windows-x64.exe",
  "asset_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "asset_size": 123456789,
  "channel": "stable",
  "minimum_updater_version": "3.0.2",
  "platform": "windows",
  "release_version": "3.0.2",
  "schema_version": 1
}
```

Parsing rejects duplicate keys, unknown fields, missing fields, invalid numeric
versions, release/manifest mismatches, same versions, downgrades, wrong platform
or architecture, non-stable channels, path separators, unexpected filenames,
invalid hashes, and implausible sizes.

## Download And Verification

1. The app selects the exact versioned EXE and manifest from GitHub metadata.
2. GitHub's reported EXE size must equal the manifest size.
3. The EXE streams into a random `.part` file below
   `%LOCALAPPDATA%\OpenFetch\updates\<version>\package`.
4. Content-Length, actual byte count, manifest size, and the global maximum size
   are enforced.
5. The file is flushed and closed, then SHA-256 is recalculated locally.
6. Only a size- and hash-matched file is atomically promoted to the staged EXE.
7. A cached staged EXE is reused only after a fresh size and SHA-256 check.

A checksum mismatch removes the partial file and cannot reach installation.

## Installation Sequence

1. The GUI shows current/new versions, release details, size, and a user-confirmed
   `Download and Install` action.
2. The app checks packaged Windows mode, official target name, writable install
   directory, safe non-temporary location, and free space.
3. The GUI creates a random transaction ID before staging and copies itself to a
   transaction- and target-specific helper directory.
4. It persists `handoff_pending` state plus a target-scoped handoff reservation
   containing the GUI PID and process-creation identity, then starts the helper
   with `--apply-update <transaction.json>`.
5. The Python runtime inside the helper validates the same transaction and
   target, atomically assumes installation ownership with its own PID and
   creation identity, and acknowledges readiness. The GUI does not store the
   PyInstaller wrapper PID and exits only after this acknowledgement.
6. The helper validates paths, ownership, version, size, disk space, and hashes
   again, then waits for the exact GUI PID and creation identity to exit. PID
   reuse is treated as the original GUI having exited.
7. It creates and verifies a backup before copying and replacing the target EXE.
8. Windows file-lock failures are retried for a bounded number of attempts.
9. The new EXE starts directly with only a controlled transaction reference.
   The confirmation nonce stays inside the transaction file rather than the
   command line. No shell, PowerShell, cmd.exe, batch file, system Python, UAC
   request, or silent elevation is used.

## Startup Confirmation And Rollback

Process creation alone is not success. After the Qt application and main window
initialize, the new process writes a transaction-, nonce-, version-, PID-, and
process-creation-bound marker inside its controlled transaction directory. The
helper accepts only that exact marker and waits for it with a bounded timeout.

After confirmation, the helper records success and removes the backup. If the
success record itself cannot be written, it keeps the verified backup
conservatively. Confirmed-success transaction metadata is cleaned only after the
retention period.

If replacement, launch, early startup, or confirmation fails, the helper stops
the failed new process, verifies and restores the backup, verifies the restored
EXE, and restarts the previous version. The restored app reports rollback status.
If rollback fails, recoverable files remain in place and a native recovery
message gives the exact backup and target paths. Sanitized helper events are in:

```text
%LOCALAPPDATA%\OpenFetch\updates\updater.log
```

## One-Folder Directory Transaction

The compliance-friendly one-folder distribution is updated by a separate
directory-wide transaction in
`src/openfetch/core/update_directory_installer.py`. It follows the
same ownership, state-machine, startup-confirmation, and rollback discipline as
the one-file transaction, with these differences:

1. The release is described by a strict per-file directory manifest
   (`schema_version`, exact file map with SHA-256 and size, bounded totals,
   Unicode-safe relative paths, and a declared replaceable Qt/PySide family).
   Symlinks/reparse points, unexpected executables, PyQt/provider payloads, and
   legacy one-file artifacts are rejected fail-closed.
2. Before handoff the GUI copies the whole installation to a sibling
   `.<name>.<transaction>.backup` directory with per-file verification and a
   recorded inventory. The detached helper is the backed-up EXE itself, so the
   helper always runs the last known-good version.
3. Recipient-replaced Qt/PySide libraries (detected against the installed
   `QT-PYSIDE-COMPONENTS.json` baseline) require an explicit
   `QtReplacementPolicy`: `abort` (default), `preserve` (carry forward), or
   `replace` (recorded consent). Nothing is overwritten silently.
4. Replacement stages a verified `.new` tree beside the target and applies two
   directory renames (`target -> .old`, `.new -> target`). Every intermediate
   layout is recoverable: startup recovery restores the original from `.old`
   or the verified backup, confirms an already-confirmed update from its
   process-bound marker, and otherwise retains files conservatively.
5. All install-side file operations use extended-length paths, so Unicode and
   long Windows installation paths are supported.

The helper mode is `--apply-directory-update`; startup confirmation and
rollback status reuse `--post-update-transaction` and
`--update-rollback-status` with the `directory-transaction.json` reference.
The GUI does not yet offer this transaction automatically; it requires a
reviewed replacement-consent dialog and a published one-folder release asset
format.

## Permissions And Manual Fallback

Automatic installation is unavailable when the app runs from source, from a
PyInstaller temporary extraction/update staging path, under a non-official EXE
name, outside Windows, in a non-writable directory, or without sufficient free
space. The app does not request elevation. In these cases the update dialog
explains the reason and keeps the `Open Download Page` manual fallback.

## Publishing 3.0.4

The workflow supports tag pushes matching `v*.*.*` and explicit
`workflow_dispatch`. It validates that the requested release version, runtime
`VERSION`, and `pyproject.toml` version are identical numeric `X.Y.Z` values
before dependencies, tests, build, manifest generation, or publishing.

Recommended owner procedure without Git CLI:

1. In GitHub Desktop, review the local file list and diff.
2. Commit the complete 3.0.4 source and documentation changes locally.
3. Push the branch with GitHub Desktop.
4. Merge that branch into the repository's default branch using the GitHub web
   interface, then confirm the default branch contains version 3.0.4 and the
   updated workflow.
5. Confirm that tag `v3.0.4` does not already exist. In GitHub Actions, open
   `Build and Release Neural Extractor V3` (now `Build and Release OpenFetch (compliance-gated)`), choose `Run workflow`, select the
   default branch, enter exactly `3.0.4`, and run it.
6. Wait for validation, tests, PyInstaller, checksum, manifest, artifact upload,
   and GitHub Release publication to complete.
7. On the `v3.0.4` release page, verify that the exact two EXEs, manifest, and
   checksum are present and that no other release assets were published.
8. Download the manifest and versioned EXE on a clean Windows profile, compare
   size and SHA-256, launch it, and test the manual update check before announcing
   the release.

`workflow_dispatch` is shown in the Actions UI only after this workflow exists on
the default branch. The manual run requires a new tag, then creates tag `v3.0.4`
and the GitHub Release automatically. An existing tag makes the manual workflow
fail rather than reusing an ambiguous release target.

## Upgrade Expectations

- `3.0.1 -> 3.0.2`: detect the release, open its page, close the application,
  manually place/run the 3.0.2 EXE once.
- `3.0.2/3.0.3 -> 3.0.4`: manually download and run 3.0.4 once because the
  installed helper handoff is defective. Do not overwrite the old EXE while it
  is running.
- `3.0.4 -> later`: check, confirm, download, verify, hand off to the detached
  helper, restart, confirm startup, and clean up automatically; roll back
  automatically on failure. Field acceptance still requires a real 3.0.4 to
  3.0.5 release test.
- Updates are optional. There are no forced or silent replacements.
