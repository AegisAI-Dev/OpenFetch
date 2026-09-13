# Qt Replacement Consent Dialog — Remaining Engineering Blocker

Status: OPEN ENGINEERING BLOCKER (GUI work). Recorded 2026-07-26.
This blocker does not change the fail-closed default; it blocks wiring the
already-implemented directory-update transaction into the GUI.

## Current implemented behavior (verified against source)

`QtReplacementPolicy` lives in
`src/openfetch/core/update_directory_installer.py` (enum at line 131:
`ABORT = "abort"`, `PRESERVE = "preserve"`, `REPLACE = "replace"`).

Detection: `detect_modified_replaceable_files()` hashes every manifest
`replaceable_paths` entry (all under `PySide6/` or `shiboken6/`) against the
installed `QT-PYSIDE-COMPONENTS.json` baseline. If the baseline is missing or
unreadable, EVERY present replaceable file is treated as recipient-modified —
detection widens, never narrows.

`prepare_and_launch_directory_update(..., qt_policy=QtReplacementPolicy.ABORT)`
(default is ABORT — fail-closed):

- **abort** (default): if any modified replaceable file is detected, raises
  `UpdateError("qt_replacement_consent_required", ...)` listing up to five
  affected paths. Nothing is backed up, no transaction is written, no side
  effect occurs. With no modified files, the update proceeds normally.
- **preserve**: the `{relative_path: sha256}` map of user-modified files is
  recorded in the transaction as `preserved_files`. The applier expects the
  USER's bytes for those paths, fails closed on drift
  (`target_drift`), carries each preserved file forward into the new tree with
  hash verification (`staging_failure` on mismatch), and verifies the final
  tree against the manifest overlaid with the preserved hashes.
- **replace**: no files are preserved; the release's files overwrite the
  user's libraries, and the explicit choice is durably recorded in
  `directory-transaction.json` as `"qt_policy": "replace"` (recorded consent).

Transaction-level enforcement: the helper re-validates `qt_policy` against the
three enum values (`invalid_transaction` otherwise); a non-empty
`preserved_files` map with any policy other than `preserve` is rejected;
preserved paths/hashes are individually validated and capped at 512 entries.

Configuration surface: the policy is ONLY a Python keyword argument. There is
no environment variable, no config key, and no CLI flag; the helper side reads
the policy from the already-written transaction file.

## What is missing (the blocker)

No GUI consent dialog exists — not even partially. Evidence:

- No `QDialog` in `src/` relates to updates (only the YouTube connection
  dialogs exist).
- `prepare_and_launch_directory_update` has no caller in `src/` outside its
  own module and the hidden `--apply-directory-update` helper entry point.
- The GUI update path (`main_window.py::on_update_available`) still routes
  one-folder installs to the legacy capability check, which returns
  `onefolder_manual_install_required` and only offers "Open Download Page" /
  "Later".

This is consistent with `docs/UPDATE_ARCHITECTURE.md` ("The GUI does not yet
offer this transaction automatically; it requires a reviewed
replacement-consent dialog and a published one-folder release asset format")
and `docs/LGPL-COMPLIANCE.md` (same, "owner-scope work").

## Required UI flow (exact)

When `on_update_available` runs inside a one-folder installation and a
directory manifest asset is available for the new release:

1. Download and validate the release's directory manifest
   (`OpenFetch-<version>-windows-x64-directory-manifest.json`) with
   `DirectoryUpdateManifest.from_json`.
2. Call `detect_modified_replaceable_files(install_root, manifest)`.
3. If the result is empty: proceed with
   `prepare_and_launch_directory_update(..., qt_policy=QtReplacementPolicy.ABORT)`
   (abort semantics never trigger without modified files; no dialog needed).
4. If modified files exist, show a modal consent dialog that:
   - lists every affected relative path (scrollable beyond five entries) with
     recorded baseline hash vs current hash;
   - explains that these Qt/PySide libraries differ from the shipped baseline
     (LGPL replacement rights);
   - offers exactly three explicit choices, none preselected as destructive:
     **Cancel update** (maps to abort — default button),
     **Keep my replaced libraries** (preserve),
     **Replace with release versions** (replace);
   - requires an affirmative click; closing the dialog means abort.
5. Re-invoke `prepare_and_launch_directory_update` with the chosen
   `qt_policy`. The choice is recorded in the transaction file; the helper
   enforces it independently.
6. On `UpdateError("qt_replacement_consent_required")` raised anyway (race:
   files changed between detection and prepare), re-run detection and reshow
   the dialog.

The dialog text must be reviewed (owner + qualified review) before release;
until then the one-folder GUI keeps directing recipients to the manual flow,
and the default remains fail-closed (abort).
