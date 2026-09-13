"""One-time migration of Neural Extractor V3 user data into OpenFetch.

OpenFetch is the renamed Neural Extractor V3. An upgraded installation keeps its
Qt settings, dedicated YouTube browser profiles and optional PO-helper
activation. The migration is deliberately conservative:

* it copies and never moves, so an update that rolls back to Neural Extractor
  still finds its own data untouched;
* it never overwrites data OpenFetch already has;
* it is idempotent and records completed items, so data the user later removes
  from OpenFetch is not silently imported again;
* browser caches and lock files are skipped because they are regenerated and can
  be large enough to delay the post-update startup confirmation;
* events name only migrated items and counts, never paths or setting values.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from openfetch.config import app_data_dir, legacy_app_data_dir

MIGRATION_SCHEMA_VERSION = 1
MIGRATION_RECORD_FILENAME = "legacy-migration.json"
MIGRATION_LOG_FILENAME = "legacy-migration.log"
SETTINGS_MARKER_KEY = "migration/neural_extractor_v3"
MIGRATED_DATA_DIRECTORIES = ("youtube", "optional-po-provider")
STAGING_MARKER = ".migrating-"

EXCLUDED_CACHE_NAMES = frozenset(
    {
        "cache",
        "cache2",
        "cachestorage",
        "code cache",
        "crashpad",
        "dawncache",
        "dawngraphitecache",
        "dawnwebgpucache",
        "gpucache",
        "grshadercache",
        "shadercache",
        "startupcache",
        "thumbnails",
    }
)
EXCLUDED_LOCK_NAMES = frozenset(
    {"lock", "lockfile", "parent.lock", "singletoncookie", "singletonlock", "singletonsocket"}
)
# Process identities of browsers started by the legacy application are only
# meaningful to that application instance.
TRANSIENT_SETTING_SUFFIXES = ("/managed_processes",)


class SettingsStore(Protocol):
    def allKeys(self) -> list[str]: ...  # noqa: N802 - Qt API name

    def value(self, key: str, defaultValue: Any = None) -> Any: ...  # noqa: N803

    def setValue(self, key: str, value: Any) -> None: ...  # noqa: N802

    def sync(self) -> None: ...


@dataclass(slots=True)
class MigrationReport:
    events: list[str] = field(default_factory=list)

    def add(self, message: str) -> None:
        self.events.append(message)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _is_reparse_point(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(details.st_mode):
        return True
    return bool(int(getattr(details, "st_file_attributes", 0)) & 0x400)


def _same_location(left: Path, right: Path) -> bool:
    try:
        return os.path.normcase(str(left.resolve())) == os.path.normcase(str(right.resolve()))
    except OSError:
        return False


def _read_record(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema_version") != MIGRATION_SCHEMA_VERSION:
        return {}
    completed = payload.get("completed")
    if not isinstance(completed, dict):
        payload["completed"] = {}
    return payload


def _write_record(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _copy_tree(source: Path, destination: Path) -> int:
    """Copy regular files below ``source``; never follow links or reparse points."""
    destination.mkdir(parents=True)
    copied = 0
    with os.scandir(source) as entries:
        for entry in entries:
            name = entry.name.casefold()
            entry_path = Path(entry.path)
            if _is_reparse_point(entry_path):
                continue
            if entry.is_dir(follow_symlinks=False):
                if name in EXCLUDED_CACHE_NAMES:
                    continue
                copied += _copy_tree(entry_path, destination / entry.name)
            elif entry.is_file(follow_symlinks=False):
                if name in EXCLUDED_LOCK_NAMES:
                    continue
                shutil.copy2(entry_path, destination / entry.name, follow_symlinks=False)
                copied += 1
    return copied


def _remove_abandoned_staging(target_root: Path) -> None:
    for name in MIGRATED_DATA_DIRECTORIES:
        for leftover in target_root.glob(f".{name}{STAGING_MARKER}*"):
            if leftover.is_dir() and not _is_reparse_point(leftover):
                shutil.rmtree(leftover, ignore_errors=True)


def migrate_legacy_app_data(
    *,
    legacy_root: Path | None = None,
    target_root: Path | None = None,
    report: MigrationReport | None = None,
) -> MigrationReport:
    """Copy durable legacy application data into the OpenFetch data directory."""
    report = report or MigrationReport()
    legacy = Path(legacy_root) if legacy_root is not None else legacy_app_data_dir()
    target = Path(target_root) if target_root is not None else app_data_dir()
    target.mkdir(parents=True, exist_ok=True)
    record_path = target / MIGRATION_RECORD_FILENAME
    record = _read_record(record_path) or {
        "schema_version": MIGRATION_SCHEMA_VERSION,
        "source": "NeuralExtractorV3",
        "completed": {},
    }
    completed: dict[str, str] = record["completed"]
    pending = [name for name in MIGRATED_DATA_DIRECTORIES if name not in completed]
    if not pending:
        return report

    legacy_usable = (
        legacy.is_dir() and not _is_reparse_point(legacy) and not _same_location(legacy, target)
    )
    _remove_abandoned_staging(target)
    for name in pending:
        source = legacy / name
        destination = target / name
        if not legacy_usable or not source.is_dir() or _is_reparse_point(source):
            completed[name] = f"nothing_to_migrate {_timestamp()}"
            continue
        if destination.exists():
            completed[name] = f"kept_existing {_timestamp()}"
            report.add(f"Legacy {name} data was not imported because OpenFetch data already exists")
            continue
        staging = target / f".{name}{STAGING_MARKER}{secrets.token_hex(6)}"
        try:
            files = _copy_tree(source, staging)
            os.replace(staging, destination)
        except OSError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            report.add(f"Legacy {name} data migration deferred after {type(exc).__name__}")
            continue
        completed[name] = f"migrated {_timestamp()}"
        report.add(f"Migrated legacy {name} data ({files} files)")

    with contextlib.suppress(OSError):
        _write_record(record_path, record)
    return report


def _rewrite_legacy_path(value: Any, legacy_root: Path, target_root: Path) -> Any:
    if not isinstance(value, str) or not value:
        return value
    legacy_text = os.path.normcase(os.path.normpath(str(legacy_root)))
    candidate = os.path.normcase(os.path.normpath(value))
    if candidate == legacy_text:
        return str(target_root)
    prefix = legacy_text.rstrip("\\/") + os.sep
    if candidate.startswith(prefix):
        return str(Path(target_root) / os.path.normpath(value)[len(prefix) :])
    return value


def migrate_legacy_settings(
    legacy: SettingsStore,
    target: SettingsStore,
    *,
    legacy_root: Path | None = None,
    target_root: Path | None = None,
    report: MigrationReport | None = None,
) -> MigrationReport:
    """Copy legacy Qt settings into empty OpenFetch settings exactly once."""
    report = report or MigrationReport()
    if target.value(SETTINGS_MARKER_KEY):
        return report
    legacy_data = Path(legacy_root) if legacy_root is not None else legacy_app_data_dir()
    target_data = Path(target_root) if target_root is not None else app_data_dir()

    existing = [key for key in target.allKeys() if key != SETTINGS_MARKER_KEY]
    legacy_keys = list(legacy.allKeys())
    if existing:
        status = "kept_existing"
        if legacy_keys:
            report.add("Legacy settings were not imported because OpenFetch settings already exist")
    elif not legacy_keys:
        status = "nothing_to_migrate"
    else:
        copied = 0
        for key in legacy_keys:
            if key == SETTINGS_MARKER_KEY or key.endswith(TRANSIENT_SETTING_SUFFIXES):
                continue
            target.setValue(key, _rewrite_legacy_path(legacy.value(key), legacy_data, target_data))
            copied += 1
        status = "migrated"
        report.add(f"Migrated {copied} legacy settings")
    target.setValue(SETTINGS_MARKER_KEY, f"{status} {_timestamp()}")
    target.sync()
    return report


def append_migration_log(report: MigrationReport, target_root: Path | None = None) -> None:
    if not report.events:
        return
    log_path = (Path(target_root) if target_root is not None else app_data_dir()) / (
        MIGRATION_LOG_FILENAME
    )
    with contextlib.suppress(OSError), log_path.open("a", encoding="utf-8") as handle:
        for event in report.events:
            handle.write(f"{_timestamp()} {event}\n")


def run_legacy_migration(
    settings_factory: Callable[[str, str], SettingsStore] | None = None,
    *,
    legacy_settings_scope: tuple[str, str] = ("Neuralshield", "NeuralExtractorV3"),
    target_settings_scope: tuple[str, str] = ("Brainbyte", "OpenFetch"),
    legacy_root: Path | None = None,
    target_root: Path | None = None,
) -> MigrationReport:
    """Migrate application data first, then settings that may point into it.

    Every failure is contained: migration must never prevent OpenFetch from
    starting, because a failed start during an update triggers a rollback.
    """
    report = MigrationReport()
    try:
        migrate_legacy_app_data(legacy_root=legacy_root, target_root=target_root, report=report)
    except Exception as exc:  # noqa: BLE001 - startup must continue
        report.add(f"Legacy data migration skipped after {type(exc).__name__}")
    if settings_factory is not None:
        try:
            migrate_legacy_settings(
                settings_factory(*legacy_settings_scope),
                settings_factory(*target_settings_scope),
                legacy_root=legacy_root,
                target_root=target_root,
                report=report,
            )
        except Exception as exc:  # noqa: BLE001 - startup must continue
            report.add(f"Legacy settings migration skipped after {type(exc).__name__}")
    append_migration_log(report, target_root)
    return report
