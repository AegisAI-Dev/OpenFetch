from __future__ import annotations

import json
from pathlib import Path

import pytest

from openfetch.core import legacy_migration
from openfetch.core.legacy_migration import (
    MIGRATION_LOG_FILENAME,
    MIGRATION_RECORD_FILENAME,
    SETTINGS_MARKER_KEY,
    migrate_legacy_app_data,
    migrate_legacy_settings,
    run_legacy_migration,
)


class FakeSettings:
    def __init__(self, values: dict[str, object] | None = None) -> None:
        self.values = dict(values or {})
        self.synced = False

    def allKeys(self) -> list[str]:  # noqa: N802 - Qt API name
        return list(self.values)

    def value(self, key, defaultValue=None):  # noqa: N803 - Qt API name
        return self.values.get(key, defaultValue)

    def setValue(self, key, value) -> None:  # noqa: N802 - Qt API name
        self.values[key] = value

    def sync(self) -> None:
        self.synced = True


def _legacy_tree(root: Path) -> Path:
    legacy = root / "NeuralExtractorV3"
    profile = legacy / "youtube" / "chrome-profile"
    (profile / "Default" / "Network").mkdir(parents=True)
    (profile / "Default" / "Network" / "Cookies").write_bytes(b"cookie-db")
    (profile / "Local State").write_text("{}", encoding="utf-8")
    (profile / "Default" / "Cache" / "Cache_Data").mkdir(parents=True)
    (profile / "Default" / "Cache" / "Cache_Data" / "data_0").write_bytes(b"x" * 64)
    (profile / "GrShaderCache").mkdir()
    (profile / "GrShaderCache" / "blob").write_bytes(b"shader")
    (profile / "SingletonLock").write_bytes(b"lock")
    firefox = legacy / "youtube" / "firefox-profile"
    (firefox / "cache2").mkdir(parents=True)
    (firefox / "cache2" / "entry").write_bytes(b"cache")
    (firefox / "cookies.sqlite").write_bytes(b"firefox-cookies")
    (firefox / "parent.lock").write_bytes(b"")
    (legacy / "optional-po-provider").mkdir()
    (legacy / "optional-po-provider" / "active.json").write_text('{"a": 1}', encoding="utf-8")
    for transient in ("updates", "process-state", "worker-temp", "updater-helper"):
        (legacy / transient).mkdir()
        (legacy / transient / "state.json").write_text("{}", encoding="utf-8")
    return legacy


def test_app_data_is_copied_without_caches_locks_or_transient_state(tmp_path):
    legacy = _legacy_tree(tmp_path)
    target = tmp_path / "OpenFetch"

    report = migrate_legacy_app_data(legacy_root=legacy, target_root=target)

    chrome = target / "youtube" / "chrome-profile"
    assert (chrome / "Default" / "Network" / "Cookies").read_bytes() == b"cookie-db"
    assert (chrome / "Local State").is_file()
    assert not (chrome / "Default" / "Cache").exists()
    assert not (chrome / "GrShaderCache").exists()
    assert not (chrome / "SingletonLock").exists()
    firefox = target / "youtube" / "firefox-profile"
    assert (firefox / "cookies.sqlite").read_bytes() == b"firefox-cookies"
    assert not (firefox / "cache2").exists()
    assert not (firefox / "parent.lock").exists()
    assert (target / "optional-po-provider" / "active.json").read_text(encoding="utf-8") == '{"a": 1}'
    for transient in ("updates", "process-state", "worker-temp", "updater-helper"):
        assert not (target / transient).exists()
    assert report.events == [
        "Migrated legacy youtube data (3 files)",
        "Migrated legacy optional-po-provider data (1 files)",
    ]
    # The legacy installation stays intact so a rolled-back update still works.
    assert (legacy / "youtube" / "chrome-profile" / "SingletonLock").is_file()
    assert (legacy / "optional-po-provider" / "active.json").is_file()
    assert not list(target.glob(".*.migrating-*"))


def test_app_data_migration_is_idempotent_and_never_reimports_removed_data(tmp_path):
    legacy = _legacy_tree(tmp_path)
    target = tmp_path / "OpenFetch"
    migrate_legacy_app_data(legacy_root=legacy, target_root=target)
    record = json.loads((target / MIGRATION_RECORD_FILENAME).read_text(encoding="utf-8"))
    assert set(record["completed"]) == {"youtube", "optional-po-provider"}

    # The user disconnects YouTube in OpenFetch; the old profile must stay gone.
    import shutil

    shutil.rmtree(target / "youtube")
    second = migrate_legacy_app_data(legacy_root=legacy, target_root=target)

    assert second.events == []
    assert not (target / "youtube").exists()


def test_existing_openfetch_data_is_never_overwritten(tmp_path):
    legacy = _legacy_tree(tmp_path)
    target = tmp_path / "OpenFetch"
    (target / "youtube").mkdir(parents=True)
    (target / "youtube" / "newer.txt").write_text("newer", encoding="utf-8")

    report = migrate_legacy_app_data(legacy_root=legacy, target_root=target)

    assert sorted(path.name for path in (target / "youtube").iterdir()) == ["newer.txt"]
    assert "Legacy youtube data was not imported because OpenFetch data already exists" in report.events
    assert (target / "optional-po-provider" / "active.json").is_file()


def test_fresh_install_without_legacy_data_records_completion_silently(tmp_path):
    target = tmp_path / "OpenFetch"

    report = migrate_legacy_app_data(legacy_root=tmp_path / "missing", target_root=target)

    assert report.events == []
    record = json.loads((target / MIGRATION_RECORD_FILENAME).read_text(encoding="utf-8"))
    assert all(value.startswith("nothing_to_migrate") for value in record["completed"].values())


def test_failed_copy_is_rolled_back_and_retried_on_next_start(tmp_path, monkeypatch):
    legacy = _legacy_tree(tmp_path)
    target = tmp_path / "OpenFetch"
    real_copy = legacy_migration.shutil.copy2
    calls = {"count": 0}

    def failing_copy(source, destination, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise PermissionError("locked")
        return real_copy(source, destination, **kwargs)

    monkeypatch.setattr(legacy_migration.shutil, "copy2", failing_copy)
    first = migrate_legacy_app_data(legacy_root=legacy, target_root=target)

    assert "Legacy youtube data migration deferred after PermissionError" in first.events
    assert not (target / "youtube").exists()
    assert not list(target.glob(".youtube.migrating-*"))

    monkeypatch.setattr(legacy_migration.shutil, "copy2", real_copy)
    second = migrate_legacy_app_data(legacy_root=legacy, target_root=target)

    assert second.events == ["Migrated legacy youtube data (3 files)"]


def test_abandoned_staging_from_a_crashed_attempt_is_removed(tmp_path):
    legacy = _legacy_tree(tmp_path)
    target = tmp_path / "OpenFetch"
    abandoned = target / ".youtube.migrating-deadbeef"
    abandoned.mkdir(parents=True)
    (abandoned / "partial").write_bytes(b"partial")

    migrate_legacy_app_data(legacy_root=legacy, target_root=target)

    assert not abandoned.exists()
    assert (target / "youtube" / "firefox-profile" / "cookies.sqlite").is_file()


def test_settings_are_copied_once_with_legacy_data_paths_rewritten(tmp_path):
    legacy_root = tmp_path / "NeuralExtractorV3"
    target_root = tmp_path / "OpenFetch"
    legacy_profile = legacy_root / "youtube" / "chrome-profile"
    unrelated = tmp_path / "Downloads"
    legacy = FakeSettings(
        {
            "output_dir": str(unrelated),
            "ui/window_geometry": b"\x01\x02",
            "ui/main_splitter_sizes": [440, 940],
            "youtube_connection/chrome/profile_path": str(legacy_profile),
            "youtube_connection/chrome/managed_processes": '[{"pid": 1, "identity": "x"}]',
            "youtube_connection/state": "connected",
        }
    )
    target = FakeSettings()

    report = migrate_legacy_settings(
        legacy, target, legacy_root=legacy_root, target_root=target_root
    )

    assert report.events == ["Migrated 5 legacy settings"]
    assert target.values["output_dir"] == str(unrelated)
    assert target.values["ui/window_geometry"] == b"\x01\x02"
    assert target.values["ui/main_splitter_sizes"] == [440, 940]
    assert Path(target.values["youtube_connection/chrome/profile_path"]) == (
        target_root / "youtube" / "chrome-profile"
    )
    assert "youtube_connection/chrome/managed_processes" not in target.values
    assert str(target.values[SETTINGS_MARKER_KEY]).startswith("migrated ")
    assert target.synced
    assert legacy.values["youtube_connection/chrome/profile_path"] == str(legacy_profile)

    target.values["output_dir"] = "changed in OpenFetch"
    again = migrate_legacy_settings(legacy, target, legacy_root=legacy_root, target_root=target_root)
    assert again.events == []
    assert target.values["output_dir"] == "changed in OpenFetch"


def test_existing_openfetch_settings_are_kept(tmp_path):
    legacy = FakeSettings({"output_dir": "legacy"})
    target = FakeSettings({"output_dir": "openfetch"})

    report = migrate_legacy_settings(
        legacy, target, legacy_root=tmp_path / "old", target_root=tmp_path / "new"
    )

    assert target.values["output_dir"] == "openfetch"
    assert str(target.values[SETTINGS_MARKER_KEY]).startswith("kept_existing ")
    assert report.events == [
        "Legacy settings were not imported because OpenFetch settings already exist"
    ]


def test_migration_failures_never_prevent_startup(tmp_path):
    def broken_factory(_organization, _application):
        raise RuntimeError("registry unavailable")

    report = run_legacy_migration(
        broken_factory,
        legacy_root=_legacy_tree(tmp_path),
        target_root=tmp_path / "OpenFetch",
    )

    assert "Legacy settings migration skipped after RuntimeError" in report.events
    log = (tmp_path / "OpenFetch" / MIGRATION_LOG_FILENAME).read_text(encoding="utf-8")
    assert "Migrated legacy youtube data" in log
    assert str(tmp_path) not in log


def test_migration_log_and_events_never_contain_setting_values_or_paths(tmp_path):
    secret_path = tmp_path / "NeuralExtractorV3" / "youtube" / "chrome-profile"
    stores = {
        ("Neuralshield", "NeuralExtractorV3"): FakeSettings(
            {"cookie_file": "C:/secret/cookies.txt", "profile": str(secret_path)}
        ),
        ("Brainbyte", "OpenFetch"): FakeSettings(),
    }

    report = run_legacy_migration(
        lambda organization, application: stores[(organization, application)],
        legacy_root=_legacy_tree(tmp_path),
        target_root=tmp_path / "OpenFetch",
    )

    text = "\n".join(report.events)
    assert "cookies.txt" not in text
    assert str(tmp_path) not in text
    assert stores[("Brainbyte", "OpenFetch")].values["cookie_file"] == "C:/secret/cookies.txt"


def test_real_qsettings_round_trip_preserves_qt_value_types(tmp_path):
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QByteArray, QSettings

    def factory(organization, application):
        return QSettings(
            str(tmp_path / f"{organization}-{application}.ini"), QSettings.Format.IniFormat
        )

    legacy = factory("Neuralshield", "NeuralExtractorV3")
    legacy.setValue("ui/window_geometry", QByteArray(b"\x00\x01geometry"))
    legacy.setValue("ui/main_splitter_sizes", [440, 940])
    legacy.setValue("output_dir", "D:/Media")
    legacy.sync()

    report = run_legacy_migration(
        factory,
        legacy_root=tmp_path / "no-legacy-data",
        target_root=tmp_path / "OpenFetch",
    )

    migrated = factory("Brainbyte", "OpenFetch")
    assert report.events == ["Migrated 3 legacy settings"]
    assert bytes(migrated.value("ui/window_geometry")) == b"\x00\x01geometry"
    assert [int(size) for size in migrated.value("ui/main_splitter_sizes")] == [440, 940]
    assert migrated.value("output_dir") == "D:/Media"
    assert migrated.value(SETTINGS_MARKER_KEY)
