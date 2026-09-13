import json
import sys
from pathlib import Path

import pytest

from scripts import qt_onefolder_compliance as qt_compliance


def _minimal_distribution(tmp_path: Path) -> Path:
    root = tmp_path / qt_compliance.DIST_NAME
    root.mkdir()
    (root / qt_compliance.EXECUTABLE_NAME).write_bytes(b"MZ-test")
    for relative in qt_compliance.REQUIRED_RECIPIENT_PATHS:
        path = root / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"test material for {relative}\n", encoding="utf-8")
    for index, relative in enumerate(qt_compliance.EXPECTED_QT_PATHS):
        path = root / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"MZ-native-{index}-{relative}".encode())
    return root


def _pin_fixture_hashes(root: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        qt_compliance,
        "EXPECTED_QT_SHA256",
        {
            relative: qt_compliance.sha256_file(root / Path(relative))
            for relative in qt_compliance.EXPECTED_QT_PATHS
        },
    )
    monkeypatch.setattr(qt_compliance, "verify_source_archives", lambda: None)
    monkeypatch.setattr(qt_compliance, "verify_locked_wheels", lambda: None)
    monkeypatch.setattr(qt_compliance, "verify_executable_boundary", lambda _path: None)


def test_spec_uses_external_onefolder_collect_layout():
    spec = qt_compliance.SPEC_PATH.read_text(encoding="utf-8")

    assert qt_compliance.SPEC_PATH.name == "OpenFetch.spec"
    assert "exclude_binaries=True" in spec
    assert 'contents_directory="."' in spec
    assert "COLLECT(" in spec
    # The one-folder root name is derived from src/openfetch/config.py.
    assert 'name=f"{EXECUTABLE_STEM}-{APPLICATION_VERSION}-windows-x64"' in spec
    assert qt_compliance.DIST_NAME == f"OpenFetch-{qt_compliance.VERSION}-windows-x64"


def test_official_source_archives_locks_and_wheel_records_are_verified():
    qt_compliance.verify_source_archives()
    qt_compliance.verify_build_environment(Path(sys.executable))


def test_component_manifest_is_exact_and_fail_closed(tmp_path, monkeypatch):
    root = _minimal_distribution(tmp_path)
    _pin_fixture_hashes(root, monkeypatch)
    manifest_path = qt_compliance.write_component_manifest(root)

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["release_gate_status"] == "HOLD"
    assert payload["distribution_layout"].startswith("pyinstaller-one-folder")
    assert [record["path"] for record in payload["files"]] == list(
        qt_compliance.EXPECTED_QT_PATHS
    )
    assert qt_compliance.verify_layout(root) == payload

    (root / qt_compliance.EXPECTED_QT_PATHS[0]).write_bytes(b"MZ-changed")
    with pytest.raises(qt_compliance.ComplianceError, match="audited wheel baseline"):
        qt_compliance.verify_layout(root)


def test_component_layout_rejects_forbidden_provider_or_pyqt_payload(
    tmp_path, monkeypatch
):
    root = _minimal_distribution(tmp_path)
    _pin_fixture_hashes(root, monkeypatch)
    qt_compliance.write_component_manifest(root)
    forbidden = root / "yt_dlp_plugins" / "getpot_bgutil.py"
    forbidden.parent.mkdir()
    forbidden.write_text("forbidden", encoding="utf-8")

    with pytest.raises(qt_compliance.ComplianceError, match="forbidden"):
        qt_compliance.verify_layout(root)


def test_component_layout_rejects_extra_qt_family_file(tmp_path, monkeypatch):
    root = _minimal_distribution(tmp_path)
    _pin_fixture_hashes(root, monkeypatch)
    qt_compliance.write_component_manifest(root)
    (root / "PySide6" / "unexpected.dll").write_bytes(b"MZ-extra")

    with pytest.raises(qt_compliance.ComplianceError, match="inventory is not exact"):
        qt_compliance.verify_layout(root)


def test_overlay_replacement_changes_hash_and_atomic_copy_restores(tmp_path):
    source = tmp_path / "source.dll"
    destination = tmp_path / "destination.dll"
    source.write_bytes(b"MZ-approved-compatible-test-set")
    destination.write_bytes(b"MZ-original")

    relative = "PySide6/plugins/platforms/qoffscreen.dll"
    qt_compliance._write_overlay_replacement(source, destination, relative)
    assert (
        destination.read_bytes()
        == source.read_bytes() + qt_compliance.REPLACEMENT_MARKER + relative.encode("ascii")
    )
    changed_hash = qt_compliance.sha256_file(destination)

    qt_compliance._atomic_copy(source, destination)
    assert destination.read_bytes() == source.read_bytes()
    assert qt_compliance.sha256_file(destination) != changed_hash
