"""Compatibility with updates installed by an existing Neural Extractor V3.

An installed Neural Extractor 3.0.4-3.0.8 downloads the legacy-named copy of an
OpenFetch release, replaces ``NeuralExtractorV3.exe`` in place, and starts it
with a transaction reference below ``%LOCALAPPDATA%\\NeuralExtractorV3``. The
old helper rolls the update back unless OpenFetch confirms that exact
transaction, so these guarantees are what makes the upgrade path work.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openfetch import config
from openfetch.core import update_installer as installer_module
from openfetch.core.update_installer import (
    RESULT_FILENAME,
    cleanup_legacy_update_state,
    read_update_recovery_message,
    write_transaction_startup_confirmation,
)
from openfetch.core.update_ownership import TransactionState
from openfetch.core.updater import UpdateError
from tests.test_update_installer import CONFIRMATION_TOKEN, TOKEN, VERSION, write_transaction


@pytest.mark.parametrize(
    "name",
    [
        "OpenFetch.exe",
        "OpenFetch-3.1.0-windows-x64.exe",
        "NeuralExtractorV3.exe",
        "NeuralExtractorV3-3.0.8-windows-x64.exe",
        "neuralextractorv3.exe",
    ],
)
def test_openfetch_and_upgraded_legacy_filenames_are_official(name):
    assert installer_module._official_target_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "OpenFetch-Updater.exe",
        "NeuralExtractorV3-Updater.exe",
        "NeuralExtractor.exe",
        "OpenFetch-3.1-windows-x64.exe",
        "Other.exe",
    ],
)
def test_other_filenames_are_not_official(name):
    assert not installer_module._official_target_name(name)


def _legacy_local_app_data(tmp_path, monkeypatch):
    local = tmp_path / "LocalAppData"
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(
        installer_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path / "not-the-system-temp"),
    )
    return local


def test_openfetch_confirms_a_transaction_left_by_an_installed_neural_extractor(
    tmp_path, monkeypatch
):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    scenario = write_transaction(
        local / "NeuralExtractorV3",
        state=TransactionState.AWAITING_CONFIRMATION,
        executable_stem="NeuralExtractorV3",
    )
    assert scenario.root == installer_module.legacy_update_root()
    assert scenario.target.name == "NeuralExtractorV3.exe"
    assert scenario.staged.name == "NeuralExtractorV3-3.0.4-windows-x64.exe"

    # No updates_root is passed: this is exactly how app.py confirms startup.
    write_transaction_startup_confirmation(
        scenario.transaction_path,
        version=VERSION,
        identity_provider=scenario.identities,
    )

    payload = json.loads(scenario.marker.read_text(encoding="utf-8"))
    assert payload["transaction_id"] == TOKEN
    assert payload["confirmation_token"] == CONFIRMATION_TOKEN
    assert payload["version"] == VERSION
    assert payload["status"] == "initialized"


def test_openfetch_still_confirms_its_own_transactions(tmp_path, monkeypatch):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    scenario = write_transaction(
        local / "OpenFetch", state=TransactionState.AWAITING_CONFIRMATION
    )
    assert scenario.root == installer_module.update_root()

    write_transaction_startup_confirmation(
        scenario.transaction_path,
        version=VERSION,
        identity_provider=scenario.identities,
    )

    assert json.loads(scenario.marker.read_text(encoding="utf-8"))["transaction_id"] == TOKEN


def test_a_transaction_outside_both_update_roots_is_rejected(tmp_path, monkeypatch):
    _legacy_local_app_data(tmp_path, monkeypatch)
    scenario = write_transaction(
        tmp_path / "elsewhere",
        state=TransactionState.AWAITING_CONFIRMATION,
        executable_stem="NeuralExtractorV3",
    )

    with pytest.raises(UpdateError) as raised:
        write_transaction_startup_confirmation(
            scenario.transaction_path,
            version=VERSION,
            identity_provider=scenario.identities,
        )

    assert raised.value.code == "invalid_transaction"
    assert not scenario.marker.exists()


def test_rollback_status_from_a_legacy_transaction_is_readable(tmp_path, monkeypatch):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    scenario = write_transaction(local / "NeuralExtractorV3", executable_stem="NeuralExtractorV3")
    (scenario.transaction_path.parent / RESULT_FILENAME).write_text(
        json.dumps({"status": "rollback_succeeded"}), encoding="utf-8"
    )

    message = read_update_recovery_message(scenario.transaction_path)

    assert message == (
        "The update failed to start correctly. OpenFetch restored and restarted the "
        "previous version."
    )


def test_legacy_environment_overrides_remain_supported(monkeypatch):
    monkeypatch.delenv("OPENFETCH_UPDATER_STARTUP_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setenv("NEURAL_EXTRACTOR_UPDATER_STARTUP_TIMEOUT_SECONDS", "17")
    assert installer_module._bounded_environment_seconds(
        "UPDATER_STARTUP_TIMEOUT_SECONDS", 60, 3, 300
    ) == 17

    monkeypatch.setenv("OPENFETCH_UPDATER_STARTUP_TIMEOUT_SECONDS", "23")
    assert installer_module._bounded_environment_seconds(
        "UPDATER_STARTUP_TIMEOUT_SECONDS", 60, 3, 300
    ) == 23


def test_legacy_data_directory_is_located_but_never_created(tmp_path, monkeypatch):
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    legacy = config.legacy_app_data_dir()

    assert legacy == tmp_path / "NeuralExtractorV3"
    assert not legacy.exists()
    assert config.app_data_dir() == tmp_path / "OpenFetch"


def _finished_legacy_transaction(
    local: Path,
    state: str = TransactionState.CONFIRMED.value,
    transaction_id: str = "A" * 48,
):
    """A legacy updates root in the state an installed Neural Extractor leaves."""
    scenario = write_transaction(
        local / "NeuralExtractorV3",
        state=TransactionState.HANDED_OFF,
        executable_stem="NeuralExtractorV3",
        transaction_id=transaction_id,
    )
    payload = json.loads(scenario.transaction_path.read_text(encoding="utf-8"))
    payload["state"] = state
    scenario.transaction_path.write_text(json.dumps(payload), encoding="utf-8")
    (scenario.transaction_path.parent / RESULT_FILENAME).write_text(
        json.dumps({"status": "success"}), encoding="utf-8"
    )
    helper = (
        local
        / "NeuralExtractorV3"
        / "updater-helper"
        / payload["target_identity"]
        / payload["transaction_id"]
        / "NeuralExtractorV3-Updater.exe"
    )
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"legacy helper copy")
    # A finished legacy helper has released its ownership record.
    ownership = scenario.root / "ownership" / f"{payload['target_identity']}.json"
    if ownership.exists():
        ownership.unlink()
    return scenario, helper


def test_finished_legacy_update_state_is_reclaimed_after_the_migration(tmp_path, monkeypatch):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    scenario, helper = _finished_legacy_transaction(local)
    assert scenario.staged.exists() and helper.exists()

    cleanup_legacy_update_state()

    assert not scenario.transaction_path.parent.exists(), "legacy transaction was retained"
    assert not scenario.staged.exists(), "legacy staged package was retained"
    assert not helper.exists(), "legacy detached helper copy was retained"
    assert scenario.target.exists(), "the upgraded executable must never be touched"


def test_unfinished_legacy_update_state_is_never_touched(tmp_path, monkeypatch):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    scenario, helper = _finished_legacy_transaction(
        local, state=TransactionState.AWAITING_CONFIRMATION.value
    )

    cleanup_legacy_update_state()

    assert scenario.transaction_path.exists()
    assert scenario.staged.exists()
    assert helper.exists()


def test_legacy_state_owned_by_a_live_helper_is_never_touched(tmp_path, monkeypatch):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    scenario, helper = _finished_legacy_transaction(local)
    payload = json.loads(scenario.transaction_path.read_text(encoding="utf-8"))
    ownership = scenario.root / "ownership" / f"{payload['target_identity']}.json"
    ownership.parent.mkdir(parents=True, exist_ok=True)
    ownership.write_text(json.dumps({"transaction_id": payload["transaction_id"]}), "utf-8")

    cleanup_legacy_update_state()

    assert scenario.transaction_path.exists()
    assert helper.exists()


def test_a_shared_staged_package_survives_while_another_transaction_remains(
    tmp_path, monkeypatch
):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    finished, finished_helper = _finished_legacy_transaction(local)
    in_flight_dir = finished.staged.parent.parent / ("B" * 48)
    in_flight_dir.mkdir()
    (in_flight_dir / finished.transaction_path.name).write_text(
        finished.transaction_path.read_text(encoding="utf-8").replace(
            "A" * 48, "B" * 48
        ).replace(TransactionState.CONFIRMED.value, TransactionState.HANDED_OFF.value),
        encoding="utf-8",
    )

    cleanup_legacy_update_state()

    assert not finished.transaction_path.exists(), "the finished transaction was retained"
    assert not finished_helper.exists()
    assert finished.staged.exists(), "a shared staged package was removed too early"
    assert in_flight_dir.exists()


def test_legacy_cleanup_does_nothing_without_a_legacy_directory(tmp_path, monkeypatch):
    local = _legacy_local_app_data(tmp_path, monkeypatch)
    openfetch_scenario = write_transaction(local / "OpenFetch")

    cleanup_legacy_update_state()

    assert openfetch_scenario.transaction_path.exists(), "the OpenFetch root must be untouched"
    assert openfetch_scenario.staged.exists()


def test_post_update_start_defers_the_legacy_cleanup():
    """The legacy helper is still finishing while the confirming start runs."""
    source = (Path(__file__).resolve().parents[1] / "src" / "openfetch" / "app.py").read_text(
        encoding="utf-8"
    )
    block = source.split("def cleanup_all_stale_update_state()", 1)[1].split("QTimer", 1)[0]
    assert "if not args.post_update_transaction:" in block
    assert "cleanup_legacy_update_state()" in block
