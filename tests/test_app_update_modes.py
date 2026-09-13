from pathlib import Path

import pytest

from openfetch import app as app_module


def test_apply_update_mode_dispatches_before_gui_initialization(monkeypatch, tmp_path):
    transaction = tmp_path / "transaction.json"
    calls = []

    monkeypatch.setattr(
        app_module,
        "run_update_helper",
        lambda path: calls.append(Path(path)) or 17,
    )
    monkeypatch.setattr(
        app_module,
        "run_gui",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("GUI must not initialize in updater-helper mode")
        ),
    )

    assert app_module.main(["--apply-update", str(transaction)]) == 17
    assert calls == [transaction]


def test_apply_directory_update_mode_dispatches_before_gui_initialization(
    monkeypatch, tmp_path
):
    transaction = tmp_path / "directory-transaction.json"
    calls = []

    monkeypatch.setattr(
        app_module,
        "run_directory_update_helper",
        lambda path: calls.append(Path(path)) or 21,
    )
    monkeypatch.setattr(
        app_module,
        "run_gui",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("GUI must not initialize in updater-helper mode")
        ),
    )

    assert app_module.main(["--apply-directory-update", str(transaction)]) == 21
    assert calls == [transaction]


def test_post_update_confirmation_arguments_must_be_complete(tmp_path):
    marker = tmp_path / "marker.json"

    assert app_module.main(["--post-update-marker", str(marker)]) == 2
    assert app_module.main(["--post-update-token", "A" * 48]) == 2
    assert (
        app_module.main(
            [
                "--post-update-transaction",
                str(tmp_path / "transaction.json"),
                "--post-update-token",
                "A" * 48,
                "--post-update-marker",
                str(marker),
            ]
        )
        == 2
    )


def test_private_update_arguments_are_hidden_from_help(capsys):
    with pytest.raises(SystemExit):
        app_module._parse_args(["--help"])
    help_text = capsys.readouterr().out

    assert "--apply-update" not in help_text
    assert "--apply-directory-update" not in help_text
    assert "--post-update-token" not in help_text
    assert "--post-update-marker" not in help_text
    assert "--post-update-transaction" not in help_text
    assert "--update-rollback-status" not in help_text
