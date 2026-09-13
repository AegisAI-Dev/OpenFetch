from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from openfetch.config import GITHUB_REPO
from openfetch.core.update_manifest import UpdateManifest, expected_exe_filename
from openfetch.core.update_ownership import TransactionState
from openfetch.core.updater import UpdateDownloader, UpdateError, UpdateInfo
from openfetch.gui import main_window as gui_module

TRANSACTION_A = "a" * 64
TRANSACTION_B = "b" * 64


class FakeResponse:
    def __init__(self, url: str, chunks: list[bytes]) -> None:
        self.url = url
        self._chunks = chunks
        self.headers = {"Content-Length": str(sum(len(chunk) for chunk in chunks))}
        self.closed = False

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int) -> object:
        del chunk_size
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, response: FakeResponse | None = None) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        if self.response is None:
            raise AssertionError("A verified cache entry must not make a network request.")
        return self.response


def _update_info(content: bytes, version: str = "3.0.5") -> UpdateInfo:
    filename = expected_exe_filename(version)
    sha256 = hashlib.sha256(content).hexdigest()
    tag_name = f"v{version}"
    download_url = f"https://github.com/{GITHUB_REPO}/releases/download/{tag_name}/{filename}"
    manifest = UpdateManifest(
        schema_version=1,
        application_name="OpenFetch",
        release_version=version,
        asset_filename=filename,
        asset_sha256=sha256,
        asset_size=len(content),
        platform="windows",
        architecture="x64",
        channel="stable",
        minimum_updater_version="3.0.4",
    )
    return UpdateInfo(
        version=version,
        tag_name=tag_name,
        name=f"OpenFetch v{version}",
        html_url=f"https://github.com/{GITHUB_REPO}/releases/tag/{tag_name}",
        download_url=download_url,
        manifest_url=f"{download_url}.manifest.json",
        checksum_url=f"{download_url}.sha256",
        published_at="2026-07-15T00:00:00Z",
        body="Updater boundary fixture",
        download_size=len(content),
        sha256=sha256,
        manifest=manifest,
    )


@pytest.mark.parametrize(
    "state",
    [
        TransactionState.CHECKING,
        TransactionState.DOWNLOADING,
        TransactionState.DOWNLOADED,
    ],
)
def test_update_install_worker_allows_cancellation_only_before_verification(state) -> None:
    worker = gui_module.UpdateInstallWorker(SimpleNamespace())
    worker.transaction_state = state

    assert worker.can_cancel()
    assert worker.request_cancel()


@pytest.mark.parametrize(
    "state",
    [
        TransactionState.VERIFIED,
        TransactionState.HELPER_PREPARED,
        TransactionState.HANDOFF_PENDING,
        TransactionState.HANDED_OFF,
        TransactionState.WAITING_FOR_PARENT_EXIT,
        TransactionState.BACKING_UP,
        TransactionState.REPLACING,
        TransactionState.LAUNCHING,
        TransactionState.AWAITING_CONFIRMATION,
        TransactionState.CONFIRMED,
        TransactionState.ROLLING_BACK,
        TransactionState.ROLLED_BACK,
        TransactionState.FAILED,
    ],
)
def test_update_install_worker_rejects_cancellation_at_and_after_verification(state) -> None:
    worker = gui_module.UpdateInstallWorker(SimpleNamespace())
    worker.transaction_state = state

    assert not worker.can_cancel()
    assert not worker.request_cancel()
    assert not worker.cancel_requested


def test_update_install_worker_honors_cancel_before_verified_handoff(monkeypatch) -> None:
    worker = gui_module.UpdateInstallWorker(SimpleNamespace())
    cancelled: list[bool] = []
    cancellation_locked: list[bool] = []
    prepare_calls: list[object] = []

    class CancellingDownloader:
        def stage(self, info, **kwargs):
            del info, kwargs
            assert worker.request_cancel()
            return Path("verified-package.exe")

    monkeypatch.setattr(gui_module, "UpdateDownloader", CancellingDownloader)
    monkeypatch.setattr(
        gui_module,
        "prepare_and_launch_update",
        lambda *args, **kwargs: prepare_calls.append((args, kwargs)),
    )
    worker.cancelled.connect(lambda: cancelled.append(True))
    worker.cancellation_locked.connect(lambda: cancellation_locked.append(True))

    worker.run()

    assert cancelled == [True]
    assert cancellation_locked == []
    assert prepare_calls == []
    assert worker.transaction_state is TransactionState.FAILED


def test_update_install_worker_locks_cancel_before_helper_handoff(monkeypatch) -> None:
    info = SimpleNamespace()
    worker = gui_module.UpdateInstallWorker(info)
    staged = Path("verified-package.exe")
    prepared_result = SimpleNamespace(helper_pid=1234)
    cancel_results: list[bool] = []
    prepare_calls: list[tuple[object, Path, dict[str, object]]] = []
    prepared_signals: list[object] = []

    class SuccessfulDownloader:
        def stage(self, staged_info, **kwargs):
            assert staged_info is info
            assert kwargs["transaction_id"] == worker.transaction_id
            return staged

    def prepare(staged_info, staged_path, **kwargs):
        prepare_calls.append((staged_info, staged_path, kwargs))
        return prepared_result

    monkeypatch.setattr(gui_module, "UpdateDownloader", SuccessfulDownloader)
    monkeypatch.setattr(gui_module, "prepare_and_launch_update", prepare)
    worker.cancellation_locked.connect(lambda: cancel_results.append(worker.request_cancel()))
    worker.prepared.connect(prepared_signals.append)

    worker.run()

    assert cancel_results == [False]
    assert len(prepare_calls) == 1
    assert prepare_calls[0][0] is info
    assert prepare_calls[0][1] == staged
    assert prepare_calls[0][2]["transaction_id"] == worker.transaction_id
    assert prepared_signals == [prepared_result]
    assert worker.transaction_state is TransactionState.VERIFIED


def test_invalid_transaction_is_rejected_before_verified_cache_reuse(tmp_path) -> None:
    content = b"verified package"
    info = _update_info(content)
    cached = tmp_path / info.version / "package" / info.manifest.asset_filename
    cached.parent.mkdir(parents=True)
    cached.write_bytes(content)
    session = FakeSession()

    with pytest.raises(UpdateError) as exc_info:
        UpdateDownloader(session=session, update_root=tmp_path).stage(
            info,
            transaction_id="unsafe transaction/id",
        )

    assert exc_info.value.code == "invalid_transaction"
    assert cached.read_bytes() == content
    assert session.calls == []


def test_failed_transaction_removes_only_its_owned_part_file(tmp_path) -> None:
    content = b"expected package"
    info = _update_info(content)
    package_dir = tmp_path / info.version / "package"
    package_dir.mkdir(parents=True)
    other_part = package_dir / f".{info.manifest.asset_filename}.{TRANSACTION_B}.part"
    other_part.write_bytes(b"another live transaction")
    response = FakeResponse(info.download_url, [b"X" * len(content)])

    with pytest.raises(UpdateError) as exc_info:
        UpdateDownloader(
            session=FakeSession(response),
            update_root=tmp_path,
        ).stage(info, transaction_id=TRANSACTION_A)

    owned_part = package_dir / f".{info.manifest.asset_filename}.{TRANSACTION_A}.part"
    assert exc_info.value.code == "checksum_mismatch"
    assert not owned_part.exists()
    assert other_part.read_bytes() == b"another live transaction"
    assert response.closed
