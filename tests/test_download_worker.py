from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from openfetch.gui import main_window as gui_module
from openfetch.models import DownloadJob, DownloadOptions


def test_cancel_marks_current_and_unstarted_jobs_and_a_new_worker_can_run(
    tmp_path,
    monkeypatch,
):
    holder: dict[str, object] = {}
    download_calls: list[str] = []

    class CancellingEngine:
        def __init__(self, options, progress_callback=None, log_callback=None):
            self.cancel_called = False
            holder["engine"] = self

        def cancel(self) -> None:
            self.cancel_called = True

        def download(self, job):
            download_calls.append(job.job_id)
            holder["worker"].request_stop()
            return SimpleNamespace(
                success=False,
                message="Download cancelled by user",
                failure_category="download_cancelled",
            )

    monkeypatch.setattr(gui_module, "DownloadEngine", CancellingEngine)
    jobs = [DownloadJob(f"https://example.test/{index}") for index in range(3)]
    worker = gui_module.DownloadWorker(jobs, DownloadOptions(output_dir=tmp_path))
    holder["worker"] = worker
    finished: list[tuple[str, bool, str, str]] = []
    batches: list[bool] = []
    worker.job_finished.connect(lambda *args: finished.append(args))
    worker.batch_finished.connect(lambda: batches.append(True))

    worker.run()

    assert download_calls == [jobs[0].job_id]
    assert finished == [
        (jobs[0].job_id, False, "Download cancelled by user", "cancelled"),
        (jobs[1].job_id, False, "Cancelled", "cancelled"),
        (jobs[2].job_id, False, "Cancelled", "cancelled"),
    ]
    assert holder["engine"].cancel_called
    assert worker.current_job_id() is None
    assert batches == [True]

    second_calls: list[str] = []

    class SuccessfulEngine:
        def __init__(self, options, progress_callback=None, log_callback=None):
            pass

        def cancel(self) -> None:
            raise AssertionError("the second worker must not inherit cancellation")

        def download(self, job):
            second_calls.append(job.job_id)
            return SimpleNamespace(
                success=True,
                message="Download completed",
                failure_category="",
            )

    monkeypatch.setattr(gui_module, "DownloadEngine", SuccessfulEngine)
    second_job = DownloadJob("https://example.test/second-run")
    second_worker = gui_module.DownloadWorker(
        [second_job],
        DownloadOptions(output_dir=tmp_path),
    )
    second_finished: list[tuple[str, bool, str, str]] = []
    second_worker.job_finished.connect(lambda *args: second_finished.append(args))

    second_worker.run()

    assert second_calls == [second_job.job_id]
    assert second_finished == [(second_job.job_id, True, "Download completed", "")]
    assert not second_worker.stop_requested


def test_worker_always_finishes_batch_after_unexpected_engine_failure(tmp_path, monkeypatch):
    class ExplodingEngine:
        def __init__(self, options, progress_callback=None, log_callback=None):
            raise RuntimeError("controlled worker failure")

    monkeypatch.setattr(gui_module, "DownloadEngine", ExplodingEngine)
    job = DownloadJob("https://example.test/failure")
    worker = gui_module.DownloadWorker([job], DownloadOptions(output_dir=tmp_path))
    finished: list[tuple[str, bool, str, str]] = []
    logs: list[str] = []
    batches: list[bool] = []
    worker.job_finished.connect(lambda *args: finished.append(args))
    worker.log.connect(logs.append)
    worker.batch_finished.connect(lambda: batches.append(True))

    worker.run()

    assert finished == [
        (
            job.job_id,
            False,
            "Download failed unexpectedly. See the Activity Log for details.",
            "unknown_ytdlp_failure",
        )
    ]
    assert batches == [True]
    assert "controlled worker failure" in logs[0]
    assert worker.current_job_id() is None


def test_progress_preserves_activity_text_deduplicates_and_switches_to_cancelling(tmp_path):
    worker = gui_module.DownloadWorker([], DownloadOptions(output_dir=tmp_path))
    emitted: list[tuple[str, int, str, str]] = []
    worker.progress.connect(lambda *args: emitted.append(args))
    event = SimpleNamespace(
        job_id="job-1",
        status="Preparing YouTube metadata",
        percent=0,
        playlist_index=None,
        playlist_total=None,
        title="",
        speed="",
        eta="",
    )

    worker._on_progress(event)
    worker._on_progress(event)
    worker.request_stop()
    worker._on_progress(event)
    worker._on_progress(event)

    assert emitted == [
        ("job-1", 0, "Preparing YouTube metadata", ""),
        ("job-1", 0, "Cancelling", "Cancelling download"),
    ]


@pytest.fixture
def main_window(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(
        gui_module,
        "ensure_youtube_js_runtime",
        lambda: SimpleNamespace(found=True, diagnostic="JavaScript runtime found for test"),
    )
    monkeypatch.setattr(gui_module.MainWindow, "check_for_updates", lambda *args, **kwargs: None)
    window = gui_module.MainWindow()
    yield window
    window.worker = None
    window.close()
    app.processEvents()


def test_queue_reruns_failed_and_cancelled_but_not_completed_jobs(main_window):
    completed = DownloadJob("https://example.test/completed")
    failed = DownloadJob("https://example.test/failed")
    cancelled = DownloadJob("https://example.test/cancelled")
    for job in (completed, failed, cancelled):
        main_window._append_job(job)

    main_window._set_status(main_window.row_by_job_id[completed.job_id], "Done")
    main_window._set_status(main_window.row_by_job_id[failed.job_id], "Failed")
    main_window._set_status(main_window.row_by_job_id[cancelled.job_id], "Cancelled")

    assert main_window._runnable_jobs() == [failed, cancelled]


def test_stop_immediately_marks_active_row_and_finished_cleanup_is_identity_safe(main_window):
    job = DownloadJob("https://example.test/active")
    main_window._append_job(job)
    main_window.active_job_id = job.job_id
    main_window._set_running_state(True)

    class FakeWorker:
        stop_requested = False

        def isRunning(self) -> bool:  # noqa: N802 - mirrors QThread's Qt API
            return True

        def request_stop(self) -> str:
            self.stop_requested = True
            return job.job_id

    active_worker = FakeWorker()
    stale_worker = FakeWorker()
    main_window.worker = active_worker

    main_window.stop_queue()

    row = main_window.row_by_job_id[job.job_id]
    assert main_window.table.item(row, 2).text() == "Cancelling"
    assert main_window.table.item(row, 4).text() == "Cancelling download"
    assert not main_window.stop_button.isEnabled()

    main_window.on_batch_finished(stale_worker)
    assert main_window.worker is active_worker

    main_window.on_batch_finished(active_worker)
    assert main_window.worker is None
    assert main_window.start_button.isEnabled()
    assert main_window.statusBar().currentMessage() == "Queue stopped"
