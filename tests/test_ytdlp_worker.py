import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from openfetch.core import ytdlp_worker
from openfetch.core.pot_provider import PROVIDER_EXTRACTOR_KEY

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolate_plugin_configuration(monkeypatch):
    monkeypatch.setattr(
        ytdlp_worker,
        "configure_yt_dlp_plugins",
        lambda *, enable_po_provider: None,
    )


def _parse_protocol_frames(output: bytes) -> list[dict]:
    lines = output.decode("utf-8").splitlines()
    assert lines
    assert all(line.startswith(ytdlp_worker.PROTOCOL_PREFIX) for line in lines)
    return [json.loads(line.removeprefix(ytdlp_worker.PROTOCOL_PREFIX)) for line in lines]


def test_worker_download_protocol_reports_phase_metadata_progress_and_success(monkeypatch):
    events = []
    captured_options = {}

    class FakeYoutubeDL:
        def __init__(self, options):
            captured_options.update(options)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def extract_info(self, url, download=False):
            assert download is False
            return {
                "formats": [
                    {
                        "format_id": "18",
                        "ext": "mp4",
                        "vcodec": "avc1",
                        "acodec": "mp4a",
                        "height": 360,
                    }
                ]
            }

        def download(self, urls):
            captured_options["progress_hooks"][0](
                {
                    "status": "downloading",
                    "downloaded_bytes": 50,
                    "total_bytes": 100,
                    "info_dict": {"title": "Offline fake"},
                }
            )
            return 0

    monkeypatch.setattr(
        ytdlp_worker, "_emit", lambda kind, **payload: events.append((kind, payload))
    )
    monkeypatch.setattr(ytdlp_worker.yt_dlp, "YoutubeDL", FakeYoutubeDL)

    exit_code = ytdlp_worker.run_worker(
        {
            "url": "https://www.youtube.com/watch?v=offline",
            "options": {"format": "18", "cookiesfrombrowser": ["firefox"]},
            "playlist": False,
            "mode": "download",
            "activity_label": "Downloading video",
        }
    )

    assert exit_code == 0
    assert captured_options["cookiesfrombrowser"] == ("firefox",)
    assert [kind for kind, _payload in events] == [
        "phase",
        "metadata",
        "phase",
        "progress",
        "result",
    ]
    assert events[1][1]["formats"][0]["format_id"] == "18"


def test_worker_discovery_removes_requested_selector_and_never_downloads(monkeypatch):
    events = []
    captured_options = {}

    class FakeYoutubeDL:
        def __init__(self, options):
            captured_options.update(options)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def extract_info(self, url, download=False):
            return {
                "formats": [
                    {
                        "format_id": "140",
                        "ext": "m4a",
                        "vcodec": "none",
                        "acodec": "mp4a",
                    }
                ]
            }

        def download(self, urls):
            raise AssertionError("format discovery must never download media")

    monkeypatch.setattr(
        ytdlp_worker, "_emit", lambda kind, **payload: events.append((kind, payload))
    )
    monkeypatch.setattr(ytdlp_worker.yt_dlp, "YoutubeDL", FakeYoutubeDL)

    exit_code = ytdlp_worker.run_worker(
        {
            "url": "https://www.youtube.com/watch?v=offline",
            "options": {"format": "unavailable-progressive-selector"},
            "playlist": False,
            "mode": "discover",
        }
    )

    assert exit_code == 0
    assert "format" not in captured_options
    assert captured_options["skip_download"] is True
    assert captured_options["ignore_no_formats_error"] is True
    assert any(kind == "metadata" for kind, _payload in events)


def test_worker_failure_reports_phase_and_traceback_without_crashing_protocol(monkeypatch):
    events = []

    class FailingYoutubeDL:
        def __init__(self, options):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def extract_info(self, url, download=False):
            raise RuntimeError("controlled offline failure")

    monkeypatch.setattr(
        ytdlp_worker, "_emit", lambda kind, **payload: events.append((kind, payload))
    )
    monkeypatch.setattr(ytdlp_worker.yt_dlp, "YoutubeDL", FailingYoutubeDL)

    exit_code = ytdlp_worker.run_worker(
        {
            "url": "https://www.youtube.com/watch?v=offline",
            "options": {},
            "playlist": False,
            "mode": "download",
        }
    )

    assert exit_code == 1
    error = next(payload for kind, payload in events if kind == "error")
    assert error["phase"] == "preflight"
    assert error["message"] == "controlled offline failure"
    assert "RuntimeError" in error["traceback"]


@pytest.mark.parametrize(
    ("extractor_args", "expected_provider_enabled"),
    [
        (
            {
                "youtube": {
                    "player_client": ["default"],
                    "fetch_pot": ["never"],
                    "pot_trace": ["false"],
                }
            },
            False,
        ),
        (
            {
                "youtube": {
                    "player_client": ["mweb"],
                    "fetch_pot": ["auto"],
                    "pot_trace": ["false"],
                },
                PROVIDER_EXTRACTOR_KEY: {"protocol": ["1"]},
            },
            True,
        ),
    ],
)
def test_worker_enables_provider_only_for_structured_bounded_attempt(
    monkeypatch,
    extractor_args,
    expected_provider_enabled,
):
    configured = []

    class FakeYoutubeDL:
        def __init__(self, options):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def extract_info(self, url, download=False):
            return {"formats": []}

    monkeypatch.setattr(
        ytdlp_worker,
        "configure_yt_dlp_plugins",
        lambda *, enable_po_provider: configured.append(enable_po_provider),
    )
    monkeypatch.setattr(ytdlp_worker, "_emit", lambda kind, **payload: None)
    monkeypatch.setattr(ytdlp_worker.yt_dlp, "YoutubeDL", FakeYoutubeDL)

    exit_code = ytdlp_worker.run_worker(
        {
            "url": "https://www.youtube.com/watch?v=offline",
            "options": {"extractor_args": extractor_args},
            "playlist": False,
            "mode": "discover",
        }
    )

    assert exit_code == 0
    assert configured == [expected_provider_enabled]


def test_provider_startup_failure_is_categorized_and_redacted(monkeypatch):
    events = []
    secret = "opaque-provider-secret-123456"

    def fail_configuration(*, enable_po_provider):
        assert enable_po_provider is True
        raise RuntimeError(f"PoTokenResponse(po_token={secret})")

    monkeypatch.setattr(ytdlp_worker, "configure_yt_dlp_plugins", fail_configuration)
    monkeypatch.setattr(
        ytdlp_worker, "_emit", lambda kind, **payload: events.append((kind, payload))
    )

    exit_code = ytdlp_worker.run_worker(
        {
            "url": "https://www.youtube.com/watch?v=offline",
            "options": {
                "extractor_args": {
                    "youtube": {"player_client": ["mweb"], "fetch_pot": ["auto"]},
                    PROVIDER_EXTRACTOR_KEY: {"protocol": ["1"]},
                }
            },
            "mode": "download",
        }
    )

    assert exit_code == 1
    assert len(events) == 1
    kind, payload = events[0]
    assert kind == "error"
    assert payload["phase"] == "startup"
    assert payload["message"].startswith("external_po_helper_unavailable:")
    assert secret not in payload["message"]
    assert "<redacted>" in payload["message"]


def test_protocol_redacts_po_token_material_recursively(monkeypatch):
    stream = io.BytesIO()
    secret = "opaque-provider-secret-123456"
    monkeypatch.setattr(ytdlp_worker, "_PROTOCOL_STREAM", stream)

    ytdlp_worker._emit(
        "log",
        message=f"PoTokenResponse(po_token={secret}, visitor_data={secret})",
        details={
            "generated": f"Generated PO Token: {secret}",
            "url": f"https://provider.invalid/pot/{secret}?pot={secret}",
        },
    )

    raw = stream.getvalue()
    assert secret.encode() not in raw
    event = _parse_protocol_frames(raw)[0]
    assert event["message"].count("<redacted>") == 2
    assert "<redacted>" in event["details"]["generated"]
    assert "<redacted>" in event["details"]["url"]


def test_protocol_stdout_is_unicode_json_without_unframed_logging(monkeypatch):
    stream = io.BytesIO()
    monkeypatch.setattr(ytdlp_worker, "_PROTOCOL_STREAM", stream)

    ytdlp_worker._emit(
        "metadata",
        title="Beyoncé 🛡️ 日本語 العربية",
        filepath=r"C:\Téléchargements\日本語\🚀.mp4",
    )

    raw_frame = stream.getvalue()
    line = raw_frame.decode("utf-8")
    assert line.count("\n") == 1
    assert line.startswith(ytdlp_worker.PROTOCOL_PREFIX)
    assert "日本語" in line
    event = json.loads(line.removeprefix(ytdlp_worker.PROTOCOL_PREFIX))
    assert event == {
        "kind": "metadata",
        "title": "Beyoncé 🛡️ 日本語 العربية",
        "filepath": r"C:\Téléchargements\日本語\🚀.mp4",
    }


def test_malformed_worker_json_emits_one_deterministic_error_event(monkeypatch):
    protocol_stream = io.BytesIO()
    monkeypatch.setattr(ytdlp_worker, "_PROTOCOL_STREAM", protocol_stream)
    monkeypatch.setattr(
        ytdlp_worker,
        "_stdio_stream",
        lambda fd, fallback, mode: io.StringIO("{not-json") if fd == 0 else fallback,
    )

    assert ytdlp_worker.main() == 2

    events = _parse_protocol_frames(protocol_stream.getvalue())
    assert len(events) == 1
    event = events[0]
    assert event["kind"] == "error"
    assert event["phase"] == "startup"
    assert event["message"].startswith("Invalid internal request:")


def test_partial_binary_writes_keep_sequential_unicode_frames_complete(monkeypatch):
    class PartialWriter(io.BytesIO):
        def write(self, value):
            return super().write(bytes(value[:7]))

    stream = PartialWriter()
    monkeypatch.setattr(ytdlp_worker, "_PROTOCOL_STREAM", stream)

    ytdlp_worker.ProtocolLogger().debug(ytdlp_worker.PROTOCOL_SMOKE_TITLE)
    ytdlp_worker.ProtocolLogger().warning("字幕 ❤️ Русская музыка العربية")

    events = _parse_protocol_frames(stream.getvalue())
    assert [event["kind"] for event in events] == ["log", "log"]
    assert events[0]["message"] == ytdlp_worker.PROTOCOL_SMOKE_TITLE
    assert events[1]["message"] == "WARNING: 字幕 ❤️ Русская музыка العربية"


def test_worker_protocol_survives_cp1252_environment_with_all_unicode_classes():
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(PROJECT_ROOT / "src"), existing_pythonpath) if part
    )
    environment["PYTHONUTF8"] = "0"
    environment["PYTHONIOENCODING"] = "cp1252"

    completed = subprocess.run(
        [sys.executable, "-m", "openfetch.core.ytdlp_worker"],
        input=json.dumps({"mode": "protocol_smoke"}).encode("utf-8"),
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=environment,
        shell=False,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0
    assert b"UnicodeEncodeError" not in completed.stderr
    assert completed.stderr == b""
    events = _parse_protocol_frames(completed.stdout)
    assert len(events) == 2
    assert [event["sequence"] for event in events] == [0, 1]
    for event in events:
        assert event["title"] == ytdlp_worker.PROTOCOL_SMOKE_TITLE
        assert "｜" in event["title"]
        assert event["subtitle_destination"].endswith("夜の名曲.srt")
        assert "❤️" in event["emoji"]
        assert event["cjk"] == "日本語 中文 한국어"
        assert event["cyrillic"] == "Русская музыка"
        assert event["arabic"] == "الموسيقى العربية"
        assert event["combining"] == "Cafe\u0301"
        assert len(event["long_windows_path"]) > 260
