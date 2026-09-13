import subprocess
from types import SimpleNamespace

from openfetch.core import diagnostics
from openfetch.core.auth import AuthResolution, AuthStrategy, CookieFileStatus
from openfetch.core.downloader import YtdlpRunResult
from openfetch.core.js_runtime import JavaScriptRuntimeStatus
from openfetch.models import DownloadOptions


def test_diagnostics_never_logs_cookie_contents(tmp_path):
    cookie_file = tmp_path / "cookies.txt"
    cookie_file.write_text(
        "# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tFALSE\t0\tSID\tsuper-secret-token\n",
        encoding="utf-8",
    )

    report = diagnostics.run_support_diagnostics(
        DownloadOptions(output_dir=tmp_path / "out", cookie_file=cookie_file),
        run_probe=False,
        check_github=False,
    )
    text = report.text()

    assert "super-secret-token" not in text
    assert "contents=not logged" in text
    assert "size=" in text
    assert str(cookie_file) in text


def test_format_probe_is_safe_and_uses_js_runtime(tmp_path, monkeypatch):
    node_path = tmp_path / "node.exe"
    captured_opts = {}
    auth_resolution = AuthResolution(
        strategies=[
            AuthStrategy(
                kind="none",
                display_name="no authentication",
                ydl_options={},
                attempted_auth=False,
            )
        ],
        messages=[],
        cookie_file_status=CookieFileStatus(None, False, "cookies.txt not loaded"),
        browser_source=None,
        browser_sources=[],
    )

    class FakeDownloadEngine:
        def __init__(self, options):
            self.js_runtime_status = JavaScriptRuntimeStatus(True, "node", node_path, "v22.17.0")

        def _run_yt_dlp(self, url, options, *, discover_only=False):
            assert discover_only
            captured_opts.update(options)
            return YtdlpRunResult(
                formats=[
                    {
                        "format_id": "18",
                        "ext": "mp4",
                        "vcodec": "avc1",
                        "acodec": "mp4a",
                        "protocol": "https",
                    }
                ]
            )

    def fake_run_command(args: list[str], *, timeout: int):
        if args and args[0] == "tasklist":
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout="v22.17.0\n", stderr="")
        if "-e" in args:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="openfetch-node-ok",
                stderr="",
            )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(
        diagnostics,
        "ensure_youtube_js_runtime",
        lambda: JavaScriptRuntimeStatus(True, "node", node_path, "v22.17.0"),
    )
    monkeypatch.setattr(
        diagnostics,
        "resolve_auth_strategies",
        lambda _cookie_file, **_kwargs: auth_resolution,
    )
    monkeypatch.setattr(diagnostics, "DownloadEngine", FakeDownloadEngine)
    monkeypatch.setattr(diagnostics, "_run_command", fake_run_command)

    report = diagnostics.run_support_diagnostics(
        DownloadOptions(output_dir=tmp_path / "out"),
        probe_url="https://www.youtube.com/watch?v=abc123",
        check_github=False,
    )

    assert captured_opts["listformats"] is True
    assert captured_opts["skip_download"] is True
    assert captured_opts["simulate"] == "list_only"
    assert captured_opts["noplaylist"] is True
    assert captured_opts["js_runtimes"] == {"node": {"path": str(node_path)}}
    assert captured_opts["remote_components"] == ["ejs:github"]
    assert captured_opts["extractor_args"]["youtube"] == {
        "player_client": ["default"],
        "fetch_pot": ["never"],
        "pot_trace": ["false"],
    }
    assert (
        "[PASS] EJS GitHub remote component: --remote-components ejs:github enabled"
        in report.text()
    )
    assert "[PASS] Safe yt-dlp format probe: 1 formats" in report.text()


def test_provider_diagnostic_redacts_token_and_binding_material(monkeypatch):
    secret = "opaque-provider-secret-123456"
    provider = SimpleNamespace(
        status=SimpleNamespace(
            available=False,
            bundled=False,
            diagnostic=(
                f"PoTokenResponse(po_token={secret}, visitor_data={secret}); "
                f"request=https://provider.invalid/pot/{secret}?pot={secret}"
            ),
        )
    )
    monkeypatch.setattr(diagnostics, "get_po_token_provider", lambda: provider)
    items = []

    diagnostics._add_po_token_provider(items)

    assert len(items) == 1
    assert items[0].name == "Optional external PO Token helper"
    assert secret not in items[0].detail
    assert "<redacted>" in items[0].detail
