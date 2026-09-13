"""Offline packaged smoke for the optional external PO helper boundary."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import MethodType, SimpleNamespace

from openfetch.core import downloader as downloader_module
from openfetch.core.auth import AuthResolution, AuthStrategy, CookieFileStatus
from openfetch.core.downloader import DownloadEngine, YtdlpRunResult
from openfetch.core.pot_provider import (
    PROVIDER_EXTRACTOR_KEY,
    configure_yt_dlp_plugins,
    get_po_token_provider,
    redact_po_token_material,
)
from openfetch.models import DownloadJob, DownloadOptions

_SMOKE_URL = "https://www.youtube.com/watch?v=offline-smoke"


def run_offline_provider_media_smoke() -> dict[str, bool]:
    """Prove that the main runtime remains usable with no helper installed."""
    helper = get_po_token_provider()
    status = helper.status
    calls: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="openfetch-provider-smoke-") as temporary:
        root = Path(temporary)
        application_data = root / "OpenFetch"
        resolution = AuthResolution(
            strategies=[AuthStrategy("none", "none", {}, attempted_auth=False)],
            messages=[],
            cookie_file_status=CookieFileStatus(None, False, "missing"),
            browser_source=None,
            browser_sources=[],
        )
        original_app_data_dir = downloader_module.app_data_dir
        original_resolver = downloader_module.resolve_auth_strategies
        downloader_module.app_data_dir = lambda: application_data
        downloader_module.resolve_auth_strategies = lambda *_args, **_kwargs: resolution
        try:
            engine = DownloadEngine(DownloadOptions(output_dir=root / "output"))
            # The smoke deliberately models the normal helper-absent state even
            # when a developer machine has an optional helper installed.
            engine.po_token_provider_status = SimpleNamespace(
                available=False,
                integrity_verified=False,
                diagnostic="Optional external PO Token helper is not installed (smoke).",
            )

            def fake_run(
                self: DownloadEngine,
                _url: str,
                options: dict,
                *,
                discover_only: bool = False,
            ) -> YtdlpRunResult:
                del self
                if discover_only:
                    raise AssertionError("normal helper-absent smoke must not discover")
                calls.append(options)
                return YtdlpRunResult()

            engine._run_yt_dlp = MethodType(fake_run, engine)  # type: ignore[method-assign]
            result = engine.download(DownloadJob(_SMOKE_URL))
            environment = engine._worker_environment(root / "attempt-temp")
        finally:
            downloader_module.app_data_dir = original_app_data_dir
            downloader_module.resolve_auth_strategies = original_resolver

    configure_yt_dlp_plugins(enable_po_provider=False)
    from yt_dlp.extractor.youtube.pot._registry import _pot_providers

    sentinel = "provider-token-sentinel-123456"
    redacted = redact_po_token_material(
        f"PoTokenResponse(po_token={sentinel}) https://x.invalid/pot/{sentinel}"
    )
    first_extractor_args = calls[0].get("extractor_args", {}) if calls else {}
    return {
        "external_helper_never_bundled": status.bundled is False,
        "helper_state_fail_closed": not status.available or status.integrity_verified,
        "normal_download_without_helper": result.success and len(calls) == 1,
        "normal_attempt_does_not_request_helper": (
            PROVIDER_EXTRACTOR_KEY not in first_extractor_args
        ),
        "no_provider_registered_by_default": not _pot_providers.value,
        "no_third_party_ytdlp_plugin_imported": not any(
            name == "yt_dlp_plugins" or name.startswith("yt_dlp_plugins.") for name in sys.modules
        ),
        "token_redaction": sentinel not in redacted,
        "attempt_cache_isolated": environment.get("XDG_CACHE_HOME", "").endswith(
            "attempt-temp\\cache"
        )
        or environment.get("XDG_CACHE_HOME", "").endswith("attempt-temp/cache"),
    }


__all__ = ["run_offline_provider_media_smoke"]
