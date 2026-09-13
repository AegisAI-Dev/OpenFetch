"""Support diagnostics for comparing OpenFetch Windows environments."""

from __future__ import annotations

import csv
import io
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from uuid import uuid4

from yt_dlp.version import __version__ as ytdlp_version

from openfetch.config import (
    APP_NAME,
    BUILD_LABEL,
    VERSION,
    YOUTUBE_EJS_REMOTE_COMPONENT,
    YOUTUBE_REMOTE_COMPONENTS,
    base_dir,
    bin_dir,
)
from openfetch.core.auth import (
    BROWSER_FALLBACK_ORDER,
    SUPPORTED_BROWSER_NAMES,
    AuthResolution,
    AuthStrategy,
    resolve_auth_strategies,
)
from openfetch.core.downloader import (
    DownloadEngine,
    YtdlpRunError,
)
from openfetch.core.format_selection import select_discovered_format
from openfetch.core.js_runtime import ensure_youtube_js_runtime
from openfetch.core.pot_provider import (
    get_po_token_provider,
    redact_po_token_material,
)
from openfetch.core.youtube_errors import FailureCategory, classify_youtube_failure
from openfetch.models import DownloadOptions

DEFAULT_DIAGNOSTIC_PROBE_URL = "https://www.youtube.com/watch?v=jNQXAC9IVRw"
EJS_GITHUB_RELEASES_URL = "https://github.com/yt-dlp/ejs/releases"
NODE_EXE_NAME = "node.exe" if sys.platform == "win32" else "node"
PROCESS_NAMES = {
    "chrome": "chrome.exe",
    "edge": "msedge.exe",
    "brave": "brave.exe",
    "firefox": "firefox.exe",
}


class DiagnosticStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class DiagnosticItem:
    name: str
    status: DiagnosticStatus
    detail: str

    def line(self) -> str:
        return f"[{self.status.value}] {self.name}: {self.detail}"


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    items: list[DiagnosticItem]

    def lines(self) -> list[str]:
        return [
            "OpenFetch environment diagnostics",
            *[item.line() for item in self.items],
        ]

    def text(self) -> str:
        return "\n".join(self.lines())


def run_support_diagnostics(
    options: DownloadOptions,
    probe_url: str | None = None,
    *,
    run_probe: bool = True,
    check_github: bool = True,
) -> DiagnosticReport:
    """Run non-destructive diagnostics for support comparisons."""
    items: list[DiagnosticItem] = []
    probe_url = probe_url or DEFAULT_DIAGNOSTIC_PROBE_URL

    js_runtime = ensure_youtube_js_runtime()
    auth_resolution = resolve_auth_strategies(
        options.cookie_file,
        dedicated_browser=options.dedicated_browser,
        dedicated_browser_profile=options.dedicated_browser_profile,
        dedicated_firefox_profile=options.dedicated_firefox_profile,
        allow_legacy_browser_fallback=options.legacy_browser_fallback,
    )

    _add_app_version(items)
    _add_windows_version(items)
    _add_runtime_mode(items)
    _add_bundled_node(items)
    _add_node_version(items, js_runtime.path)
    _add_ytdlp_version(items)
    _add_cache_status(items)
    _add_ffmpeg_status(items)
    _add_output_status(items, options.output_dir)
    _add_cookie_status(items, options.cookie_file)
    _add_browser_availability(items, auth_resolution)
    _add_youtube_connection(items, options)
    _add_po_token_provider(items)
    _add_browser_processes(items)
    _add_ejs_remote_status(items)
    if check_github:
        _add_ejs_github_access(items)
    _add_node_execution_status(items, js_runtime.path)
    if run_probe:
        _add_format_probe(items, options, probe_url, auth_resolution, js_runtime.ytdlp_options())

    return DiagnosticReport(items)


def _add_app_version(items: list[DiagnosticItem]) -> None:
    items.append(
        DiagnosticItem(
            "App version/build",
            DiagnosticStatus.PASS,
            f"{APP_NAME} {VERSION}, build {BUILD_LABEL}",
        )
    )


def _add_windows_version(items: list[DiagnosticItem]) -> None:
    win = platform.win32_ver()
    detail = f"{platform.platform()} (release={win[0] or 'unknown'}, build={win[1] or 'unknown'})"
    items.append(DiagnosticItem("Windows version", DiagnosticStatus.PASS, detail))


def _add_runtime_mode(items: list[DiagnosticItem]) -> None:
    mode = "packaged PyInstaller EXE" if getattr(sys, "frozen", False) else "Python source/runtime"
    items.append(
        DiagnosticItem("Packaged/runtime mode", DiagnosticStatus.PASS, f"{mode}; base={base_dir()}")
    )


def _add_bundled_node(items: list[DiagnosticItem]) -> None:
    bundled_node = bin_dir() / NODE_EXE_NAME
    status = DiagnosticStatus.PASS if bundled_node.exists() else DiagnosticStatus.WARNING
    items.append(
        DiagnosticItem(
            "Bundled node.exe exists",
            status,
            f"{bundled_node} exists={_yes_no(bundled_node.exists())}",
        )
    )


def _add_node_version(items: list[DiagnosticItem], node_path: Path | None) -> None:
    if not node_path:
        items.append(
            DiagnosticItem("Node version command", DiagnosticStatus.FAIL, "Node runtime not found")
        )
        return
    completed = _run_command([str(node_path), "--version"], timeout=8)
    if completed.returncode == 0:
        output = (completed.stdout or completed.stderr).strip()
        items.append(
            DiagnosticItem(
                "Node version command",
                DiagnosticStatus.PASS,
                f"{output or '<empty>'} via {node_path}",
            )
        )
    else:
        items.append(
            DiagnosticItem(
                "Node version command",
                DiagnosticStatus.FAIL,
                _command_failure_detail(completed),
            )
        )


def _add_ytdlp_version(items: list[DiagnosticItem]) -> None:
    items.append(DiagnosticItem("yt-dlp version", DiagnosticStatus.PASS, ytdlp_version))


def _add_cache_status(items: list[DiagnosticItem]) -> None:
    cache_dir = _ytdlp_cache_dir()
    writable, detail = _directory_writable(cache_dir, create=True)
    status = DiagnosticStatus.PASS if writable else DiagnosticStatus.FAIL
    items.append(
        DiagnosticItem("yt-dlp cache directory", status, f"{cache_dir}; writable={detail}")
    )


def _add_ffmpeg_status(items: list[DiagnosticItem]) -> None:
    bundled = bin_dir() / ("ffmpeg.exe" if sys.platform == "win32" else "ffmpeg")
    path_ffmpeg = shutil.which("ffmpeg")
    exists = bundled.exists() or bool(path_ffmpeg)
    status = DiagnosticStatus.PASS if exists else DiagnosticStatus.FAIL
    detail = (
        f"bundled={bundled} exists={_yes_no(bundled.exists())}; PATH={path_ffmpeg or 'not found'}"
    )
    items.append(DiagnosticItem("ffmpeg path exists", status, detail))


def _add_output_status(items: list[DiagnosticItem], output_dir: Path) -> None:
    writable, detail = _directory_writable(output_dir, create=True)
    status = DiagnosticStatus.PASS if writable else DiagnosticStatus.FAIL
    items.append(
        DiagnosticItem("Output folder writable", status, f"{output_dir}; writable={detail}")
    )


def _add_cookie_status(items: list[DiagnosticItem], cookie_file: Path | None) -> None:
    if not cookie_file:
        items.append(
            DiagnosticItem(
                "cookies.txt metadata", DiagnosticStatus.WARNING, "No cookies.txt selected"
            )
        )
        return

    path = Path(cookie_file).expanduser()
    if not path.exists():
        items.append(
            DiagnosticItem(
                "cookies.txt metadata",
                DiagnosticStatus.FAIL,
                f"{path}; exists=no",
            )
        )
        return
    try:
        stat = path.stat()
    except OSError as exc:
        items.append(
            DiagnosticItem(
                "cookies.txt metadata",
                DiagnosticStatus.FAIL,
                f"{path}; exists=yes; cannot stat file: {exc}",
            )
        )
        return

    modified = datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
    items.append(
        DiagnosticItem(
            "cookies.txt metadata",
            DiagnosticStatus.PASS,
            f"{path}; exists=yes; size={stat.st_size} bytes; modified={modified}; contents=not logged",
        )
    )


def _add_browser_availability(items: list[DiagnosticItem], auth_resolution: AuthResolution) -> None:
    available = {source.browser for source in auth_resolution.browser_sources}
    parts = []
    for browser in BROWSER_FALLBACK_ORDER:
        parts.append(f"{SUPPORTED_BROWSER_NAMES[browser]}={_yes_no(browser in available)}")
    status = DiagnosticStatus.PASS if available else DiagnosticStatus.WARNING
    items.append(DiagnosticItem("Browser fallback availability", status, ", ".join(parts)))


def _add_youtube_connection(items: list[DiagnosticItem], options: DownloadOptions) -> None:
    configured = bool(
        options.dedicated_browser
        and options.dedicated_browser_profile
        and options.dedicated_browser_last_verified
    )
    status = DiagnosticStatus.PASS if configured else DiagnosticStatus.WARNING
    detail = (
        f"Exact dedicated OpenFetch {options.dedicated_browser} provider configured; "
        f"last_verified={options.dedicated_browser_last_verified} (path redacted)"
        if configured
        else "Dedicated YouTube connection not configured"
    )
    items.append(DiagnosticItem("YouTube connection", status, detail))


def _add_po_token_provider(items: list[DiagnosticItem]) -> None:
    helper = get_po_token_provider()
    refresh_provider = getattr(helper, "refresh_status", None)
    provider = refresh_provider() if callable(refresh_provider) else helper.status
    status = (
        DiagnosticStatus.PASS
        if provider.available and provider.integrity_verified
        else DiagnosticStatus.WARNING
    )
    items.append(
        DiagnosticItem(
            "Optional external PO Token helper",
            status,
            redact_po_token_material(provider.diagnostic),
        )
    )


def _add_browser_processes(items: list[DiagnosticItem]) -> None:
    running_names, error = _running_process_names()
    if error:
        items.append(DiagnosticItem("Browser processes running", DiagnosticStatus.WARNING, error))
        return

    parts = []
    any_running = False
    for browser in BROWSER_FALLBACK_ORDER:
        process = PROCESS_NAMES[browser]
        running = process.lower() in running_names
        any_running = any_running or running
        parts.append(f"{SUPPORTED_BROWSER_NAMES[browser]}={_yes_no(running)}")
    status = DiagnosticStatus.WARNING if any_running else DiagnosticStatus.PASS
    detail = ", ".join(parts)
    if any_running:
        detail += "; close running browsers if browser cookie extraction fails"
    items.append(DiagnosticItem("Browser processes running", status, detail))


def _add_ejs_remote_status(items: list[DiagnosticItem]) -> None:
    enabled = YOUTUBE_EJS_REMOTE_COMPONENT in YOUTUBE_REMOTE_COMPONENTS
    status = DiagnosticStatus.PASS if enabled else DiagnosticStatus.WARNING
    detail = (
        f"--remote-components {YOUTUBE_EJS_REMOTE_COMPONENT} enabled"
        if enabled
        else f"--remote-components {YOUTUBE_EJS_REMOTE_COMPONENT} disabled; "
        "using bundled/cached challenge solver scripts"
    )
    items.append(DiagnosticItem("EJS GitHub remote component", status, detail))


def _add_ejs_github_access(items: list[DiagnosticItem]) -> None:
    request = urllib.request.Request(EJS_GITHUB_RELEASES_URL, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            status_code = getattr(response, "status", 0)
    except urllib.error.HTTPError as exc:
        status = DiagnosticStatus.PASS if exc.code < 400 else DiagnosticStatus.WARNING
        items.append(
            DiagnosticItem(
                "GitHub access for EJS",
                status,
                f"{EJS_GITHUB_RELEASES_URL}; HTTP {exc.code}",
            )
        )
    except (OSError, urllib.error.URLError) as exc:
        items.append(
            DiagnosticItem(
                "GitHub access for EJS",
                DiagnosticStatus.WARNING,
                f"{EJS_GITHUB_RELEASES_URL}; unreachable: {exc}",
            )
        )
    else:
        status = DiagnosticStatus.PASS if status_code < 400 else DiagnosticStatus.WARNING
        items.append(
            DiagnosticItem(
                "GitHub access for EJS",
                status,
                f"{EJS_GITHUB_RELEASES_URL}; HTTP {status_code}",
            )
        )


def _add_node_execution_status(items: list[DiagnosticItem], node_path: Path | None) -> None:
    if not node_path:
        items.append(
            DiagnosticItem(
                "node.exe antivirus/permission execution",
                DiagnosticStatus.FAIL,
                "Node runtime not found",
            )
        )
        return

    completed = _run_command(
        [str(node_path), "-e", "process.stdout.write('openfetch-node-ok')"],
        timeout=8,
    )
    if completed.returncode == 0 and completed.stdout.strip() == "openfetch-node-ok":
        items.append(
            DiagnosticItem(
                "node.exe antivirus/permission execution",
                DiagnosticStatus.PASS,
                f"node.exe executed successfully via {node_path}",
            )
        )
    else:
        items.append(
            DiagnosticItem(
                "node.exe antivirus/permission execution",
                DiagnosticStatus.FAIL,
                "node.exe failed to execute; possible antivirus or permission block: "
                f"{_command_failure_detail(completed)}",
            )
        )


def _add_format_probe(
    items: list[DiagnosticItem],
    options: DownloadOptions,
    probe_url: str,
    auth_resolution: AuthResolution,
    js_runtimes: dict[str, dict[str, str]],
) -> None:
    last_error = ""
    warnings: list[str] = []
    engine = DownloadEngine(options)

    public = next(
        (strategy for strategy in auth_resolution.strategies if not strategy.attempted_auth),
        None,
    )
    dedicated = next(
        (
            strategy
            for strategy in auth_resolution.strategies
            if strategy.is_dedicated_browser
            and strategy.browser == str(options.dedicated_browser or "").casefold()
        ),
        None,
    )
    strategies = [strategy for strategy in (public, dedicated) if strategy is not None]

    for index, auth_strategy in enumerate(strategies):
        probe_opts = _format_probe_options(options, auth_strategy, js_runtimes)
        command = _format_probe_command(probe_url, probe_opts)
        try:
            result = engine._run_yt_dlp(probe_url, probe_opts, discover_only=True)
        except YtdlpRunError as exc:
            analysis = classify_youtube_failure(
                exc.diagnostic_text(),
                auth_kind=auth_strategy.kind,
                javascript_runtime_available=engine.js_runtime_status.found,
            )
            detail = (
                f"{auth_strategy.display_name}: {analysis.category.value}: "
                f"{_one_line(exc.diagnostic_text())}"
            )
            last_error = detail
            fallback_is_justified = analysis.category in {
                FailureCategory.AUTHENTICATION_REQUIRED,
                FailureCategory.COOKIE_FILE_REJECTED,
                FailureCategory.BROWSER_COOKIE_DATABASE_LOCKED,
                FailureCategory.BROWSER_COOKIE_DECRYPTION_FAILED,
                FailureCategory.BROWSER_COOKIE_EXTRACTION_FAILED,
            }
            if fallback_is_justified and index < len(strategies) - 1:
                warnings.append(detail)
                continue
            items.append(
                DiagnosticItem(
                    "Safe yt-dlp format probe",
                    DiagnosticStatus.FAIL,
                    f"{detail}; command={command}; previous warnings={'; '.join(warnings) or 'none'}",
                )
            )
            return

        count = len(result.formats)
        selection = select_discovered_format(result.formats, options.media_mode)
        has_media = bool(selection.selector or selection.media_format_count)
        status = DiagnosticStatus.PASS if has_media else DiagnosticStatus.FAIL
        detail = (
            f"{count} formats from {probe_url}; auth={auth_strategy.display_name}; "
            f"command={command}; previous warnings={'; '.join(warnings) or 'none'}"
        )
        if not has_media:
            detail += "; only_sabr_or_image_formats"
        items.append(DiagnosticItem("Safe yt-dlp format probe", status, detail))
        return

    items.append(
        DiagnosticItem(
            "Safe yt-dlp format probe",
            DiagnosticStatus.FAIL,
            last_error or "No authentication strategy was available for probing",
        )
    )


def _format_probe_options(
    options: DownloadOptions,
    auth_strategy: AuthStrategy,
    js_runtimes: dict[str, dict[str, str]],
) -> dict[str, object]:
    probe_opts: dict[str, object] = {
        "format": "best",
        "listformats": True,
        "skip_download": True,
        "simulate": "list_only",
        "noplaylist": True,
        "quiet": False,
        "no_warnings": False,
        "windowsfilenames": True,
        "extractor_args": {
            "youtube": {
                "player_client": ["default"],
                "fetch_pot": ["never"],
                "pot_trace": ["false"],
            }
        },
    }
    if js_runtimes:
        probe_opts["js_runtimes"] = js_runtimes
    if YOUTUBE_REMOTE_COMPONENTS:
        probe_opts["remote_components"] = list(YOUTUBE_REMOTE_COMPONENTS)

    local_bin = bin_dir()
    if local_bin.exists():
        probe_opts["ffmpeg_location"] = str(local_bin)

    probe_opts.update(auth_strategy.ydl_options)
    return probe_opts


def _format_probe_command(probe_url: str, probe_opts: dict[str, object]) -> str:
    args = ["yt-dlp", "-F", "--skip-download", "--no-playlist"]
    extractor_args = probe_opts.get("extractor_args")
    if isinstance(extractor_args, dict):
        youtube_args = extractor_args.get("youtube")
        if isinstance(youtube_args, dict):
            clients = youtube_args.get("player_client") or []
            fetch_pot = youtube_args.get("fetch_pot") or []
            pot_trace = youtube_args.get("pot_trace") or []
            rendered = (
                f"youtube:player_client={','.join(map(str, clients))};"
                f"fetch_pot={','.join(map(str, fetch_pot))};"
                f"pot_trace={','.join(map(str, pot_trace))}"
            )
            args.extend(["--extractor-args", rendered])
    if probe_opts.get("cookiefile"):
        args.extend(["--cookies", "<cookies.txt>"])
    if probe_opts.get("cookiesfrombrowser"):
        browser = probe_opts["cookiesfrombrowser"][0]  # type: ignore[index]
        args.extend(["--cookies-from-browser", str(browser)])
    if probe_opts.get("js_runtimes"):
        runtime_parts = []
        js_runtimes = probe_opts["js_runtimes"]
        if isinstance(js_runtimes, dict):
            for name, config in js_runtimes.items():
                path = config.get("path") if isinstance(config, dict) else None
                runtime_parts.append(f"{name}:{path}" if path else str(name))
        args.extend(["--js-runtimes", ",".join(runtime_parts)])
    if probe_opts.get("remote_components"):
        for component in probe_opts["remote_components"]:  # type: ignore[union-attr]
            args.extend(["--remote-components", str(component)])
    args.append(probe_url)
    return redact_po_token_material(subprocess.list2cmdline(args))


def _ytdlp_cache_dir() -> Path:
    cache_root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(cache_root).expanduser() / "yt-dlp"


def _directory_writable(path: Path, *, create: bool) -> tuple[bool, str]:
    try:
        if create:
            path.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            return False, "no (folder does not exist)"
        if not path.is_dir():
            return False, "no (path is not a folder)"
        test_file = path / f".openfetch_write_test_{uuid4().hex}.tmp"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
    except OSError as exc:
        return False, f"no ({exc})"
    return True, "yes"


def _running_process_names() -> tuple[set[str], str]:
    if sys.platform != "win32":
        return set(), "Process check is only implemented for Windows."
    completed = _run_command(["tasklist", "/FO", "CSV", "/NH"], timeout=8)
    if completed.returncode != 0:
        return set(), _command_failure_detail(completed)
    names: set[str] = set()
    reader = csv.reader(io.StringIO(completed.stdout))
    for row in reader:
        if row:
            names.add(row[0].lower())
    return names, ""


def _run_command(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except Exception as exc:
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr=str(exc))


def _command_failure_detail(completed: subprocess.CompletedProcess[str]) -> str:
    output = (completed.stderr or completed.stdout or "").strip()
    return f"exit={completed.returncode}; output={_one_line(output) or '<empty>'}"


def _one_line(value: str, limit: int = 260) -> str:
    text = " ".join(redact_po_token_material(value).split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
