"""Application bootstrap for OpenFetch."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from openfetch.config import (
    APP_NAME,
    EXECUTABLE_STEM,
    LEGACY_SETTINGS_APPLICATION,
    LEGACY_SETTINGS_ORGANIZATION,
    SETTINGS_APPLICATION,
    SETTINGS_ORGANIZATION,
    VERSION,
    assets_dir,
    base_dir,
    bin_dir,
)
from openfetch.core.diagnostics import run_support_diagnostics
from openfetch.core.downloader import DownloadEngine, recover_stale_download_processes
from openfetch.core.legacy_migration import run_legacy_migration
from openfetch.core.update_directory_installer import (
    DIRECTORY_TRANSACTION_FILENAME,
    cleanup_stale_directory_update_state,
    read_directory_update_recovery_message,
    recover_stale_directory_updates,
    run_directory_update_helper,
    write_directory_startup_confirmation,
)
from openfetch.core.update_installer import (
    cleanup_legacy_update_state,
    cleanup_stale_update_state,
    read_update_recovery_message,
    recover_stale_update_ownership,
    run_update_helper,
    write_startup_confirmation,
    write_transaction_startup_confirmation,
)
from openfetch.models import DownloadJob, DownloadOptions, MediaMode, PlaylistMode


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=EXECUTABLE_STEM)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--url", action="append", help="YouTube URL. Can be passed more than once.")
    parser.add_argument("--output", default=None, help="Output directory.")
    parser.add_argument(
        "--mode",
        choices=[mode.value for mode in MediaMode],
        default=MediaMode.VIDEO.value,
        help="Download mode.",
    )
    parser.add_argument(
        "--playlist",
        choices=[mode.value for mode in PlaylistMode],
        default=PlaylistMode.AUTO.value,
        help="Playlist handling mode.",
    )
    parser.add_argument("--quality", default="Best available", help="Video quality preset.")
    parser.add_argument("--audio-quality", default="320", help="Audio bitrate for MP3/M4A.")
    parser.add_argument("--subs", default="nl", help="Subtitle language code, for example nl or en.")
    parser.add_argument("--no-subs", action="store_true", help="Disable subtitle download.")
    parser.add_argument("--no-thumbnail", action="store_true", help="Disable thumbnail download.")
    parser.add_argument("--cookies", default=None, help="Path to cookies.txt.")
    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Print environment diagnostics for support and exit without downloading.",
    )
    parser.add_argument(
        "--diagnostics-probe-url",
        default=None,
        help="YouTube URL for the safe format probe. Defaults to the first --url or a public test video.",
    )
    parser.add_argument("--apply-update", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--apply-directory-update", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--post-update-token", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--post-update-marker", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--post-update-transaction", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--update-rollback-status", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--internal-ytdlp-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--internal-youtube-connection-smoke", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--internal-provider-media-smoke", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--internal-gui-startup-smoke", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--internal-windows-gui-smoke", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--internal-runtime-smoke", default=None, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def _options_from_args(args: argparse.Namespace) -> DownloadOptions:
    output_dir = Path(args.output).expanduser() if args.output else Path.home() / "Downloads"
    return DownloadOptions(
        output_dir=output_dir,
        media_mode=MediaMode(args.mode),
        playlist_mode=PlaylistMode(args.playlist),
        quality=args.quality,
        audio_quality=args.audio_quality,
        subtitle_language=args.subs,
        subtitles=not args.no_subs,
        thumbnail=not args.no_thumbnail,
        cookie_file=Path(args.cookies).expanduser() if args.cookies else None,
    )


def run_diagnostics_cli(args: argparse.Namespace) -> int:
    run_legacy_migration()
    recover_stale_download_processes(print)
    options = _options_from_args(args)
    probe_url = args.diagnostics_probe_url or (args.url[0] if args.url else None)
    report = run_support_diagnostics(options, probe_url)
    print(report.text())
    return 0


def run_cli(args: argparse.Namespace) -> int:
    run_legacy_migration()
    recover_stale_download_processes(print)
    options = _options_from_args(args)
    engine = DownloadEngine(
        options=options,
        progress_callback=lambda event: print(event.compact_status()),
        log_callback=print,
    )

    exit_code = 0
    for url in args.url:
        result = engine.download(DownloadJob(url=url))
        print(result.message)
        if not result.success:
            exit_code = 1
    return exit_code


def run_gui(argv: list[str], args: argparse.Namespace) -> int:
    from PySide6.QtCore import QSettings, QTimer
    from PySide6.QtWidgets import QApplication, QMessageBox

    from openfetch.gui.main_window import MainWindow

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(SETTINGS_ORGANIZATION)
    # Runs before any settings or application data are read; failures are
    # contained so an update's startup confirmation is never blocked.
    migration = run_legacy_migration(
        QSettings,
        legacy_settings_scope=(LEGACY_SETTINGS_ORGANIZATION, LEGACY_SETTINGS_APPLICATION),
        target_settings_scope=(SETTINGS_ORGANIZATION, SETTINGS_APPLICATION),
    )
    window = MainWindow()
    window.show()
    for event in migration.events:
        window.log(event)
    recover_stale_download_processes(window.log)
    if not args.post_update_transaction:
        recover_stale_directory_updates(window.log)
        recovery = recover_stale_update_ownership(window.log)
        if recovery.shutdown_required:
            window.log("Detached updater recovery accepted the transaction; closing safely")
            QTimer.singleShot(0, app.quit)
            return app.exec()

    if args.post_update_transaction or (args.post_update_token and args.post_update_marker):
        def confirm_startup() -> None:
            try:
                if args.post_update_transaction:
                    transaction_path = Path(args.post_update_transaction)
                    if transaction_path.name == DIRECTORY_TRANSACTION_FILENAME:
                        write_directory_startup_confirmation(
                            transaction_path,
                            version=VERSION,
                        )
                    else:
                        write_transaction_startup_confirmation(
                            transaction_path,
                            version=VERSION,
                        )
                else:
                    write_startup_confirmation(
                        args.post_update_token,
                        Path(args.post_update_marker),
                        version=VERSION,
                    )
                window.log(f"Update startup confirmed for version {VERSION}")
            except Exception:
                window.log("Update startup confirmation failed; the updater will restore the previous version")
                QTimer.singleShot(0, app.quit)
                return
            try:
                recover_stale_update_ownership(window.log)
            except Exception:
                window.log("Startup was confirmed, but deferred updater cleanup will retry later")

        QTimer.singleShot(1200, confirm_startup)

    if args.update_rollback_status:
        def show_recovery_status() -> None:
            status_path = Path(args.update_rollback_status)
            if status_path.name == DIRECTORY_TRANSACTION_FILENAME:
                message = read_directory_update_recovery_message(status_path)
            else:
                message = read_update_recovery_message(status_path)
            window.log(message)
            QMessageBox.warning(window, "Update Recovery", message)

        QTimer.singleShot(800, show_recovery_status)

    def cleanup_all_stale_update_state() -> None:
        cleanup_stale_update_state()
        cleanup_stale_directory_update_state()
        if not args.post_update_transaction:
            # Not during the update itself: the legacy helper that handed this
            # start off is still completing its own bookkeeping.
            cleanup_legacy_update_state()

    QTimer.singleShot(10_000, cleanup_all_stale_update_state)
    return app.exec()


def _write_internal_smoke_result(result_path: str, payload: dict[str, object]) -> None:
    path = Path(result_path).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if temp_root != path.parent and temp_root not in path.parents:
        raise ValueError("Internal smoke result must be written below the temporary directory.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def run_youtube_connection_smoke(result_path: str) -> int:
    from openfetch.core.youtube_connection_smoke import (
        run_offline_youtube_connection_smoke,
    )

    results = run_offline_youtube_connection_smoke()
    passed = all(results.values())
    _write_internal_smoke_result(result_path, {"passed": passed, "checks": results})
    return 0 if passed else 1


def run_provider_media_smoke(result_path: str) -> int:
    from openfetch.core.provider_media_smoke import (
        run_offline_provider_media_smoke,
    )

    results = run_offline_provider_media_smoke()
    passed = all(results.values())
    _write_internal_smoke_result(result_path, {"passed": passed, "checks": results})
    return 0 if passed else 1


def run_gui_startup_smoke(
    argv: list[str], result_path: str, *, platform_name: str = "offscreen"
) -> int:
    os.environ["QT_QPA_PLATFORM"] = platform_name
    from PySide6 import QtCore as QtCoreModule
    from PySide6 import QtGui as QtGuiModule
    from PySide6 import QtWidgets as QtWidgetsModule
    from PySide6.QtCore import QLibraryInfo, QSettings, QTimer
    from PySide6.QtGui import QPixmap
    from PySide6.QtWidgets import QApplication
    from shiboken6 import Shiboken as ShibokenModule

    from openfetch.gui.main_window import MainWindow

    settings_root = str(
        Path(tempfile.gettempdir())
        / f"openfetch-gui-smoke-settings-{platform_name}-{os.getpid()}"
    )
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, settings_root)
    app = QApplication(argv)
    window = MainWindow()
    window.show()

    def loaded_windows_modules() -> dict[str, str]:
        if sys.platform != "win32":
            return {}
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        kernel32.GetModuleFileNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        kernel32.GetModuleFileNameW.restype = ctypes.c_uint32
        names = (
            "Qt6Core.dll",
            "Qt6Gui.dll",
            "Qt6Widgets.dll",
            "pyside6.abi3.dll",
            "shiboken6.abi3.dll",
            "qoffscreen.dll",
            "qwindows.dll",
            "qico.dll",
        )
        result: dict[str, str] = {}
        for name in names:
            module = kernel32.GetModuleHandleW(name)
            if not module:
                continue
            buffer = ctypes.create_unicode_buffer(32_768)
            length = kernel32.GetModuleFileNameW(module, buffer, len(buffer))
            if length:
                result[name] = str(Path(buffer.value).resolve())
        return result

    state = {"complete": False}

    def finish(payload: dict[str, object]) -> None:
        if state["complete"]:
            return
        state["complete"] = True
        try:
            _write_internal_smoke_result(result_path, payload)
        finally:
            window.close()
            app.quit()

    def complete() -> None:
        try:
            checks = window.responsive_layout_smoke_checks()
            checks["qt_png_asset"] = not QPixmap(
                str(assets_dir() / "OpenFetchIcon.png")
            ).isNull()
            checks["qt_ico_plugin"] = not QPixmap(
                str(assets_dir() / "OpenFetch.ico")
            ).isNull()
            checks["requested_platform_plugin"] = app.platformName().casefold() == platform_name
            finish(
                {
                    "passed": window.isVisible() and all(checks.values()),
                    "window_title": window.windowTitle(),
                    "platform": app.platformName(),
                    "qt_plugins_path": QLibraryInfo.path(
                        QLibraryInfo.LibraryPath.PluginsPath
                    ),
                    "qt_library_paths": list(app.libraryPaths()),
                    "qt_binding_module_paths": {
                        "QtCore.pyd": str(Path(QtCoreModule.__file__).resolve()),
                        "QtGui.pyd": str(Path(QtGuiModule.__file__).resolve()),
                        "QtWidgets.pyd": str(Path(QtWidgetsModule.__file__).resolve()),
                        "Shiboken.pyd": str(Path(ShibokenModule.__file__).resolve()),
                    },
                    "qt_loaded_library_paths": loaded_windows_modules(),
                    "checks": checks,
                }
            )
        except Exception:
            finish({"passed": False, "checks": {"smoke_callback_completed": False}})

    def watchdog() -> None:
        finish({"passed": False, "checks": {"gui_watchdog_timeout": False}})

    QTimer.singleShot(500, complete)
    QTimer.singleShot(15_000, watchdog)
    return app.exec()


def _run_internal_smoke(name: str, runner: Callable[[], int]) -> int:
    """Run an internal smoke so it can never hang a windowed executable.

    The packaged build is a windowed (``console=False``) PyInstaller binary. An
    unhandled exception there is caught by PyInstaller's windowed traceback
    handler, which shows a modal dialog: with no interactive desktop the process
    then waits forever and a supervising CI step can only time out. Internal
    smokes must instead fail fast and loudly, so every exception is reported on
    stderr and turned into a non-zero exit code.

    This wrapper is reached only through the hidden ``--internal-*-smoke``
    flags, so ordinary application behaviour is unchanged.
    """
    try:
        return runner()
    except BaseException as exc:  # noqa: BLE001 - a smoke must never hang the EXE
        import traceback

        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        sys.stderr.write(f"internal {name} smoke failed: {type(exc).__name__}: {exc}\n")
        sys.stderr.write(detail)
        sys.stderr.flush()
        return 3


def _internal_smoke_trace_path(result_path: str) -> Path:
    """Trace file beside the smoke result, under the same temp-dir constraint."""
    path = Path(result_path).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if temp_root != path.parent and temp_root not in path.parents:
        raise ValueError("Internal smoke trace must be written below the temporary directory.")
    return path.with_name(path.name + ".trace")


def run_runtime_smoke(result_path: str) -> int:
    """Exercise packaged ctypes/libffi and the pinned external runtimes."""
    import _ctypes
    import ctypes
    import hashlib
    import subprocess
    import time

    smoke_started = time.monotonic()
    trace_path = _internal_smoke_trace_path(result_path)

    def trace(phase: str, **extra: object) -> None:
        # Diagnostics only, and only for the internal smoke: each phase is
        # appended and flushed immediately so a supervising harness can read
        # partial progress if this process is killed. Never raises into the
        # smoke itself, and never logs user data.
        event: dict[str, object] = {
            "phase": phase,
            "elapsed": round(time.monotonic() - smoke_started, 3),
        }
        event.update(extra)
        try:
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            with trace_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            pass

    def process_uptime_seconds() -> float | None:
        # How long this process existed before the smoke ran: for a PyInstaller
        # one-file build this measures archive extraction plus interpreter and
        # application import time.
        if sys.platform != "win32":
            return None
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            creation = ctypes.c_ulonglong()
            exit_time = ctypes.c_ulonglong()
            kernel = ctypes.c_ulonglong()
            user = ctypes.c_ulonglong()
            if not kernel32.GetProcessTimes(
                kernel32.GetCurrentProcess(),
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            now = ctypes.c_ulonglong()
            kernel32.GetSystemTimeAsFileTime(ctypes.byref(now))
            return round((now.value - creation.value) / 10_000_000, 3)
        except (OSError, AttributeError):
            return None

    trace("process_started", uptime_before_smoke=process_uptime_seconds(), pid=os.getpid())
    trace("runtime_smoke_entered")

    checks: dict[str, bool] = {}
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    callback = callback_type(lambda value: value + 7)
    checks["ctypes_callback"] = callback(35) == 42
    trace("ctypes_callback_complete")

    libffi = base_dir() / "libffi-8.dll"
    libffi_hash = hashlib.sha256(libffi.read_bytes()).hexdigest() if libffi.is_file() else ""
    checks["cpython_libffi_3_4_2"] = (
        libffi_hash
        == "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e"
    )
    ctypes_extension = Path(_ctypes.__file__).resolve()
    ctypes_hash = hashlib.sha256(ctypes_extension.read_bytes()).hexdigest()
    checks["cpython_ctypes_extension"] = (
        ctypes_extension.parent == base_dir().resolve()
        and ctypes_hash
        == "6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41"
    )

    loaded_libffi = ""
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        kernel32.GetModuleFileNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        kernel32.GetModuleFileNameW.restype = ctypes.c_uint32
        handle = kernel32.GetModuleHandleW("libffi-8.dll")
        buffer = ctypes.create_unicode_buffer(32_768)
        if handle and kernel32.GetModuleFileNameW(handle, buffer, len(buffer)):
            loaded_libffi = buffer.value
    checks["loaded_libffi_from_bundle_root"] = bool(loaded_libffi) and (
        Path(loaded_libffi).resolve() == libffi.resolve()
    )
    trace("libffi_checks_complete")

    def run_bounded_runtime(
        name: str, command: list[str], marker: str, timeout_seconds: float
    ) -> tuple[bool, dict[str, object]]:
        # Each external runtime is independently bounded and observable: on
        # timeout the complete child process tree is terminated and a
        # structured, non-passing record is kept instead of a silent stall.
        started = time.monotonic()
        trace(f"{name}_started")
        detail: dict[str, object] = {"timed_out": False, "returncode": None}
        stdout = stderr = ""
        ok = False
        try:
            child = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            detail["spawn_error"] = type(exc).__name__
        else:
            try:
                stdout, stderr = child.communicate(timeout=timeout_seconds)
                detail["returncode"] = child.returncode
                output = f"{stdout}\n{stderr}".casefold()
                ok = child.returncode == 0 and marker in output
            except subprocess.TimeoutExpired:
                detail["timed_out"] = True
                if sys.platform == "win32":
                    taskkill = (
                        Path(os.environ.get("SystemRoot", r"C:\Windows"))
                        / "System32"
                        / "taskkill.exe"
                    )
                    subprocess.run(  # noqa: S603 - fixed system tool, numeric PID
                        [str(taskkill), "/PID", str(child.pid), "/T", "/F"],
                        shell=False,
                        check=False,
                        capture_output=True,
                        timeout=30,
                    )
                else:
                    child.kill()
                try:
                    stdout, stderr = child.communicate(timeout=10)
                except (subprocess.SubprocessError, OSError, ValueError):
                    stdout, stderr = "", ""
        detail["elapsed"] = round(time.monotonic() - started, 3)
        # Bounded diagnostic tails only; these tools emit version banners, not
        # user data.
        detail["stdout_tail"] = stdout[-300:]
        detail["stderr_tail"] = stderr[-300:]
        trace(f"{name}_finished", **detail)
        return ok, detail

    runtime_details: dict[str, dict[str, object]] = {}
    commands = {
        "node": ([str(bin_dir() / "node.exe"), "-e", "process.stdout.write('node-ok')"], "node-ok"),
        "ffmpeg": ([str(bin_dir() / "ffmpeg.exe"), "-hide_banner", "-version"], "ffmpeg version"),
        "ffprobe": ([str(bin_dir() / "ffprobe.exe"), "-hide_banner", "-version"], "ffprobe version"),
    }
    for name, (command, marker) in commands.items():
        ok, detail = run_bounded_runtime(name, command, marker, 15)
        checks[f"{name}_runtime"] = ok
        runtime_details[name] = detail

    passed = all(checks.values())
    _write_internal_smoke_result(
        result_path,
        {
            "passed": passed,
            "checks": checks,
            "libffi_sha256": libffi_hash,
            "ctypes_sha256": ctypes_hash,
            "runtime_details": runtime_details,
        },
    )
    trace("result_written", passed=passed)
    trace("process_exiting")
    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.internal_ytdlp_worker:
        from openfetch.core.ytdlp_worker import main as run_ytdlp_worker

        return run_ytdlp_worker()
    if args.internal_youtube_connection_smoke:
        return _run_internal_smoke(
            "youtube-connection",
            lambda: run_youtube_connection_smoke(args.internal_youtube_connection_smoke),
        )
    if args.internal_provider_media_smoke:
        return _run_internal_smoke(
            "provider-media",
            lambda: run_provider_media_smoke(args.internal_provider_media_smoke),
        )
    if args.internal_gui_startup_smoke:
        return _run_internal_smoke(
            "gui-startup",
            lambda: run_gui_startup_smoke(
                [EXECUTABLE_STEM, "--internal-gui-startup-smoke"],
                args.internal_gui_startup_smoke,
            ),
        )
    if args.internal_windows_gui_smoke:
        return _run_internal_smoke(
            "windows-gui",
            lambda: run_gui_startup_smoke(
                [EXECUTABLE_STEM, "--internal-windows-gui-smoke"],
                args.internal_windows_gui_smoke,
                platform_name="windows",
            ),
        )
    if args.internal_runtime_smoke:
        return _run_internal_smoke(
            "runtime", lambda: run_runtime_smoke(args.internal_runtime_smoke)
        )
    if args.apply_update:
        return run_update_helper(Path(args.apply_update))
    if args.apply_directory_update:
        return run_directory_update_helper(Path(args.apply_directory_update))
    if args.post_update_transaction and (args.post_update_token or args.post_update_marker):
        return 2
    if bool(args.post_update_token) != bool(args.post_update_marker):
        return 2
    if args.diagnostics:
        return run_diagnostics_cli(args)
    if args.url:
        return run_cli(args)
    return run_gui(
        sys.argv if argv is None else [EXECUTABLE_STEM, *argv],
        args,
    )
