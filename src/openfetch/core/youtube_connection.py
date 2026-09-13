"""Managed browser profiles and the guided YouTube connection lifecycle.

Chrome and Firefox are launched only with OpenFetch-owned profiles below
LocalAppData.  Normal browser profiles are never selected, modified, or removed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from openfetch.config import YOUTUBE_HOSTS, app_data_dir
from openfetch.core.process_control import process_creation_identity

SETTINGS_PREFIX = "youtube_connection"
ACTIVE_PROVIDER_KEY = f"{SETTINGS_PREFIX}/active_provider"
CHROME_PROFILE_DIRECTORY = "chrome-profile"
FIREFOX_PROFILE_DIRECTORY = "firefox-profile"
CHROME_COOKIE_DATABASES = (Path("Default/Network/Cookies"), Path("Default/Cookies"))
FIREFOX_COOKIE_DATABASE = "cookies.sqlite"
CHROME_LOCK_FILES = ("SingletonLock", "SingletonCookie", "SingletonSocket", "lockfile")
FIREFOX_LOCK_FILES = ("parent.lock", ".parentlock", "lock")
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DEFAULT_CONNECTION_URL = "https://www.youtube.com/"

_SENSITIVE_QUERY_NAMES = {
    "access_token",
    "auth",
    "authorization",
    "cookie",
    "credential",
    "key",
    "password",
    "po_token",
    "token",
}
_AUTH_COOKIE_NAMES = {
    "APISID",
    "HSID",
    "LOGIN_INFO",
    "SAPISID",
    "SID",
    "SSID",
    "__SECURE-1PAPISID",
    "__SECURE-1PSID",
    "__SECURE-3PAPISID",
    "__SECURE-3PSID",
}


class ConnectionState(str, Enum):
    NOT_CONFIGURED = "not_configured"
    FIREFOX_MISSING = "firefox_missing"
    BROWSER_MISSING = "firefox_missing"
    PROFILE_READY = "profile_ready"
    WAITING_FOR_LOGIN = "waiting_for_login"
    BROWSER_OPEN = "browser_open"
    VERIFYING = "verifying"
    CONNECTED = "connected"
    EXPIRED = "expired"
    LOCKED = "locked"
    INVALID = "invalid"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class ManagedBrowser(str, Enum):
    CHROME = "chrome"
    FIREFOX = "firefox"

    @property
    def display_name(self) -> str:
        return "Google Chrome" if self is ManagedBrowser.CHROME else "Firefox"

    @property
    def executable_name(self) -> str:
        return "chrome.exe" if self is ManagedBrowser.CHROME else "firefox.exe"

    @property
    def profile_directory(self) -> str:
        return (
            CHROME_PROFILE_DIRECTORY
            if self is ManagedBrowser.CHROME
            else FIREFOX_PROFILE_DIRECTORY
        )

    @property
    def lock_files(self) -> tuple[str, ...]:
        return CHROME_LOCK_FILES if self is ManagedBrowser.CHROME else FIREFOX_LOCK_FILES


@dataclass(frozen=True, slots=True)
class FirefoxDiscoveryResult:
    executable: Path | None
    source: str
    reason: str = ""


ChromeDiscoveryResult = FirefoxDiscoveryResult


@dataclass(frozen=True, slots=True)
class FirefoxProcessIdentity:
    pid: int
    creation_identity: str
    command: tuple[str, ...]


ManagedBrowserProcessIdentity = FirefoxProcessIdentity


@dataclass(frozen=True, slots=True)
class ConnectionSnapshot:
    state: ConnectionState
    profile_path: Path
    firefox_path: Path | None
    last_verified: str
    failure_reason: str
    browser: ManagedBrowser = ManagedBrowser.FIREFOX

    @property
    def connected(self) -> bool:
        return self.state == ConnectionState.CONNECTED

    @property
    def executable_path(self) -> Path | None:
        return self.firefox_path


@dataclass(frozen=True, slots=True)
class VerificationResult:
    success: bool
    code: str
    message: str
    warning: str = ""


@dataclass(frozen=True, slots=True)
class DisconnectResult:
    success: bool
    code: str
    message: str
    manual_cleanup_path: Path | None = None


class SettingsStore(Protocol):
    def value(self, key: str, default: Any = None) -> Any: ...

    def setValue(self, key: str, value: Any) -> None: ...  # noqa: N802

    def remove(self, key: str) -> None: ...

    def sync(self) -> None: ...


RegistryReader = Callable[[], Iterable[Path | str]]
BinaryValidator = Callable[[Path], bool]
PopenFactory = Callable[..., subprocess.Popen[Any]]
IdentityProvider = Callable[[int], str | None]
ProcessTreeProvider = Callable[[int], Iterable[int]]
Verifier = Callable[[Path, str], VerificationResult]


def youtube_data_root(application_data: Path | None = None) -> Path:
    return Path(application_data or app_data_dir()) / "youtube"


def dedicated_firefox_profile_path(application_data: Path | None = None) -> Path:
    return youtube_data_root(application_data) / FIREFOX_PROFILE_DIRECTORY


def dedicated_chrome_profile_path(application_data: Path | None = None) -> Path:
    return youtube_data_root(application_data) / CHROME_PROFILE_DIRECTORY


def dedicated_browser_profile_path(
    browser: ManagedBrowser | str,
    application_data: Path | None = None,
) -> Path:
    selected = ManagedBrowser(browser)
    return youtube_data_root(application_data) / selected.profile_directory


def _normalized_path(path: Path | str, *, strict: bool = False) -> Path:
    candidate = Path(path).expanduser()
    return candidate.resolve(strict=strict)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _is_reparse_point(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(details.st_mode):
        return True
    attributes = int(getattr(details, "st_file_attributes", 0))
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def validate_managed_profile_path(
    profile_path: Path | str,
    *,
    browser: ManagedBrowser | str,
    application_data: Path | None = None,
    require_exists: bool = True,
) -> Path:
    """Return the exact managed profile or reject traversal/reparse escapes."""
    selected = ManagedBrowser(browser)
    application_root = Path(application_data or app_data_dir()).expanduser()
    root = youtube_data_root(application_root)
    expected = dedicated_browser_profile_path(selected, application_root)
    try:
        normalized_root = _normalized_path(root)
        normalized_expected = _normalized_path(expected)
        normalized_profile = _normalized_path(profile_path)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Dedicated browser profile path is invalid.") from exc

    if not _same_path(normalized_profile, normalized_expected):
        raise ValueError("Dedicated browser profile path is outside the managed location.")
    if normalized_profile == normalized_root or normalized_profile.parent != normalized_root:
        raise ValueError("Dedicated browser profile path is not a safe child directory.")
    if require_exists and (not normalized_profile.exists() or not normalized_profile.is_dir()):
        raise ValueError("Dedicated browser profile does not exist.")

    # A junction on the application-owned ancestor could otherwise make the
    # fixed logical profile path resolve outside OpenFetch's tree.
    for candidate in (application_root, root, expected):
        if candidate.exists() and _is_reparse_point(candidate):
            raise ValueError("Dedicated browser profile uses an unsafe reparse point.")
    if require_exists and _is_reparse_point(normalized_profile):
        raise ValueError("Dedicated browser profile uses an unsafe reparse point.")
    return normalized_profile


def validate_dedicated_profile_path(
    profile_path: Path | str,
    *,
    application_data: Path | None = None,
    require_exists: bool = True,
) -> Path:
    """Compatibility validator for the V3.0.5 managed Firefox profile."""
    return validate_managed_profile_path(
        profile_path,
        browser=ManagedBrowser.FIREFOX,
        application_data=application_data,
        require_exists=require_exists,
    )


def _strip_registry_value(value: Path | str) -> Path:
    raw = os.path.expandvars(str(value)).strip().strip('"')
    return Path(raw)


def _read_firefox_app_paths_registry() -> list[Path]:
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    candidates: list[Path] = []
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe"
    views = (0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in dict.fromkeys(views):
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                    value, _ = winreg.QueryValueEx(key, None)
            except OSError:
                continue
            if isinstance(value, str) and value.strip():
                candidates.append(_strip_registry_value(value))
    return candidates


def _read_chrome_app_paths_registry() -> list[Path]:
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    candidates: list[Path] = []
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
    views = (0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in dict.fromkeys(views):
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view) as key:
                    value, _ = winreg.QueryValueEx(key, None)
            except OSError:
                continue
            if isinstance(value, str) and value.strip():
                candidates.append(_strip_registry_value(value))
    return candidates


def _windows_binary_matches(
    path: Path,
    *,
    product_token: str,
    company_token: str,
    original_filename: str,
) -> bool:
    if sys.platform != "win32":
        return True
    import ctypes
    from ctypes import wintypes

    version = ctypes.WinDLL("version", use_last_error=True)
    get_size = version.GetFileVersionInfoSizeW
    get_size.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    get_size.restype = wintypes.DWORD
    get_info = version.GetFileVersionInfoW
    get_info.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    get_info.restype = wintypes.BOOL
    query_value = version.VerQueryValueW
    query_value.argtypes = [
        wintypes.LPCVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.UINT),
    ]
    query_value.restype = wintypes.BOOL

    ignored = wintypes.DWORD()
    size = int(get_size(str(path), ctypes.byref(ignored)))
    if size <= 0:
        return False
    buffer = ctypes.create_string_buffer(size)
    if not get_info(str(path), 0, size, buffer):
        return False

    translations_pointer = wintypes.LPVOID()
    translations_length = wintypes.UINT()
    translations: list[tuple[int, int]] = []
    if query_value(
        buffer,
        r"\VarFileInfo\Translation",
        ctypes.byref(translations_pointer),
        ctypes.byref(translations_length),
    ):
        count = int(translations_length.value) // (2 * ctypes.sizeof(wintypes.WORD))
        words = ctypes.cast(translations_pointer, ctypes.POINTER(wintypes.WORD))
        translations.extend((int(words[index * 2]), int(words[index * 2 + 1])) for index in range(count))
    if not translations:
        translations.append((0x0409, 0x04B0))

    def version_string(name: str) -> str:
        for language, codepage in translations:
            pointer = wintypes.LPVOID()
            length = wintypes.UINT()
            key = rf"\StringFileInfo\{language:04x}{codepage:04x}\{name}"
            if query_value(buffer, key, ctypes.byref(pointer), ctypes.byref(length)) and length.value:
                return ctypes.wstring_at(pointer, length.value).rstrip("\x00")
        return ""

    product = version_string("ProductName").casefold()
    description = version_string("FileDescription").casefold()
    company = version_string("CompanyName").casefold()
    original = version_string("OriginalFilename").casefold()
    return (
        product_token in f"{product} {description}"
        and company_token in company
        and original == original_filename
    )


def _windows_binary_is_firefox(path: Path) -> bool:
    return _windows_binary_matches(
        path,
        product_token="firefox",
        company_token="mozilla",
        original_filename="firefox.exe",
    )


def _windows_binary_is_chrome(path: Path) -> bool:
    return _windows_binary_matches(
        path,
        product_token="chrome",
        company_token="google",
        original_filename="chrome.exe",
    )


class FirefoxDiscovery:
    """Find and validate a Firefox executable without executing candidates."""

    def __init__(
        self,
        *,
        registry_reader: RegistryReader = _read_firefox_app_paths_registry,
        environ: Mapping[str, str] | None = None,
        binary_validator: BinaryValidator = _windows_binary_is_firefox,
    ) -> None:
        self.registry_reader = registry_reader
        self.environ = dict(os.environ if environ is None else environ)
        self.binary_validator = binary_validator

    def validate_executable(self, path: Path | str | None) -> Path | None:
        if not path or "\x00" in str(path):
            return None
        try:
            candidate = _normalized_path(_strip_registry_value(path), strict=True)
            if not candidate.is_file() or candidate.name.casefold() != "firefox.exe":
                return None
            with candidate.open("rb") as handle:
                if handle.read(2) != b"MZ":
                    return None
            if not self.binary_validator(candidate):
                return None
        except (OSError, RuntimeError, ValueError):
            return None
        return candidate

    def standard_candidates(self) -> list[Path]:
        candidates: list[Path] = []
        for variable in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            root = self.environ.get(variable)
            if root:
                candidates.append(Path(root) / "Mozilla Firefox" / "firefox.exe")
        return candidates

    def discover(self, stored_path: Path | str | None = None) -> FirefoxDiscoveryResult:
        if stored_path:
            validated = self.validate_executable(stored_path)
            if validated:
                return FirefoxDiscoveryResult(validated, "stored")

        with contextlib.suppress(Exception):
            for candidate in self.registry_reader():
                validated = self.validate_executable(candidate)
                if validated:
                    return FirefoxDiscoveryResult(validated, "registry")

        for candidate in self.standard_candidates():
            validated = self.validate_executable(candidate)
            if validated:
                return FirefoxDiscoveryResult(validated, "standard_install")
        return FirefoxDiscoveryResult(
            None,
            "missing",
            "Firefox is not installed or no valid firefox.exe could be found.",
        )


class ChromeDiscovery:
    """Find and validate Google Chrome without executing untrusted candidates."""

    def __init__(
        self,
        *,
        registry_reader: RegistryReader = _read_chrome_app_paths_registry,
        environ: Mapping[str, str] | None = None,
        binary_validator: BinaryValidator = _windows_binary_is_chrome,
    ) -> None:
        self.registry_reader = registry_reader
        self.environ = dict(os.environ if environ is None else environ)
        self.binary_validator = binary_validator

    def validate_executable(self, path: Path | str | None) -> Path | None:
        if not path or "\x00" in str(path):
            return None
        try:
            candidate = _normalized_path(_strip_registry_value(path), strict=True)
            if not candidate.is_file() or candidate.name.casefold() != "chrome.exe":
                return None
            with candidate.open("rb") as handle:
                if handle.read(2) != b"MZ":
                    return None
            if not self.binary_validator(candidate):
                return None
        except (OSError, RuntimeError, ValueError):
            return None
        return candidate

    def standard_candidates(self) -> list[tuple[Path, str]]:
        candidates: list[tuple[Path, str]] = []
        local = self.environ.get("LOCALAPPDATA")
        if local:
            candidates.append(
                (Path(local) / "Google" / "Chrome" / "Application" / "chrome.exe", "user_install")
            )
        for variable in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            root = self.environ.get(variable)
            if root:
                candidates.append(
                    (
                        Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe",
                        "standard_install",
                    )
                )
        return candidates

    def discover(self, stored_path: Path | str | None = None) -> ChromeDiscoveryResult:
        if stored_path:
            validated = self.validate_executable(stored_path)
            if validated:
                return ChromeDiscoveryResult(validated, "stored")

        with contextlib.suppress(Exception):
            for candidate in self.registry_reader():
                validated = self.validate_executable(candidate)
                if validated:
                    return ChromeDiscoveryResult(validated, "registry")

        for candidate, source in self.standard_candidates():
            validated = self.validate_executable(candidate)
            if validated:
                return ChromeDiscoveryResult(validated, source)
        return ChromeDiscoveryResult(
            None,
            "missing",
            "Google Chrome is not installed or no valid chrome.exe could be found.",
        )


class ManagedBrowserProvider(Protocol):
    """Browser-specific discovery, profile, launch, and yt-dlp path behavior."""

    browser: ManagedBrowser
    discovery: FirefoxDiscovery | ChromeDiscovery

    def profile_path(self, application_data: Path) -> Path: ...

    def launch_arguments(self, executable: Path, profile: Path, target_url: str) -> list[str]: ...

    def extraction_profile(self, profile: Path) -> Path: ...


@dataclass(slots=True)
class ManagedChromeProvider:
    discovery: ChromeDiscovery
    browser: ManagedBrowser = ManagedBrowser.CHROME

    def profile_path(self, application_data: Path) -> Path:
        return dedicated_chrome_profile_path(application_data)

    def launch_arguments(self, executable: Path, profile: Path, target_url: str) -> list[str]:
        return [
            str(executable),
            f"--user-data-dir={profile}",
            "--new-window",
            "--no-first-run",
            "--no-default-browser-check",
            target_url,
        ]

    def extraction_profile(self, profile: Path) -> Path:
        return profile / "Default"


@dataclass(slots=True)
class ManagedFirefoxProvider:
    discovery: FirefoxDiscovery
    browser: ManagedBrowser = ManagedBrowser.FIREFOX

    def profile_path(self, application_data: Path) -> Path:
        return dedicated_firefox_profile_path(application_data)

    def launch_arguments(self, executable: Path, profile: Path, target_url: str) -> list[str]:
        return [
            str(executable),
            "-no-remote",
            "-profile",
            str(profile),
            "-url",
            target_url,
        ]

    def extraction_profile(self, profile: Path) -> Path:
        return profile


def _safe_youtube_url(url: str | None) -> str:
    if not url:
        return DEFAULT_CONNECTION_URL
    try:
        parsed = urlsplit(str(url).strip())
    except ValueError:
        return DEFAULT_CONNECTION_URL
    host = (parsed.hostname or "").casefold()
    if parsed.scheme != "https" or host not in YOUTUBE_HOSTS or parsed.username or parsed.password:
        return DEFAULT_CONNECTION_URL
    safe_query = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if name.casefold() in _SENSITIVE_QUERY_NAMES:
            continue
        safe_query.append((name, value))
    sanitized = urlunsplit(("https", parsed.netloc, parsed.path or "/", urlencode(safe_query), ""))
    return sanitized if len(sanitized) <= 2048 else DEFAULT_CONNECTION_URL


def _sanitize_failure_reason(reason: str) -> str:
    cleaned = " ".join(str(reason or "").split())
    cleaned = re.sub(
        r"(?i)\b(cookie|authorization|password|token)\s*[:=]\s*\S+",
        r"\1=<redacted>",
        cleaned,
    )
    home = str(Path.home())
    if home:
        cleaned = cleaned.replace(home, "<user-profile>")
    return cleaned[:500]


def _firefox_cookie_database(profile: Path) -> Path:
    return profile / FIREFOX_COOKIE_DATABASE


def _browser_cookie_databases(profile: Path, browser: ManagedBrowser) -> tuple[Path, ...]:
    if browser is ManagedBrowser.CHROME:
        return tuple(profile / relative for relative in CHROME_COOKIE_DATABASES)
    return (_firefox_cookie_database(profile),)


def _lock_marker_exists(path: Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return False
    return True


def profile_lock_reason(
    profile: Path,
    browser: ManagedBrowser | str = ManagedBrowser.FIREFOX,
    *,
    include_markers: bool = True,
) -> str:
    selected = ManagedBrowser(browser)
    if include_markers and any(
        _lock_marker_exists(profile / name) for name in selected.lock_files
    ):
        return f"Dedicated {selected.display_name} left profile lock state."
    for database in _browser_cookie_databases(profile, selected):
        if database.exists() and _windows_file_is_locked(database):
            return f"The dedicated {selected.display_name} profile data is locked."
    return ""


def _recover_stale_lock_markers(profile: Path, browser: ManagedBrowser) -> bool:
    """Remove only exact inert lock markers from one validated managed profile."""
    markers = [profile / name for name in browser.lock_files]
    present = [marker for marker in markers if _lock_marker_exists(marker)]
    if not present:
        return False
    for marker in present:
        if _is_reparse_point(marker) or marker.is_dir():
            raise ValueError("Managed browser lock marker is unsafe.")
    if profile_lock_reason(profile, browser, include_markers=False):
        return False
    for marker in present:
        marker.unlink()
    return True


def _windows_file_is_locked(path: Path) -> bool:
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    open_existing = 3
    file_attribute_normal = 0x80
    invalid_handle = wintypes.HANDLE(-1).value
    handle = create_file(
        str(path),
        generic_read,
        0,
        None,
        open_existing,
        file_attribute_normal,
        None,
    )
    if handle == invalid_handle:
        return ctypes.get_last_error() in {5, 32, 33}
    close_handle(handle)
    return False


def inspect_youtube_session_cookies(
    profile: Path,
    browser: ManagedBrowser | str = ManagedBrowser.FIREFOX,
) -> tuple[bool, str]:
    """Inspect cookie names/domains only; cookie values are never selected."""
    selected = ManagedBrowser(browser)
    database = next(
        (
            candidate
            for candidate in _browser_cookie_databases(profile, selected)
            if candidate.exists() and candidate.is_file()
        ),
        None,
    )
    if database is None:
        return False, f"The dedicated profile has no {selected.display_name} cookie database yet."
    if profile_lock_reason(profile, selected):
        return False, f"The dedicated {selected.display_name} profile data is locked."

    uri = f"file:{database.as_posix()}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        if selected is ManagedBrowser.CHROME:
            rows = connection.execute(
                "SELECT host_key, name FROM cookies "
                "WHERE host_key LIKE '%youtube.com' OR host_key LIKE '%google.com'"
            )
        else:
            rows = connection.execute(
                "SELECT host, name FROM moz_cookies "
                "WHERE host LIKE '%youtube.com' OR host LIKE '%google.com'"
            )
        for host, name in rows:
            normalized_host = str(host or "").casefold()
            normalized_name = str(name or "").upper()
            if normalized_host.endswith(("youtube.com", "google.com")) and (
                normalized_name in _AUTH_COOKIE_NAMES
            ):
                return True, "YouTube account session markers were found."
    except (OSError, sqlite3.Error):
        return False, f"The {selected.display_name} cookie database could not be inspected safely."
    finally:
        if connection is not None:
            connection.close()
    return False, "YouTube sign-in was not completed in the dedicated profile."


def _process_tree_pids(root_pid: int) -> tuple[int, ...]:
    """Return a best-effort descendant snapshot without invoking a shell."""
    if root_pid <= 0:
        return ()
    parents: dict[int, int] = {}
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_snapshot = kernel32.CreateToolhelp32Snapshot
        create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        create_snapshot.restype = wintypes.HANDLE
        process_first = kernel32.Process32FirstW
        process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32)]
        process_first.restype = wintypes.BOOL
        process_next = kernel32.Process32NextW
        process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32)]
        process_next.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        snapshot = create_snapshot(0x00000002, 0)
        invalid_handle = wintypes.HANDLE(-1).value
        if snapshot == invalid_handle:
            return (root_pid,)
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(ProcessEntry32)
        try:
            has_entry = bool(process_first(snapshot, ctypes.byref(entry)))
            while has_entry:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                has_entry = bool(process_next(snapshot, ctypes.byref(entry)))
        finally:
            close_handle(snapshot)
    else:
        proc = Path("/proc")
        with contextlib.suppress(OSError):
            for item in proc.iterdir():
                if not item.name.isdigit():
                    continue
                with contextlib.suppress(OSError, ValueError, IndexError):
                    fields = (item / "stat").read_text(encoding="utf-8").split()
                    parents[int(item.name)] = int(fields[3])

    found = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in found and pid not in found:
                found.add(pid)
                changed = True
    return tuple(sorted(found))


class YouTubeConnectionManager:
    """Persist one isolated managed-browser connection and its process identities."""

    def __init__(
        self,
        settings: SettingsStore,
        *,
        browser: ManagedBrowser | str = ManagedBrowser.FIREFOX,
        application_data: Path | None = None,
        discovery: FirefoxDiscovery | ChromeDiscovery | None = None,
        popen_factory: PopenFactory = subprocess.Popen,
        identity_provider: IdentityProvider = process_creation_identity,
        process_tree_provider: ProcessTreeProvider = _process_tree_pids,
        log_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.browser = ManagedBrowser(browser)
        self.settings_prefix = (
            SETTINGS_PREFIX
            if self.browser is ManagedBrowser.FIREFOX
            else f"{SETTINGS_PREFIX}/{self.browser.value}"
        )
        self.application_data = Path(application_data or app_data_dir())
        if self.browser is ManagedBrowser.CHROME:
            if discovery is not None and not isinstance(discovery, ChromeDiscovery):
                raise TypeError("Chrome manager requires ChromeDiscovery.")
            self.provider: ManagedBrowserProvider = ManagedChromeProvider(
                discovery or ChromeDiscovery()
            )
        else:
            if discovery is not None and not isinstance(discovery, FirefoxDiscovery):
                raise TypeError("Firefox manager requires FirefoxDiscovery.")
            self.provider = ManagedFirefoxProvider(discovery or FirefoxDiscovery())
        self.profile_path = self.provider.profile_path(self.application_data)
        self.discovery = self.provider.discovery
        self.popen_factory = popen_factory
        self.identity_provider = identity_provider
        self.process_tree_provider = process_tree_provider
        self.log_callback = log_callback
        self.events: list[str] = []
        self._process: subprocess.Popen[Any] | None = None
        self._process_identity: ManagedBrowserProcessIdentity | None = None
        self._process_probe_uncertain = False
        self._tracked_processes = self._load_tracked_processes()

        self.state = self._load_state()
        self.executable_path = self._load_path(f"{self.browser.value}_path")
        self.last_verified = str(self._value("last_verified", "") or "")
        self.failure_reason = _sanitize_failure_reason(str(self._value("failure_reason", "") or ""))
        self._reconcile_stored_profile()
        self.refresh_browser_state()

    @property
    def firefox_path(self) -> Path | None:
        return self.executable_path if self.browser is ManagedBrowser.FIREFOX else None

    @property
    def chrome_path(self) -> Path | None:
        return self.executable_path if self.browser is ManagedBrowser.CHROME else None

    @property
    def display_name(self) -> str:
        return self.browser.display_name

    def _key(self, name: str) -> str:
        return f"{self.settings_prefix}/{name}"

    def _value(self, name: str, default: Any = None) -> Any:
        return self.settings.value(self._key(name), default)

    def _load_state(self) -> ConnectionState:
        raw = str(self._value("state", ConnectionState.NOT_CONFIGURED.value) or "")
        with contextlib.suppress(ValueError):
            return ConnectionState(raw)
        return ConnectionState.ERROR

    def _load_path(self, name: str) -> Path | None:
        raw = str(self._value(name, "") or "").strip()
        return Path(raw) if raw else None

    def _load_tracked_processes(self) -> dict[int, str]:
        raw = str(self._value("managed_processes", "") or "")
        if not raw:
            return {}
        try:
            values = json.loads(raw)
            if not isinstance(values, list) or len(values) > 128:
                return {}
            tracked = {
                int(item["pid"]): str(item["identity"])
                for item in values
                if isinstance(item, dict)
                and int(item.get("pid", 0)) > 0
                and isinstance(item.get("identity"), str)
                and item["identity"]
            }
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return tracked

    def _save_tracked_processes(self) -> None:
        if not self._tracked_processes:
            self.settings.remove(self._key("managed_processes"))
        else:
            payload = [
                {"pid": pid, "identity": identity}
                for pid, identity in sorted(self._tracked_processes.items())
            ]
            self.settings.setValue(self._key("managed_processes"), json.dumps(payload))
        self.settings.sync()

    def _emit_event(self, message: str) -> None:
        self.events.append(message)
        if self.log_callback is not None:
            with contextlib.suppress(Exception):
                self.log_callback(message)

    def _reconcile_stored_profile(self) -> None:
        stored = self._load_path("profile_path")
        if stored:
            try:
                matches = _same_path(_normalized_path(stored), _normalized_path(self.profile_path))
            except (OSError, RuntimeError, ValueError):
                matches = False
            if not matches:
                self._set_state(ConnectionState.INVALID, "Stored dedicated profile path was rejected.")
                self.settings.remove(self._key("profile_path"))
                self.settings.sync()
                return
        if self.state == ConnectionState.CONNECTED:
            try:
                validate_managed_profile_path(
                    self.profile_path,
                    browser=self.browser,
                    application_data=self.application_data,
                )
            except ValueError:
                self._set_state(
                    ConnectionState.INVALID,
                    f"Dedicated {self.display_name} profile is unavailable.",
                )

    def snapshot(self) -> ConnectionSnapshot:
        return ConnectionSnapshot(
            self.state,
            self.profile_path,
            self.executable_path,
            self.last_verified,
            self.failure_reason,
            self.browser,
        )

    def _set_state(self, state: ConnectionState, reason: str = "") -> None:
        self.state = state
        self.failure_reason = _sanitize_failure_reason(reason)
        self.settings.setValue(self._key("state"), state.value)
        if self.profile_path.exists():
            self.settings.setValue(self._key("profile_path"), str(self.profile_path))
        if self.failure_reason:
            self.settings.setValue(self._key("failure_reason"), self.failure_reason)
        else:
            self.settings.remove(self._key("failure_reason"))
        self.settings.sync()

    def discover_browser(self) -> FirefoxDiscoveryResult:
        result = self.discovery.discover(self.executable_path)
        if result.executable:
            self.executable_path = result.executable
            self.settings.setValue(
                self._key(f"{self.browser.value}_path"), str(result.executable)
            )
            self.settings.sync()
        else:
            self._set_state(ConnectionState.FIREFOX_MISSING, result.reason)
        return result

    def discover_firefox(self) -> FirefoxDiscoveryResult:
        return self.discover_browser()

    def discover_chrome(self) -> ChromeDiscoveryResult:
        return self.discover_browser()

    def set_browser_path(self, path: Path | str) -> bool:
        validated = self.discovery.validate_executable(path)
        if not validated:
            self._set_state(
                ConnectionState.FIREFOX_MISSING,
                f"{self.display_name} executable is invalid.",
            )
            return False
        self.executable_path = validated
        self.settings.setValue(self._key(f"{self.browser.value}_path"), str(validated))
        self.settings.sync()
        if self.state == ConnectionState.FIREFOX_MISSING:
            self._set_state(ConnectionState.NOT_CONFIGURED)
        return True

    def set_firefox_path(self, path: Path | str) -> bool:
        return self.set_browser_path(path)

    def set_chrome_path(self, path: Path | str) -> bool:
        return self.set_browser_path(path)

    def create_profile(self) -> Path:
        root = youtube_data_root(self.application_data)
        if (
            self.application_data.exists()
            and _is_reparse_point(self.application_data)
        ) or (
            root.exists()
            and _is_reparse_point(root)
        ):
            self._set_state(ConnectionState.INVALID, "Managed YouTube directory is unsafe.")
            raise ValueError("Managed YouTube directory is unsafe.")
        try:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.profile_path.mkdir(parents=False, exist_ok=True, mode=0o700)
            with contextlib.suppress(OSError):
                root.chmod(0o700)
                self.profile_path.chmod(0o700)
            validated = validate_managed_profile_path(
                self.profile_path,
                browser=self.browser,
                application_data=self.application_data,
            )
        except (OSError, ValueError) as exc:
            self._set_state(ConnectionState.ERROR, "Dedicated profile could not be created.")
            raise RuntimeError("Dedicated profile could not be created.") from exc
        self._set_state(ConnectionState.PROFILE_READY)
        return validated

    def build_launch_command(self, target_url: str | None = None) -> list[str]:
        discovery = self.discovery.discover(self.executable_path)
        if not discovery.executable:
            self._set_state(ConnectionState.FIREFOX_MISSING, discovery.reason)
            raise RuntimeError(f"{self.display_name} is not installed.")
        self.executable_path = discovery.executable
        profile = self.create_profile()
        return self.provider.launch_arguments(
            discovery.executable,
            profile,
            _safe_youtube_url(target_url),
        )

    def launch(self, target_url: str | None = None) -> ManagedBrowserProcessIdentity:
        self.refresh_browser_state()
        if self.browser_is_open():
            self._set_state(
                ConnectionState.BROWSER_OPEN,
                f"Dedicated {self.display_name} is already running.",
            )
            raise RuntimeError(f"Dedicated {self.display_name} is already running.")
        command = self.build_launch_command(target_url)
        kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "shell": False,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            process = self.popen_factory(command, **kwargs)
        except (OSError, subprocess.SubprocessError) as exc:
            self._set_state(
                ConnectionState.ERROR,
                f"Dedicated {self.display_name} could not be started.",
            )
            raise RuntimeError(f"Dedicated {self.display_name} could not be started.") from exc
        identity = self.identity_provider(process.pid) or ""
        self._process = process
        self._process_identity = ManagedBrowserProcessIdentity(
            process.pid, identity, tuple(command)
        )
        self._tracked_processes = {process.pid: identity} if identity else {}
        self._capture_process_tree(process.pid)
        self._save_tracked_processes()
        self._set_state(ConnectionState.BROWSER_OPEN)
        return self._process_identity

    def _capture_process_tree(self, root_pid: int) -> None:
        with contextlib.suppress(Exception):
            for pid in self.process_tree_provider(root_pid):
                if pid <= 0:
                    continue
                identity = self.identity_provider(pid)
                if identity:
                    self._tracked_processes[pid] = identity

    def _live_tracked_pids(self) -> tuple[int, ...]:
        live: list[int] = []
        exited_root = (
            self._process.pid
            if self._process is not None and self._process.poll() is not None
            else None
        )
        for pid, identity in tuple(self._tracked_processes.items()):
            if pid == exited_root:
                continue
            try:
                if self.identity_provider(pid) == identity:
                    live.append(pid)
            except (OSError, PermissionError):
                self._process_probe_uncertain = True
        return tuple(live)

    def browser_is_open(self) -> bool:
        self._process_probe_uncertain = False
        if self._process is not None and self._process.poll() is None:
            tracked = self._process_identity
            if tracked and tracked.creation_identity:
                try:
                    if self.identity_provider(tracked.pid) == tracked.creation_identity:
                        self._capture_process_tree(tracked.pid)
                        self._save_tracked_processes()
                        return True
                except (OSError, PermissionError):
                    self._process_probe_uncertain = True
            elif tracked:
                return True
        return bool(self._live_tracked_pids())

    def recover_stale_state(self) -> bool:
        if self.browser_is_open() or self._process_probe_uncertain or not self.profile_path.exists():
            return False
        try:
            profile = validate_managed_profile_path(
                self.profile_path,
                browser=self.browser,
                application_data=self.application_data,
            )
            recovered = _recover_stale_lock_markers(profile, self.browser)
        except (OSError, ValueError):
            return False
        if recovered:
            self._emit_event("Recovered stale managed-browser profile state.")
        return recovered

    def wait_for_exit(self, timeout_seconds: float = 15.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while time.monotonic() < deadline:
            if not self.browser_is_open():
                self.recover_stale_state()
                return True
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        return not self.browser_is_open()

    def refresh_browser_state(self) -> ConnectionState:
        if self.browser_is_open():
            if self.state in {
                ConnectionState.BROWSER_OPEN,
                ConnectionState.WAITING_FOR_LOGIN,
                ConnectionState.PROFILE_READY,
            }:
                self._set_state(ConnectionState.BROWSER_OPEN)
            return self.state
        if self._process_probe_uncertain:
            self._set_state(
                ConnectionState.ERROR,
                "Managed browser process state could not be validated safely.",
            )
            return self.state
        if self._tracked_processes:
            self._tracked_processes = {}
            self._save_tracked_processes()
        if self._process is not None:
            self._process = None
            self._process_identity = None
        self.recover_stale_state()
        if self.state == ConnectionState.BROWSER_OPEN:
            self._set_state(ConnectionState.WAITING_FOR_LOGIN)
        return self.state

    def verify(self, verifier: Verifier, target_url: str) -> VerificationResult:
        self.refresh_browser_state()
        if self._process_probe_uncertain:
            result = VerificationResult(
                False,
                "process_state_unknown",
                "Managed browser process state could not be validated safely.",
            )
            self._set_state(ConnectionState.ERROR, result.message)
            return result
        if self.browser_is_open():
            result = VerificationResult(
                False,
                "browser_open",
                f"Close the dedicated {self.display_name} window before checking again.",
            )
            self._set_state(ConnectionState.LOCKED, result.message)
            return result
        try:
            profile = validate_managed_profile_path(
                self.profile_path,
                browser=self.browser,
                application_data=self.application_data,
            )
        except ValueError:
            result = VerificationResult(
                False,
                "invalid",
                f"Dedicated {self.display_name} profile is invalid.",
            )
            self._set_state(ConnectionState.INVALID, result.message)
            return result
        self.recover_stale_state()
        if profile_lock_reason(profile, self.browser, include_markers=False):
            result = VerificationResult(
                False,
                "locked",
                f"The dedicated {self.display_name} profile data is locked by another process.",
            )
            self._set_state(ConnectionState.LOCKED, result.message)
            return result
        cookies_present, cookie_reason = inspect_youtube_session_cookies(profile, self.browser)
        if not cookies_present:
            result = VerificationResult(False, "sign_in_incomplete", cookie_reason)
            self._set_state(ConnectionState.INVALID, result.message)
            return result

        self._set_state(ConnectionState.VERIFYING)
        try:
            result = verifier(profile, _safe_youtube_url(target_url))
        except Exception:
            result = VerificationResult(False, "error", "YouTube session verification failed.")
        if result.success:
            self.last_verified = datetime.now(UTC).isoformat(timespec="seconds")
            self.settings.setValue(self._key("last_verified"), self.last_verified)
            # Persist the provider identity in the same settings sync as the
            # verified state. Other managed profiles may still exist, but they
            # must never override the session that was actually verified.
            self.settings.setValue(ACTIVE_PROVIDER_KEY, self.browser.value)
            self._set_state(ConnectionState.CONNECTED)
        elif result.code in {"expired", "session_rejected", "authentication_required"}:
            self._set_state(ConnectionState.EXPIRED, result.message)
        elif result.code in {"locked", "browser_open"}:
            self._set_state(ConnectionState.LOCKED, result.message)
        elif result.code == "invalid":
            self._set_state(ConnectionState.INVALID, result.message)
        else:
            self._set_state(ConnectionState.ERROR, result.message)
        return result

    def mark_expired(self, reason: str = "YouTube session expired.") -> None:
        self._set_state(ConnectionState.EXPIRED, reason)

    def connected_profile(self) -> Path | None:
        if self.state != ConnectionState.CONNECTED:
            return None
        try:
            return validate_managed_profile_path(
                self.profile_path,
                browser=self.browser,
                application_data=self.application_data,
            )
        except ValueError:
            self._set_state(
                ConnectionState.INVALID,
                f"Dedicated {self.display_name} profile is unavailable.",
            )
            return None

    def disconnect(self) -> DisconnectResult:
        self.refresh_browser_state()
        if self._process_probe_uncertain:
            result = DisconnectResult(
                False,
                "process_state_unknown",
                "Managed browser process state could not be validated safely.",
            )
            self._set_state(ConnectionState.ERROR, result.message)
            return result
        if self.browser_is_open():
            result = DisconnectResult(
                False,
                "locked",
                f"Close the dedicated {self.display_name} window before disconnecting.",
            )
            self._set_state(ConnectionState.LOCKED, result.message)
            return result
        if not self.profile_path.exists():
            self._clear_connection_settings()
            self.state = ConnectionState.DISCONNECTED
            return DisconnectResult(True, "disconnected", "YouTube is disconnected.")
        try:
            profile = validate_managed_profile_path(
                self.profile_path,
                browser=self.browser,
                application_data=self.application_data,
            )
            self.recover_stale_state()
            if profile_lock_reason(profile, self.browser):
                raise PermissionError("profile is locked")
            self._reject_reparse_tree(profile)
            shutil.rmtree(profile)
        except (OSError, ValueError) as exc:
            result = DisconnectResult(
                False,
                "remove_failed",
                "Dedicated profile could not be removed.",
                self.profile_path,
            )
            detail = "Dedicated profile could not be removed safely."
            if isinstance(exc, PermissionError):
                detail = f"Dedicated {self.display_name} profile is still locked."
            self._set_state(ConnectionState.ERROR, detail)
            return result
        self._clear_connection_settings()
        self.state = ConnectionState.DISCONNECTED
        return DisconnectResult(True, "disconnected", "YouTube is disconnected.")

    @staticmethod
    def _reject_reparse_tree(profile: Path) -> None:
        if _is_reparse_point(profile):
            raise ValueError("managed profile is a reparse point")
        for root, directories, files in os.walk(profile, topdown=True, followlinks=False):
            for name in [*directories, *files]:
                candidate = Path(root) / name
                if _is_reparse_point(candidate):
                    raise ValueError("managed profile contains a reparse point")

    def _clear_connection_settings(self) -> None:
        for name in (
            "state",
            "profile_path",
            "last_verified",
            "failure_reason",
            "managed_processes",
        ):
            self.settings.remove(self._key(name))
        active_provider = str(self.settings.value(ACTIVE_PROVIDER_KEY, "") or "")
        if active_provider.casefold() == self.browser.value:
            self.settings.remove(ACTIVE_PROVIDER_KEY)
        self.settings.sync()
        self.last_verified = ""
        self.failure_reason = ""
        self._tracked_processes = {}


__all__ = [
    "ACTIVE_PROVIDER_KEY",
    "ChromeDiscovery",
    "ChromeDiscoveryResult",
    "ConnectionSnapshot",
    "ConnectionState",
    "DEFAULT_CONNECTION_URL",
    "DisconnectResult",
    "FirefoxDiscovery",
    "FirefoxDiscoveryResult",
    "FirefoxProcessIdentity",
    "ManagedBrowser",
    "ManagedBrowserProvider",
    "ManagedBrowserProcessIdentity",
    "ManagedChromeProvider",
    "ManagedFirefoxProvider",
    "VerificationResult",
    "YouTubeConnectionManager",
    "dedicated_browser_profile_path",
    "dedicated_chrome_profile_path",
    "dedicated_firefox_profile_path",
    "inspect_youtube_session_cookies",
    "profile_lock_reason",
    "validate_dedicated_profile_path",
    "validate_managed_profile_path",
    "youtube_data_root",
]
