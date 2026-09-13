"""Authentication option resolution for yt-dlp."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from openfetch.core.youtube_connection import (
    ManagedBrowser,
    validate_dedicated_profile_path,
    validate_managed_profile_path,
)

BROWSER_FALLBACK_ORDER = ("chrome", "edge", "brave", "firefox")

SUPPORTED_BROWSER_NAMES = {
    "brave": "Brave",
    "chrome": "Chrome",
    "edge": "Edge",
    "firefox": "Firefox",
}

AUTH_COOKIE_DOMAINS = (
    "youtube.com",
    ".youtube.com",
    "google.com",
    ".google.com",
    "accounts.google.com",
)


@dataclass(frozen=True, slots=True)
class CookieFileStatus:
    path: Path | None
    valid: bool
    reason: str

    @property
    def display_name(self) -> str:
        if not self.path:
            return "cookies.txt"
        return self.path.name or "cookies.txt"


@dataclass(frozen=True, slots=True)
class BrowserCookieSource:
    browser: str
    display_name: str
    profile_path: Path


@dataclass(frozen=True, slots=True)
class AuthStrategy:
    kind: str
    display_name: str
    ydl_options: dict[str, Any]
    attempted_auth: bool = False

    @property
    def is_cookie_file(self) -> bool:
        return self.kind == "cookies_file"

    @property
    def is_browser(self) -> bool:
        return self.kind in {"browser", "dedicated_browser", "dedicated_firefox"}

    @property
    def is_dedicated_browser(self) -> bool:
        return self.kind in {"dedicated_browser", "dedicated_firefox"}

    @property
    def is_dedicated_firefox(self) -> bool:
        return self.kind == "dedicated_firefox"

    @property
    def browser(self) -> str | None:
        if not self.is_browser:
            return None
        configured = self.ydl_options.get("cookiesfrombrowser")
        if isinstance(configured, str):
            return configured.lower()
        if isinstance(configured, tuple | list) and configured:
            return str(configured[0]).lower()
        return None

    @property
    def provider_id(self) -> str:
        if self.is_dedicated_browser:
            return f"dedicated_{self.browser or 'browser'}"
        if self.is_browser:
            return f"browser:{self.browser or self.display_name.lower()}"
        return self.kind


@dataclass(frozen=True, slots=True)
class AuthResolution:
    strategies: list[AuthStrategy]
    messages: list[str]
    cookie_file_status: CookieFileStatus
    browser_source: BrowserCookieSource | None
    browser_sources: list[BrowserCookieSource]


BrowserDetector = Callable[[], list[BrowserCookieSource]]


@dataclass(slots=True)
class AuthenticationState:
    """Mutable, per-job state for bounded authenticated fallback selection."""

    resolution: AuthResolution
    authenticated_fallback_justified: bool = False
    cookie_file_rejected: bool = False
    cookie_file_rejection_reason: str = ""
    attempted_provider_ids: set[str] = field(default_factory=set)
    disabled_browser_reasons: dict[str, str] = field(default_factory=dict)

    def justify_authenticated_fallback(self) -> None:
        self.authenticated_fallback_justified = True

    def mark_attempted(self, strategy: AuthStrategy) -> None:
        if strategy.attempted_auth:
            self.attempted_provider_ids.add(strategy.provider_id)

    def reject_cookie_file(self, reason: str = "") -> None:
        self.cookie_file_rejected = True
        self.cookie_file_rejection_reason = reason
        self.attempted_provider_ids.add("cookies_file")

    def disable_browser(self, browser: str, reason: str) -> None:
        normalized = browser.strip().lower()
        if not normalized:
            return
        self.disabled_browser_reasons[normalized] = reason
        self.attempted_provider_ids.add(f"browser:{normalized}")

    def is_browser_disabled(self, browser: str) -> bool:
        return browser.strip().lower() in self.disabled_browser_reasons

    def eligible_authenticated_strategies(self) -> list[AuthStrategy]:
        if not self.authenticated_fallback_justified:
            return []

        eligible: list[AuthStrategy] = []
        for strategy in self.resolution.strategies:
            if not strategy.attempted_auth or strategy.provider_id in self.attempted_provider_ids:
                continue
            if strategy.is_cookie_file and self.cookie_file_rejected:
                continue
            if strategy.is_browser and strategy.browser:
                if self.is_browser_disabled(strategy.browser):
                    continue
            eligible.append(strategy)
        return eligible

    def next_authenticated_strategy(self) -> AuthStrategy | None:
        eligible = self.eligible_authenticated_strategies()
        if not eligible:
            return None
        strategy = eligible[0]
        self.mark_attempted(strategy)
        return strategy


class BrowserCookieFailureKind(str, Enum):
    LOCKED = "locked"
    DECRYPTION_FAILED = "decryption_failed"
    UNSUPPORTED = "unsupported"
    EXTRACTION_FAILED = "extraction_failed"


def inspect_cookie_file(cookie_file: Path | None) -> CookieFileStatus:
    """Validate whether a cookies.txt file looks usable for YouTube auth."""
    if not cookie_file:
        return CookieFileStatus(None, False, "cookies.txt not loaded")

    path = Path(cookie_file).expanduser()
    if not path.exists():
        return CookieFileStatus(path, False, "cookies.txt not found")
    if not path.is_file():
        return CookieFileStatus(path, False, "cookies.txt path is not a file")
    try:
        if path.stat().st_size <= 0:
            return CookieFileStatus(path, False, "cookies.txt is empty")
    except OSError:
        return CookieFileStatus(path, False, "cookies.txt cannot be inspected")

    try:
        has_cookie_rows = False
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                has_cookie_rows = True
                lowered = stripped.lower()
                if any(domain in lowered for domain in AUTH_COOKIE_DOMAINS):
                    return CookieFileStatus(path, True, "cookies.txt contains YouTube/Google cookies")
    except OSError:
        return CookieFileStatus(path, False, "cookies.txt cannot be read")

    if not has_cookie_rows:
        return CookieFileStatus(path, False, "cookies.txt contains no cookie rows")
    return CookieFileStatus(path, False, "cookies.txt contains no YouTube/Google cookie rows")


def detect_browser_cookie_sources() -> list[BrowserCookieSource]:
    """Return supported browser profiles in fallback order."""
    path_by_browser: dict[str, Path]
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", "")).expanduser()
        roaming = Path(os.environ.get("APPDATA", "")).expanduser()
        path_by_browser = {
            "chrome": local / "Google" / "Chrome" / "User Data",
            "edge": local / "Microsoft" / "Edge" / "User Data",
            "brave": local / "BraveSoftware" / "Brave-Browser" / "User Data",
            "firefox": roaming / "Mozilla" / "Firefox" / "Profiles",
        }
    elif sys.platform == "darwin":
        support = Path.home() / "Library" / "Application Support"
        path_by_browser = {
            "chrome": support / "Google" / "Chrome",
            "edge": support / "Microsoft Edge",
            "brave": support / "BraveSoftware" / "Brave-Browser",
            "firefox": support / "Firefox" / "Profiles",
        }
    else:
        config = Path.home() / ".config"
        path_by_browser = {
            "chrome": config / "google-chrome",
            "edge": config / "microsoft-edge",
            "brave": config / "BraveSoftware" / "Brave-Browser",
            "firefox": Path.home() / ".mozilla" / "firefox",
        }

    sources: list[BrowserCookieSource] = []
    for browser in BROWSER_FALLBACK_ORDER:
        profile_path = path_by_browser[browser]
        if profile_path.exists():
            sources.append(
                BrowserCookieSource(
                    browser=browser,
                    display_name=SUPPORTED_BROWSER_NAMES[browser],
                    profile_path=profile_path,
                )
            )
    return sources


def resolve_auth_strategies(
    cookie_file: Path | None,
    browser_detector: BrowserDetector = detect_browser_cookie_sources,
    *,
    dedicated_browser: str | None = None,
    dedicated_browser_profile: Path | None = None,
    dedicated_firefox_profile: Path | None = None,
    dedicated_application_data: Path | None = None,
    allow_legacy_browser_fallback: bool = True,
) -> AuthResolution:
    """Build ordered auth strategies for yt-dlp.

    Public videos are attempted without authentication first. A valid cookies.txt and
    detected browser profiles are retained as deterministic authenticated fallbacks.
    """
    messages: list[str] = []
    strategies: list[AuthStrategy] = [
        AuthStrategy(
            kind="none",
            display_name="no authentication",
            attempted_auth=False,
            ydl_options={},
        )
    ]

    if dedicated_browser and dedicated_browser_profile:
        try:
            selected_browser = ManagedBrowser(dedicated_browser)
            profile = validate_managed_profile_path(
                dedicated_browser_profile,
                browser=selected_browser,
                application_data=dedicated_application_data,
            )
        except (ValueError, TypeError):
            messages.append("dedicated OpenFetch browser profile is invalid")
        else:
            display_name = selected_browser.display_name
            extraction_profile = (
                profile / "Default" if selected_browser is ManagedBrowser.CHROME else profile
            )
            messages.append(f"dedicated OpenFetch {display_name} profile available")
            strategies.append(
                AuthStrategy(
                    kind="dedicated_browser",
                    display_name=f"Dedicated OpenFetch {display_name} profile",
                    attempted_auth=True,
                    ydl_options={
                        "cookiesfrombrowser": (
                            selected_browser.value,
                            str(extraction_profile),
                        ),
                    },
                )
            )
    elif dedicated_firefox_profile:
        try:
            profile = validate_dedicated_profile_path(
                dedicated_firefox_profile,
                application_data=dedicated_application_data,
            )
        except ValueError:
            messages.append("dedicated OpenFetch Firefox profile is invalid")
        else:
            messages.append("dedicated OpenFetch Firefox profile available")
            strategies.append(
                AuthStrategy(
                    kind="dedicated_firefox",
                    display_name="Dedicated OpenFetch Firefox profile",
                    attempted_auth=True,
                    ydl_options={
                        "cookiesfrombrowser": ("firefox", str(profile)),
                    },
                )
            )

    cookie_status = inspect_cookie_file(cookie_file)
    if cookie_status.valid and cookie_status.path:
        messages.append(
            f"cookies.txt available: {cookie_status.display_name} "
            "(held for authenticated fallback)"
        )
        strategies.append(
            AuthStrategy(
                kind="cookies_file",
                display_name="cookies.txt",
                attempted_auth=True,
                ydl_options={
                    "cookiefile": str(cookie_status.path),
                },
            )
        )
    elif cookie_file:
        messages.append(f"cookies.txt invalid: {cookie_status.display_name} ({cookie_status.reason})")
    else:
        messages.append("cookies.txt not loaded")

    browser_sources = browser_detector() if allow_legacy_browser_fallback else []
    if browser_sources:
        browser_names = ", ".join(source.display_name for source in browser_sources)
        messages.append(f"browser cookie fallback available: {browser_names}")
        for browser_source in browser_sources:
            strategies.append(
                AuthStrategy(
                    kind="browser",
                    display_name=browser_source.display_name,
                    attempted_auth=True,
                    ydl_options={
                        "cookiesfrombrowser": (browser_source.browser,),
                    },
                )
            )
    elif allow_legacy_browser_fallback:
        messages.append(
            "browser cookies unavailable: no Chrome, Edge, Brave, or Firefox profile found"
        )
    else:
        messages.append("legacy browser cookie fallback disabled")

    return AuthResolution(
        strategies=strategies,
        messages=messages,
        cookie_file_status=cookie_status,
        browser_source=browser_sources[0] if browser_sources else None,
        browser_sources=browser_sources,
    )


def is_live_event_ended_error(error_text: str) -> bool:
    """Return True when YouTube reports an ended live event."""
    lowered = error_text.lower()
    return "this live event has ended" in lowered


def clean_live_event_ended_error() -> str:
    return "This live event has ended and is not currently downloadable."


def classify_browser_cookie_extraction_error(
    error_text: str,
) -> BrowserCookieFailureKind | None:
    """Classify local browser cookie failures without treating them as media errors."""
    lowered = error_text.lower()
    locked_patterns = (
        "could not copy chrome cookie database",
        "could not copy edge cookie database",
        "could not copy brave cookie database",
        "could not copy firefox cookie database",
        "database is locked",
        "database table is locked",
        "cookie database is locked",
    )
    if any(pattern in lowered for pattern in locked_patterns):
        return BrowserCookieFailureKind.LOCKED

    unsupported_patterns = (
        "app-bound",
        "app bound encryption",
        "application-bound",
        "app_bound_encrypted_key",
        'cookie version: "v20"',
        "chrome cookie encryption is not supported",
    )
    if any(pattern in lowered for pattern in unsupported_patterns):
        return BrowserCookieFailureKind.UNSUPPORTED

    decryption_patterns = (
        "dpapi",
        "failed to decrypt",
        "could not decrypt",
        "unable to decrypt",
        "keyring",
        "secretstorage",
    )
    if any(pattern in lowered for pattern in decryption_patterns):
        return BrowserCookieFailureKind.DECRYPTION_FAILED

    extraction_patterns = (
        "cookie database",
        "browser cookies",
        "cookies from browser",
        "failed to load cookies",
        "could not load cookies",
        "failed loading cookies",
    )
    if any(pattern in lowered for pattern in extraction_patterns):
        return BrowserCookieFailureKind.EXTRACTION_FAILED
    return None


def is_browser_cookie_locked_error(error_text: str) -> bool:
    return classify_browser_cookie_extraction_error(error_text) == BrowserCookieFailureKind.LOCKED


def is_browser_cookie_decryption_error(error_text: str) -> bool:
    return (
        classify_browser_cookie_extraction_error(error_text)
        == BrowserCookieFailureKind.DECRYPTION_FAILED
    )


def is_browser_cookie_extraction_error(error_text: str) -> bool:
    """Compatibility helper for any local browser cookie extraction failure."""
    return classify_browser_cookie_extraction_error(error_text) is not None


def clean_browser_cookie_failure(
    kind: BrowserCookieFailureKind,
    browser_name: str = "",
) -> str:
    browser = browser_name.strip()
    if kind == BrowserCookieFailureKind.LOCKED:
        if browser:
            return f"{browser} cookie database is locked. Close {browser} and try again."
        return "Browser cookie database is locked. Close the browser and try again."
    if kind == BrowserCookieFailureKind.DECRYPTION_FAILED:
        suffix = f" for {browser}" if browser else ""
        return (
            f"Browser cookie decryption failed{suffix}. "
            "Try cookies.txt or another signed-in browser."
        )
    if kind == BrowserCookieFailureKind.UNSUPPORTED:
        return (
            "Chrome session could not be read securely. "
            "Try the managed Firefox connection."
        )
    suffix = f" for {browser}" if browser else ""
    return (
        f"Browser cookie extraction failed{suffix}. "
        "Try cookies.txt or another supported browser."
    )


def clean_browser_cookie_extraction_error(
    error_text: str = "",
    browser_name: str = "",
) -> str:
    kind = (
        classify_browser_cookie_extraction_error(error_text)
        or BrowserCookieFailureKind.EXTRACTION_FAILED
    )
    return clean_browser_cookie_failure(kind, browser_name)


def is_authentication_error(error_text: str) -> bool:
    """Return True when a yt-dlp error is likely auth/cookie related."""
    if is_live_event_ended_error(error_text) or is_browser_cookie_extraction_error(error_text):
        return False

    lowered = error_text.lower()
    patterns = (
        "sign in to confirm",
        "not a bot",
        "use --cookies",
        "cookies-from-browser",
        "cookies from browser",
        "cookie file",
        "login required",
        "private video",
        "members-only",
        "members only",
        "confirm your age",
        "age-restricted",
        "authentication",
    )
    return any(pattern in lowered for pattern in patterns)


def clean_authentication_error(auth_was_attempted: bool) -> str:
    if auth_was_attempted:
        return "Cookies appear expired or invalid. Please export fresh cookies from your browser."
    return (
        "Authentication unavailable. Add a fresh cookies.txt file or sign in with "
        "Chrome, Edge, Firefox, or Brave so browser cookies can be used."
    )
