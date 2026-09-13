"""Precise YouTube/yt-dlp failure classification for retry decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailureCategory(str, Enum):
    """Stable failure buckets used by the engine, GUI, and offline tests."""

    AUTHENTICATION_REQUIRED = "authentication_required"
    YOUTUBE_SESSION_EXPIRED = "youtube_session_expired"
    YOUTUBE_ACCESS_RESTRICTED = "youtube_access_restricted"
    DEDICATED_PROFILE_INVALID = "dedicated_profile_invalid"
    COOKIE_FILE_REJECTED = "cookie_file_rejected"
    BROWSER_COOKIE_DATABASE_LOCKED = "browser_cookie_database_locked"
    BROWSER_COOKIE_DECRYPTION_FAILED = "browser_cookie_decryption_failed"
    BROWSER_COOKIE_EXTRACTION_FAILED = "browser_cookie_extraction_failed"
    HTTP_403_MEDIA_REJECTED = "http_403_media_rejected"
    VERIFIED_PROVIDER_NOT_APPLIED = "verified_provider_not_applied"
    VERIFIED_SESSION_MEDIA_403 = "verified_session_media_403"
    PO_TOKEN_PROVIDER_UNAVAILABLE = "po_token_provider_unavailable"
    PO_TOKEN_FETCH_FAILED = "po_token_fetch_failed"
    PO_TOKEN_MEDIA_403 = "po_token_media_403"
    MEDIA_ACCESS_REJECTED_AFTER_AUTHENTICATION = "media_access_rejected_after_authentication"
    PO_TOKEN_REQUIRED = "po_token_required"
    REQUESTED_FORMAT_UNAVAILABLE = "requested_format_unavailable"
    ONLY_SABR_OR_IMAGE_FORMATS = "only_sabr_or_image_formats"
    ONLY_IMAGE_FORMATS_AVAILABLE = "only_sabr_or_image_formats"
    NETWORK_TRANSIENT = "network_transient"
    NETWORK_INACTIVITY_TIMEOUT = "network_inactivity_timeout"
    TOTAL_ATTEMPT_TIMEOUT = "total_attempt_timeout"
    DOWNLOAD_CANCELLED = "download_cancelled"
    WORKER_PROTOCOL_ERROR = "worker_protocol_error"
    JAVASCRIPT_RUNTIME_UNAVAILABLE = "javascript_runtime_unavailable"
    CHALLENGE_SOLVER_COMPONENT_UNAVAILABLE = "challenge_solver_component_unavailable"
    LIVE_EVENT_ENDED = "live_event_ended"
    UNKNOWN = "unknown_ytdlp_failure"


@dataclass(frozen=True, slots=True)
class FailureAnalysis:
    category: FailureCategory
    user_message: str
    authentication_specific: bool = False
    transient: bool = False


_AUTH_PATTERNS = (
    "sign in to confirm",
    "login required",
    "private video",
    "members-only",
    "members only",
    "confirm your age",
    "age-restricted",
    "age restricted",
    "this video may be inappropriate for some users",
    "authentication is required",
    "account authentication",
    "use --cookies",
)

_EXPIRED_COOKIE_PATTERNS = (
    "cookies are no longer valid",
    "cookies are no longer fresh",
    "cookies have been rotated",
    "cookie has expired",
    "cookies have expired",
    "session has expired",
)

_DEDICATED_SESSION_REJECTION_PATTERNS = (
    "sign in to confirm",
    "login required",
    "authentication is required",
    "account authentication",
    "use --cookies",
)

_ACCOUNT_ACCESS_PATTERNS = (
    "private video",
    "members-only",
    "members only",
    "confirm your age",
    "age-restricted",
    "age restricted",
)

_TRANSIENT_NETWORK_PATTERNS = (
    "connection reset",
    "connection aborted",
    "connection refused",
    "remote end closed connection",
    "remote disconnected",
    "temporary failure in name resolution",
    "temporarily unavailable",
    "network is unreachable",
    "read timed out",
    "connection timed out",
    "operation timed out",
    "socket timeout",
    "unable to resolve host",
    "name resolution",
    "http error 408",
    "http error 429",
    "http error 500",
    "http error 502",
    "http error 503",
    "http error 504",
)

_PO_TOKEN_PATTERNS = (
    "po token",
    "pot token",
    "proof of origin token",
)

_PO_PROVIDER_UNAVAILABLE_PATTERNS = (
    "external_po_helper_unavailable",
    "external_po_helper_helper_unavailable",
    "po_token_provider_unavailable",
    "po token provider unavailable",
    "no po token providers registered",
    "no po token providers were able",
    "po token provider is not available",
)

_PO_FETCH_FAILURE_PATTERNS = (
    "external_po_helper_",
    "_get_pot_via_script failed",
    "error fetching po token",
    "unexpected error when fetching po token",
    "invalid po token response",
    "script did not respond with a po_token",
    "failed while generating pot",
    "failed to check script version",
    "timeout expired when trying to run script",
)

_MISSING_RUNTIME_PATTERNS = (
    "no supported javascript runtime could be found",
    "no javascript runtime could be found",
    "javascript runtime is unavailable",
    "youtube extraction without a js runtime",
)

_COMPONENT_PATTERNS = (
    "no usable challenge solver",
    "remote component challenge solver script was skipped",
    "failed to download challenge solver",
    "failed to read builtin challenge solver",
    "failed to load challenge solver",
    "challenge solver lib script",
    "challenge solver core script",
)


def classify_youtube_failure(
    error_text: str,
    *,
    auth_kind: str = "none",
    javascript_runtime_available: bool = True,
    attempt_kind: str = "public",
) -> FailureAnalysis:
    """Classify actual yt-dlp output, never a rendered command line.

    The runtime availability input is intentionally authoritative. A generic
    n-challenge, image-only, HTTP 403, or format failure must not be converted
    into a missing-Node diagnostic when Node was already found and executed.
    """

    lowered = (error_text or "").lower()

    if _is_worker_unicode_transport_failure(lowered):
        return FailureAnalysis(
            FailureCategory.WORKER_PROTOCOL_ERROR,
            "The internal yt-dlp worker could not transport Unicode output safely.",
        )

    if auth_kind in {"dedicated_browser", "dedicated_firefox"} and any(
        pattern in lowered for pattern in _ACCOUNT_ACCESS_PATTERNS
    ):
        return FailureAnalysis(
            FailureCategory.YOUTUBE_ACCESS_RESTRICTED,
            "The connected account does not have access to this restricted video.",
            authentication_specific=True,
        )

    if auth_kind in {"dedicated_browser", "dedicated_firefox"} and (
        any(pattern in lowered for pattern in _EXPIRED_COOKIE_PATTERNS)
        or any(pattern in lowered for pattern in _DEDICATED_SESSION_REJECTION_PATTERNS)
    ):
        return FailureAnalysis(
            FailureCategory.YOUTUBE_SESSION_EXPIRED,
            "The dedicated YouTube session expired or was rejected. Renew the YouTube connection.",
            authentication_specific=True,
        )

    if "this live event has ended" in lowered:
        return FailureAnalysis(
            FailureCategory.LIVE_EVENT_ENDED,
            "This live event has ended and is not currently downloadable.",
        )

    if _is_cookie_database_locked(lowered):
        return FailureAnalysis(
            FailureCategory.BROWSER_COOKIE_DATABASE_LOCKED,
            "The browser cookie database is locked. Close that browser and retry, or use cookies.txt.",
            authentication_specific=True,
        )

    if _is_cookie_decryption_failure(lowered):
        return FailureAnalysis(
            FailureCategory.BROWSER_COOKIE_DECRYPTION_FAILED,
            "Windows could not decrypt this browser's cookies. Try another authenticated source.",
            authentication_specific=True,
        )

    if _is_browser_cookie_extraction_failure(lowered):
        return FailureAnalysis(
            FailureCategory.BROWSER_COOKIE_EXTRACTION_FAILED,
            "Browser cookie extraction failed. Try another authenticated source or export cookies.txt.",
            authentication_specific=True,
        )

    if any(pattern in lowered for pattern in _PO_PROVIDER_UNAVAILABLE_PATTERNS):
        return FailureAnalysis(
            FailureCategory.PO_TOKEN_PROVIDER_UNAVAILABLE,
            "The optional external PO Token helper is unavailable.",
        )

    if any(pattern in lowered for pattern in _PO_FETCH_FAILURE_PATTERNS):
        return FailureAnalysis(
            FailureCategory.PO_TOKEN_FETCH_FAILED,
            "The optional external PO Token helper could not obtain a valid token.",
        )

    if any(
        pattern in lowered
        for pattern in (
            "only sabr formats",
            "only sabr or image formats",
            "sabr-only",
            "only images are available",
            "only image formats",
            "only storyboard formats",
        )
    ):
        return FailureAnalysis(
            FailureCategory.ONLY_SABR_OR_IMAGE_FORMATS,
            "YouTube exposed only SABR or image formats; no directly downloadable media format was available.",
        )

    if any(token in lowered for token in _PO_TOKEN_PATTERNS) and any(
        marker in lowered
        for marker in ("required", "requires", "missing", "not provided", "without")
    ):
        return FailureAnalysis(
            FailureCategory.PO_TOKEN_REQUIRED,
            "The selected YouTube client requires a PO Token to expose downloadable media formats.",
        )

    if any(pattern in lowered for pattern in _COMPONENT_PATTERNS):
        return FailureAnalysis(
            FailureCategory.CHALLENGE_SOLVER_COMPONENT_UNAVAILABLE,
            "YouTube challenge processing failed because the supported solver component was unavailable.",
        )

    if not javascript_runtime_available and (
        any(pattern in lowered for pattern in _MISSING_RUNTIME_PATTERNS)
        or "n challenge solving failed" in lowered
    ):
        return FailureAnalysis(
            FailureCategory.JAVASCRIPT_RUNTIME_UNAVAILABLE,
            "YouTube challenge solver unavailable. Install Node.js or use the bundled runtime.",
        )

    if any(pattern in lowered for pattern in _AUTH_PATTERNS):
        return FailureAnalysis(
            FailureCategory.AUTHENTICATION_REQUIRED,
            "This video requires YouTube authentication. OpenFetch will try an available cookie source.",
            authentication_specific=True,
        )

    if "http error 403" in lowered or "http status 403" in lowered or "403 forbidden" in lowered:
        if attempt_kind == "po_token":
            return FailureAnalysis(
                FailureCategory.PO_TOKEN_MEDIA_403,
                "The PO Token provider ran, but YouTube still rejected the media request.",
            )
        if attempt_kind == "verified_session":
            return FailureAnalysis(
                FailureCategory.VERIFIED_SESSION_MEDIA_403,
                "The browser session is valid, but YouTube rejected the media request. A PO Token may be required.",
                authentication_specific=True,
            )
        if attempt_kind == "authenticated":
            return FailureAnalysis(
                FailureCategory.MEDIA_ACCESS_REJECTED_AFTER_AUTHENTICATION,
                "YouTube rejected the media request after authentication.",
                authentication_specific=True,
            )
        if auth_kind == "cookies_file":
            return FailureAnalysis(
                FailureCategory.COOKIE_FILE_REJECTED,
                "cookies.txt was rejected or may be stale.",
                authentication_specific=True,
            )
        return FailureAnalysis(
            FailureCategory.HTTP_403_MEDIA_REJECTED,
            "YouTube rejected media access with HTTP 403. Authentication is not assumed from this error alone.",
        )

    if _is_format_unavailable(lowered):
        return FailureAnalysis(
            FailureCategory.REQUESTED_FORMAT_UNAVAILABLE,
            "The requested media format is not available for this video.",
        )

    if any(pattern in lowered for pattern in _TRANSIENT_NETWORK_PATTERNS):
        return FailureAnalysis(
            FailureCategory.NETWORK_TRANSIENT,
            "A temporary network failure interrupted the YouTube attempt.",
            transient=True,
        )

    if "n challenge solving failed" in lowered:
        return FailureAnalysis(
            FailureCategory.UNKNOWN,
            "YouTube challenge processing failed even though the JavaScript runtime was available.",
        )

    return FailureAnalysis(
        FailureCategory.UNKNOWN,
        "yt-dlp failed for an unknown reason. See the Activity Log for details.",
    )


def _is_cookie_database_locked(lowered: str) -> bool:
    return (
        "could not copy" in lowered
        and "cookie database" in lowered
        or "database is locked" in lowered
        or "database table is locked" in lowered
    )


def _is_cookie_decryption_failure(lowered: str) -> bool:
    return any(
        pattern in lowered
        for pattern in (
            "dpapi",
            "failed to decrypt",
            "could not decrypt",
            "unable to decrypt",
            "decrypt cookie",
            "app-bound",
            "app bound",
            "application-bound",
            'cookie version: "v20"',
        )
    )


def _is_browser_cookie_extraction_failure(lowered: str) -> bool:
    return any(
        pattern in lowered
        for pattern in (
            "failed to load cookies",
            "could not load cookies",
            "failed loading cookies",
            "cookies from browser",
            "browser cookies",
            "keyring",
            "secretstorage",
        )
    )


def _is_format_unavailable(lowered: str) -> bool:
    return any(
        pattern in lowered
        for pattern in (
            "requested format is not available",
            "requested format not available",
            "format is not available",
            "no suitable formats",
            "no video formats found",
        )
    )


def _is_worker_unicode_transport_failure(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "unicodeencodeerror",
            "unicodedecodeerror",
            "codec can't encode character",
            "codec can't decode byte",
        )
    ) and any(
        marker in lowered
        for marker in (
            "charmap",
            "cp1252",
            "utf-8",
            "unicodeencodeerror",
            "unicodedecodeerror",
        )
    )
