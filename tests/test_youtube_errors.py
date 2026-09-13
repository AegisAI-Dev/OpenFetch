import pytest

from openfetch.core.youtube_errors import (
    FailureCategory,
    classify_youtube_failure,
)


@pytest.mark.parametrize(
    ("message", "category"),
    [
        (
            "ERROR: Could not copy Chrome cookie database",
            FailureCategory.BROWSER_COOKIE_DATABASE_LOCKED,
        ),
        (
            "ERROR: Failed to decrypt cookies with Windows DPAPI",
            FailureCategory.BROWSER_COOKIE_DECRYPTION_FAILED,
        ),
        (
            "WARNING: This client requires a PO Token for video playback",
            FailureCategory.PO_TOKEN_REQUIRED,
        ),
        (
            "ERROR: No PO Token providers registered; a PO Token is required",
            FailureCategory.PO_TOKEN_PROVIDER_UNAVAILABLE,
        ),
        (
            "ERROR: _get_pot_via_script failed while fetching PO Token",
            FailureCategory.PO_TOKEN_FETCH_FAILED,
        ),
        (
            "ERROR: Requested format is not available",
            FailureCategory.REQUESTED_FORMAT_UNAVAILABLE,
        ),
        (
            "WARNING: n challenge solving failed. Only images are available",
            FailureCategory.ONLY_SABR_OR_IMAGE_FORMATS,
        ),
        (
            "WARNING: The web client exposed only SABR formats",
            FailureCategory.ONLY_SABR_OR_IMAGE_FORMATS,
        ),
        (
            "ERROR: Sign in to confirm your age. Use --cookies",
            FailureCategory.AUTHENTICATION_REQUIRED,
        ),
    ],
)
def test_failure_categories_are_separate(message, category):
    analysis = classify_youtube_failure(message)

    assert analysis.category == category


def test_node_found_plus_http_403_is_not_missing_node():
    analysis = classify_youtube_failure(
        "ERROR: unable to download video data: HTTP Error 403: Forbidden",
        javascript_runtime_available=True,
    )

    assert analysis.category == FailureCategory.HTTP_403_MEDIA_REJECTED
    assert "runtime" not in analysis.user_message.lower()


def test_node_found_plus_format_unavailable_is_not_missing_node():
    analysis = classify_youtube_failure(
        "ERROR: Requested format is not available",
        javascript_runtime_available=True,
    )

    assert analysis.category == FailureCategory.REQUESTED_FORMAT_UNAVAILABLE
    assert "runtime" not in analysis.user_message.lower()


def test_generic_n_challenge_with_node_found_is_not_missing_node():
    analysis = classify_youtube_failure(
        "WARNING: n challenge solving failed",
        javascript_runtime_available=True,
    )

    assert analysis.category == FailureCategory.UNKNOWN
    assert "even though" in analysis.user_message


def test_genuine_missing_javascript_runtime_is_detected():
    analysis = classify_youtube_failure(
        "WARNING: No supported JavaScript runtime could be found",
        javascript_runtime_available=False,
    )

    assert analysis.category == FailureCategory.JAVASCRIPT_RUNTIME_UNAVAILABLE


def test_cookie_file_http_403_is_rejected_cookie_not_generic_auth_requirement():
    analysis = classify_youtube_failure(
        "ERROR: unable to download video data: HTTP Error 403: Forbidden",
        auth_kind="cookies_file",
    )

    assert analysis.category == FailureCategory.COOKIE_FILE_REJECTED


def test_generic_http_403_does_not_claim_authentication_is_required():
    analysis = classify_youtube_failure(
        "ERROR: unable to download video data: HTTP Error 403: Forbidden",
        auth_kind="none",
    )

    assert analysis.category == FailureCategory.HTTP_403_MEDIA_REJECTED
    assert not analysis.authentication_specific


def test_cp1252_unicode_transport_failure_has_specific_worker_category():
    analysis = classify_youtube_failure(
        "UnicodeEncodeError: 'charmap' codec can't encode character '\\uff5c' "
        "using encodings/cp1252.py",
    )

    assert analysis.category == FailureCategory.WORKER_PROTOCOL_ERROR
    assert analysis.category != FailureCategory.UNKNOWN


def test_new_recovery_failure_categories_have_distinct_stable_values():
    categories = {
        FailureCategory.VERIFIED_PROVIDER_NOT_APPLIED,
        FailureCategory.VERIFIED_SESSION_MEDIA_403,
        FailureCategory.PO_TOKEN_PROVIDER_UNAVAILABLE,
        FailureCategory.PO_TOKEN_FETCH_FAILED,
        FailureCategory.PO_TOKEN_MEDIA_403,
        FailureCategory.ONLY_SABR_OR_IMAGE_FORMATS,
        FailureCategory.MEDIA_ACCESS_REJECTED_AFTER_AUTHENTICATION,
    }

    assert {category.value for category in categories} == {
        "verified_provider_not_applied",
        "verified_session_media_403",
        "po_token_provider_unavailable",
        "po_token_fetch_failed",
        "po_token_media_403",
        "only_sabr_or_image_formats",
        "media_access_rejected_after_authentication",
    }


@pytest.mark.parametrize(
    ("attempt_kind", "category", "authentication_specific"),
    [
        ("public", FailureCategory.HTTP_403_MEDIA_REJECTED, False),
        ("verified_session", FailureCategory.VERIFIED_SESSION_MEDIA_403, True),
        ("authenticated", FailureCategory.MEDIA_ACCESS_REJECTED_AFTER_AUTHENTICATION, True),
        ("po_token", FailureCategory.PO_TOKEN_MEDIA_403, False),
    ],
)
def test_media_403_category_records_the_exact_attempt_that_failed(
    attempt_kind,
    category,
    authentication_specific,
):
    analysis = classify_youtube_failure(
        "ERROR: unable to download video data: HTTP Error 403: Forbidden",
        attempt_kind=attempt_kind,
    )

    assert analysis.category == category
    assert analysis.authentication_specific is authentication_specific


def test_verified_session_media_403_uses_required_user_message_verbatim():
    analysis = classify_youtube_failure(
        "ERROR: HTTP Error 403: Forbidden",
        attempt_kind="verified_session",
    )

    assert analysis.user_message == (
        "The browser session is valid, but YouTube rejected the media request. "
        "A PO Token may be required."
    )


def test_provider_failures_take_priority_over_generic_po_token_requirement():
    unavailable = classify_youtube_failure(
        "No PO Token providers registered; this client requires a PO Token",
    )
    fetch_failed = classify_youtube_failure(
        "_get_pot_via_script failed: PO Token was required",
    )

    assert unavailable.category == FailureCategory.PO_TOKEN_PROVIDER_UNAVAILABLE
    assert fetch_failed.category == FailureCategory.PO_TOKEN_FETCH_FAILED
