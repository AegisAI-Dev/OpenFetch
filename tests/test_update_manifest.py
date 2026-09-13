import json

import pytest

from openfetch.core.update_manifest import (
    EXPECTED_APPLICATION_NAME,
    MANIFEST_SCHEMA_VERSION,
    MIN_UPDATE_SIZE_BYTES,
    UpdateManifest,
    UpdateValidationError,
    expected_exe_filename,
    is_newer_version,
    parse_numeric_version,
    release_version_from_tag,
)


def manifest_payload(version: str = "3.0.3", **overrides):
    payload = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "application_name": EXPECTED_APPLICATION_NAME,
        "release_version": version,
        "asset_filename": expected_exe_filename(version),
        "asset_sha256": "a" * 64,
        "asset_size": MIN_UPDATE_SIZE_BYTES,
        "platform": "windows",
        "architecture": "x64",
        "channel": "stable",
        "minimum_updater_version": "3.0.2",
    }
    payload.update(overrides)
    return payload


def parse_manifest(payload, *, release_version="3.0.3", current_version="3.0.2"):
    return UpdateManifest.from_json(
        json.dumps(payload),
        release_version=release_version,
        current_version=current_version,
    )


def test_strict_numeric_versions_accept_newer_and_reject_equal_or_older():
    assert parse_numeric_version("3.0.2") == (3, 0, 2)
    assert release_version_from_tag("v3.0.2") == "3.0.2"
    assert is_newer_version("3.0.3", "3.0.2")
    assert not is_newer_version("3.0.2", "3.0.2")
    assert not is_newer_version("3.0.1", "3.0.2")
    assert is_newer_version("3.0.4", "3.0.2")
    assert is_newer_version("3.0.4", "3.0.3")


@pytest.mark.parametrize(
    "value",
    ["v3.0.2", "3.0", "3.0.2-beta", "03.0.2", "release-3.0.2", ""],
)
def test_invalid_numeric_versions_are_rejected(value):
    with pytest.raises(UpdateValidationError):
        parse_numeric_version(value)


def test_valid_manifest_is_strictly_bound_to_release_and_current_version():
    manifest = parse_manifest(manifest_payload())

    assert manifest.release_version == "3.0.3"
    assert manifest.asset_filename == "OpenFetch-3.0.3-windows-x64.exe"
    assert manifest.asset_sha256 == "a" * 64


def test_release_manifest_version_mismatch_is_rejected():
    with pytest.raises(UpdateValidationError, match="versions do not match"):
        parse_manifest(manifest_payload(version="3.0.4"))


@pytest.mark.parametrize(
    "filename",
    [
        "OpenFetch.exe",
        "OpenFetch-Updater.exe",
        "NeuralExtractorV3-3.0.3-windows-x64.exe",
        "OpenFetch-3.0.4-windows-x64.exe",
        "../OpenFetch-3.0.3-windows-x64.exe",
        r"folder\OpenFetch-3.0.3-windows-x64.exe",
        "OpenFetch-3.0.3-windows-x64.exe/extra",
    ],
)
def test_unversioned_similar_and_path_traversal_assets_are_rejected(filename):
    with pytest.raises(UpdateValidationError):
        parse_manifest(manifest_payload(asset_filename=filename))


def test_wrong_platform_and_architecture_are_rejected():
    with pytest.raises(UpdateValidationError, match="not for Windows"):
        parse_manifest(manifest_payload(platform="linux"))
    with pytest.raises(UpdateValidationError, match="not for x64"):
        parse_manifest(manifest_payload(architecture="arm64"))


def test_missing_invalid_and_duplicate_checksum_metadata_are_rejected():
    missing = manifest_payload()
    missing.pop("asset_sha256")
    with pytest.raises(UpdateValidationError, match="missing required fields"):
        parse_manifest(missing)

    with pytest.raises(UpdateValidationError, match="SHA-256"):
        parse_manifest(manifest_payload(asset_sha256="not-a-hash"))

    duplicate = json.dumps(manifest_payload())
    duplicate = duplicate.replace(
        '"asset_sha256": "' + "a" * 64 + '",',
        '"asset_sha256": "' + "a" * 64 + '", "asset_sha256": "' + "b" * 64 + '",',
    )
    with pytest.raises(UpdateValidationError, match="Duplicate manifest field"):
        UpdateManifest.from_json(
            duplicate,
            release_version="3.0.3",
            current_version="3.0.2",
        )


def test_same_version_downgrade_and_too_old_updater_are_rejected():
    with pytest.raises(UpdateValidationError, match="not newer"):
        parse_manifest(manifest_payload(version="3.0.2"), release_version="3.0.2")
    with pytest.raises(UpdateValidationError, match="requires a newer"):
        parse_manifest(
            manifest_payload(minimum_updater_version="3.0.3"),
            current_version="3.0.2",
        )


@pytest.mark.parametrize("current_version", ["3.0.2", "3.0.3"])
def test_v304_manifest_requires_the_repaired_v304_updater(current_version):
    with pytest.raises(UpdateValidationError) as error:
        parse_manifest(
            manifest_payload(version="3.0.4", minimum_updater_version="3.0.4"),
            release_version="3.0.4",
            current_version=current_version,
        )

    assert error.value.code == "updater_too_old"


def test_v304_updater_accepts_a_future_release_with_v304_minimum():
    manifest = parse_manifest(
        manifest_payload(version="3.0.5", minimum_updater_version="3.0.4"),
        release_version="3.0.5",
        current_version="3.0.4",
    )

    assert manifest.minimum_updater_version == "3.0.4"


def test_unexpected_manifest_fields_are_rejected():
    with pytest.raises(UpdateValidationError, match="unexpected fields"):
        parse_manifest(manifest_payload(command="run-this"))
