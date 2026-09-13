"""Strict release-manifest handling for OpenFetch updates."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePath
from typing import Any

from openfetch.config import APP_NAME, EXECUTABLE_STEM, LEGACY_APP_NAME, LEGACY_EXECUTABLE_STEM

MANIFEST_SCHEMA_VERSION = 1
MANIFEST_MAX_BYTES = 64 * 1024
MIN_UPDATE_SIZE_BYTES = 1 * 1024 * 1024
MAX_UPDATE_SIZE_BYTES = 1024 * 1024 * 1024

EXPECTED_APPLICATION_NAME = APP_NAME
EXPECTED_PLATFORM = "windows"
EXPECTED_ARCHITECTURE = "x64"
EXPECTED_CHANNEL = "stable"

STRICT_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

REQUIRED_MANIFEST_FIELDS = {
    "schema_version",
    "application_name",
    "release_version",
    "asset_filename",
    "asset_sha256",
    "asset_size",
    "platform",
    "architecture",
    "channel",
}
OPTIONAL_MANIFEST_FIELDS = {"minimum_updater_version"}


@dataclass(frozen=True, slots=True)
class ReleaseNaming:
    """Application name and asset prefix that one family of updaters requests."""

    application_name: str
    asset_prefix: str

    def exe_filename(self, version: str) -> str:
        parse_numeric_version(version)
        return f"{self.asset_prefix}-{version}-windows-x64.exe"

    def manifest_filename(self, version: str) -> str:
        parse_numeric_version(version)
        return f"{self.asset_prefix}-{version}-manifest.json"

    def checksum_filename(self, version: str) -> str:
        return f"{self.exe_filename(version)}.sha256"


# OpenFetch updaters request OpenFetch assets. Installed Neural Extractor V3
# updaters (3.0.4 and later) only understand the legacy names, so releases in
# the shared feed also carry a legacy-named copy of the same executable.
OPENFETCH_RELEASE = ReleaseNaming(APP_NAME, EXECUTABLE_STEM)
LEGACY_RELEASE = ReleaseNaming(LEGACY_APP_NAME, LEGACY_EXECUTABLE_STEM)


class UpdateValidationError(ValueError):
    """Raised when release metadata is unsafe or internally inconsistent."""

    def __init__(self, message: str, code: str = "invalid_release_metadata") -> None:
        self.code = code
        super().__init__(message)


def parse_numeric_version(value: str) -> tuple[int, int, int]:
    """Parse the strict numeric semantic-version format used by releases."""
    match = STRICT_VERSION_PATTERN.fullmatch(str(value or ""))
    if not match:
        raise UpdateValidationError(
            f"Invalid release version: {value!r}",
            code="invalid_version",
        )
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def release_version_from_tag(tag_name: str) -> str:
    """Return a validated version from an exact vMAJOR.MINOR.PATCH tag."""
    tag = str(tag_name or "")
    if not tag.startswith("v"):
        raise UpdateValidationError("Release tag must start with 'v'.", code="invalid_version")
    version = tag[1:]
    parse_numeric_version(version)
    return version


def is_newer_version(candidate: str, current: str) -> bool:
    return parse_numeric_version(candidate) > parse_numeric_version(current)


def expected_exe_filename(version: str, naming: ReleaseNaming = OPENFETCH_RELEASE) -> str:
    return naming.exe_filename(version)


def expected_manifest_filename(version: str, naming: ReleaseNaming = OPENFETCH_RELEASE) -> str:
    return naming.manifest_filename(version)


def expected_checksum_filename(version: str, naming: ReleaseNaming = OPENFETCH_RELEASE) -> str:
    return naming.checksum_filename(version)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateValidationError(
                f"Duplicate manifest field: {key}",
                code="duplicate_manifest_field",
            )
        result[key] = value
    return result


def _validate_asset_filename(filename: str, version: str, naming: ReleaseNaming) -> None:
    if not filename or filename != PurePath(filename).name:
        raise UpdateValidationError(
            "Manifest asset filename contains a path.",
            code="invalid_asset_filename",
        )
    if "/" in filename or "\\" in filename or ".." in filename:
        raise UpdateValidationError(
            "Manifest asset filename is unsafe.",
            code="invalid_asset_filename",
        )
    expected = naming.exe_filename(version)
    if filename != expected:
        raise UpdateValidationError(
            f"Manifest asset filename must be exactly {expected}.",
            code="invalid_asset_filename",
        )


@dataclass(frozen=True, slots=True)
class UpdateManifest:
    schema_version: int
    application_name: str
    release_version: str
    asset_filename: str
    asset_sha256: str
    asset_size: int
    platform: str
    architecture: str
    channel: str
    minimum_updater_version: str | None = None

    @classmethod
    def from_json(
        cls,
        document: str | bytes,
        *,
        release_version: str,
        current_version: str | None = None,
        naming: ReleaseNaming = OPENFETCH_RELEASE,
    ) -> UpdateManifest:
        if isinstance(document, bytes):
            if len(document) > MANIFEST_MAX_BYTES:
                raise UpdateValidationError("Release manifest is too large.")
            try:
                text = document.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise UpdateValidationError("Release manifest is not valid UTF-8.") from exc
        else:
            text = document
            if len(text.encode("utf-8")) > MANIFEST_MAX_BYTES:
                raise UpdateValidationError("Release manifest is too large.")

        try:
            payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        except UpdateValidationError:
            raise
        except (json.JSONDecodeError, TypeError) as exc:
            raise UpdateValidationError("Release manifest is not valid JSON.") from exc

        if not isinstance(payload, dict):
            raise UpdateValidationError("Release manifest must be a JSON object.")

        fields = set(payload)
        missing = REQUIRED_MANIFEST_FIELDS - fields
        unexpected = fields - REQUIRED_MANIFEST_FIELDS - OPTIONAL_MANIFEST_FIELDS
        if missing:
            raise UpdateValidationError(
                f"Release manifest is missing required fields: {', '.join(sorted(missing))}."
            )
        if unexpected:
            raise UpdateValidationError(
                f"Release manifest contains unexpected fields: {', '.join(sorted(unexpected))}."
            )

        if payload["schema_version"] != MANIFEST_SCHEMA_VERSION:
            raise UpdateValidationError(
                "Unsupported release manifest schema version.",
                code="unsupported_manifest_schema",
            )
        if payload["application_name"] != naming.application_name:
            raise UpdateValidationError("Release manifest application name is invalid.")
        if payload["platform"] != EXPECTED_PLATFORM:
            raise UpdateValidationError("Release package is not for Windows.", code="wrong_platform")
        if payload["architecture"] != EXPECTED_ARCHITECTURE:
            raise UpdateValidationError("Release package is not for x64.", code="wrong_architecture")
        if payload["channel"] != EXPECTED_CHANNEL:
            raise UpdateValidationError("Release package is not from the stable channel.")

        manifest_version = str(payload["release_version"])
        parse_numeric_version(manifest_version)
        parse_numeric_version(release_version)
        if manifest_version != release_version:
            raise UpdateValidationError(
                "Release and manifest versions do not match.",
                code="release_manifest_version_mismatch",
            )
        if current_version is not None and not is_newer_version(manifest_version, current_version):
            raise UpdateValidationError(
                "Release version is not newer than the installed version.",
                code="not_newer",
            )

        filename = str(payload["asset_filename"])
        _validate_asset_filename(filename, manifest_version, naming)

        sha256_value = str(payload["asset_sha256"])
        if not SHA256_PATTERN.fullmatch(sha256_value):
            raise UpdateValidationError(
                "Release manifest SHA-256 is invalid.",
                code="invalid_checksum",
            )

        size_value = payload["asset_size"]
        if isinstance(size_value, bool) or not isinstance(size_value, int):
            raise UpdateValidationError("Release manifest asset size must be an integer.")
        if not MIN_UPDATE_SIZE_BYTES <= size_value <= MAX_UPDATE_SIZE_BYTES:
            raise UpdateValidationError(
                "Release package size is outside the permitted range.",
                code="invalid_file_size",
            )

        minimum_updater = payload.get("minimum_updater_version")
        if minimum_updater is not None:
            minimum_updater = str(minimum_updater)
            parse_numeric_version(minimum_updater)
            if current_version is not None and parse_numeric_version(
                current_version
            ) < parse_numeric_version(minimum_updater):
                raise UpdateValidationError(
                    "This release requires a newer automatic updater.",
                    code="updater_too_old",
                )

        return cls(
            schema_version=MANIFEST_SCHEMA_VERSION,
            application_name=naming.application_name,
            release_version=manifest_version,
            asset_filename=filename,
            asset_sha256=sha256_value.lower(),
            asset_size=size_value,
            platform=EXPECTED_PLATFORM,
            architecture=EXPECTED_ARCHITECTURE,
            channel=EXPECTED_CHANNEL,
            minimum_updater_version=minimum_updater,
        )

    @classmethod
    def for_executable(
        cls,
        *,
        version: str,
        executable: Path,
        minimum_updater_version: str | None = None,
        naming: ReleaseNaming = OPENFETCH_RELEASE,
    ) -> UpdateManifest:
        parse_numeric_version(version)
        if minimum_updater_version is not None:
            parse_numeric_version(minimum_updater_version)
        executable = Path(executable)
        expected_name = naming.exe_filename(version)
        if executable.name != expected_name:
            raise UpdateValidationError(f"Release executable must be named {expected_name}.")
        size = executable.stat().st_size
        if not MIN_UPDATE_SIZE_BYTES <= size <= MAX_UPDATE_SIZE_BYTES:
            raise UpdateValidationError("Release executable size is outside the permitted range.")
        return cls(
            schema_version=MANIFEST_SCHEMA_VERSION,
            application_name=naming.application_name,
            release_version=version,
            asset_filename=expected_name,
            asset_sha256=sha256_file(executable),
            asset_size=size,
            platform=EXPECTED_PLATFORM,
            architecture=EXPECTED_ARCHITECTURE,
            channel=EXPECTED_CHANNEL,
            minimum_updater_version=minimum_updater_version,
        )

    def to_json(self) -> str:
        payload = asdict(self)
        if self.minimum_updater_version is None:
            payload.pop("minimum_updater_version")
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
