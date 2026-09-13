"""Secure GitHub release checks and bounded update staging for OpenFetch."""

from __future__ import annotations

import contextlib
import hmac
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests

from openfetch.config import (
    APP_NAME,
    GITHUB_LATEST_RELEASE_API,
    GITHUB_RELEASES_URL,
    GITHUB_REPO,
    UPDATE_CHECK_TIMEOUT_SECONDS,
    VERSION,
    app_data_dir,
)
from openfetch.core.update_manifest import (
    MANIFEST_MAX_BYTES,
    MAX_UPDATE_SIZE_BYTES,
    UpdateManifest,
    UpdateValidationError,
    expected_checksum_filename,
    expected_exe_filename,
    expected_manifest_filename,
    is_newer_version,
    parse_numeric_version,
    release_version_from_tag,
    sha256_file,
)

UPDATE_CONNECT_TIMEOUT_SECONDS = 10
UPDATE_READ_TIMEOUT_SECONDS = 45
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

ProgressCallback = Callable[[int, str], None]
CancelCallback = Callable[[], bool]
STAGING_TRANSACTION_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class UpdateError(RuntimeError):
    """A classified update failure suitable for GUI presentation."""

    def __init__(self, code: str, user_message: str, technical: str = "") -> None:
        self.code = code
        self.user_message = user_message
        self.technical = technical
        super().__init__(user_message)


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    version: str
    tag_name: str
    name: str
    html_url: str
    published_at: str
    body: str
    exe_url: str
    exe_size: int
    manifest_url: str
    checksum_url: str


@dataclass(frozen=True, slots=True)
class UpdateInfo:
    """Strictly validated information about a newer stable release."""

    version: str
    tag_name: str
    name: str
    html_url: str
    download_url: str
    manifest_url: str
    checksum_url: str
    published_at: str
    body: str
    download_size: int
    sha256: str
    manifest: UpdateManifest


def version_tuple(value: str) -> tuple[int, int, int]:
    """Compatibility helper using the strict numeric release version format."""
    normalized = value[1:] if str(value).startswith("v") else str(value)
    return parse_numeric_version(normalized)


def _official_release_asset_url(tag_name: str, filename: str) -> str:
    return f"https://github.com/{GITHUB_REPO}/releases/download/{tag_name}/{quote(filename)}"


def _validate_https_url(url: str, *, expected: str | None = None) -> None:
    parsed = urlparse(str(url or ""))
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise UpdateError(
            "invalid_release_metadata",
            "The update release contains an unsafe download URL.",
        )
    if expected is not None and url != expected:
        raise UpdateError(
            "invalid_release_metadata",
            "The update release asset URL does not match the official repository.",
        )


def _safe_child(root: Path, *parts: str) -> Path:
    root = Path(root).resolve()
    candidate = root.joinpath(*parts).resolve()
    if candidate != root and root not in candidate.parents:
        raise UpdateError("unsafe_path", "The update staging path is unsafe.")
    return candidate


class UpdateChecker:
    """Checks the pinned official GitHub release and validates its manifest."""

    def __init__(
        self,
        api_url: str = GITHUB_LATEST_RELEASE_API,
        releases_url: str = GITHUB_RELEASES_URL,
        timeout: int = UPDATE_CHECK_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        if api_url != GITHUB_LATEST_RELEASE_API or releases_url != GITHUB_RELEASES_URL:
            raise ValueError("The automatic updater source is pinned to the official repository.")
        self.api_url = GITHUB_LATEST_RELEASE_API
        self.releases_url = GITHUB_RELEASES_URL
        self.timeout = timeout
        self.session = session or requests.Session()

    def check(self, current_version: str = VERSION) -> UpdateInfo | None:
        parse_numeric_version(current_version)
        payload = self._get_release_payload()
        candidate = self.parse_release(payload, current_version)
        if candidate is None:
            return None
        manifest_document = self._download_manifest(candidate.manifest_url)
        return self.bind_manifest(candidate, manifest_document, current_version)

    def _get_release_payload(self) -> dict[str, Any]:
        response: requests.Response | None = None
        try:
            response = self.session.get(
                self.api_url,
                timeout=(UPDATE_CONNECT_TIMEOUT_SECONDS, self.timeout),
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": f"{APP_NAME.replace(' ', '-')}/{VERSION}",
                },
                allow_redirects=False,
                verify=True,
            )
            if response.status_code == 404:
                raise UpdateError(
                    "release_source_unavailable",
                    f"No published {APP_NAME} release was found in the official repository.",
                    technical="HTTP 404",
                )
            if 300 <= response.status_code < 400:
                # requests does not raise for 3xx, and this updater deliberately
                # does not follow redirects: GitHub answers a renamed or
                # transferred repository this way, and a moved release source
                # must never be trusted automatically. Reported precisely
                # instead of being parsed as release metadata.
                raise UpdateError(
                    "release_source_moved",
                    "The official release feed has moved. Download the latest "
                    f"{APP_NAME} release manually from the project page.",
                    technical=f"HTTP {response.status_code}",
                )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise UpdateError(
                "network_failure",
                "Could not check the official GitHub release. Check your connection and try again.",
                technical=str(exc),
            ) from exc
        finally:
            if response is not None:
                with contextlib.suppress(Exception):
                    response.close()
        if not isinstance(payload, dict):
            raise UpdateError(
                "invalid_release_metadata",
                "GitHub returned invalid release metadata.",
            )
        return payload

    def parse_release(
        self,
        payload: dict[str, Any],
        current_version: str = VERSION,
    ) -> ReleaseCandidate | None:
        if payload.get("draft") or payload.get("prerelease"):
            return None

        try:
            version = release_version_from_tag(str(payload.get("tag_name") or ""))
            parse_numeric_version(current_version)
        except UpdateValidationError as exc:
            raise UpdateError(exc.code, "The latest release has an invalid version.") from exc
        if not is_newer_version(version, current_version):
            return None

        tag_name = f"v{version}"
        exe_name = expected_exe_filename(version)
        manifest_name = expected_manifest_filename(version)
        checksum_name = expected_checksum_filename(version)
        assets = payload.get("assets") or []
        if not isinstance(assets, list):
            raise UpdateError("invalid_release_metadata", "GitHub returned an invalid asset list.")

        assets_by_name: dict[str, dict[str, Any]] = {}
        for asset in assets:
            if not isinstance(asset, dict):
                raise UpdateError("invalid_release_metadata", "GitHub returned an invalid release asset.")
            name = str(asset.get("name") or "")
            if name in assets_by_name:
                raise UpdateError(
                    "invalid_release_metadata",
                    f"The release contains duplicate assets named {name}.",
                )
            assets_by_name[name] = asset

        exe_asset = assets_by_name.get(exe_name)
        manifest_asset = assets_by_name.get(manifest_name)
        checksum_asset = assets_by_name.get(checksum_name)
        if not exe_asset:
            raise UpdateError(
                "missing_asset",
                f"The release is missing the required Windows package: {exe_name}",
            )
        if not manifest_asset:
            raise UpdateError(
                "missing_asset",
                f"The release is missing the required update manifest: {manifest_name}",
            )

        exe_url = str(exe_asset.get("browser_download_url") or "")
        manifest_url = str(manifest_asset.get("browser_download_url") or "")
        checksum_url = (
            str(checksum_asset.get("browser_download_url") or "") if checksum_asset else ""
        )
        _validate_https_url(
            exe_url,
            expected=_official_release_asset_url(tag_name, exe_name),
        )
        _validate_https_url(
            manifest_url,
            expected=_official_release_asset_url(tag_name, manifest_name),
        )
        if checksum_url:
            _validate_https_url(
                checksum_url,
                expected=_official_release_asset_url(tag_name, checksum_name),
            )

        exe_size = exe_asset.get("size")
        if isinstance(exe_size, bool) or not isinstance(exe_size, int) or exe_size <= 0:
            raise UpdateError(
                "invalid_release_metadata",
                "The release package size is invalid.",
            )

        expected_html = f"https://github.com/{GITHUB_REPO}/releases/tag/{tag_name}"
        html_url = str(payload.get("html_url") or "")
        if html_url != expected_html:
            html_url = expected_html

        return ReleaseCandidate(
            version=version,
            tag_name=tag_name,
            name=str(payload.get("name") or f"{APP_NAME} {tag_name}"),
            html_url=html_url,
            published_at=str(payload.get("published_at") or ""),
            body=str(payload.get("body") or ""),
            exe_url=exe_url,
            exe_size=exe_size,
            manifest_url=manifest_url,
            checksum_url=checksum_url,
        )

    def _download_manifest(self, manifest_url: str) -> bytes:
        response: requests.Response | None = None
        try:
            response = self.session.get(
                manifest_url,
                timeout=(UPDATE_CONNECT_TIMEOUT_SECONDS, UPDATE_READ_TIMEOUT_SECONDS),
                headers={"User-Agent": f"{APP_NAME.replace(' ', '-')}/{VERSION}"},
                allow_redirects=True,
                stream=True,
                verify=True,
            )
            response.raise_for_status()
            _validate_https_url(str(response.url))
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MANIFEST_MAX_BYTES:
                raise UpdateError(
                    "invalid_release_metadata",
                    "The release manifest is too large.",
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=16 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MANIFEST_MAX_BYTES:
                    raise UpdateError(
                        "invalid_release_metadata",
                        "The release manifest is too large.",
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        except UpdateError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise UpdateError(
                "network_failure",
                "Could not download the update manifest.",
                technical=str(exc),
            ) from exc
        finally:
            if response is not None:
                with contextlib.suppress(Exception):
                    response.close()

    def bind_manifest(
        self,
        candidate: ReleaseCandidate,
        manifest_document: str | bytes,
        current_version: str = VERSION,
    ) -> UpdateInfo:
        try:
            manifest = UpdateManifest.from_json(
                manifest_document,
                release_version=candidate.version,
                current_version=current_version,
            )
        except UpdateValidationError as exc:
            raise UpdateError(
                exc.code,
                f"The update manifest is invalid: {exc}",
            ) from exc
        if manifest.asset_size != candidate.exe_size:
            raise UpdateError(
                "file_size_mismatch",
                "The release manifest size does not match the GitHub package size.",
            )
        return UpdateInfo(
            version=candidate.version,
            tag_name=candidate.tag_name,
            name=candidate.name,
            html_url=candidate.html_url,
            download_url=candidate.exe_url,
            manifest_url=candidate.manifest_url,
            checksum_url=candidate.checksum_url,
            published_at=candidate.published_at,
            body=candidate.body,
            download_size=manifest.asset_size,
            sha256=manifest.asset_sha256,
            manifest=manifest,
        )


class UpdateDownloader:
    """Streams a verified release package into the controlled staging directory."""

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        update_root: Path | None = None,
    ) -> None:
        self.session = session or requests.Session()
        self.update_root = Path(update_root or (app_data_dir() / "updates")).resolve()

    def stage(
        self,
        info: UpdateInfo,
        *,
        transaction_id: str | None = None,
        progress_callback: ProgressCallback | None = None,
        cancel_callback: CancelCallback | None = None,
    ) -> Path:
        if transaction_id is not None and not STAGING_TRANSACTION_PATTERN.fullmatch(
            transaction_id
        ):
            raise UpdateError("invalid_transaction", "The update staging transaction is invalid.")
        _validate_https_url(
            info.download_url,
            expected=_official_release_asset_url(info.tag_name, info.manifest.asset_filename),
        )
        version_dir = (
            _safe_child(self.update_root, info.version, transaction_id, "package")
            if transaction_id is not None
            else _safe_child(self.update_root, info.version, "package")
        )
        version_dir.mkdir(parents=True, exist_ok=True)
        final_path = _safe_child(version_dir, info.manifest.asset_filename)

        if final_path.exists():
            if self._verified_file(final_path, info.manifest):
                self._progress(progress_callback, 100, "Using previously verified update package")
                return final_path
            with contextlib.suppress(OSError):
                final_path.unlink()

        partial_identity = transaction_id or secrets.token_urlsafe(36)
        part_path = _safe_child(
            version_dir,
            f".{info.manifest.asset_filename}.{partial_identity}.part",
        )
        with contextlib.suppress(OSError):
            part_path.unlink()
        self._progress(progress_callback, 0, "Downloading update")

        response: requests.Response | None = None
        try:
            response = self.session.get(
                info.download_url,
                timeout=(UPDATE_CONNECT_TIMEOUT_SECONDS, UPDATE_READ_TIMEOUT_SECONDS),
                headers={"User-Agent": f"{APP_NAME.replace(' ', '-')}/{VERSION}"},
                allow_redirects=True,
                stream=True,
                verify=True,
            )
            response.raise_for_status()
            _validate_https_url(str(response.url))

            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise UpdateError(
                        "invalid_release_metadata",
                        "The update server returned an invalid package size.",
                    ) from exc
                if declared_length > MAX_UPDATE_SIZE_BYTES:
                    raise UpdateError("oversized_download", "The update package is too large.")
                if declared_length != info.manifest.asset_size:
                    raise UpdateError(
                        "file_size_mismatch",
                        "The downloaded package size does not match the release manifest.",
                    )

            total = 0
            with part_path.open("xb") as handle:
                for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                    if self._cancelled(cancel_callback):
                        raise UpdateError("cancelled", "Update download cancelled.")
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > info.manifest.asset_size or total > MAX_UPDATE_SIZE_BYTES:
                        raise UpdateError("oversized_download", "The update package is too large.")
                    handle.write(chunk)
                    percent = int(total / info.manifest.asset_size * 80)
                    self._progress(progress_callback, min(80, percent), "Downloading update")
                handle.flush()
                os.fsync(handle.fileno())

            if total != info.manifest.asset_size:
                raise UpdateError(
                    "file_size_mismatch",
                    "The update download ended before the expected number of bytes arrived.",
                )
            self._progress(progress_callback, 85, "Verifying SHA-256")
            actual_hash = sha256_file(part_path)
            if not hmac.compare_digest(actual_hash, info.manifest.asset_sha256):
                raise UpdateError(
                    "checksum_mismatch",
                    "The update checksum did not match. Nothing was installed.",
                )
            os.replace(part_path, final_path)
            self._progress(progress_callback, 90, "Update package verified")
            return final_path
        except UpdateError:
            with contextlib.suppress(OSError):
                part_path.unlink()
            raise
        except (requests.RequestException, OSError) as exc:
            with contextlib.suppress(OSError):
                part_path.unlink()
            raise UpdateError(
                "network_failure" if isinstance(exc, requests.RequestException) else "staging_failure",
                "The update could not be downloaded and staged safely.",
                technical=str(exc),
            ) from exc
        finally:
            if response is not None:
                with contextlib.suppress(Exception):
                    response.close()

    @staticmethod
    def _verified_file(path: Path, manifest: UpdateManifest) -> bool:
        try:
            if path.stat().st_size != manifest.asset_size:
                return False
            return hmac.compare_digest(sha256_file(path), manifest.asset_sha256)
        except OSError:
            return False

    @staticmethod
    def _remove_partial_files(directory: Path, asset_filename: str) -> None:
        for path in directory.glob(f".{asset_filename}.*.part"):
            with contextlib.suppress(OSError):
                path.unlink()

    @staticmethod
    def _cancelled(cancel_callback: CancelCallback | None) -> bool:
        return bool(cancel_callback and cancel_callback())

    @staticmethod
    def _progress(callback: ProgressCallback | None, percent: int, message: str) -> None:
        if callback:
            callback(max(0, min(100, percent)), message)
