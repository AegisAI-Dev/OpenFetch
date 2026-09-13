import hashlib
import json
from pathlib import Path

import pytest

from openfetch.config import (
    APP_NAME,
    GITHUB_LATEST_RELEASE_API,
    GITHUB_RELEASES_URL,
    GITHUB_REPO,
    LEGACY_APP_NAME,
)
from openfetch.core.update_manifest import (
    LEGACY_RELEASE,
    MAX_UPDATE_SIZE_BYTES,
    MIN_UPDATE_SIZE_BYTES,
    OPENFETCH_RELEASE,
    UpdateManifest,
    UpdateValidationError,
    expected_checksum_filename,
    expected_exe_filename,
    expected_manifest_filename,
)
from openfetch.core.updater import (
    UpdateChecker,
    UpdateDownloader,
    UpdateError,
)


class FakeResponse:
    def __init__(
        self,
        *,
        url: str,
        content: bytes = b"",
        payload=None,
        headers=None,
        chunks=None,
        status_code: int = 200,
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.content = content
        self.payload = payload
        self.headers = headers or {}
        self.chunks = chunks
        self.closed = False

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self.payload

    def iter_content(self, chunk_size=8192):
        if self.chunks is not None:
            yield from self.chunks
            return
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected network request")
        return self.responses.pop(0)


def asset_url(version: str, filename: str) -> str:
    return f"https://github.com/{GITHUB_REPO}/releases/download/v{version}/{filename}"


def manifest_document(version: str, content: bytes, **overrides) -> bytes:
    payload = {
        "schema_version": 1,
        "application_name": APP_NAME,
        "release_version": version,
        "asset_filename": expected_exe_filename(version),
        "asset_sha256": hashlib.sha256(content).hexdigest(),
        "asset_size": len(content),
        "platform": "windows",
        "architecture": "x64",
        "channel": "stable",
        "minimum_updater_version": "3.0.2",
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


def release_payload(version: str, size: int, *, draft=False, prerelease=False, assets=None):
    exe_name = expected_exe_filename(version)
    manifest_name = expected_manifest_filename(version)
    checksum_name = expected_checksum_filename(version)
    if assets is None:
        assets = [
            {
                "name": "OpenFetch.exe",
                "size": size,
                "browser_download_url": asset_url(version, "OpenFetch.exe"),
            },
            {
                "name": exe_name,
                "size": size,
                "browser_download_url": asset_url(version, exe_name),
            },
            {
                "name": manifest_name,
                "size": 500,
                "browser_download_url": asset_url(version, manifest_name),
            },
            {
                "name": checksum_name,
                "size": 100,
                "browser_download_url": asset_url(version, checksum_name),
            },
        ]
    return {
        "tag_name": f"v{version}",
        "name": f"{APP_NAME} v{version}",
        "html_url": f"https://github.com/{GITHUB_REPO}/releases/tag/v{version}",
        "published_at": "2026-07-12T12:00:00Z",
        "body": "Secure updater release",
        "draft": draft,
        "prerelease": prerelease,
        "assets": assets,
    }


@pytest.fixture(scope="module")
def package_content() -> bytes:
    return b"N" * MIN_UPDATE_SIZE_BYTES


def validated_update(package_content: bytes, version: str = "3.0.3"):
    checker = UpdateChecker()
    candidate = checker.parse_release(
        release_payload(version, len(package_content)),
        "3.0.2",
    )
    assert candidate is not None
    return checker.bind_manifest(
        candidate,
        manifest_document(version, package_content),
        "3.0.2",
    )


def test_checker_source_is_pinned_to_official_repository():
    with pytest.raises(ValueError, match="pinned"):
        UpdateChecker(api_url="https://example.test/latest")
    assert UpdateChecker().api_url == GITHUB_LATEST_RELEASE_API
    assert UpdateChecker().releases_url == GITHUB_RELEASES_URL


def test_draft_prerelease_equal_and_older_releases_are_rejected(package_content):
    checker = UpdateChecker()
    assert checker.parse_release(
        release_payload("3.0.3", len(package_content), draft=True), "3.0.2"
    ) is None
    assert checker.parse_release(
        release_payload("3.0.3", len(package_content), prerelease=True), "3.0.2"
    ) is None
    assert checker.parse_release(release_payload("3.0.2", len(package_content)), "3.0.2") is None
    assert checker.parse_release(release_payload("3.0.1", len(package_content)), "3.0.2") is None


def test_invalid_release_version_is_rejected(package_content):
    payload = release_payload("3.0.3", len(package_content))
    payload["tag_name"] = "release-3.0.3"
    with pytest.raises(UpdateError, match="invalid version"):
        UpdateChecker().parse_release(payload, "3.0.2")


def test_exact_versioned_exe_and_manifest_are_selected_not_unversioned(package_content):
    checker = UpdateChecker()
    candidate = checker.parse_release(
        release_payload("3.0.3", len(package_content)),
        "3.0.2",
    )

    assert candidate is not None
    assert candidate.exe_url.endswith("/OpenFetch-3.0.3-windows-x64.exe")
    assert candidate.manifest_url.endswith("/OpenFetch-3.0.3-manifest.json")
    assert not candidate.exe_url.endswith("/OpenFetch.exe")


def test_similar_or_missing_exact_asset_is_rejected(package_content):
    version = "3.0.3"
    assets = [
        {
            "name": "OpenFetch.exe",
            "size": len(package_content),
            "browser_download_url": asset_url(version, "OpenFetch.exe"),
        },
        {
            "name": "OpenFetch-3.0.3-windows-x64-helper.exe",
            "size": len(package_content),
            "browser_download_url": asset_url(
                version, "OpenFetch-3.0.3-windows-x64-helper.exe"
            ),
        },
    ]
    with pytest.raises(UpdateError) as exc_info:
        UpdateChecker().parse_release(
            release_payload(version, len(package_content), assets=assets),
            "3.0.2",
        )
    assert exc_info.value.code == "missing_asset"


def test_manifest_and_github_asset_size_must_match(package_content):
    checker = UpdateChecker()
    candidate = checker.parse_release(
        release_payload("3.0.3", len(package_content)),
        "3.0.2",
    )
    assert candidate is not None
    with pytest.raises(UpdateError) as exc_info:
        checker.bind_manifest(
            candidate,
            manifest_document("3.0.3", package_content, asset_size=len(package_content) + 1),
            "3.0.2",
        )
    assert exc_info.value.code == "file_size_mismatch"


def test_full_check_uses_tls_timeouts_and_manifest_before_returning(package_content):
    version = "3.0.3"
    payload = release_payload(version, len(package_content))
    document = manifest_document(version, package_content)
    manifest_url = asset_url(version, expected_manifest_filename(version))
    api_response = FakeResponse(url=GITHUB_LATEST_RELEASE_API, payload=payload)
    manifest_response = FakeResponse(
        url=manifest_url,
        content=document,
        headers={"Content-Length": str(len(document))},
    )
    session = FakeSession(api_response, manifest_response)

    info = UpdateChecker(session=session).check("3.0.2")

    assert info is not None
    assert info.sha256 == hashlib.sha256(package_content).hexdigest()
    assert all(call[1]["verify"] is True for call in session.calls)
    assert session.calls[0][1]["allow_redirects"] is False
    assert session.calls[1][1]["allow_redirects"] is True
    assert api_response.closed
    assert manifest_response.closed
    assert all(isinstance(call[1]["timeout"], tuple) for call in session.calls)


def test_valid_staged_file_is_verified_and_accepted(tmp_path, package_content):
    info = validated_update(package_content)
    response = FakeResponse(
        url=info.download_url,
        content=package_content,
        headers={"Content-Length": str(len(package_content))},
    )
    session = FakeSession(response)
    progress = []

    staged = UpdateDownloader(session=session, update_root=tmp_path).stage(
        info,
        progress_callback=lambda percent, message: progress.append((percent, message)),
    )

    assert staged.name == expected_exe_filename(info.version)
    assert staged.read_bytes() == package_content
    assert not list(staged.parent.glob("*.part"))
    assert progress[-1][0] == 90
    assert session.calls[0][1]["verify"] is True
    assert response.closed


def test_transaction_scoped_stages_do_not_delete_each_other(tmp_path, package_content):
    info = validated_update(package_content)
    session = FakeSession(
        FakeResponse(
            url=info.download_url,
            content=package_content,
            headers={"Content-Length": str(len(package_content))},
        ),
        FakeResponse(
            url=info.download_url,
            content=package_content,
            headers={"Content-Length": str(len(package_content))},
        ),
    )
    downloader = UpdateDownloader(session=session, update_root=tmp_path)

    first = downloader.stage(info, transaction_id="A" * 48)
    second = downloader.stage(info, transaction_id="B" * 48)

    assert first != second
    assert first == (
        tmp_path / info.version / ("A" * 48) / "package" / info.manifest.asset_filename
    ).resolve()
    assert second == (
        tmp_path / info.version / ("B" * 48) / "package" / info.manifest.asset_filename
    ).resolve()
    first.unlink()
    assert not first.exists()
    assert second.read_bytes() == package_content


def test_existing_verified_stage_is_reused_without_network(tmp_path, package_content):
    info = validated_update(package_content)
    staged = tmp_path / info.version / "package" / info.manifest.asset_filename
    staged.parent.mkdir(parents=True)
    staged.write_bytes(package_content)
    session = FakeSession()

    result = UpdateDownloader(session=session, update_root=tmp_path).stage(info)

    assert result == staged.resolve()
    assert session.calls == []


def test_corrupt_cached_stage_is_redownloaded(tmp_path, package_content):
    info = validated_update(package_content)
    staged = tmp_path / info.version / "package" / info.manifest.asset_filename
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b"X" * len(package_content))
    session = FakeSession(
        FakeResponse(
            url=info.download_url,
            content=package_content,
            headers={"Content-Length": str(len(package_content))},
        )
    )

    result = UpdateDownloader(session=session, update_root=tmp_path).stage(info)

    assert result.read_bytes() == package_content
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        (
            lambda info, content: FakeResponse(
                url=info.download_url,
                content=b"X" * len(content),
                headers={"Content-Length": str(len(content))},
            ),
            "checksum_mismatch",
        ),
        (
            lambda info, content: FakeResponse(
                url=info.download_url,
                chunks=[content[:-1]],
                headers={},
            ),
            "file_size_mismatch",
        ),
        (
            lambda info, content: FakeResponse(
                url=info.download_url,
                chunks=[],
                headers={"Content-Length": str(MAX_UPDATE_SIZE_BYTES + 1)},
            ),
            "oversized_download",
        ),
    ],
)
def test_invalid_download_is_rejected_and_partial_file_removed(
    tmp_path,
    package_content,
    response,
    expected_code,
):
    info = validated_update(package_content)
    session = FakeSession(response(info, package_content))
    downloader = UpdateDownloader(session=session, update_root=tmp_path)

    with pytest.raises(UpdateError) as exc_info:
        downloader.stage(info)

    assert exc_info.value.code == expected_code
    package_dir = tmp_path / info.version / "package"
    assert not list(package_dir.glob("*.part"))
    assert not (package_dir / info.manifest.asset_filename).exists()


def test_cancelled_download_cleans_partial_file(tmp_path, package_content):
    info = validated_update(package_content)
    session = FakeSession(
        FakeResponse(
            url=info.download_url,
            chunks=[package_content[:100], package_content[100:]],
            headers={"Content-Length": str(len(package_content))},
        )
    )

    with pytest.raises(UpdateError) as exc_info:
        UpdateDownloader(session=session, update_root=tmp_path).stage(
            info,
            cancel_callback=lambda: True,
        )

    assert exc_info.value.code == "cancelled"
    assert not list(Path(tmp_path).rglob("*.part"))


def _family_assets(version: str, size: int, naming):
    return [
        {
            "name": naming.exe_filename(version),
            "size": size,
            "browser_download_url": asset_url(version, naming.exe_filename(version)),
        },
        {
            "name": naming.manifest_filename(version),
            "size": 500,
            "browser_download_url": asset_url(version, naming.manifest_filename(version)),
        },
        {
            "name": naming.checksum_filename(version),
            "size": 100,
            "browser_download_url": asset_url(version, naming.checksum_filename(version)),
        },
    ]


def test_release_with_both_asset_families_selects_the_openfetch_assets(package_content):
    version = "3.1.0"
    size = len(package_content)
    assets = _family_assets(version, size, OPENFETCH_RELEASE) + _family_assets(
        version, size, LEGACY_RELEASE
    )
    checker = UpdateChecker()

    candidate = checker.parse_release(
        release_payload(version, size, assets=assets), current_version="3.0.8"
    )

    assert candidate is not None
    assert candidate.exe_url.endswith("/OpenFetch-3.1.0-windows-x64.exe")
    assert candidate.manifest_url.endswith("/OpenFetch-3.1.0-manifest.json")
    info = checker.bind_manifest(candidate, manifest_document(version, package_content), "3.0.8")
    assert info.manifest.application_name == "OpenFetch"


def test_legacy_named_assets_alone_are_not_installed_by_openfetch(package_content):
    version = "3.1.1"
    assets = _family_assets(version, len(package_content), LEGACY_RELEASE)

    with pytest.raises(UpdateError) as exc_info:
        UpdateChecker().parse_release(
            release_payload(version, len(package_content), assets=assets), "3.1.0"
        )

    assert exc_info.value.code == "missing_asset"


def test_openfetch_rejects_a_legacy_manifest_for_its_own_asset(package_content):
    document = manifest_document(
        "3.1.0",
        package_content,
        application_name=LEGACY_APP_NAME,
        asset_filename=LEGACY_RELEASE.exe_filename("3.1.0"),
    )

    with pytest.raises(UpdateValidationError, match="application name"):
        UpdateManifest.from_json(document, release_version="3.1.0", current_version="3.0.8")


def test_compatibility_manifest_satisfies_the_installed_neural_extractor_contract(
    package_content,
):
    """The legacy asset family must parse under the rules 3.0.4-3.0.8 enforce."""
    document = manifest_document(
        "3.1.0",
        package_content,
        application_name="Neural Extractor V3",
        asset_filename="NeuralExtractorV3-3.1.0-windows-x64.exe",
        minimum_updater_version="3.0.4",
    )

    for installed in ("3.0.4", "3.0.7", "3.0.8"):
        manifest = UpdateManifest.from_json(
            document,
            release_version="3.1.0",
            current_version=installed,
            naming=LEGACY_RELEASE,
        )
        assert manifest.asset_filename == "NeuralExtractorV3-3.1.0-windows-x64.exe"
        assert manifest.minimum_updater_version == "3.0.4"


def test_moved_release_feed_is_reported_instead_of_an_invalid_version():
    redirect = FakeResponse(
        url=GITHUB_LATEST_RELEASE_API,
        status_code=301,
        payload={
            "message": "Moved Permanently",
            "url": "https://api.github.com/repositories/1/releases/latest",
        },
    )
    session = FakeSession(redirect)

    with pytest.raises(UpdateError) as exc_info:
        UpdateChecker(session=session).check("3.1.0")

    assert exc_info.value.code == "release_source_moved"
    assert exc_info.value.technical == "HTTP 301"
    assert session.calls[0][1]["allow_redirects"] is False
    assert redirect.closed


def test_openfetch_checks_only_the_canonical_repository():
    assert GITHUB_REPO == "AegisAI-Dev/OpenFetch"
    assert GITHUB_LATEST_RELEASE_API == (
        "https://api.github.com/repos/AegisAI-Dev/OpenFetch/releases/latest"
    )
    checker = UpdateChecker()
    assert checker.api_url == GITHUB_LATEST_RELEASE_API
    assert checker.releases_url == GITHUB_RELEASES_URL


def test_a_repository_without_releases_is_reported_as_unavailable():
    """A fresh canonical repository answers /releases/latest with 404."""
    missing = FakeResponse(url=GITHUB_LATEST_RELEASE_API, status_code=404, payload={})
    session = FakeSession(missing)

    with pytest.raises(UpdateError) as exc_info:
        UpdateChecker(session=session).check("3.1.0")

    assert exc_info.value.code == "release_source_unavailable"
    assert exc_info.value.technical == "HTTP 404"
    assert missing.closed


def test_redirects_are_never_followed_for_the_release_feed(package_content):
    """GitHub answers a renamed repository with 301; following it is unsafe."""
    payload = release_payload("3.1.1", len(package_content))
    session = FakeSession(
        FakeResponse(url=GITHUB_LATEST_RELEASE_API, status_code=301, payload=payload)
    )

    with pytest.raises(UpdateError) as exc_info:
        UpdateChecker(session=session).check("3.1.0")

    # Even a redirect whose body would parse as a valid release is refused.
    assert exc_info.value.code == "release_source_moved"
    assert session.calls[0][1]["allow_redirects"] is False
