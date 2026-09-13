"""The two-repository migration bridge.

The GitHub repository was renamed to ``AegisAI-Dev/OpenFetch``. Installed
Neural Extractor V3 updaters (3.0.4-3.0.8) are pinned to the pre-rename slug,
call the release API with ``allow_redirects=False`` and require exact asset URLs
under that slug, so GitHub's rename redirect leaves them unable to update at
all: they parse the redirect body, find no ``tag_name`` and fail with
``invalid_version``.

The migration therefore uses two repositories, both owned by AegisAI-Dev:

* ``AegisAI-Dev/OpenFetch`` - canonical OpenFetch feed, the only repository
  OpenFetch itself ever trusts;
* ``AegisAI-Dev/NeuralExtractor`` - a bridge repository keeping the exact
  pre-rename name, carrying one legacy-named release that delivers OpenFetch to
  those installed clients.

These tests pin that contract, and that trusting the bridge is never delegated
to a redirect or to an unrelated namespace.
"""

from __future__ import annotations

import json

import pytest

from openfetch import config
from openfetch.core.update_manifest import LEGACY_RELEASE, OPENFETCH_RELEASE, UpdateManifest
from openfetch.core.updater import UpdateChecker
from scripts.release_tools import BOOTSTRAP_UPDATER_VERSION, generate_manifest

LEGACY_CLIENT_VERSIONS = ("3.0.4", "3.0.5", "3.0.6", "3.0.7", "3.0.8")


def test_openfetch_trusts_only_the_canonical_repository():
    assert config.GITHUB_REPO == "AegisAI-Dev/OpenFetch"
    assert config.GITHUB_LATEST_RELEASE_API == (
        "https://api.github.com/repos/AegisAI-Dev/OpenFetch/releases/latest"
    )
    assert config.GITHUB_RELEASES_URL == "https://github.com/AegisAI-Dev/OpenFetch/releases"
    # The bridge is never an OpenFetch update source.
    assert config.LEGACY_BRIDGE_REPO not in config.GITHUB_LATEST_RELEASE_API


def test_both_repositories_stay_under_the_same_owner():
    canonical_owner = config.GITHUB_REPO.split("/", 1)[0]
    bridge_owner = config.LEGACY_BRIDGE_REPO.split("/", 1)[0]
    assert canonical_owner == bridge_owner == "AegisAI-Dev"
    assert config.LEGACY_BRIDGE_REPO == "AegisAI-Dev/NeuralExtractor"


def test_the_updater_source_cannot_be_repointed_at_the_bridge():
    """Even the bridge is refused as an OpenFetch feed: the source is pinned."""
    bridge_api = f"https://api.github.com/repos/{config.LEGACY_BRIDGE_REPO}/releases/latest"
    with pytest.raises(ValueError, match="pinned"):
        UpdateChecker(api_url=bridge_api)
    with pytest.raises(ValueError, match="pinned"):
        UpdateChecker(releases_url=config.LEGACY_BRIDGE_RELEASES_URL)


def test_bridge_release_asset_names_are_exactly_what_legacy_clients_request():
    version = config.VERSION
    assert LEGACY_RELEASE.exe_filename(version) == f"NeuralExtractorV3-{version}-windows-x64.exe"
    assert LEGACY_RELEASE.manifest_filename(version) == (
        f"NeuralExtractorV3-{version}-manifest.json"
    )
    assert LEGACY_RELEASE.checksum_filename(version) == (
        f"NeuralExtractorV3-{version}-windows-x64.exe.sha256"
    )


def test_bridge_asset_urls_match_the_pinned_legacy_expectation():
    """A 3.0.x client compares browser_download_url against this exact string."""
    version = config.VERSION
    base = f"https://github.com/{config.LEGACY_BRIDGE_REPO}/releases/download/v{version}"
    for filename in (
        LEGACY_RELEASE.exe_filename(version),
        LEGACY_RELEASE.manifest_filename(version),
        LEGACY_RELEASE.checksum_filename(version),
    ):
        assert f"{base}/{filename}".startswith(
            "https://github.com/AegisAI-Dev/NeuralExtractor/releases/download/v"
        )
    # The canonical repository serves different URLs, which those clients reject.
    canonical = f"https://github.com/{config.GITHUB_REPO}/releases/download/v{version}"
    assert canonical != base


def test_bridge_manifest_satisfies_every_installed_legacy_client(tmp_path):
    version = config.VERSION
    executable = tmp_path / LEGACY_RELEASE.exe_filename(version)
    executable.write_bytes(b"O" * (2 * 1024 * 1024))
    output = tmp_path / LEGACY_RELEASE.manifest_filename(version)

    generate_manifest(version=version, executable=executable, output=output, naming="legacy")
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["application_name"] == "Neural Extractor V3"
    assert payload["asset_filename"] == LEGACY_RELEASE.exe_filename(version)
    assert payload["minimum_updater_version"] == BOOTSTRAP_UPDATER_VERSION == "3.0.4"
    assert payload["platform"] == "windows"
    assert payload["architecture"] == "x64"
    assert payload["channel"] == "stable"
    assert payload["schema_version"] == 1

    document = output.read_text(encoding="utf-8")
    for installed in LEGACY_CLIENT_VERSIONS:
        manifest = UpdateManifest.from_json(
            document,
            release_version=version,
            current_version=installed,
            naming=LEGACY_RELEASE,
        )
        assert manifest.asset_sha256 == payload["asset_sha256"]
        assert manifest.asset_size == executable.stat().st_size


def test_openfetch_rejects_the_bridge_manifest_for_its_own_updates(tmp_path):
    """The bridge family is for legacy clients only; OpenFetch requires its own."""
    version = config.VERSION
    executable = tmp_path / LEGACY_RELEASE.exe_filename(version)
    executable.write_bytes(b"O" * (2 * 1024 * 1024))
    output = tmp_path / LEGACY_RELEASE.manifest_filename(version)
    generate_manifest(version=version, executable=executable, output=output, naming="legacy")

    with pytest.raises(Exception, match="application name"):
        UpdateManifest.from_json(
            output.read_text(encoding="utf-8"),
            release_version=version,
            current_version="3.0.8",
            naming=OPENFETCH_RELEASE,
        )


def test_the_bridge_delivers_the_same_executable_as_the_canonical_release(tmp_path):
    """One build, two names: the legacy asset must not be a separate artifact."""
    version = config.VERSION
    payload = b"O" * (2 * 1024 * 1024)
    legacy_exe = tmp_path / LEGACY_RELEASE.exe_filename(version)
    openfetch_exe = tmp_path / OPENFETCH_RELEASE.exe_filename(version)
    legacy_exe.write_bytes(payload)
    openfetch_exe.write_bytes(payload)

    legacy_manifest = tmp_path / LEGACY_RELEASE.manifest_filename(version)
    openfetch_manifest = tmp_path / OPENFETCH_RELEASE.manifest_filename(version)
    generate_manifest(
        version=version, executable=legacy_exe, output=legacy_manifest, naming="legacy"
    )
    generate_manifest(version=version, executable=openfetch_exe, output=openfetch_manifest)

    legacy_payload = json.loads(legacy_manifest.read_text(encoding="utf-8"))
    openfetch_payload = json.loads(openfetch_manifest.read_text(encoding="utf-8"))
    assert legacy_payload["asset_sha256"] == openfetch_payload["asset_sha256"]
    assert legacy_payload["asset_size"] == openfetch_payload["asset_size"]
    assert legacy_payload["release_version"] == openfetch_payload["release_version"] == version


def test_documentation_describes_the_two_repository_bridge():
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[1] / "docs" / "OPENFETCH-MIGRATION.md").read_text(
        encoding="utf-8"
    )
    assert "AegisAI-Dev/OpenFetch" in doc
    assert "AegisAI-Dev/NeuralExtractor" in doc
    assert "301" in doc
    assert "bridge" in doc.casefold()
    # The superseded claim must not survive anywhere in the document.
    assert "stays on the same repository" not in doc.casefold()
