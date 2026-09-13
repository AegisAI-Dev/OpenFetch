from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scripts import build_offline_distribution as offline_build
from scripts import generate_source_bundle as source_bundle
from scripts import prepare_offline_inputs as prepare
from scripts import release_compliance_gate as release_gate
from scripts import verify_distribution_closure as closure


@pytest.mark.parametrize(
    ("path", "components"),
    [
        ("OpenFetch.exe", {"project", "pyinstaller", "cpython-runtime", "python-package"}),
        ("_internal/bin/node.exe", {"node"}),
        ("_internal/bin/ffmpeg.exe", {"ffmpeg"}),
        ("_internal/PySide6/Qt6Core.dll", {"pyside", "qt"}),
        (
            "_internal/PySide6/VCRUNTIME140.dll",
            {"pyside", "microsoft-runtime"},
        ),
        ("_internal/libffi-8.dll", {"libffi", "cpython-runtime"}),
        ("_internal/_ctypes.pyd", {"cpython-runtime"}),
        ("compliance/LICENSE", {"compliance-material"}),
    ],
)
def test_one_folder_component_classification(path, components):
    assert set(closure.classify(path)) == components


def test_distribution_closure_rejects_provider_path(tmp_path):
    distribution = tmp_path / "distribution"
    provider = distribution / "_internal" / "yt_dlp_plugins" / "getpot_bgutil.py"
    provider.parent.mkdir(parents=True)
    provider.write_text("provider", encoding="utf-8")

    report = closure.audit_distribution(distribution, tmp_path)

    assert report["technical_mapping_status"] == "HOLD"
    assert report["prohibited_entries"][0]["path"].endswith("getpot_bgutil.py")


def test_binary_map_self_reference_is_canonical(tmp_path):
    distribution = tmp_path / "distribution"
    binary_map = distribution / "compliance" / "BINARY-TO-SOURCE-MAP.json"
    binary_map.parent.mkdir(parents=True)
    binary_map.write_text("{}\n", encoding="utf-8")
    (distribution / "OpenFetch.exe").write_bytes(b"MZ-candidate")

    first = closure.audit_distribution(distribution, tmp_path)
    binary_map.write_text(json.dumps(first, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    second = closure.audit_distribution(distribution, tmp_path)

    assert first == second
    map_row = next(row for row in second["files"] if row["path"].endswith("SOURCE-MAP.json"))
    assert map_row["sha256"] == "SELF-REFERENTIAL"
    assert map_row["size"] == "SELF-REFERENTIAL"


def test_clean_build_destination_refuses_existing_content(tmp_path):
    destination = tmp_path / "workspace"
    destination.mkdir()
    (destination / "owned.txt").write_text("preserve", encoding="utf-8")

    with pytest.raises(RuntimeError, match="new or empty"):
        offline_build.ensure_empty_destination(destination)

    assert (destination / "owned.txt").read_text(encoding="utf-8") == "preserve"


def test_source_bundle_path_filter_blocks_secret_files():
    assert source_bundle.is_forbidden_path(Path("private/.env"))
    assert source_bundle.is_forbidden_path(Path("keys/signing.key"))
    assert source_bundle.is_forbidden_path(Path(".git/config"))
    assert not source_bundle.is_forbidden_path(Path("src/core/pot_provider.py"))


def test_source_bundle_scans_credentials_inside_archives(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("nested/token.txt", "gh" + "p_" + "A" * 24)

    with pytest.raises(RuntimeError, match="credential-like"):
        source_bundle.assert_no_secret_material(archive, Path("source.zip"))


def test_source_bundle_rejects_real_pem_keys_but_not_tls_parser_constants(tmp_path):
    pem_key = (
        "-----BEGIN RSA " + "PRIVATE KEY-----\n"
        + "\n".join("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w" for _ in range(4))
        + "\n-----END RSA " + "PRIVATE KEY-----\n"
    )
    leaking = tmp_path / "leaking.zip"
    with zipfile.ZipFile(leaking, "w") as handle:
        handle.writestr("nested/deploy.pem", pem_key)
    with pytest.raises(RuntimeError, match="Private-key"):
        source_bundle.assert_no_secret_material(leaking, Path("leaking.zip"))

    # TLS libraries embed the bare PEM header as a parser constant; a binary
    # containing only the marker must not be rejected.
    benign = tmp_path / "benign.zip"
    with zipfile.ZipFile(benign, "w") as handle:
        handle.writestr(
            "bin/player.exe",
            b"MZ\x90\x00" + b"-----BEGIN " + b"PRIVATE KEY-----\x00more-code",
        )
    source_bundle.assert_no_secret_material(benign, Path("benign.zip"))


def test_source_bundle_rejects_case_collisions_inside_archives(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("Source/File.txt", "one")
        handle.writestr("source/file.txt", "two")

    with pytest.raises(RuntimeError, match="case-colliding"):
        source_bundle.assert_no_secret_material(archive, Path("source.zip"))


def test_node_source_hash_pin_is_valid_sha256():
    row = next(item for item in prepare.STATIC_DOWNLOADS if item["component"] == "node-source")
    assert row["sha256"] == (
        "f8bf095ff559033edf04108fb1f14f72e2be337c609d4f83e8af1e299af7f4b4"
    )
    assert len(row["sha256"]) == 64


def test_python_wheels_are_selected_for_pinned_cp312_windows_target():
    project_root = Path(__file__).resolve().parents[1]
    supported = set(prepare.target_wheel_tags())
    downloads = prepare.locked_python_downloads(project_root)
    wheels = [item for item in downloads if item.kind == "python-build-wheel"]

    assert wheels
    assert all(
        prepare.TARGET_WHEELHOUSE.as_posix() in item.destination.as_posix()
        for item in wheels
    )
    for item in wheels:
        _name, _version, _build, tags = prepare.parse_wheel_filename(
            item.destination.name
        )
        assert tags & supported, item.destination.name


def test_tree_manifest_is_stable_and_content_sensitive(tmp_path):
    root = tmp_path / "dist"
    root.mkdir()
    (root / "b.txt").write_text("b", encoding="utf-8")
    (root / "a.txt").write_text("a", encoding="utf-8")

    rows, first = offline_build.tree_manifest(root)
    _, second = offline_build.tree_manifest(root)
    assert [row["path"] for row in rows] == ["a.txt", "b.txt"]
    assert first == second

    (root / "a.txt").write_text("changed", encoding="utf-8")
    _, third = offline_build.tree_manifest(root)
    assert third != first


def test_build_input_lock_is_machine_readable(tmp_path):
    (tmp_path / "build_inputs").mkdir()
    (tmp_path / "third_party_sources").mkdir()
    (tmp_path / "bin").mkdir()
    wheel = tmp_path / "build_inputs" / "wheel.whl"
    wheel.write_bytes(b"wheel")
    (tmp_path / "third_party_sources" / "source.tar").write_bytes(b"source")
    (tmp_path / "build_inputs" / "PREPARATION-MANIFEST.json").write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": "build_inputs/wheel.whl",
                        "size": wheel.stat().st_size,
                        "sha256": source_bundle.sha256_file(wheel),
                        "component": "fixture",
                        "version": "1",
                        "url": "https://example.invalid/wheel.whl",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    for name in ("ffmpeg.exe", "ffprobe.exe", "node.exe"):
        (tmp_path / "bin" / name).write_bytes(name.encode())

    payload = source_bundle.generate_build_inputs_lock(tmp_path)
    encoded = json.dumps(payload)

    assert payload["public_distribution_verdict"] == "HOLD"
    assert len(payload["inputs"]) == 3
    assert "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac" in encoded


def test_release_artifact_gate_rejects_provider_and_requires_one_folder_layout(tmp_path):
    artifact = tmp_path / "candidate.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("OpenFetch/OpenFetch.exe", b"candidate")
        archive.writestr("OpenFetch/yt_dlp_plugins/getpot_bgutil.py", b"provider")

    failures = release_gate.verify_artifact(tmp_path, artifact)

    assert any("Prohibited main-artifact path" in failure for failure in failures)
    assert any("compliance/LICENSE" in failure for failure in failures)


def test_release_gate_detects_prohibited_old_hash(tmp_path, monkeypatch):
    artifact = tmp_path / "legacy.exe"
    artifact.write_bytes(b"legacy")
    monkeypatch.setattr(
        release_gate,
        "sha256_file",
        lambda _path: release_gate.PROHIBITED_OLD_SHA256,
    )

    failures = release_gate.scan_prohibited_artifacts(tmp_path)

    assert failures == [f"Prohibited legacy one-file artifact detected: {artifact}"]


def test_release_gate_detects_both_prohibited_legacy_hashes(tmp_path, monkeypatch):
    legacy_304_hash = (
        "02fbde8845bcb7b8946a44f320aa1f88a63a70ceac9765f800276ce11bfa6ed7"
    )
    assert legacy_304_hash in release_gate.PROHIBITED_LEGACY_SHA256S
    assert release_gate.PROHIBITED_OLD_SHA256 in release_gate.PROHIBITED_LEGACY_SHA256S
    artifact = tmp_path / "legacy-3.0.4.exe"
    artifact.write_bytes(b"legacy")
    monkeypatch.setattr(release_gate, "sha256_file", lambda _path: legacy_304_hash)

    failures = release_gate.scan_prohibited_artifacts(tmp_path)

    assert failures == [f"Prohibited legacy one-file artifact detected: {artifact}"]
