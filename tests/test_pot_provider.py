from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from yt_dlp.extractor.youtube.pot.provider import PoTokenContext, PoTokenRequest

from openfetch.core import pot_provider as provider_module
from openfetch.core.pot_provider import (
    HELPER_ID,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    PROVIDER_CAPABILITY,
    PROVIDER_EXTRACTOR_KEY,
    PROVIDER_ID,
    PROVIDER_VERSION,
    ExternalPoHelperError,
    ExternalPoTokenHelper,
    configure_yt_dlp_plugins,
    options_request_po_provider,
    redact_po_token_material,
    verify_helper_package,
)
from openfetch.core.process_control import (
    ProcessOutcome,
    ProcessResult,
    ProcessTotalTimeoutError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _write_package(tmp_path: Path) -> tuple[Path, Path, dict]:
    application_root = tmp_path / "application"
    application_root.mkdir()
    package_root = tmp_path / "separate-helper"
    package_root.mkdir()
    files = {
        "node.exe": b"separately installed Node runtime\n",
        "helper.mjs": b"// separately installed protocol entry module\n",
        "runtime/provider.dat": b"external provider runtime\n",
    }
    entries = []
    for relative_path, payload in files.items():
        path = package_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        entries.append(
            {
                "path": relative_path,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    entries.sort(key=lambda item: item["path"].casefold())
    package_digest = hashlib.sha256()
    for item in entries:
        package_digest.update(item["path"].encode("utf-8"))
        package_digest.update(b"\0")
        package_digest.update(str(item["size"]).encode("ascii"))
        package_digest.update(b"\0")
        package_digest.update(item["sha256"].encode("ascii"))
        package_digest.update(b"\n")
    manifest = {
        "schema_version": 1,
        "helper_id": HELPER_ID,
        "helper_version": "1.0.0",
        "provider_version": PROVIDER_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "package_root": str(package_root.resolve()),
        "entrypoint": "node.exe",
        "arguments": ["helper.mjs"],
        "package_sha256": package_digest.hexdigest(),
        "files": entries,
    }
    activation = tmp_path / "configuration" / "active.json"
    activation.parent.mkdir()
    activation.write_text(json.dumps(manifest), encoding="utf-8")
    return activation, application_root, manifest


def _write_real_node_package(tmp_path: Path) -> tuple[Path, Path]:
    path_node = shutil.which("node.exe") or shutil.which("node")
    node_source = Path(path_node) if path_node else PROJECT_ROOT / "bin" / "node.exe"
    if not node_source.is_file():
        pytest.skip("the audited offline Node runtime is not available")
    application_root = tmp_path / "application"
    application_root.mkdir()
    package_root = tmp_path / "separate-helper"
    package_root.mkdir()
    node_target = package_root / "node.exe"
    try:
        os.link(node_source, node_target)
    except OSError:
        shutil.copy2(node_source, node_target)
    (package_root / "helper.mjs").write_text(
        """
import fs from "node:fs";
let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
const manifest = JSON.parse(fs.readFileSync("../configuration/active.json", "utf8"));
const result = request.action === "hello"
  ? {capabilities: ["mweb.gvs"], provider_version: manifest.provider_version}
  : {po_token: "dG9rZW4", expires_at: null};
process.stdout.write(JSON.stringify({
  protocol: request.protocol,
  protocol_version: request.protocol_version,
  request_id: request.request_id,
  helper_id: manifest.helper_id,
  helper_version: manifest.helper_version,
  provider_version: manifest.provider_version,
  package_sha256: manifest.package_sha256,
  ok: true,
  result,
}));
""".strip()
        + "\n",
        encoding="utf-8",
    )
    entries = []
    for path in sorted(package_root.iterdir(), key=lambda item: item.name.casefold()):
        payload = path.read_bytes()
        entries.append(
            {
                "path": path.name,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    package_digest = hashlib.sha256()
    for item in entries:
        package_digest.update(item["path"].encode("utf-8"))
        package_digest.update(b"\0")
        package_digest.update(str(item["size"]).encode("ascii"))
        package_digest.update(b"\0")
        package_digest.update(item["sha256"].encode("ascii"))
        package_digest.update(b"\n")
    manifest = {
        "schema_version": 1,
        "helper_id": HELPER_ID,
        "helper_version": "1.0.0",
        "provider_version": PROVIDER_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "package_root": str(package_root.resolve()),
        "entrypoint": "node.exe",
        "arguments": ["helper.mjs"],
        "package_sha256": package_digest.hexdigest(),
        "files": entries,
    }
    activation = tmp_path / "configuration" / "active.json"
    activation.parent.mkdir()
    activation.write_text(json.dumps(manifest), encoding="utf-8")
    return activation, application_root


class _ProtocolSupervisor:
    calls: list[dict] = []
    generate_result: dict = {"po_token": "dG9rZW4", "expires_at": None}
    stderr = ""
    returncode = 0
    cancelled = False

    def __init__(self, *_args, **_kwargs) -> None:
        self.__class__.cancelled = False

    def cancel(self) -> None:
        self.__class__.cancelled = True

    def run(self, args, **kwargs):
        request = json.loads(kwargs["stdin_data"])
        manifest = json.loads(
            (Path(kwargs["cwd"]).parent / "configuration" / "active.json").read_text(
                encoding="utf-8"
            )
        )
        self.__class__.calls.append(
            {
                "args": tuple(args),
                "request": request,
                "cwd": kwargs["cwd"],
                "env": kwargs["env"],
            }
        )
        result = (
            {
                "capabilities": [PROVIDER_CAPABILITY],
                "provider_version": PROVIDER_VERSION,
            }
            if request["action"] == "hello"
            else dict(self.__class__.generate_result)
        )
        response = {
            "protocol": PROTOCOL_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request["request_id"],
            "helper_id": HELPER_ID,
            "helper_version": manifest["helper_version"],
            "provider_version": manifest["provider_version"],
            "package_sha256": manifest["package_sha256"],
            "ok": True,
            "result": result,
        }
        return SimpleNamespace(
            returncode=self.__class__.returncode,
            stdout=json.dumps(response),
            stderr=self.__class__.stderr,
        )


@pytest.fixture(autouse=True)
def _reset_provider_state(monkeypatch):
    provider_module._DEFAULT_PROVIDER = None
    _ProtocolSupervisor.calls = []
    _ProtocolSupervisor.generate_result = {"po_token": "dG9rZW4", "expires_at": None}
    _ProtocolSupervisor.stderr = ""
    _ProtocolSupervisor.returncode = 0
    monkeypatch.delenv("YTDLP_NO_PLUGINS", raising=False)
    yield
    provider_module._DEFAULT_PROVIDER = None


def test_complete_external_package_is_verified_and_tampering_fails_closed(tmp_path):
    activation, application_root, manifest = _write_package(tmp_path)

    package = verify_helper_package(activation, application_root=application_root)

    assert package.root == Path(manifest["package_root"])
    assert package.entrypoint == package.root / "node.exe"
    assert package.arguments == ("helper.mjs",)
    assert package.provider_version == PROVIDER_VERSION
    assert package.package_sha256 == manifest["package_sha256"]

    (package.root / "runtime" / "provider.dat").write_bytes(b"tampered")
    with pytest.raises(ExternalPoHelperError, match="package_integrity_failed"):
        verify_helper_package(activation, application_root=application_root)


def test_unlisted_package_file_and_app_embedded_package_are_rejected(tmp_path):
    activation, application_root, manifest = _write_package(tmp_path)
    package_root = Path(manifest["package_root"])
    (package_root / "unlisted.js").write_text("unexpected", encoding="utf-8")

    with pytest.raises(ExternalPoHelperError, match="package_integrity_failed"):
        verify_helper_package(activation, application_root=application_root)

    manifest["package_root"] = str((application_root / "provider").resolve())
    activation.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ExternalPoHelperError, match="package_integrity_failed"):
        verify_helper_package(activation, application_root=application_root)


def test_helper_absence_is_clear_optional_and_fail_safe(tmp_path):
    helper = ExternalPoTokenHelper(
        activation_manifest=tmp_path / "missing.json",
        application_root=tmp_path / "application",
    )

    assert not helper.status.available
    assert not helper.status.installed
    assert not helper.status.bundled
    assert "not installed" in helper.status.diagnostic
    with pytest.raises(ExternalPoHelperError, match="helper_unavailable"):
        helper.ytdlp_options()


def test_hello_and_generation_use_only_static_argv_and_json_pipes(tmp_path, monkeypatch):
    activation, application_root, manifest = _write_package(tmp_path)
    monkeypatch.setattr(provider_module, "OwnedProcessSupervisor", _ProtocolSupervisor)
    helper = ExternalPoTokenHelper(
        activation_manifest=activation,
        application_root=application_root,
    )

    assert helper.status.available
    options = helper.ytdlp_options()
    secret_binding = "binding-sentinel-123456"
    token, expires_at = helper.generate(
        context="gvs",
        client_name="MWEB",
        content_binding=secret_binding,
        content_binding_type="video_id",
        innertube_context={
            "client": {
                "clientName": "MWEB",
                "clientVersion": "2.20260722.01.00",
                "hl": "nl",
            },
            "credentials": "must-not-cross",
        },
        authenticated=False,
        bypass_cache=False,
    )

    assert token == "dG9rZW4"
    assert expires_at is None
    assert options["extractor_args"][PROVIDER_EXTRACTOR_KEY] == {"protocol": ["1"]}
    generation = _ProtocolSupervisor.calls[-1]
    assert generation["args"] == (
        str(Path(manifest["package_root"]) / "node.exe"),
        "helper.mjs",
    )
    assert secret_binding not in " ".join(generation["args"])
    assert secret_binding not in json.dumps(generation["env"])
    assert generation["request"] == {
        "action": "generate",
        "payload": {
            "authenticated": False,
            "bypass_cache": False,
            "client_name": "MWEB",
            "content_binding": secret_binding,
            "content_binding_type": "video_id",
            "context": "gvs",
            "innertube_context": {
                "client": {
                    "clientName": "MWEB",
                    "clientVersion": "2.20260722.01.00",
                    "hl": "nl",
                }
            },
        },
        "protocol": PROTOCOL_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": generation["request"]["request_id"],
    }


def test_real_offline_node_boundary_round_trip(tmp_path):
    activation, application_root = _write_real_node_package(tmp_path)
    helper = ExternalPoTokenHelper(
        activation_manifest=activation,
        application_root=application_root,
    )

    assert helper.status.available
    token, expires_at = helper.generate(
        context="gvs",
        client_name="MWEB",
        content_binding="offline-video-binding",
        content_binding_type="video_id",
        innertube_context={
            "client": {
                "clientName": "MWEB",
                "clientVersion": "2.20260722.01.00",
            }
        },
        authenticated=False,
        bypass_cache=True,
    )

    assert token == "dG9rZW4"
    assert expires_at is None


def test_yt_dlp_adapter_applies_helper_token_without_third_party_import(tmp_path, monkeypatch):
    activation, application_root, _manifest = _write_package(tmp_path)
    monkeypatch.setattr(provider_module, "OwnedProcessSupervisor", _ProtocolSupervisor)
    helper = ExternalPoTokenHelper(
        activation_manifest=activation,
        application_root=application_root,
    )
    monkeypatch.setattr(provider_module, "get_po_token_provider", lambda: helper)

    configure_yt_dlp_plugins(enable_po_provider=True)
    from yt_dlp.extractor.youtube.pot._registry import _pot_providers

    assert len(_pot_providers.value) == 1
    provider_class = next(iter(_pot_providers.value.values()))
    assert provider_class.PROVIDER_NAME == PROVIDER_ID
    provider = provider_class(SimpleNamespace(), SimpleNamespace(), {})
    response = provider.request_pot(
        PoTokenRequest(
            context=PoTokenContext.GVS,
            innertube_context={
                "client": {
                    "clientName": "MWEB",
                    "clientVersion": "2.20260722.01.00",
                }
            },
            internal_client_name="mweb",
            video_id="video-binding-123",
            _gvs_bind_to_video_id=True,
        )
    )

    assert response.po_token == "dG9rZW4"
    assert _ProtocolSupervisor.calls[-1]["request"]["payload"]["content_binding"] == (
        "video-binding-123"
    )
    assert not any(
        name in __import__("sys").modules
        for name in (
            "yt_dlp_plugins.extractor.getpot_bgutil",
            "yt_dlp_plugins.extractor.getpot_bgutil_script",
            "yt_dlp_plugins.extractor.getpot_bgutil_http",
        )
    )


def test_external_helper_timeout_and_cancel_are_typed_and_never_echo_payload(tmp_path, monkeypatch):
    activation, application_root, _manifest = _write_package(tmp_path)

    class TimeoutSupervisor(_ProtocolSupervisor):
        def run(self, args, **kwargs):
            result = ProcessResult(
                args=tuple(args),
                pid=123,
                returncode=None,
                outcome=ProcessOutcome.TOTAL_TIMEOUT,
                stdout="",
                stderr="secret-token-must-not-surface",
                elapsed_seconds=30,
            )
            raise ProcessTotalTimeoutError("timed out", result)

    monkeypatch.setattr(provider_module, "OwnedProcessSupervisor", TimeoutSupervisor)
    helper = ExternalPoTokenHelper(
        activation_manifest=activation,
        application_root=application_root,
    )
    with pytest.raises(ExternalPoHelperError) as error:
        helper.generate(
            context="gvs",
            client_name="MWEB",
            content_binding="secret-binding",
            content_binding_type="video_id",
            innertube_context={"client": {"clientName": "MWEB"}},
            authenticated=False,
            bypass_cache=False,
        )
    assert error.value.code == "helper_timeout"
    assert "secret" not in str(error.value)

    active = _ProtocolSupervisor()
    helper._active_supervisor = active
    helper.cancel()
    assert active.cancelled


def test_stderr_and_wrong_response_identity_fail_without_echoing_secrets(tmp_path, monkeypatch):
    activation, application_root, _manifest = _write_package(tmp_path)
    monkeypatch.setattr(provider_module, "OwnedProcessSupervisor", _ProtocolSupervisor)
    _ProtocolSupervisor.stderr = "po_token=secret-token"
    helper = ExternalPoTokenHelper(
        activation_manifest=activation,
        application_root=application_root,
    )

    assert not helper.status.available
    assert "secret-token" not in helper.status.diagnostic


@pytest.mark.parametrize(
    "options",
    [
        {},
        {
            "extractor_args": {
                "youtube": {"player_client": ["mweb"], "fetch_pot": ["auto"]},
                PROVIDER_EXTRACTOR_KEY: {"protocol": ["2"]},
            }
        },
        {
            "extractor_args": {
                "youtube": {
                    "player_client": ["web"],
                    "fetch_pot": ["auto"],
                    "pot_trace": ["false"],
                },
                PROVIDER_EXTRACTOR_KEY: {"protocol": ["1"]},
            }
        },
    ],
)
def test_only_exact_bounded_attempt_requests_external_helper(options):
    assert not options_request_po_provider(options)

    assert options_request_po_provider(
        {
            "extractor_args": {
                "youtube": {
                    "player_client": ["mweb"],
                    "fetch_pot": ["auto"],
                    "pot_trace": ["false"],
                },
                PROVIDER_EXTRACTOR_KEY: {"protocol": ["1"]},
            }
        }
    )


@pytest.mark.parametrize(
    "diagnostic",
    [
        "poToken=token-sentinel-123456",
        "po_token: token-sentinel-123456",
        "Generated POT: token-sentinel-123456",
        "PoTokenResponse(po_token='token-sentinel-123456')",
        "https://provider.invalid/pot/token-sentinel-123456/result",
        "https://youtube.invalid/media?pot=token-sentinel-123456&x=1",
        '{"integrityToken":"token-sentinel-123456"}',
        '{"visitorData":"token-sentinel-123456"}',
        '{"content_binding":"token-sentinel-123456"}',
    ],
)
def test_all_protocol_secret_shapes_are_redacted(diagnostic):
    assert "token-sentinel-123456" not in redact_po_token_material(diagnostic)


def test_worker_and_adapter_source_have_no_gpl_provider_imports():
    sources = [
        Path(provider_module.__file__).read_text(encoding="utf-8"),
        (Path(provider_module.__file__).with_name("ytdlp_worker.py").read_text(encoding="utf-8")),
    ]
    joined = "\n".join(sources)
    assert "importlib.import_module" not in joined
    assert "yt_dlp_plugins.extractor.getpot_bgutil" not in joined
    assert "vendor/bgutil-ytdlp-pot-provider" not in joined
    assert "vendor\\bgutil-ytdlp-pot-provider" not in joined
