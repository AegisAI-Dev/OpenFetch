"""Optional out-of-process PO Token helper integration.

The helper is a separately installed program.  OpenFetch verifies an
explicit activation manifest and the complete helper package before every
launch, starts only the manifest-pinned command with ``shell=False``, and
exchanges one bounded JSON request/response through anonymous pipes.  No
third-party provider module is imported into OpenFetch or its yt-dlp
worker.

Token material and content bindings are transported only in the pipe payload.
They are never placed in argv, environment variables, ownership records, or
diagnostic messages.  This is a stronger technical process boundary; it is not
a legal conclusion about whether the programs are separate works.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from uuid import uuid4

from openfetch.config import app_data_dir, base_dir
from openfetch.core.process_control import (
    OwnedProcessSupervisor,
    ProcessCancelledError,
    ProcessControlError,
    ProcessLaunchError,
    ProcessLimits,
)

# The external-helper identifiers below are a published protocol contract with
# the separately installed PO helper package and its activation manifests, so
# they intentionally keep their Neural Extractor-era values after the OpenFetch
# rename. Changing them would break every existing helper installation.
PROVIDER_ID = "neural-extractor:external-helper"
PROVIDER_VERSION = "1.3.1"
HELPER_ID = "org.neuralshield.neural-extractor.po-helper"
HELPER_ACTIVATION_FILENAME = "active.json"
HELPER_ACTIVATION_DIRECTORY = "optional-po-provider"
HELPER_MANIFEST_SCHEMA_VERSION = 1
PROTOCOL_NAME = "neural-extractor.po-helper"
PROTOCOL_VERSION = 1
PROVIDER_EXTRACTOR_KEY = "youtubepot-neuralextractorexternalhelper"
PROVIDER_CAPABILITY = "mweb.gvs"

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PACKAGE_FILES = 20_000
MAX_PACKAGE_ENTRIES = 40_000
MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
MAX_PROTOCOL_BYTES = 64 * 1024
MAX_CONTENT_BINDING_LENGTH = 16 * 1024
MAX_TOKEN_LENGTH = 32 * 1024
HELLO_TIMEOUT_SECONDS = 8.0
GENERATION_TIMEOUT_SECONDS = 30.0
TERMINATION_GRACE_SECONDS = 2.0

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_VERSION_PATTERN = re.compile(r"0|[1-9]\d*(?:\.(?:0|[1-9]\d*)){2}(?:[-+][0-9A-Za-z.-]+)?")
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_SAFE_ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")


class ExternalPoHelperError(RuntimeError):
    """A fail-closed helper error carrying only a non-sensitive code."""

    def __init__(self, code: str) -> None:
        self.code = code if _SAFE_ERROR_CODE_PATTERN.fullmatch(code) else "helper_failure"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class HelperPackageFile:
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedHelperPackage:
    root: Path
    entrypoint: Path
    arguments: tuple[str, ...]
    helper_version: str
    provider_version: str
    package_sha256: str
    files: tuple[HelperPackageFile, ...]

    @property
    def command(self) -> tuple[str, ...]:
        return (str(self.entrypoint), *self.arguments)


@dataclass(frozen=True, slots=True)
class PoTokenProviderStatus:
    available: bool
    bundled: bool
    installed: bool
    integrity_verified: bool
    provider_id: str
    version: str
    helper_version: str
    protocol_version: int
    diagnostic: str


class PoTokenProvider(Protocol):
    @property
    def status(self) -> PoTokenProviderStatus: ...

    def ytdlp_options(self) -> dict[str, Any]: ...

    def refresh_status(self) -> PoTokenProviderStatus: ...

    def cancel(self) -> None: ...


class ExternalPoTokenHelper:
    """Validate and invoke one manually installed optional helper package."""

    def __init__(
        self,
        *,
        activation_manifest: Path | None = None,
        application_root: Path | None = None,
    ) -> None:
        self.activation_manifest = Path(
            activation_manifest
            or app_data_dir() / HELPER_ACTIVATION_DIRECTORY / HELPER_ACTIVATION_FILENAME
        )
        self.application_root = Path(application_root or base_dir()).resolve()
        self._active_lock = threading.Lock()
        self._active_supervisor: OwnedProcessSupervisor | None = None

    @cached_property
    def status(self) -> PoTokenProviderStatus:
        try:
            package = verify_helper_package(
                self.activation_manifest,
                application_root=self.application_root,
            )
            response = self._invoke("hello", {}, timeout=HELLO_TIMEOUT_SECONDS)
            result = _require_object(response.get("result"), "invalid_hello_response")
            if set(result) != {"capabilities", "provider_version"}:
                raise ExternalPoHelperError("invalid_hello_response")
            capabilities = result.get("capabilities")
            if (
                not isinstance(capabilities, list)
                or not all(isinstance(item, str) for item in capabilities)
                or PROVIDER_CAPABILITY not in capabilities
                or result.get("provider_version") != package.provider_version
            ):
                raise ExternalPoHelperError("unsupported_helper_capability")
        except ExternalPoHelperError as exc:
            installed = exc.code != "helper_not_installed"
            detail = {
                "helper_not_installed": (
                    "Optional external PO Token helper is not installed. "
                    "Normal downloads remain available; install the helper manually if needed."
                ),
                "package_integrity_failed": (
                    "Optional external PO Token helper failed its package integrity check."
                ),
                "helper_timeout": "Optional external PO Token helper did not respond in time.",
                "helper_cancelled": "Optional external PO Token helper was cancelled safely.",
            }.get(exc.code, "Optional external PO Token helper is unavailable.")
            return PoTokenProviderStatus(
                available=False,
                bundled=False,
                installed=installed,
                integrity_verified=False,
                provider_id=PROVIDER_ID,
                version=PROVIDER_VERSION,
                helper_version="",
                protocol_version=PROTOCOL_VERSION,
                diagnostic=detail,
            )
        return PoTokenProviderStatus(
            available=True,
            bundled=False,
            installed=True,
            integrity_verified=True,
            provider_id=PROVIDER_ID,
            version=package.provider_version,
            helper_version=package.helper_version,
            protocol_version=PROTOCOL_VERSION,
            diagnostic=(
                "Optional external PO Token helper ready: "
                f"helper {package.helper_version}, provider {package.provider_version}, "
                f"protocol v{PROTOCOL_VERSION} (separately installed)."
            ),
        )

    def refresh_status(self) -> PoTokenProviderStatus:
        """Re-check a manual install or removal without restarting the app."""
        self.__dict__.pop("status", None)
        return self.status

    def ytdlp_options(self) -> dict[str, Any]:
        """Return a marker for the bounded external-helper attempt, never secrets."""
        status = self.status
        if not status.available or not status.integrity_verified:
            raise ExternalPoHelperError("helper_unavailable")
        return {
            "extractor_args": {
                "youtube": {
                    "player_client": ["mweb"],
                    "fetch_pot": ["auto"],
                    "pot_trace": ["false"],
                },
                PROVIDER_EXTRACTOR_KEY: {
                    "protocol": [str(PROTOCOL_VERSION)],
                },
            },
        }

    def generate(
        self,
        *,
        context: str,
        client_name: str,
        content_binding: str,
        content_binding_type: str,
        innertube_context: Mapping[str, Any],
        authenticated: bool,
        bypass_cache: bool,
    ) -> tuple[str, int | None]:
        """Request one token through stdin/stdout without logging its payload."""
        if context != "gvs" or client_name != "MWEB":
            raise ExternalPoHelperError("unsupported_helper_request")
        if (
            not content_binding
            or len(content_binding) > MAX_CONTENT_BINDING_LENGTH
            or any(ord(character) < 0x20 for character in content_binding)
        ):
            raise ExternalPoHelperError("invalid_content_binding")
        if content_binding_type not in {
            "datasync_id",
            "video_id",
            "visitor_data",
            "visitor_id",
        }:
            raise ExternalPoHelperError("invalid_content_binding")

        payload = {
            "context": context,
            "client_name": client_name,
            "content_binding": content_binding,
            "content_binding_type": content_binding_type,
            "innertube_context": _minimal_innertube_context(innertube_context),
            "authenticated": bool(authenticated),
            "bypass_cache": bool(bypass_cache),
        }
        response = self._invoke("generate", payload, timeout=GENERATION_TIMEOUT_SECONDS)
        result = _require_object(response.get("result"), "invalid_generate_response")
        if set(result) != {"expires_at", "po_token"}:
            raise ExternalPoHelperError("invalid_generate_response")
        token = result.get("po_token")
        expires_at = result.get("expires_at")
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= MAX_TOKEN_LENGTH
            or not _TOKEN_PATTERN.fullmatch(token)
        ):
            raise ExternalPoHelperError("invalid_generate_response")
        if expires_at is not None and (
            not isinstance(expires_at, int) or isinstance(expires_at, bool)
        ):
            raise ExternalPoHelperError("invalid_generate_response")
        return token, expires_at

    def cancel(self) -> None:
        """Cancel the active helper and let its supervisor clean the whole tree."""
        with self._active_lock:
            supervisor = self._active_supervisor
        if supervisor is not None:
            supervisor.cancel()

    def _invoke(self, action: str, payload: Mapping[str, Any], *, timeout: float) -> dict[str, Any]:
        package = verify_helper_package(
            self.activation_manifest,
            application_root=self.application_root,
        )
        request_id = uuid4().hex
        request = {
            "protocol": PROTOCOL_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "action": action,
            "payload": dict(payload),
        }
        request_bytes = json.dumps(
            request,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(request_bytes) > MAX_PROTOCOL_BYTES:
            raise ExternalPoHelperError("request_too_large")

        output_size = 0
        output_limit_hit = threading.Event()
        limits = ProcessLimits(
            inactivity_timeout=timeout,
            total_timeout=timeout,
            status_interval=max(1.0, min(5.0, timeout / 2)),
            termination_grace=TERMINATION_GRACE_SECONDS,
            force_kill_wait=TERMINATION_GRACE_SECONDS,
            poll_interval=0.05,
            pipe_join_timeout=TERMINATION_GRACE_SECONDS,
        )
        record = (
            app_data_dir()
            / "process-state"
            / f"active-po-helper-{os.getpid()}-{uuid4().hex[:8]}.json"
        )
        supervisor = OwnedProcessSupervisor(limits, ownership_record=record)

        def count_output(chunk: str) -> None:
            nonlocal output_size
            output_size += len(chunk.encode("utf-8", errors="replace"))
            if output_size > MAX_PROTOCOL_BYTES:
                output_limit_hit.set()
                supervisor.cancel()

        with self._active_lock:
            if self._active_supervisor is not None:
                raise ExternalPoHelperError("helper_busy")
            self._active_supervisor = supervisor
        try:
            result = supervisor.run(
                package.command,
                stdin_data=request_bytes,
                cwd=package.root,
                env=_helper_environment(package.root),
                stdout_callback=count_output,
                stderr_callback=count_output,
            )
        except ProcessCancelledError:
            if output_limit_hit.is_set():
                raise ExternalPoHelperError("response_too_large") from None
            raise ExternalPoHelperError("helper_cancelled") from None
        except ProcessControlError:
            raise ExternalPoHelperError("helper_timeout") from None
        except ProcessLaunchError:
            raise ExternalPoHelperError("helper_launch_failed") from None
        finally:
            with self._active_lock:
                if self._active_supervisor is supervisor:
                    self._active_supervisor = None

        if output_limit_hit.is_set():
            raise ExternalPoHelperError("response_too_large")
        if result.returncode != 0:
            raise ExternalPoHelperError("helper_process_failed")
        if result.stderr.strip():
            # Never surface helper stderr: it could contain token or binding material.
            raise ExternalPoHelperError("helper_protocol_violation")
        if len(result.stdout.encode("utf-8", errors="replace")) > MAX_PROTOCOL_BYTES:
            raise ExternalPoHelperError("response_too_large")
        try:
            response = json.loads(result.stdout, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, UnicodeError, ValueError):
            raise ExternalPoHelperError("invalid_helper_json") from None
        document = _require_object(response, "invalid_helper_response")
        _validate_response_envelope(
            document,
            request_id=request_id,
            package=package,
        )
        return document


def verify_helper_package(
    activation_manifest: Path,
    *,
    application_root: Path,
) -> VerifiedHelperPackage:
    """Verify a complete separately installed package against SHA-256 records."""
    manifest_path = Path(activation_manifest)
    if not manifest_path.is_file():
        raise ExternalPoHelperError("helper_not_installed")
    resolved_application_root = Path(application_root).resolve()
    try:
        resolved_manifest_path = manifest_path.resolve(strict=True)
    except OSError as exc:
        raise ExternalPoHelperError("invalid_activation_manifest") from exc
    if _is_reparse_point(manifest_path) or _is_relative_to(
        resolved_manifest_path, resolved_application_root
    ):
        raise ExternalPoHelperError("helper_must_be_external")
    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ExternalPoHelperError("invalid_activation_manifest")
        with manifest_path.open("rb") as stream:
            manifest_bytes = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ExternalPoHelperError("invalid_activation_manifest")
        document = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except ExternalPoHelperError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExternalPoHelperError("invalid_activation_manifest") from exc
    manifest = _require_object(document, "invalid_activation_manifest")
    required_keys = {
        "schema_version",
        "helper_id",
        "helper_version",
        "provider_version",
        "protocol_version",
        "package_root",
        "entrypoint",
        "arguments",
        "package_sha256",
        "files",
    }
    if set(manifest) != required_keys:
        raise ExternalPoHelperError("invalid_activation_manifest")
    if (
        manifest.get("schema_version") != HELPER_MANIFEST_SCHEMA_VERSION
        or manifest.get("helper_id") != HELPER_ID
        or manifest.get("protocol_version") != PROTOCOL_VERSION
        or manifest.get("provider_version") != PROVIDER_VERSION
    ):
        raise ExternalPoHelperError("unsupported_helper_version")
    helper_version = manifest.get("helper_version")
    if not isinstance(helper_version, str) or not _VERSION_PATTERN.fullmatch(helper_version):
        raise ExternalPoHelperError("invalid_activation_manifest")
    expected_package_hash = manifest.get("package_sha256")
    if not isinstance(expected_package_hash, str) or not _SHA256_PATTERN.fullmatch(
        expected_package_hash
    ):
        raise ExternalPoHelperError("invalid_activation_manifest")

    raw_root = manifest.get("package_root")
    if (
        not isinstance(raw_root, str)
        or not raw_root
        or len(raw_root) > 32_768
        or "\x00" in raw_root
    ):
        raise ExternalPoHelperError("invalid_activation_manifest")
    root_candidate = Path(raw_root)
    if not root_candidate.is_absolute():
        raise ExternalPoHelperError("invalid_activation_manifest")
    try:
        root = root_candidate.resolve(strict=True)
    except OSError as exc:
        raise ExternalPoHelperError("package_integrity_failed") from exc
    if not root.is_dir() or _is_reparse_point(root):
        raise ExternalPoHelperError("package_integrity_failed")
    if root == Path(root.anchor):
        raise ExternalPoHelperError("invalid_activation_manifest")
    if _is_relative_to(root, resolved_application_root) or _is_relative_to(
        resolved_application_root, root
    ):
        raise ExternalPoHelperError("helper_must_be_external")

    entrypoint_relative = _validate_relative_path(manifest.get("entrypoint"))
    if entrypoint_relative.casefold() != "node.exe":
        raise ExternalPoHelperError("invalid_activation_manifest")
    arguments = _validate_arguments(manifest.get("arguments"))
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files or len(raw_files) > MAX_PACKAGE_FILES:
        raise ExternalPoHelperError("invalid_activation_manifest")

    files: list[HelperPackageFile] = []
    seen_paths: set[str] = set()
    declared_size = 0
    for raw_file in raw_files:
        item = _require_object(raw_file, "invalid_activation_manifest")
        if set(item) != {"path", "sha256", "size"}:
            raise ExternalPoHelperError("invalid_activation_manifest")
        relative_path = _validate_relative_path(item.get("path"))
        collision_key = relative_path.casefold()
        if collision_key in seen_paths:
            raise ExternalPoHelperError("invalid_activation_manifest")
        seen_paths.add(collision_key)
        size = item.get("size")
        sha256 = item.get("sha256")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or not _SHA256_PATTERN.fullmatch(sha256)
        ):
            raise ExternalPoHelperError("invalid_activation_manifest")
        declared_size += size
        if declared_size > MAX_PACKAGE_BYTES:
            raise ExternalPoHelperError("invalid_activation_manifest")
        files.append(HelperPackageFile(relative_path, size, sha256))

    required_command_files = {entrypoint_relative.casefold(), "helper.mjs"}
    if not required_command_files.issubset(seen_paths):
        raise ExternalPoHelperError("invalid_activation_manifest")
    files.sort(key=lambda item: item.relative_path.casefold())
    actual_paths: list[str] = []
    visited_entries = 0
    try:
        for path in root.rglob("*"):
            visited_entries += 1
            if visited_entries > MAX_PACKAGE_ENTRIES:
                raise ExternalPoHelperError("package_integrity_failed")
            if _is_reparse_point(path):
                raise ExternalPoHelperError("package_integrity_failed")
            if path.is_file():
                actual_paths.append(path.relative_to(root).as_posix())
                if len(actual_paths) > MAX_PACKAGE_FILES:
                    raise ExternalPoHelperError("package_integrity_failed")
    except OSError as exc:
        raise ExternalPoHelperError("package_integrity_failed") from exc
    actual_path_keys = [path.casefold() for path in actual_paths]
    if (
        len(actual_path_keys) != len(set(actual_path_keys))
        or len(actual_path_keys) != len(files)
        or set(actual_path_keys) != seen_paths
    ):
        raise ExternalPoHelperError("package_integrity_failed")

    package_digest = hashlib.sha256()
    for item in files:
        path = root / Path(*PurePosixPath(item.relative_path).parts)
        _verify_file(path, expected_size=item.size, expected_sha256=item.sha256)
        package_digest.update(item.relative_path.encode("utf-8"))
        package_digest.update(b"\0")
        package_digest.update(str(item.size).encode("ascii"))
        package_digest.update(b"\0")
        package_digest.update(item.sha256.encode("ascii"))
        package_digest.update(b"\n")
    if package_digest.hexdigest() != expected_package_hash:
        raise ExternalPoHelperError("package_integrity_failed")

    entrypoint = root / Path(*PurePosixPath(entrypoint_relative).parts)
    if not entrypoint.is_file() or _is_reparse_point(entrypoint):
        raise ExternalPoHelperError("package_integrity_failed")
    if os.name == "nt":
        if entrypoint.suffix.casefold() != ".exe":
            raise ExternalPoHelperError("invalid_activation_manifest")
    elif not os.access(entrypoint, os.X_OK):
        raise ExternalPoHelperError("package_integrity_failed")
    return VerifiedHelperPackage(
        root=root,
        entrypoint=entrypoint,
        arguments=arguments,
        helper_version=helper_version,
        provider_version=PROVIDER_VERSION,
        package_sha256=expected_package_hash,
        files=tuple(files),
    )


def configure_yt_dlp_plugins(*, enable_po_provider: bool) -> None:
    """Register only OpenFetch's first-party external-helper adapter."""
    from yt_dlp.extractor.youtube.pot._registry import (
        _pot_cache_provider_preferences,
        _pot_cache_providers,
        _pot_pcs_providers,
        _pot_providers,
        _ptp_preferences,
    )
    from yt_dlp.globals import all_plugins_loaded, plugin_dirs

    # Fail closed against installed or user-supplied yt-dlp plugins.  No GPL
    # provider path is added to sys.path and no third-party module is imported.
    plugin_dirs.value = []
    all_plugins_loaded.value = True
    os.environ["YTDLP_NO_PLUGINS"] = "1"
    _pot_providers.value = {}
    _ptp_preferences.value = set()
    _pot_pcs_providers.value = {}
    _pot_cache_providers.value = {}
    _pot_cache_provider_preferences.value = set()

    if not enable_po_provider:
        return
    helper = get_po_token_provider()
    status = helper.status
    if not status.available or not status.integrity_verified:
        raise ExternalPoHelperError("helper_unavailable")

    from yt_dlp.extractor.youtube.pot.provider import (
        PoTokenContext,
        PoTokenProviderError,
        PoTokenResponse,
    )
    from yt_dlp.extractor.youtube.pot.provider import (
        PoTokenProvider as YtdlpPoTokenProvider,
    )
    from yt_dlp.extractor.youtube.pot.utils import get_webpo_content_binding

    class NeuralExtractorExternalHelperPTP(YtdlpPoTokenProvider):
        PROVIDER_NAME = PROVIDER_ID
        PROVIDER_VERSION = status.helper_version
        BUG_REPORT_LOCATION = "OpenFetch support"
        _SUPPORTED_CONTEXTS = (PoTokenContext.GVS,)
        _SUPPORTED_CLIENTS = ("MWEB",)
        _SUPPORTED_EXTERNAL_REQUEST_FEATURES = ()

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._helper = get_po_token_provider()

        def is_available(self) -> bool:
            current = self._helper.status
            return current.available and current.integrity_verified

        def close(self) -> None:
            self._helper.cancel()

        def _real_request_pot(self, request: Any) -> Any:
            content_binding, binding_type = get_webpo_content_binding(request)
            client = request.innertube_context.get("client") or {}
            client_name = str(client.get("clientName") or "")
            if not content_binding or binding_type is None:
                raise PoTokenProviderError(
                    "external_po_helper_rejected_request",
                    expected=True,
                )
            try:
                token, expires_at = self._helper.generate(
                    context=request.context.value,
                    client_name=client_name,
                    content_binding=str(content_binding),
                    content_binding_type=binding_type.value,
                    innertube_context=request.innertube_context,
                    authenticated=bool(request.is_authenticated),
                    bypass_cache=bool(request.bypass_cache),
                )
            except ExternalPoHelperError as exc:
                raise PoTokenProviderError(
                    f"external_po_helper_{exc.code}",
                    expected=True,
                ) from None
            return PoTokenResponse(po_token=token, expires_at=expires_at)

    _pot_providers.value = {
        NeuralExtractorExternalHelperPTP.PROVIDER_KEY: NeuralExtractorExternalHelperPTP
    }


def options_request_po_provider(options: Mapping[str, Any]) -> bool:
    extractor_args = options.get("extractor_args") or {}
    if not isinstance(extractor_args, Mapping):
        return False
    youtube_args = extractor_args.get("youtube") or {}
    provider_args = extractor_args.get(PROVIDER_EXTRACTOR_KEY) or {}
    if not isinstance(youtube_args, Mapping) or not isinstance(provider_args, Mapping):
        return False
    fetch_policy = _option_values(youtube_args.get("fetch_pot"))
    player_clients = _option_values(youtube_args.get("player_client"))
    pot_trace = _option_values(youtube_args.get("pot_trace"))
    protocol = _option_values(provider_args.get("protocol"))
    return (
        {value.casefold() for value in player_clients} == {"mweb"}
        and {value.casefold() for value in fetch_policy} == {"auto"}
        and (not pot_trace or {value.casefold() for value in pot_trace} == {"false"})
        and protocol == (str(PROTOCOL_VERSION),)
    )


def redact_po_token_material(value: str) -> str:
    """Remove token, binding, session, and credential material from diagnostics."""
    text = str(value or "")
    names = (
        r"(?:po_?token|potoken|integrity_?token|visitor_?data|data_?sync_?id|"
        r"content_?binding|authorization|cookie)"
    )
    text = re.sub(
        rf"(?i)([\"']?{names}[\"']?\s*[:=]\s*)([\"'])(.*?)(\2)",
        r"\1\2<redacted>\4",
        text,
    )
    text = re.sub(
        rf"(?i)(\b{names}\b\s*[:=]\s*)(?!<redacted>)[^\s,;)&\]}}]+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)(generated\s+(?:a\s+)?(?:po\s*token|pot)\s*[:=]\s*)\S+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)(PoTokenResponse\s*\(\s*po_token\s*=\s*)([^,)]+)",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)(/pot/)[A-Za-z0-9._~%+\-=]{8,}",
        r"\1<redacted>",
        text,
    )
    text = re.sub(r"(?i)([?&]pot=)[^&#\s]+", r"\1<redacted>", text)
    return text


def _validate_response_envelope(
    document: dict[str, Any],
    *,
    request_id: str,
    package: VerifiedHelperPackage,
) -> None:
    base_keys = {
        "protocol",
        "protocol_version",
        "request_id",
        "helper_id",
        "helper_version",
        "provider_version",
        "package_sha256",
        "ok",
    }
    if document.get("ok") is True:
        expected_keys = base_keys | {"result"}
    elif document.get("ok") is False:
        expected_keys = base_keys | {"error"}
    else:
        raise ExternalPoHelperError("invalid_helper_response")
    if set(document) != expected_keys:
        raise ExternalPoHelperError("invalid_helper_response")
    if (
        document.get("protocol") != PROTOCOL_NAME
        or document.get("protocol_version") != PROTOCOL_VERSION
        or document.get("request_id") != request_id
        or document.get("helper_id") != HELPER_ID
        or document.get("helper_version") != package.helper_version
        or document.get("provider_version") != package.provider_version
        or document.get("package_sha256") != package.package_sha256
    ):
        raise ExternalPoHelperError("helper_identity_mismatch")
    if document["ok"] is False:
        error = _require_object(document.get("error"), "invalid_helper_response")
        if set(error) != {"code"}:
            raise ExternalPoHelperError("invalid_helper_response")
        code = error.get("code")
        if not isinstance(code, str) or not _SAFE_ERROR_CODE_PATTERN.fullmatch(code):
            raise ExternalPoHelperError("invalid_helper_response")
        # Preserve only the fact that generation failed.  Never forward an
        # external message which could echo a token or content binding.
        raise ExternalPoHelperError("helper_reported_failure")


def _minimal_innertube_context(context: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise ExternalPoHelperError("invalid_innertube_context")
    client = context.get("client")
    if not isinstance(client, Mapping):
        raise ExternalPoHelperError("invalid_innertube_context")
    allowed_client_fields = {
        "browserName",
        "browserVersion",
        "clientFormFactor",
        "clientName",
        "clientVersion",
        "deviceMake",
        "deviceModel",
        "gl",
        "hl",
        "osName",
        "osVersion",
        "platform",
        "timeZone",
        "userAgent",
        "utcOffsetMinutes",
    }
    sanitized_client: dict[str, Any] = {}
    for key in sorted(allowed_client_fields):
        value = client.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            sanitized_client[key] = value
        elif isinstance(value, int) and -100_000 <= value <= 100_000:
            sanitized_client[key] = value
        elif (
            isinstance(value, str)
            and len(value) <= 2_048
            and not any(ord(character) < 0x20 for character in value)
        ):
            sanitized_client[key] = value
        else:
            raise ExternalPoHelperError("invalid_innertube_context")
    if sanitized_client.get("clientName") != "MWEB":
        raise ExternalPoHelperError("invalid_innertube_context")
    return {"client": sanitized_client}


def _helper_environment(package_root: Path) -> dict[str, str]:
    environment: dict[str, str] = {
        "NO_COLOR": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": "",
    }
    allowed = (
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LANG",
        "LOCALAPPDATA",
        "PATHEXT",
        "PROGRAMDATA",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    )
    for name in allowed:
        value = os.environ.get(name)
        if value and "\x00" not in value:
            environment[name] = value
    if os.name == "nt":
        system_root = environment.get("SystemRoot") or environment.get("WINDIR")
        search_paths = [str(package_root)]
        if system_root:
            search_paths.append(str(Path(system_root) / "System32"))
        environment["PATH"] = os.pathsep.join(search_paths)
    else:
        environment["PATH"] = os.pathsep.join((str(package_root), "/usr/bin", "/bin"))
    return environment


def _verify_file(path: Path, *, expected_size: int, expected_sha256: str) -> None:
    try:
        before = path.stat()
        if not path.is_file() or _is_reparse_point(path) or before.st_size != expected_size:
            raise ExternalPoHelperError("package_integrity_failed")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        after = path.stat()
    except ExternalPoHelperError:
        raise
    except OSError as exc:
        raise ExternalPoHelperError("package_integrity_failed") from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or digest.hexdigest() != expected_sha256
    ):
        raise ExternalPoHelperError("package_integrity_failed")


def _validate_relative_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4_096
        or "\x00" in value
        or "\\" in value
    ):
        raise ExternalPoHelperError("invalid_activation_manifest")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ExternalPoHelperError("invalid_activation_manifest")
    if any(":" in part for part in path.parts):
        raise ExternalPoHelperError("invalid_activation_manifest")
    return path.as_posix()


def _validate_arguments(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ExternalPoHelperError("invalid_activation_manifest")
    arguments = tuple(value)
    # Runtime data never belongs in argv.  The separately packaged Node runtime
    # may execute only this exact, manifest-hashed protocol entry module.
    if arguments != ("helper.mjs",):
        raise ExternalPoHelperError("invalid_activation_manifest")
    return arguments


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _require_object(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExternalPoHelperError(code)
    return value


def _option_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, Sequence) or isinstance(value, bytes | bytearray):
        return ()
    return tuple(str(item) for item in value)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return True
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


_DEFAULT_PROVIDER: ExternalPoTokenHelper | None = None


def get_po_token_provider() -> ExternalPoTokenHelper:
    global _DEFAULT_PROVIDER
    if _DEFAULT_PROVIDER is None:
        _DEFAULT_PROVIDER = ExternalPoTokenHelper()
    return _DEFAULT_PROVIDER


__all__ = [
    "ExternalPoHelperError",
    "ExternalPoTokenHelper",
    "HELPER_ACTIVATION_DIRECTORY",
    "HELPER_ACTIVATION_FILENAME",
    "HELPER_ID",
    "HELPER_MANIFEST_SCHEMA_VERSION",
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "PROVIDER_CAPABILITY",
    "PROVIDER_EXTRACTOR_KEY",
    "PROVIDER_ID",
    "PROVIDER_VERSION",
    "PoTokenProvider",
    "PoTokenProviderStatus",
    "VerifiedHelperPackage",
    "configure_yt_dlp_plugins",
    "get_po_token_provider",
    "options_request_po_provider",
    "redact_po_token_material",
    "verify_helper_package",
]
