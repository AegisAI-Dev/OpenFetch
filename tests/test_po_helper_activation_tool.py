"""The first-party activation tool for the separately installed PO helper.

``scripts/New-OpenFetchPoHelperActivation.ps1`` must produce exactly the
manifest that ``verify_helper_package`` accepts, and must never loosen what the
verifier later enforces. These tests run the real script in Windows PowerShell
and verify its output with OpenFetch's own verifier.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from openfetch.core import pot_provider
from openfetch.core.pot_provider import ExternalPoHelperError, verify_helper_package

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "New-OpenFetchPoHelperActivation.ps1"
POWERSHELL = shutil.which("powershell")

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or POWERSHELL is None,
    reason="the activation tool targets Windows PowerShell",
)


def _helper_source(**overrides: str) -> str:
    declarations = {
        "PROTOCOL_VERSION": str(pot_provider.PROTOCOL_VERSION),
        "HELPER_ID": f'"{pot_provider.HELPER_ID}"',
        "HELPER_VERSION": '"1.0.0"',
        "PROVIDER_VERSION": f'"{pot_provider.PROVIDER_VERSION}"',
    }
    declarations.update(overrides)
    lines = [f"const {name} = {value};" for name, value in declarations.items()]
    return "// test helper\n" + "\n".join(lines) + "\n"


@pytest.fixture
def package(tmp_path: Path) -> Path:
    root = tmp_path / "Helper Package 1.3.1"
    (root / "provider" / "build").mkdir(parents=True)
    (root / "node.exe").write_bytes(b"MZ-test-runtime")
    (root / "helper.mjs").write_text(_helper_source(), encoding="utf-8", newline="\n")
    (root / "provider" / "build" / "session_manager.js").write_bytes(b"export {};\n")
    (root / "LICENSE").write_bytes(b"GPL-3.0-only\n")
    return root


def _run(*arguments: str, local_app_data: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ, LOCALAPPDATA=str(local_app_data))
    return subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        env=environment,
        timeout=180,
    )


def _summary(completed: subprocess.CompletedProcess[str]) -> dict:
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_default_output_is_the_location_openfetch_reads(package, tmp_path):
    local_app_data = tmp_path / "LocalAppData"
    summary = _summary(_run("-PackageRoot", str(package), local_app_data=local_app_data))

    expected = (
        local_app_data
        / "OpenFetch"
        / pot_provider.HELPER_ACTIVATION_DIRECTORY
        / pot_provider.HELPER_ACTIVATION_FILENAME
    )
    assert Path(summary["output"]) == expected
    assert expected.is_file()
    assert summary["files"] == 4


def test_generated_manifest_is_accepted_by_the_openfetch_verifier(package, tmp_path):
    output = tmp_path / "activation" / "active.json"
    summary = _summary(
        _run("-PackageRoot", str(package), "-OutputPath", str(output), local_app_data=tmp_path)
    )

    verified = verify_helper_package(output, application_root=tmp_path / "OpenFetch-app")
    assert verified.package_sha256 == summary["package_sha256"]
    assert verified.helper_version == "1.0.0"
    assert verified.arguments == ("helper.mjs",)
    assert {item.relative_path for item in verified.files} == {
        "LICENSE",
        "helper.mjs",
        "node.exe",
        "provider/build/session_manager.js",
    }
    raw = output.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert raw.endswith(b"\n")


@pytest.mark.parametrize("change", ["modify", "add", "remove"])
def test_any_later_package_change_is_rejected(package, tmp_path, change):
    output = tmp_path / "active.json"
    _summary(
        _run("-PackageRoot", str(package), "-OutputPath", str(output), local_app_data=tmp_path)
    )

    if change == "modify":
        (package / "provider" / "build" / "session_manager.js").write_bytes(b"export {1};\n")
    elif change == "add":
        (package / "unexpected.js").write_bytes(b"x")
    else:
        (package / "LICENSE").unlink()

    with pytest.raises(ExternalPoHelperError, match="package_integrity_failed"):
        verify_helper_package(output, application_root=tmp_path / "OpenFetch-app")


def test_refuses_to_write_the_manifest_inside_the_package(package, tmp_path):
    completed = _run(
        "-PackageRoot",
        str(package),
        "-OutputPath",
        str(package / "active.json"),
        local_app_data=tmp_path,
    )
    assert completed.returncode != 0
    assert "outside the package root" in completed.stderr
    assert not (package / "active.json").exists()


def test_refuses_to_replace_an_existing_manifest_without_force(package, tmp_path):
    output = tmp_path / "active.json"
    output.write_text("previous", encoding="utf-8")

    refused = _run(
        "-PackageRoot", str(package), "-OutputPath", str(output), local_app_data=tmp_path
    )
    assert refused.returncode != 0
    assert "-Force" in refused.stderr
    assert output.read_text(encoding="utf-8") == "previous"

    _summary(
        _run(
            "-PackageRoot",
            str(package),
            "-OutputPath",
            str(output),
            "-Force",
            local_app_data=tmp_path,
        )
    )
    verify_helper_package(output, application_root=tmp_path / "OpenFetch-app")
    assert not list(tmp_path.glob(".active-*.tmp"))


@pytest.mark.parametrize("missing", ["node.exe", "helper.mjs"])
def test_refuses_a_directory_that_is_not_the_helper_package(package, tmp_path, missing):
    (package / missing).unlink()
    output = tmp_path / "active.json"
    completed = _run(
        "-PackageRoot", str(package), "-OutputPath", str(output), local_app_data=tmp_path
    )
    assert completed.returncode != 0
    assert missing in completed.stderr
    assert not output.exists()


def test_refuses_a_helper_that_declares_a_different_contract(package, tmp_path):
    (package / "helper.mjs").write_text(
        _helper_source(PROVIDER_VERSION='"9.9.9"'), encoding="utf-8", newline="\n"
    )
    output = tmp_path / "active.json"
    completed = _run(
        "-PackageRoot", str(package), "-OutputPath", str(output), local_app_data=tmp_path
    )
    assert completed.returncode != 0
    assert "supported helper contract" in completed.stderr
    assert not output.exists()


def test_script_contract_constants_match_the_verifier():
    text = SCRIPT.read_text(encoding="utf-8")

    def assigned(name: str) -> str:
        match = re.search(rf"^\${name} = '?([^'\r\n]+?)'?$", text, re.MULTILINE)
        assert match, name
        return match.group(1)

    assert int(assigned("SchemaVersion")) == pot_provider.HELPER_MANIFEST_SCHEMA_VERSION
    assert assigned("HelperId") == pot_provider.HELPER_ID
    assert assigned("ProviderVersion") == pot_provider.PROVIDER_VERSION
    assert int(assigned("ProtocolVersion")) == pot_provider.PROTOCOL_VERSION
    assert int(assigned("MaxPackageFiles")) == pot_provider.MAX_PACKAGE_FILES
    assert int(assigned("MaxPackageEntries")) == pot_provider.MAX_PACKAGE_ENTRIES
    assert assigned("MaxPackageBytes") == "4GB"
    assert pot_provider.MAX_PACKAGE_BYTES == 4 * 1024**3
