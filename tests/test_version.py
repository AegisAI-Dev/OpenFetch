import tomllib
from pathlib import Path

from openfetch.config import BUILD_LABEL, VERSION
from openfetch.core.update_manifest import is_newer_version

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_v310_authoritative_version_and_diagnostic_label_are_consistent():
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert VERSION == "3.1.0"
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "openfetch.config.VERSION"}
    assert BUILD_LABEL == "openfetch-brainbyte-migration"


def test_installed_neural_extractor_updaters_detect_v310_as_newer():
    for installed in ("3.0.4", "3.0.7", "3.0.8"):
        assert is_newer_version("3.1.0", installed)
