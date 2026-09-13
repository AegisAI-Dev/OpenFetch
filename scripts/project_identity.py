"""Product identity for build, packaging, and compliance scripts.

Everything is derived from ``src/openfetch/config.py`` so no script carries its
own copy of the application version or executable name.
"""

from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "src" / "openfetch" / "config.py"


def config_constants(config_path: Path = CONFIG_PATH) -> dict[str, str]:
    tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    constants: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = node.value.value
    return constants


_CONSTANTS = config_constants()

APP_NAME = _CONSTANTS["APP_NAME"]
APP_PUBLISHER = _CONSTANTS["APP_PUBLISHER"]
EXECUTABLE_STEM = _CONSTANTS["EXECUTABLE_STEM"]
APPLICATION_VERSION = _CONSTANTS["VERSION"]
EXECUTABLE_NAME = f"{EXECUTABLE_STEM}.exe"
ONEFOLDER_SPEC_NAME = f"{EXECUTABLE_STEM}.spec"
ONEFILE_SPEC_NAME = f"{EXECUTABLE_STEM}-onefile.spec"
ONEFOLDER_DIST_NAME = f"{EXECUTABLE_STEM}-{APPLICATION_VERSION}-windows-x64"
