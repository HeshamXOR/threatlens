"""Locate bundled model artifacts, whether run from source or an installed wheel."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def _models_root() -> Path:
    # importlib.resources works for both a source tree and an installed wheel.
    return Path(str(resources.files("threatlens"))) / "models"


def url_models_dir() -> Path:
    return _models_root() / "url"


def pe_models_dir() -> Path:
    return _models_root() / "pe"
