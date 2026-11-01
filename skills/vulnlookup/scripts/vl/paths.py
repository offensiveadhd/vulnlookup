"""Where the tool keeps things, per platform. Overridable with environment variables so tests
and CI never touch the real user profile.

    VULNLOOKUP_CACHE_DIR   cache (JSON files, safe to delete)
    VULNLOOKUP_CONFIG_DIR  config (the key file fallback, 0600)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP = "vulnlookup"


def cache_dir() -> Path:
    env = os.environ.get("VULNLOOKUP_CACHE_DIR")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP / "cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / APP
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / APP


def config_dir() -> Path:
    env = os.environ.get("VULNLOOKUP_CONFIG_DIR")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / APP
