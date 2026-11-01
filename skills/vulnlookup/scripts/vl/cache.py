"""A JSON file cache with one TTL per source.

Keys are hashed to file names; every entry carries the time it was stored and the TTL it was
stored with, so ``--offline`` can answer from a stale entry and say how stale. Nothing in here
is secret: the cache holds public NVD / FIRST / CISA responses only.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths

# Default TTLs in seconds, by source. Overridable with --ttl SOURCE=HOURS.
TTL = {
    "kev": 24 * 3600,
    "epss": 24 * 3600,
    "cpe": 7 * 24 * 3600,
    "cve": 6 * 3600,
}


@dataclass
class Entry:
    value: Any
    age: float  # seconds since stored
    fresh: bool


class Cache:
    def __init__(self, root: Path | None = None, ttl: dict[str, int] | None = None, enabled: bool = True):
        self.root = root or paths.cache_dir()
        self.ttl = dict(TTL)
        if ttl:
            self.ttl.update(ttl)
        self.enabled = enabled

    def _path(self, source: str, key: str) -> Path:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
        return self.root / source / (h + ".json")

    def get(self, source: str, key: str) -> Entry | None:
        if not self.enabled:
            return None
        p = self._path(source, key)
        try:
            with p.open("r", encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, ValueError):
            return None
        age = time.time() - float(rec.get("t", 0))
        return Entry(rec.get("v"), age, age <= self.ttl.get(source, 0))

    def put(self, source: str, key: str, value: Any) -> None:
        if not self.enabled:
            return
        p = self._path(source, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump({"t": time.time(), "k": key, "v": value}, fh, separators=(",", ":"))
        os.replace(tmp, p)

    def clear(self, source: str | None = None) -> int:
        n = 0
        dirs = [self.root / source] if source else list(self.root.iterdir()) if self.root.exists() else []
        for d in dirs:
            if not d.is_dir():
                continue
            for f in d.glob("*.json"):
                try:
                    f.unlink()
                    n += 1
                except OSError:
                    pass
        return n

    def stats(self) -> dict[str, Any]:
        out: dict[str, Any] = {"dir": str(self.root), "sources": {}}
        if not self.root.exists():
            return out
        for d in sorted(self.root.iterdir()):
            if d.is_dir():
                files = list(d.glob("*.json"))
                out["sources"][d.name] = {
                    "entries": len(files),
                    "bytes": sum(f.stat().st_size for f in files),
                    "ttl_hours": self.ttl.get(d.name, 0) / 3600,
                }
        return out
