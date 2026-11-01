"""Shared fixtures: the scripts on sys.path, a fake fetcher that answers from the recorded
responses and refuses anything else, and an isolated cache / config directory per test."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "vulnlookup" / "scripts"
sys.path.insert(0, str(SCRIPTS))

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
EPSS = "https://api.first.org/data/v1/epss"


@pytest.fixture(scope="session")
def responses() -> dict:
    with (FIXTURES / "responses.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


class FakeFetch:
    """Answers recorded URLs; records every request; raises on an unknown URL so a test can
    never leak onto the network by accident."""

    def __init__(self, responses: dict, fail: dict | None = None):
        self.responses = responses
        self.calls: list[str] = []
        self.fail = fail or {}  # url -> status to return instead
        # EPSS batches depend on what is already cached, so answer them from the pooled scores
        self.epss: dict[str, dict] = {}
        self.epss_asked: set[str] = set()
        for u, j in responses.items():
            if u.startswith(EPSS):
                for d in j.get("data", []):
                    self.epss[d["cve"]] = d
                for i in u.split("cve=", 1)[1].split("&")[0].split("%2C"):
                    self.epss_asked.add(i)

    def __call__(self, url: str, headers: dict) -> tuple[int, bytes]:
        self.calls.append(url)
        if url in self.fail:
            return self.fail[url], b"{}"
        if url.startswith(EPSS) and url not in self.responses:
            ids = url.split("cve=", 1)[1].split("&")[0].split("%2C")
            unknown = [i for i in ids if i not in self.epss_asked]
            if unknown:
                raise AssertionError(f"EPSS asked for ids the fixtures never recorded: {unknown}")
            data = [self.epss[i] for i in ids if i in self.epss]
            body = {"status": "OK", "status-code": 200, "version": "1.0", "total": len(data), "data": data}
            return 200, json.dumps(body).encode("utf-8")
        if url not in self.responses:
            raise AssertionError(f"unrecorded request: {url}")
        return 200, json.dumps(self.responses[url]).encode("utf-8")


@pytest.fixture
def fetch(responses) -> FakeFetch:
    return FakeFetch(responses)


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNLOOKUP_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("VULNLOOKUP_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("VULNLOOKUP_OFFLINE", raising=False)
    # never touch the real credential store from a test
    from vl import keystore

    monkeypatch.setattr(keystore, "store_kind", lambda force_file=False: "file")
    yield tmp_path


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    import time as _t

    from vl import http

    monkeypatch.setattr(http.time, "sleep", lambda s: None)
    monkeypatch.setattr(_t, "sleep", lambda s: None)
