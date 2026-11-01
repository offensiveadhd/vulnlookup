"""Pacing, backoff, URL building, the cache TTLs and the key store's file path."""

from __future__ import annotations

import json
import os
import stat
import sys
import time

import pytest
from vl import keystore
from vl.cache import Cache
from vl.http import Client, HttpError, Pacer, build_url


def test_build_url_encodes_everything():
    u = build_url(
        "https://x/y", {"keywordSearch": "exchange server & more", "cpeName": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", "skip": None}
    )
    assert u == "https://x/y?keywordSearch=exchange+server+%26+more&cpeName=cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"


def test_pacer_waits_when_the_window_is_full(tmp_path):
    now = [1000.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    p = Pacer(tmp_path / "w.json", per_window=3, window_s=30, sleep=sleep, now=lambda: now[0])
    for _ in range(3):
        assert p.wait() == 0
    waited = p.wait()
    assert waited > 29 and slept and slept[0] > 29
    # the stamps persist: a second Pacer on the same file sees the one stamp the wait just made
    p2 = Pacer(tmp_path / "w.json", per_window=3, window_s=30, sleep=sleep, now=lambda: now[0])
    assert p2._load() == [now[0]]
    assert p2.wait() == 0 and p2.wait() == 0 and p2.wait() > 29


def test_client_backs_off_on_403_then_succeeds(tmp_path):
    calls = []

    def fetch(url, headers):
        calls.append(url)
        return (403, b"") if len(calls) < 3 else (200, b'{"ok": true}')

    slept = []
    c = Client(tmp_path, None, fetch=fetch, sleep=slept.append)
    assert c.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=X") == {"ok": True}
    assert len(calls) == 3 and slept[:2] == [6.0, 12.0]


def test_client_gives_up_after_retries(tmp_path):
    c = Client(tmp_path, None, fetch=lambda u, h: (503, b""), sleep=lambda s: None)
    with pytest.raises(HttpError) as e:
        c.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=X", retries=2)
    assert e.value.status == 503


def test_client_404_is_not_retried(tmp_path):
    n = []
    c = Client(tmp_path, None, fetch=lambda u, h: (n.append(1), (404, b"nope"))[1], sleep=lambda s: None)
    with pytest.raises(HttpError):
        c.get_json("https://api.first.org/x")
    assert len(n) == 1


def test_client_keyed_window_is_fifty(tmp_path):
    assert Client(tmp_path, "k" * 32).pacer.per_window == 50
    assert Client(tmp_path, None).pacer.per_window == 5


def test_cache_ttl_and_stale(tmp_path, monkeypatch):
    c = Cache(tmp_path, {"cve": 10})
    c.put("cve", "k", {"a": 1})
    e = c.get("cve", "k")
    assert e.fresh and e.value == {"a": 1}
    t = time.time
    monkeypatch.setattr(time, "time", lambda: t() + 11)
    e = c.get("cve", "k")
    assert e is not None and not e.fresh and e.value == {"a": 1}
    assert c.get("cve", "other") is None
    assert c.clear("cve") == 1 and c.get("cve", "k") is None


def test_cache_disabled_stores_nothing(tmp_path):
    c = Cache(tmp_path, enabled=False)
    c.put("cve", "k", 1)
    assert c.get("cve", "k") is None and not list(tmp_path.rglob("*.json"))


def test_cache_write_is_atomic_and_keyed_by_hash(tmp_path):
    c = Cache(tmp_path)
    c.put("kev", "feed", {"x": 1})
    files = list((tmp_path / "kev").glob("*"))
    assert len(files) == 1 and files[0].suffix == ".json" and len(files[0].stem) == 40
    assert json.loads(files[0].read_text())["k"] == "feed"


def test_keystore_file_fallback_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNLOOKUP_CONFIG_DIR", str(tmp_path / "cfg"))
    kind = keystore.set_key("abcdefghijklmnopqrstuvwxyz", force_file=True)
    assert kind == "file"
    p = tmp_path / "cfg" / "nvd_api_key"
    assert p.read_text().strip() == "abcdefghijklmnopqrstuvwxyz"
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert keystore.get_key() == ("abcdefghijklmnopqrstuvwxyz", "file")
    assert keystore.status().hint == "wxyz"
    assert keystore.clear_key() == ["file"]
    assert keystore.get_key() == (None, "none")


def test_keystore_validation():
    with pytest.raises(ValueError):
        keystore.set_key("nope")
    with pytest.raises(ValueError):
        keystore.set_key("a" * 30 + " with spaces")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Credential Manager")
def test_windows_credential_manager_roundtrip(monkeypatch):
    """Writes and removes a real generic credential named vulnlookup/nvd-api-key. Skipped unless
    VULNLOOKUP_TEST_CREDMAN=1, so a plain test run never touches the user's store."""
    if os.environ.get("VULNLOOKUP_TEST_CREDMAN") != "1":
        pytest.skip("set VULNLOOKUP_TEST_CREDMAN=1 to exercise the real store")
    monkeypatch.setattr(keystore, "store_kind", lambda force_file=False: "credential-manager")
    keystore._win_write("testkeytestkeytestkey1234")
    assert keystore._win_read() == "testkeytestkeytestkey1234"
    assert keystore._win_delete()
    assert keystore._win_read() is None
