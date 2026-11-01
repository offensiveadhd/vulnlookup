"""Opt-in live smoke test against the real APIs. Skipped unless VULNLOOKUP_LIVE=1.

    VULNLOOKUP_LIVE=1 python -m pytest tests/test_live.py -q

About a dozen NVD requests (a minute unkeyed). Checks the shapes the fixtures were recorded
from have not drifted, and the known answers still hold.
"""

from __future__ import annotations

import io
import json
import os

import pytest
from vl import cli

pytestmark = pytest.mark.skipif(os.environ.get("VULNLOOKUP_LIVE") != "1", reason="live test; set VULNLOOKUP_LIVE=1")


def run(*args):
    out = io.StringIO()
    code = cli.main(list(args), out=out)
    return code, out.getvalue()


def test_live_log4shell():
    code, text = run("cve", "CVE-2021-44228", "--format", "json")
    assert code == 0
    r = json.loads(text)["rows"][0]
    assert r["cvss"]["score"] == 10.0 and r["kev"] and r["epss"]


def test_live_httpd_2_4_49_exact_hit_and_no_platform_rows():
    code, text = run("product", "apache httpd 2.4.49", "--format", "json")
    assert code == 0
    d = json.loads(text)
    by = {r["id"]: r for r in d["rows"]}
    assert by["CVE-2021-41773"]["verdict"] == "EXACT"
    assert "CVE-2007-4723" not in by
    assert all(r["verdict"] in ("EXACT", "RANGE", "ANY") for r in d["rows"])


def test_live_resolve_and_snap():
    code, text = run("resolve", "log4j 2.14.1")
    assert code == 0 and text.startswith("cpe:2.3:a:apache:log4j:2.14.1:")


def test_live_version_not_in_dictionary():
    code, text = run("product", "log4j 2.99", "--format", "json")
    assert code in (0, 4) and "NOT in the NVD dictionary" in json.loads(text)["subject"]
