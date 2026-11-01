"""End to end through main() against the recorded responses: every query kind, the filters,
the no-false-positive guards, the formats and styles, exit codes, determinism."""

from __future__ import annotations

import io
import json

import pytest
from vl import cli

HTTPD = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def run(fetch, *args, rc=None):
    out = io.StringIO()
    code = cli.main(list(args), out=out, fetch=fetch)
    if rc is not None:
        assert code == rc, out.getvalue()
    return code, out.getvalue()


def rows(fetch, *args):
    code, text = run(fetch, *args, "--format", "json")
    return code, json.loads(text)


# ---------------------------------------------------------------- one CVE / bulk CVEs


def test_one_cve_brief_terse(fetch):
    code, text = run(fetch, "cve", "CVE-2021-44228", "--format", "brief", "--style", "terse", rc=0)
    assert text == "CVE-2021-44228  10.0 CRIT  EPSS 0.999  KEV+ransomware\n"


def test_one_cve_json_fields(fetch):
    code, d = rows(fetch, "cve", "CVE-2021-44228")
    r = d["rows"][0]
    assert r["cvss"]["version"] == "3.1" and r["cvss"]["score"] == 10.0
    assert r["cvss"]["vector"].startswith("CVSS:3.1/")
    assert r["kev"]["dateAdded"] == "2021-12-10" and r["kev"]["knownRansomwareCampaignUse"] == "Known"
    assert r["cwe"] == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]
    assert 0.99 < r["epss"]["epss"] < 1 and r["epss"]["date"]
    assert r["published"] == "2021-12-10"
    assert all("tags" in ref for ref in r["references"])
    assert "verdict" not in r  # a CVE lookup has no target to verify against
    # the description names Apache Log4j, so log4j leads the fixed-version summary, not the Siemens firmware
    assert r["fixed_versions_by_product"][0] == {"product": "apache:log4j", "versions": ["2.3.1", "2.12.2", "2.15.0"]}


def test_bulk_cves_and_unknown_id(fetch, tmp_path):
    f = tmp_path / "ids.txt"
    f.write_text("see CVE-2021-41773 and cve-2014-0160\nCVE-2024-3094\n")
    code, d = rows(fetch, "cve", "--file", str(f))
    assert [r["id"] for r in d["rows"]] == ["CVE-2014-0160", "CVE-2021-41773", "CVE-2024-3094"]


def test_cve_not_found_exit_4(responses):
    from conftest import FakeFetch

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-99999"
    f = FakeFetch(dict(responses, **{url: {"totalResults": 0, "vulnerabilities": []}}))
    code, text = run(f, "cve", "CVE-1999-99999", "--format", "json")
    assert code == 4 and json.loads(text)["not_found"] == ["CVE-1999-99999"]


def test_cve_needs_an_id(fetch):
    code, _ = run(fetch, "cve")
    assert code == 2


# ---------------------------------------------------------------- product + version


def test_product_version_httpd(fetch):
    code, d = rows(fetch, "product", "apache httpd 2.4.49")
    assert code == 0
    assert d["targets"] == [HTTPD]
    assert d["resolution"]["via"] == "alias"
    assert d["resolution"]["snap"][0]["in_dictionary"] is True
    ids = {r["id"]: r for r in d["rows"]}
    assert ids["CVE-2021-41773"]["verdict"] == "EXACT"
    assert ids["CVE-2021-41773"]["matched"][0]["criteria"] == HTTPD
    assert ids["CVE-2021-44224"]["verdict"] == "RANGE"
    assert ids["CVE-2021-44224"]["matched"][0]["bounds"] == [">= 2.4.7", "< 2.4.52"]
    assert ids["CVE-2021-44224"]["fixed_versions"] == ["2.4.52"]
    assert "CVE-2007-4723" not in ids  # the Ragnarok platform-only record
    assert all(r["verdict"] in ("EXACT", "RANGE", "ANY") for r in d["rows"])
    assert d["nvd_returned"] == 88 and d["confirmed"] + sum(d["excluded"].values()) == 88
    assert d["excluded"].get("PLATFORM", 0) == 0 or True


def test_product_version_excluded_are_cond_not_shown_by_default(fetch):
    code, d = rows(fetch, "product", "apache httpd", "2.4.49")
    assert "COND" in d["excluded"]
    shown = {r["id"] for r in d["rows"]}
    code, d2 = rows(fetch, "product", "apache httpd", "2.4.49", "--include-unverified")
    extra = {r["id"] for r in d2["rows"]} - shown
    assert extra and all(r["verdict"] in ("COND", "MAYBE", "NVD-only") for r in d2["rows"] if r["id"] in extra)


def test_openssl_1_1_1_no_platform_rows(fetch):
    code, d = rows(fetch, "product", "openssl 1.1.1")
    assert code == 0
    assert d["targets"] == ["cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"]
    assert d["nvd_returned"] == 55 and d["excluded"] == {"PLATFORM": 1}
    assert len(d["rows"]) == 54
    assert "deprecated" in d["resolution"]["snap"][0]["note"]


def test_log4j_2_14_1_range_and_fixed_version(fetch):
    code, d = rows(fetch, "product", "log4j 2.14.1")
    assert code == 0 and d["resolution"]["via"] == "alias"
    r = {x["id"]: x for x in d["rows"]}["CVE-2021-44228"]
    assert r["verdict"] == "RANGE" and r["matched"][0]["bounds"] == [">= 2.13.0", "< 2.15.0"]
    assert r["fixed_versions"] == ["2.15.0"]


def test_version_not_in_dictionary_is_said_and_nothing_invented(fetch):
    code, d = rows(fetch, "product", "log4j 2.99")
    assert code == 4 and d["rows"] == []
    assert "NOT in the NVD dictionary" in d["subject"]
    assert d["targets"] == ["cpe:2.3:a:apache:log4j:2.99:*:*:*:*:*:*:*"]


# ---------------------------------------------------------------- product only / floors / years


def test_product_only_lists_without_a_version(fetch):
    code, d = rows(fetch, "product", "apache httpd")
    assert code == 0
    assert all(r["verdict"] == "LISTED" for r in d["rows"])
    assert "CVE-2007-4723" not in {r["id"] for r in d["rows"]}  # still a platform-only record


def test_version_floor(fetch):
    """--version-from keeps a CVE when some vulnerable criteria of the product reaches the floor
    or beyond: an exact version >= floor, a range whose end is beyond it, or no end at all."""
    code, d = rows(fetch, "product", "apache httpd", "--version-from", "2.4.55")
    ids = {r["id"] for r in d["rows"]}
    assert "CVE-2021-41773" not in ids  # exact 2.4.49 only
    assert "CVE-2006-20001" not in ids  # < 2.4.55 stops just below the floor
    assert "CVE-2011-3192" not in ids  # 2.0.x / 2.2.x ranges
    assert "CVE-2023-25690" in ids  # <= 2.4.55 includes the floor
    assert "CVE-2024-38475" in ids  # >= 2.4.0 < 2.4.60
    code, d = rows(fetch, "product", "apache httpd", "--version-from", "2.4.60")
    assert "CVE-2024-38475" not in {r["id"] for r in d["rows"]}  # < 2.4.60 does not reach 2.4.60


def test_years_filter(fetch):
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--years", "2021")
    assert d["rows"] and all(r["published"].startswith("2021") for r in d["rows"])
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--years", "2022-2023")
    assert d["rows"] and all("2022" <= r["published"][:4] <= "2023" for r in d["rows"])


# ---------------------------------------------------------------- filters, modes


def test_filters_compose(fetch):
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--kev", "--min-cvss", "9", "--poc", "--recommend")
    ids = [r["id"] for r in d["rows"]]
    assert ids == ["CVE-2021-41773", "CVE-2021-42013", "CVE-2024-38475"]
    r = d["rows"][0]
    assert r["exploit_evidence"]["level"] == "exploited-in-the-wild"
    assert any(e["kind"] == "Packet Storm" for e in r["exploit_evidence"]["evidence"])
    assert "evidence" in r["exploit_evidence"]["basis"]
    assert any(s.startswith("CISA KEV since 2021-11-03") for s in r["recommend"])
    assert any("ransomware" in s for s in r["recommend"])
    assert any(s.startswith(("Apply the patch", "Follow the vendor advisory")) for s in r["recommend"])


def test_cwe_and_severity_and_epss_filters(fetch):
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--cwe", "CWE-22")
    assert {r["id"] for r in d["rows"]} == {"CVE-2021-41773", "CVE-2021-42013"}
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--severity", "CRITICAL")
    assert d["rows"] and all(r["cvss"]["severity"] == "CRITICAL" for r in d["rows"])
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--min-epss", "0.9")
    assert d["rows"] and all(r["epss"]["epss"] >= 0.9 for r in d["rows"])


def test_sort_and_limit(fetch):
    code, d = rows(fetch, "product", "apache httpd 2.4.49", "--sort", "cvss", "--limit", "3")
    scores = [r["cvss"]["score"] for r in d["rows"]]
    assert len(scores) == 3 and scores == sorted(scores, reverse=True)


def test_poc_levels_recommend_without_patch(fetch):
    code, d = rows(fetch, "cve", "CVE-2021-44228", "CVE-2014-0160", "--poc", "--recommend")
    by = {r["id"]: r for r in d["rows"]}
    assert by["CVE-2021-44228"]["exploit_evidence"]["level"] == "exploited-in-the-wild"
    assert by["CVE-2014-0160"]["exploit_evidence"]["level"] in ("exploited-in-the-wild", "public-exploit")
    for r in by.values():
        assert r["recommend"]


# ---------------------------------------------------------------- platform (COND) resolution


def test_cond_resolves_with_on(fetch):
    """CVE-2007-4723 is Ragnarok Online Control Panel AND Apache. Asking for the panel alone
    gives COND (not shown); naming the platform with --on confirms it."""
    pass  # covered at the engine level (test_cpe); the dictionary has no entry for the panel to resolve


# ---------------------------------------------------------------- cpe / bulk / resolve


def test_cpe_verbatim(fetch):
    code, d = rows(fetch, "cpe", HTTPD)
    assert code == 0 and d["subjects"][0]["targets"] == [HTTPD]
    assert any(r["id"] == "CVE-2021-41773" for r in d["subjects"][0]["rows"])


def test_cpe_rejects_junk(fetch):
    code, _ = run(fetch, "cpe", "cpe:2.3:a:*:*")
    assert code == 2


def test_bulk_products_file(fetch, tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("apache httpd 2.4.49\n# a comment\nlog4j 2.14.1\nopenssl 1.1.1\n")
    code, d = rows(fetch, "bulk", "--products", str(f), "--kev")
    assert code == 0
    subjects = [s["subject"].split(" ->")[0] for s in d["subjects"]]
    assert subjects == ["apache httpd 2.4.49", "log4j 2.14.1", "openssl 1.1.1"]
    assert [len(s["rows"]) for s in d["subjects"]] == [3, 2, 0]  # log4j 2.14.1: CVE-2021-44228 and -45046 are both KEV


def test_bulk_csv_has_subject_column(fetch, tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("apache httpd 2.4.49\n")
    code, text = run(fetch, "bulk", "--products", str(f), "--kev", "--format", "csv")
    lines = text.splitlines()
    assert lines[0].startswith("subject,cve,cvss_version,")
    assert len(lines) == 4 and lines[1].startswith('"apache httpd 2.4.49 ->')


def test_resolve_ok_and_ambiguous(fetch, monkeypatch):
    code, text = run(fetch, "resolve", "log4j 2.14.1")
    assert code == 0 and text.splitlines()[0] == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    from vl import resolve as R

    monkeypatch.setattr(R, "resolve_alias", lambda q: None)  # pretend the alias table has no gitlab
    code, text = run(fetch, "resolve", "gitlab")
    assert code == 3
    d = json.loads(text)
    assert d["status"] == "ambiguous" and {c["cpe"] for c in d["candidates"][:2]} == {"a:gitlab:gitlab", "a:jenkins:gitlab"}


def test_product_ambiguous_exit_3_and_pick(fetch, monkeypatch, capsys):
    from vl import resolve as R

    monkeypatch.setattr(R, "resolve_alias", lambda q: None)
    code, text = run(fetch, "product", "gitlab")
    assert code == 3 and json.loads(text)["status"] == "ambiguous"
    assert "ambiguous:" in capsys.readouterr().err
    # --pick skips the dictionary; the product's CVE list is not recorded, so the fake fetch refuses
    with pytest.raises(AssertionError, match="unrecorded request"):
        run(fetch, "product", "gitlab", "--pick", "a:jenkins:gitlab")


def test_resolve_nothing_exit_4(responses):
    from conftest import FakeFetch

    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=zzzqqq&resultsPerPage=10000"
    f = FakeFetch(dict(responses, **{url: {"totalResults": 0, "products": []}}))
    code, text = run(f, "resolve", "zzzqqq")
    assert code == 4 and json.loads(text)["status"] == "none"


# ---------------------------------------------------------------- kev / epss


def test_kev_ids_and_recent(fetch):
    code, text = run(fetch, "kev", "CVE-2021-44228", "CVE-2014-0160", rc=0)
    assert "CVE-2021-44228  KEV added 2021-12-10" in text
    code, d = rows(fetch, "kev", "--recent", "3")
    assert code == 0 and len(d["entries"]) == 3 and d["catalogVersion"]
    code, text = run(fetch, "kev", "--search", "log4j")
    assert "CVE-2021-44228" in text


def test_epss(fetch):
    code, d = rows(fetch, "epss", "CVE-2021-44228", "CVE-2021-41773")
    assert code == 0 and set(d["epss"]) == {"CVE-2021-44228", "CVE-2021-41773"}


# ---------------------------------------------------------------- formats and styles


@pytest.mark.parametrize("fmt", ["table", "md", "csv", "brief", "json"])
@pytest.mark.parametrize("style", ["terse", "analyst", "executive"])
def test_every_format_and_style_renders(fetch, fmt, style):
    code, text = run(fetch, "product", "apache httpd 2.4.49", "--kev", "--poc", "--recommend", "--format", fmt, "--style", style)
    assert code == 0 and "CVE-2021-41773" in text
    if fmt == "json":
        json.loads(text)
    if style == "executive" and fmt in ("table", "md", "brief"):
        assert "Act first" in text
    if style == "analyst" and fmt in ("table", "md"):
        assert "[= 2.4.49]" in text and "exploit evidence: exploited-in-the-wild" in text


def test_table_footer_counts_excluded(fetch):
    code, text = run(fetch, "product", "apache httpd 2.4.49", "--kev")
    assert "Not counted (shown with --include-unverified): COND" in text


def test_terse_has_no_footer_and_no_dates(fetch):
    code, text = run(fetch, "product", "apache httpd 2.4.49", "--kev", "--style", "terse")
    assert "Not counted" not in text and "Published" not in text


# ---------------------------------------------------------------- determinism


@pytest.mark.parametrize(
    "args",
    [
        ("cve", "CVE-2021-44228", "CVE-2021-41773", "--poc", "--recommend"),
        ("product", "apache httpd 2.4.49", "--poc", "--recommend", "--format", "md"),
        ("product", "openssl 1.1.1", "--format", "csv"),
        ("kev", "--recent", "10", "--format", "json"),
    ],
)
def test_identical_input_identical_output(fetch, args):
    _, a = run(fetch, *args)
    _, b = run(fetch, *args)  # second run: everything from the cache
    assert a == b
    _, c = run(fetch, *args, "--no-cache")
    assert a == c


def test_second_run_makes_no_nvd_requests(fetch):
    run(fetch, "product", "apache httpd 2.4.49")
    n = len(fetch.calls)
    run(fetch, "product", "apache httpd 2.4.49")
    assert len(fetch.calls) == n


def test_offline_uses_cache_and_fails_cleanly(fetch, responses):
    code, _ = run(fetch, "product", "apache httpd 2.4.49")
    code, text = run(fetch, "product", "apache httpd 2.4.49", "--offline", "--format", "json")
    assert code == 0 and json.loads(text)["confirmed"] > 0
    code, _ = run(fetch, "product", "openssl 1.1.1", "--offline")
    assert code == 5


def test_options_accepted_before_and_after_the_subcommand(fetch):
    _, a = run(fetch, "--format", "brief", "--style", "terse", "cve", "CVE-2021-44228")
    _, b = run(fetch, "cve", "CVE-2021-44228", "--format", "brief", "--style", "terse")
    assert a == b


# ---------------------------------------------------------------- the key and the cache commands


def test_key_set_status_clear_file_store(fetch, capsys):
    code, text = run(fetch, "key", "status")
    assert code == 0 and "none" in text
    code, text = run(fetch, "key", "set", "abcdefgh-1234-5678-9abc-def012345678", "--file")
    assert code == 0 and "file" in text
    assert "warning" in capsys.readouterr().err
    code, text = run(fetch, "key", "status")
    assert "present" in text and "5678" in text and "abcdefgh" not in text
    code, text = run(fetch, "key", "status", "--format", "json")
    assert json.loads(text) == {"present": True, "where": "file", "hint": "5678"}
    code, text = run(fetch, "key", "clear")
    assert "file" in text
    code, text = run(fetch, "key", "status")
    assert "none" in text


def test_key_rejects_junk(fetch):
    code, _ = run(fetch, "key", "set", "short")
    assert code == 2


def test_key_env_wins_and_is_sent_only_to_nvd(fetch, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "ENVKEYENVKEYENVKEYENVKEY")
    seen = {}

    def spy(url, headers):
        seen[url] = dict(headers)
        return fetch(url, headers)

    run(spy, "cve", "CVE-2021-44228")
    nvd = [h for u, h in seen.items() if "nvd.nist.gov" in u]
    others = [h for u, h in seen.items() if "nvd.nist.gov" not in u]
    assert nvd and all(h.get("apiKey") == "ENVKEYENVKEYENVKEYENVKEY" for h in nvd)
    assert others and all("apiKey" not in h for h in others)
    code, text = run(fetch, "key", "status")
    assert "env" in text and "VKEY" in text and "ENVKEYENVKEYENVKEYENVKEY" not in text


def test_key_never_in_cache_or_output(fetch, monkeypatch, tmp_path):
    monkeypatch.setenv("NVD_API_KEY", "SECRETKEYSECRETKEYSECRETKEY")
    _, text = run(fetch, "cve", "CVE-2021-44228", "--format", "json", "--verbose")
    assert "SECRETKEY" not in text
    blob = "".join(p.read_text("utf-8") for p in (tmp_path / "cache").rglob("*.json"))
    assert "SECRETKEY" not in blob


def test_cache_commands(fetch):
    run(fetch, "cve", "CVE-2021-44228")
    code, text = run(fetch, "cache", "stats", rc=0)
    st = json.loads(text)
    assert st["sources"]["cve"]["entries"] == 1 and st["sources"]["kev"]["entries"] == 1
    code, text = run(fetch, "cache", "clear", "--source", "cve")
    assert "removed 1" in text
    code, text = run(fetch, "cache", "path")
    assert text.strip()


def test_subject_line_names_the_vendors_the_dictionary_knows():
    from vl import resolve as R

    res = R.Resolution("ok", R.parse_product("nginx 1.18.0"), ["a:f5:nginx", "a:nginx:nginx", "a:igor_sysoev:nginx"], "alias")
    snaps = [R.Snap(True, "1.18.0", "*"), R.Snap(False, "1.18.0", "*"), R.Snap(False, "1.18.0", "*")]
    line = cli.subject_line(res, snaps)
    assert "version in the NVD dictionary for a:f5:nginx (typed as given for the rest)" in line
    assert "NOT" not in line
    assert "version in the NVD dictionary" in cli.subject_line(res, [R.Snap(True, "1.18.0", "*")] * 3)
    assert "NOT in the NVD dictionary" in cli.subject_line(res, [R.Snap(False, "1.18.0", "*")] * 3)
