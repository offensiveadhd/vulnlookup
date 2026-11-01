"""Query parsing, the alias table, the dictionary ranking and the ambiguity decision."""

from __future__ import annotations

import json

import pytest
from vl import cpe as C
from vl import resolve as R
from vl.cache import Cache
from vl.http import Client
from vl.sources import Sources


@pytest.mark.parametrize(
    "text,version,want",
    [
        ("apache httpd 2.4.49", None, ("apache httpd", "2.4.49", "*")),
        ("apache httpd", "2.4.49", ("apache httpd", "2.4.49", "*")),
        ("nginx/1.18.0", None, ("nginx", "1.18.0", "*")),
        ("Server: Apache/2.4.49 (Ubuntu)", None, ("apache", "2.4.49", "*")),
        ("php 7.4.0 alpha1", None, ("php", "7.4.0", "alpha1")),
        ("php 7.4.0alpha1", None, ("php", "7.4.0", "alpha1")),
        ("jdk 1.8.0 update 5", None, ("jdk", "1.8.0", "update_5")),
        ("windows 7 sp1", None, ("windows", "7", "sp1")),
        ("openssl 1.1.1k", None, ("openssl", "1.1.1k", "*")),
        ("openssh 9.3p1", None, ("openssh", "9.3", "p1")),
        ("openssl", None, ("openssl", "*", "*")),
        ("log4j v2.14.1", None, ("log4j", "2.14.1", "*")),
        ("Apache HTTP Server version 2.4.49", None, ("apache http server", "2.4.49", "*")),
    ],
)
def test_parse_product(text, version, want):
    q = R.parse_product(text, version)
    assert (q.text, q.version, q.update) == want


def test_alias_hits_longest_form_and_lists_every_vendor():
    res = R.resolve_alias(R.parse_product("nginx 1.18.0"))
    assert res is not None and res.status == "ok" and res.via == "alias"
    assert res.pairs == ["a:f5:nginx", "a:nginx:nginx", "a:igor_sysoev:nginx"]
    assert [str(t) for t in res.targets()][0] == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"


def test_alias_family_windows_10():
    res = R.resolve_alias(R.parse_product("windows 10 1809"))
    assert res is not None
    assert res.pairs == ["o:microsoft:windows_10"]
    assert res.family == ["o:microsoft:windows_10_1809"]
    assert [str(t) for t in res.targets()] == [
        "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*",  # the family product carries its own build numbers
    ]


def test_alias_miss_is_none():
    assert R.resolve_alias(R.parse_product("some unknown thing 1.0")) is None


def groups(responses, keyword):
    url = next(u for u in responses if f"keywordSearch={keyword}" in u.replace("+", " ").replace("%20", " "))
    from vl.sources import slim_cpe

    return [slim_cpe(p["cpe"]) for p in responses[url]["products"]]


def test_rank_log4j_exact_token_beats_log4js(responses):
    cands = R.rank_groups(R.parse_product("log4j"), groups(responses, "log4j"))
    assert cands[0].cpe == "a:apache:log4j" and cands[0].confidence >= 0.95
    assert all(c.confidence < 0.95 for c in cands[1:])
    assert R.decide(R.parse_product("log4j"), cands).status == "ok"


def test_rank_struts_unambiguous(responses):
    cands = R.rank_groups(R.parse_product("struts 2.3.5"), groups(responses, "struts"))
    assert R.decide(R.parse_product("struts 2.3.5"), cands).pairs == ["a:apache:struts"]


def test_rank_gitlab_is_ambiguous_without_the_alias(responses):
    """gitlab:gitlab and jenkins:gitlab both have the product name 'gitlab': two exact matches
    is not an answer, it is a question. (The alias table settles it in real use.)"""
    cands = R.rank_groups(R.parse_product("gitlab"), groups(responses, "gitlab"))
    exact = [c.cpe for c in cands if c.confidence >= 0.95]
    assert "a:gitlab:gitlab" in exact and "a:jenkins:gitlab" in exact
    res = R.decide(R.parse_product("gitlab"), cands)
    assert res.status == "ambiguous" and len(res.candidates) >= 2
    assert all(c.reason for c in res.candidates)


def test_rank_vendor_plus_product_settles_it(responses):
    cands = R.rank_groups(R.parse_product("jenkins gitlab"), groups(responses, "gitlab"))
    assert cands[0].cpe == "a:jenkins:gitlab"
    assert R.decide(R.parse_product("jenkins gitlab"), cands).pairs == ["a:jenkins:gitlab"]


def test_rank_exchange_server(responses):
    cands = R.rank_groups(R.parse_product("exchange server"), groups(responses, "exchange"))
    assert R.decide(R.parse_product("exchange server"), cands).pairs == ["a:microsoft:exchange_server"]


def test_rank_nothing_matches():
    assert R.decide(R.parse_product("zzz"), R.rank_groups(R.parse_product("zzz"), [])).status == "none"


def make_sources(tmp_path, fetch) -> Sources:
    cache = Cache(tmp_path / "c")
    return Sources(Client(cache.root, None, fetch=fetch), cache)


def test_snap_exact_entry(tmp_path, fetch):
    src = make_sources(tmp_path, fetch)
    s = R.snap_version("a:apache:http_server", R.parse_product("apache httpd 2.4.49"), src)
    assert s.in_dictionary and s.version == "2.4.49" and s.update == "*"
    assert s.cpe_name == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_snap_follows_deprecated_to_dash_and_keeps_update_any(tmp_path, fetch):
    """openssl:openssl:1.1.1:* is deprecated by 1.1.1:-; the query must not end up asking
    only for criteria with a '-' update (that hid 53 of 55 CVEs in development)."""
    src = make_sources(tmp_path, fetch)
    s = R.snap_version("a:openssl:openssl", R.parse_product("openssl 1.1.1"), src)
    assert s.in_dictionary and s.version == "1.1.1" and s.update == "*"
    assert "deprecated" in s.note


def test_snap_version_not_in_dictionary_is_kept_as_typed(tmp_path, fetch):
    src = make_sources(tmp_path, fetch)
    s = R.snap_version("a:apache:log4j", R.parse_product("log4j 2.99"), src)
    assert not s.in_dictionary and s.version == "2.99" and "not in the NVD dictionary" in s.note


def test_snap_update_spelling(tmp_path, fetch):
    src = make_sources(tmp_path, fetch)
    s = R.snap_version("a:php:php", R.parse_product("php 7.4.0 alpha1"), src)
    assert s.in_dictionary and s.update == "alpha1"


def test_aliases_file_is_well_formed():
    data = json.loads((R.REFERENCES / "aliases.json").read_text("utf-8"))
    seen: dict[str, str] = {}
    for a in data["aliases"]:
        assert a["q"] and a["cpe"]
        for pair in a["cpe"]:
            part, vendor, product = pair.split(":")
            assert part in ("a", "o", "h") and vendor and product
        for nf in {R.norm_text(form) for form in a["q"]}:
            assert nf not in seen, f"{nf!r} claimed by {seen[nf]} and {a['cpe']}"
            seen[nf] = str(a["cpe"])
    assert data["qualifiers"]["alpha"] < data["qualifiers"]["rc"] < data["qualifiers"]["release"] == 0 < data["qualifiers"]["sp"]
    assert C.QUALIFIERS["alpha"] == -40


def test_snap_does_not_follow_a_platform_specific_replacement():
    """windows_10:1809:* is deprecated by an arm64 edition; adopting it would restrict the query."""
    entries = [
        {
            "cpeName": "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*",
            "deprecated": True,
            "deprecatedBy": ["cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:arm64:*"],
            "title": "Windows 10 1809",
        },
    ]
    s = R.snap_version("o:microsoft:windows_10", R.parse_product("windows 10 1809"), None, entries)
    assert s.in_dictionary and s.version == "1809" and s.update == "*"
    assert s.cpe_name == "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*" and "platform" in s.note
