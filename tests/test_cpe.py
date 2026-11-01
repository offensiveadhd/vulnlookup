"""The engine: CPE strings, version ordering, criteria matching, whole configurations.

Every vector here is a false positive or false negative somebody could hit. The first block
is the regression set SCAN 0.0 accumulated; the recorded configurations are real NVD records,
trimmed. When a new mismatch is found, it becomes a line here.
"""

from __future__ import annotations

import pytest
from vl import cpe as C

Q = C.QUALIFIERS


def cmp(a, b):
    return C.vcmp(a, b, Q).cmp


def sure(a, b):
    return C.vcmp(a, b, Q).certain


# ---------------------------------------------------------------- version ordering


@pytest.mark.parametrize(
    "a,b,want",
    [
        ("2.4.49", "2.4.50", -1),
        ("2.4", "2.4.0", 0),
        ("2.4.1", "2.4", 1),
        ("10.0", "9.9", 1),
        ("1.0.2k", "1.0.2", 1),
        ("1.0.2k", "1.0.2a", 1),
        ("1.0.2a", "1.0.2", 1),  # patch letter, not alpha
        ("1.0a1", "1.0", -1),  # alpha 1
        ("1.0b2", "1.0a1", 1),
        ("7.4.0-alpha1", "7.4.0", -1),
        ("7.4.0-rc6", "7.4.0-beta4", 1),
        ("7.4.0-rc1", "7.4.0.1", -1),
        ("1.8.0-update_5", "1.8.0", 1),
        ("1.8.0-update_202", "1.8.0-update_5", 1),
        ("9.3p1", "9.3p1", 0),
        ("9.3p2", "9.3p1", 1),
        ("9.3p1", "9.3", 1),  # portable patch, post-release
        ("2.4.49-r1", "2.4.49", 1),
        ("v2.4.49", "2.4.49", 0),
        ("1.02", "1.2", 0),
        ("10.0.17763.1234", "10.0.17763.999", 1),
        ("20240101", "20231231", 1),
        ("4.av4", "4.av3", 1),
        ("6.0-sp1", "6.0", 1),
        ("115.0esr", "115.0", 0),
        ("115.0esr", "115.1", -1),
        ("1.1.1k", "1.1.1", 1),
        ("1.1.1k", "1.1.1l", -1),
        ("3.0.0", "1.1.1w", 1),
    ],
)
def test_order(a, b, want):
    assert cmp(a, b) == want


@pytest.mark.parametrize(
    "a,b,want",
    [
        ("1.0.2k", "1.0.2", True),
        ("7.4.0-rc1", "7.4.0.1", True),
        ("4.av4", "4.1", False),
        ("4.av4", "4", False),
        ("1.0.foo", "1.0.bar", False),
    ],
)
def test_certainty(a, b, want):
    assert sure(a, b) is want


def test_unknown_equal_is_certain():
    assert C.vcmp("4.av4", "4.av4", Q) == C.Cmp(0, True)


def test_norm_update():
    assert C.norm_update("update_5") == C.norm_update("u5") == "update5"
    assert C.norm_update("Service Pack 1") == C.norm_update("sp1") == "sp1"
    assert C.norm_update("a1") == "alpha1"


# ---------------------------------------------------------------- CPE strings


def test_parse_basic():
    p = C.parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert (p.part, p.vendor, p.product, p.version, p.update) == ("a", "apache", "http_server", "2.4.49", "*")


def test_parse_escapes_and_roundtrip():
    s = "cpe:2.3:a:joomla:joomla\\!:3.9.0:*:*:*:*:*:*:*"
    p = C.parse_cpe(s)
    assert p.product == "joomla!"
    assert C.format_cpe(p) == s
    assert C.parse_cpe("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.5:*:*:*:*:*:*:*").product == "notepad++"


def test_format_escapes_typed_value():
    assert C.format_cpe(C.make_cpe("a", "x", "y", "1.0 (beta)")) == "cpe:2.3:a:x:y:1.0\\ \\(beta\\):*:*:*:*:*:*:*"


def test_parse_wildcard_and_short_and_junk():
    assert "version" in C.parse_cpe("cpe:2.3:a:x:y:2.4.*:*:*:*:*:*:*:*").wild
    assert C.parse_cpe("cpe:2.3:o:microsoft:windows_10:1607").other == "*"
    assert C.parse_cpe("not a cpe") is None


def test_prefix_match_string():
    assert C.prefix_match_string(C.make_cpe("a", "openssl", "openssl", "1.1.1")) == "cpe:2.3:a:openssl:openssl:1.1.1"
    assert C.prefix_match_string(C.make_cpe("a", "openssl", "openssl")) == "cpe:2.3:a:openssl:openssl"


# ---------------------------------------------------------------- tri-state attributes


@pytest.mark.parametrize(
    "crit,tgt,want",
    [
        ("*", "sp1", C.T),
        ("sp1", "*", C.U),
        ("-", "-", C.T),
        ("-", "sp1", C.F),
        ("sp1", "sp1", C.T),
        ("sp1", "sp2", C.F),
    ],
)
def test_attr_match(crit, tgt, want):
    assert C.attr_match(crit, tgt) == want


# ---------------------------------------------------------------- criteria

TGT = C.make_cpe("a", "apache", "http_server", "2.4.49")
EXACT = {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "matchCriteriaId": "x"}
RANGE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.7",
    "versionEndIncluding": "2.4.51",
    "matchCriteriaId": "y",
}


def crit(**kw):
    d = {"vulnerable": True, "criteria": kw.pop("c")}
    d.update(kw)
    return d


def test_exact_hit_and_miss():
    assert C.match_criteria(EXACT, TGT).r == C.T
    assert C.match_criteria(EXACT, C.make_cpe("a", "apache", "http_server", "2.4.50")).r == C.F


def test_range_edges():
    assert C.match_criteria(RANGE, TGT).r == C.T
    assert C.match_criteria(RANGE, TGT).how == "range"
    assert C.match_criteria(RANGE, C.make_cpe("a", "apache", "http_server", "2.4.6")).r == C.F
    assert C.match_criteria(RANGE, C.make_cpe("a", "apache", "http_server", "2.4.52")).r == C.F
    assert C.match_criteria(RANGE, TGT).bounds == [">= 2.4.7", "<= 2.4.51"]


def test_end_excluding_openssl_letters():
    cm = crit(c="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", versionStartIncluding="1.0.2", versionEndExcluding="1.0.2k")
    assert C.match_criteria(cm, C.make_cpe("a", "openssl", "openssl", "1.0.2k")).r == C.F
    assert C.match_criteria(cm, C.make_cpe("a", "openssl", "openssl", "1.0.2j")).r == C.T


def test_foreign_and_any():
    assert C.match_criteria(EXACT, C.make_cpe("a", "nginx", "nginx", "1.0")).foreign is True
    assert C.match_criteria(crit(c="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"), TGT).how == "any"


PHP = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"


def php(v, u="*"):
    return C.make_cpe("a", "php", "php", v, u)


def test_prerelease_boundaries_are_unknown_not_guessed():
    assert (
        C.match_criteria(crit(c=PHP, versionStartIncluding="7.4.0", versionEndExcluding="7.4.5"), php("7.4.0", "alpha1")).r == C.U
    )
    assert (
        C.match_criteria(crit(c=PHP, versionStartIncluding="7.3.0", versionEndExcluding="7.4.0"), php("7.4.0", "alpha1")).r == C.U
    )
    assert (
        C.match_criteria(crit(c=PHP, versionStartIncluding="7.3.0", versionEndExcluding="7.4.5"), php("7.4.0", "alpha1")).r == C.T
    )
    assert (
        C.match_criteria(crit(c=PHP, versionStartIncluding="8.0.0", versionEndExcluding="8.0.10"), php("7.4.0", "alpha1")).r
        == C.F
    )
    m = C.match_criteria(crit(c=PHP, versionStartIncluding="7.4.0", versionEndExcluding="7.4.23"), php("7.4.0", "alpha1"))
    assert m.r == C.U and "inside as 7.4.0" in m.why


def test_update_field_rules():
    assert C.match_criteria(crit(c="cpe:2.3:a:php:php:7.4.0:alpha1:*:*:*:*:*:*"), php("7.4.0")).r == C.U
    assert C.match_criteria(crit(c="cpe:2.3:a:php:php:7.4.0:-:*:*:*:*:*:*"), php("7.4.0")).r == C.T
    assert C.match_criteria(crit(c="cpe:2.3:a:php:php:7.4.0:-:*:*:*:*:*:*"), php("7.4.0", "alpha1")).r == C.F
    assert (
        C.match_criteria(
            crit(c="cpe:2.3:a:oracle:jdk:1.8.0:update_5:*:*:*:*:*:*"), C.make_cpe("a", "oracle", "jdk", "1.8.0", "u5")
        ).r
        == C.T
    )
    assert (
        C.match_criteria(
            crit(c="cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", versionStartIncluding="1.8.0", versionEndExcluding="1.9.0"),
            C.make_cpe("a", "oracle", "jdk", "1.8.0", "update_5"),
        ).r
        == C.T
    )


def test_uncertain_is_unknown_and_target_sw_is_a_note():
    assert (
        C.match_criteria(crit(c="cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", versionEndExcluding="4.1"), C.make_cpe("a", "x", "y", "4.av4")).r
        == C.U
    )
    m = C.match_criteria(
        crit(c="cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:node.js:*:*"), C.make_cpe("a", "jquery", "jquery", "3.4.1")
    )
    assert m.r == C.T and m.notes == ["target_sw=node.js"]


# ---------------------------------------------------------------- whole configurations (recorded, trimmed)

RAGNAROK = {
    "id": "CVE-2007-4723",
    "configurations": [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:ragnarok_online_control_panel_project:ragnarok_online_control_panel:4.3.4a:*:*:*:*:*:*:*",
                            "matchCriteriaId": "12F2E1BB",
                        }
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                            "matchCriteriaId": "5A6CD1F4",
                        }
                    ],
                },
            ],
        }
    ],
}

RAG = C.make_cpe("a", "ragnarok_online_control_panel_project", "ragnarok_online_control_panel", "4.3.4a")


def test_platform_only_mention_is_not_a_hit():
    v = C.eval_cve(RAGNAROK, [TGT])
    assert v.verdict == "PLATFORM" and not v.confirmed


def test_vulnerable_side_is_conditional_and_lists_platform():
    v = C.eval_cve(RAGNAROK, [RAG])
    assert v.verdict == "COND"
    assert v.platforms == ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"]


def test_cond_resolves_when_platform_given():
    v = C.eval_cve(RAGNAROK, [RAG, C.make_cpe("a", "apache", "http_server", "2.2.0")])
    assert v.verdict == "EXACT" and v.confirmed


LOG4J = {
    "id": "CVE-2021-44228",
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.0.1",
                            "versionEndExcluding": "2.3.1",
                            "matchCriteriaId": "A",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.4.0",
                            "versionEndExcluding": "2.12.2",
                            "matchCriteriaId": "B",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.13.0",
                            "versionEndExcluding": "2.15.0",
                            "matchCriteriaId": "C",
                        },
                        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*", "matchCriteriaId": "D"},
                        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", "matchCriteriaId": "E"},
                    ],
                }
            ]
        }
    ],
}


def l4j(v, u="*"):
    return C.make_cpe("a", "apache", "log4j", v, u)


@pytest.mark.parametrize(
    "version,want",
    [
        ("2.14.1", "RANGE"),
        ("2.15.0", "NONE"),
        ("2.3.1", "NONE"),
        ("2.3.0", "RANGE"),
        ("2.12.2", "NONE"),
        ("2.12.1", "RANGE"),
        ("2.0.1", "RANGE"),
        ("1.2.17", "NONE"),
        ("2.17.1", "NONE"),
    ],
)
def test_log4shell_ranges(version, want):
    v = C.eval_cve(LOG4J, [l4j(version)])
    assert v.verdict == want


def test_log4shell_names_the_node_and_bounds():
    v = C.eval_cve(LOG4J, [l4j("2.14.1")])
    assert [m["matchCriteriaId"] for m in v.explain()] == ["C"]
    assert v.explain()[0]["bounds"] == [">= 2.13.0", "< 2.15.0"]


def test_log4shell_2_0_release_vs_beta():
    assert C.eval_cve(LOG4J, [l4j("2.0")]).verdict == "EXACT"  # 2.0:- matches a plain 2.0
    assert C.eval_cve(LOG4J, [l4j("2.0", "beta9")]).verdict == "EXACT"
    assert C.eval_cve(LOG4J, [l4j("2.0", "beta8")]).verdict == "NONE"


def test_fixed_versions_from_end_excluding():
    assert C.fixed_versions(LOG4J, l4j("2.14.1")) == ["2.15.0"]
    assert C.fixed_versions(LOG4J, l4j("2.3.0")) == ["2.3.1"]


NEGATED = {
    "id": "X",
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", "matchCriteriaId": "N"}],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:v:p:2.0:*:*:*:*:*:*:*", "matchCriteriaId": "P"}],
                },
            ]
        }
    ],
}


def test_negated_node_never_produces_a_hit():
    assert C.eval_cve(NEGATED, [C.make_cpe("a", "v", "p", "1.0")]).verdict == "NONE"
    assert C.eval_cve(NEGATED, [C.make_cpe("a", "v", "p", "2.0")]).verdict == "EXACT"


def test_no_version_is_unknown_not_a_hit():
    v = C.eval_cve(LOG4J, [l4j("*")])
    assert v.verdict == "MAYBE" and all(h.res.why == "version unspecified" for h in v.matched)


def test_and_with_failing_sibling_is_not_a_hit():
    cfg = {
        "id": "Y",
        "configurations": [
            {
                "operator": "AND",
                "nodes": [
                    {"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}]},
                    {"operator": "OR", "cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:o:os:x:2.0:*:*:*:*:*:*:*"}]},
                ],
            }
        ],
    }
    assert C.eval_cve(cfg, [C.make_cpe("a", "v", "p", "1.0"), C.make_cpe("o", "os", "x", "3.0")]).verdict == "NONE"
    assert C.eval_cve(cfg, [C.make_cpe("a", "v", "p", "1.0"), C.make_cpe("o", "os", "x", "2.0")]).verdict == "EXACT"
    assert C.eval_cve(cfg, [C.make_cpe("a", "v", "p", "1.0")]).verdict == "COND"
