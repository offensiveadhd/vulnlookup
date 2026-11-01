"""CPE 2.3 strings, version ordering and configuration matching.

A port of the engine that SCAN 0.0 (offensiveadhd-scan0) proved in the browser, kept
deterministic and dependency-free:

* formatted-string binding (NISTIR 7695 6.2): ``\\``-escaping, ``*`` = ANY, ``-`` = NA,
  ``*`` / ``?`` wildcards inside a component;
* a version comparator that returns *how sure it is*: numbers numerically, qualifier words by
  rank (alpha < beta < rc < release < patch < sp < update), a single letter glued to digits
  is a patch letter (``1.0.2k``) unless digits follow (``1.0a1`` = alpha 1), and anything that
  rests on a word it cannot order is reported ``certain=False`` so the caller never guesses;
* tri-state attribute matching (NISTIR 7696): a criteria ``*`` matches, a target the user did
  not specify against a specific requirement is *unknown*, not *false*;
* a walk over the NVD ``configurations`` tree that names the node that matched and why, and
  tells a vulnerable product apart from the platform it runs on (``vulnerable: false``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

ATTRS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
ANY = "*"
NA = "-"

# tri-state
T, U, F = 1, 0, -1

# Version qualifiers, rank relative to a plain release (0). Negative = pre-release,
# positive = post-release. From scan0's catalog; extend in references/aliases.json.
QUALIFIERS: dict[str, int] = {
    "dev": -60,
    "nightly": -55,
    "snapshot": -50,
    "canary": -50,
    "pre": -45,
    "prerelease": -45,
    "preview": -45,
    "alpha": -40,
    "a": -40,
    "beta": -30,
    "b": -30,
    "milestone": -20,
    "m": -20,
    "rc": -10,
    "cr": -10,
    "release": 0,
    "final": 0,
    "ga": 0,
    "stable": 0,
    "esr": 0,
    "lts": 0,
    "ltsc": 0,
    "x": 0,
    "build": 5,
    "p": 10,
    "pl": 10,
    "patch": 10,
    "r": 10,
    "rev": 10,
    "revision": 10,
    "hotfix": 10,
    "fix": 10,
    "sp": 20,
    "servicepack": 20,
    "service_pack": 20,
    "u": 30,
    "update": 30,
    "upd": 30,
    "cu": 30,
}


# --------------------------------------------------------------------------- strings


def unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def escape(s: str) -> str:
    s = str(s)
    if s in (ANY, NA):
        return s
    return re.sub(r"[^A-Za-z0-9_.\-]", lambda m: "\\" + m.group(0), s)


def _wild_re(raw: str) -> re.Pattern[str]:
    out = "^"
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\":
            i += 1
            out += re.escape(raw[i]) if i < len(raw) else ""
        elif c == "*":
            out += ".*"
        elif c == "?":
            out += "."
        else:
            out += re.escape(c)
        i += 1
    return re.compile(out + "$", re.IGNORECASE)


@dataclass
class Cpe:
    """A parsed CPE 2.3 name. Values are lower-cased and unescaped; ``*`` and ``-`` kept."""

    part: str = ANY
    vendor: str = ANY
    product: str = ANY
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY
    wild: dict[str, re.Pattern[str]] = field(default_factory=dict, repr=False, compare=False)

    def get(self, attr: str) -> str:
        return getattr(self, attr)

    def short(self) -> str:
        return f"{self.part}:{self.vendor}:{self.product}"

    def __str__(self) -> str:
        return format_cpe(self)


def parse_cpe(text: str) -> Cpe | None:
    parts = re.split(r"(?<!\\):", str(text).strip())
    if len(parts) < 3 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    comps = parts[2:13]
    while len(comps) < 11:
        comps.append(ANY)
    o = Cpe()
    for attr, raw in zip(ATTRS, comps):
        raw = raw or ANY
        if raw == ANY:
            val = ANY
        elif raw == NA:
            val = NA
        else:
            val = unescape(raw).lower()
        setattr(o, attr, val)
        if raw != ANY and re.search(r"(^|[^\\])[*?]", raw):
            o.wild[attr] = _wild_re(raw)
    return o


def format_cpe(o: Cpe) -> str:
    return "cpe:2.3:" + ":".join(escape(getattr(o, a) or ANY) for a in ATTRS)


def make_cpe(part: str, vendor: str, product: str, version: str = ANY, update: str = ANY, **extra: str) -> Cpe:
    o = Cpe(
        part=part or "a",
        vendor=vendor.lower(),
        product=product.lower(),
        version=(version or ANY).lower(),
        update=(update or ANY).lower(),
    )
    for k, v in extra.items():
        if k in ATTRS and v:
            setattr(o, k, v.lower())
    return o


def prefix_match_string(o: Cpe) -> str:
    """The shortest match string that still names what the user said (for the NVD query)."""
    comps = [getattr(o, a) for a in ATTRS]
    while len(comps) > 3 and comps[-1] == ANY:
        comps.pop()
    return "cpe:2.3:" + ":".join(escape(c) for c in comps)


# --------------------------------------------------------------------------- versions


@dataclass
class _Tok:
    num: bool
    v: str
    att: bool = False
    rank: int | None = None
    patch: bool = False


def vtokens(v: str, q: dict[str, int] | None = None) -> list[_Tok]:
    q = QUALIFIERS if q is None else q
    s = str(v).lower().strip()
    s = re.sub(r"^version\s*", "", s)
    s = re.sub(r"^v(?=\d)", "", s)
    out: list[_Tok] = []
    for piece in [p for p in re.split(r"[.\-_+~\s:,/\\]+", s) if p]:
        ms = re.findall(r"\d+|[a-z]+", piece)
        for i, t in enumerate(ms):
            if t[0].isdigit():
                out.append(_Tok(True, re.sub(r"^0+(?=\d)", "", t)))
                continue
            att = i > 0
            last = i == len(ms) - 1
            nxt = ms[i + 1] if i + 1 < len(ms) else None
            rank: int | None = None
            if len(t) == 1 and att:
                if last:
                    out.append(_Tok(False, t, att, 1, True))
                    continue
                if nxt and nxt[0].isdigit() and t in q:
                    rank = q[t]
            elif t in q:
                rank = q[t]
            elif att and last and len(t) <= 2:
                rank = 1
            out.append(_Tok(False, t, att, rank))
    return out


def _cmp_num(a: str, b: str) -> int:
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return -1 if a < b else (1 if a > b else 0)


@dataclass(frozen=True)
class Cmp:
    cmp: int
    certain: bool


def vcmp(a: str, b: str, q: dict[str, int] | None = None) -> Cmp:
    """Order two version strings. ``certain`` is False when the answer rests on a word the
    qualifier table does not know; callers turn that into *unknown*, never a guess."""
    A, B = vtokens(a, q), vtokens(b, q)
    certain = True
    for i in range(max(len(A), len(B))):
        x = A[i] if i < len(A) else None
        y = B[i] if i < len(B) else None
        if x is None or y is None:
            rest = (A if x else B)[i:]
            sign = 1 if x else -1
            if all(t.num and t.v == "0" for t in rest):
                return Cmp(0, certain)
            t = rest[0]
            if t.num:
                return Cmp(sign, certain)
            if t.rank is not None:
                return Cmp(-sign if t.rank < 0 else (sign if t.rank > 0 else 0), certain)
            return Cmp(sign, False)
        if x.num and y.num:
            c = _cmp_num(x.v, y.v)
            if c:
                return Cmp(c, certain)
            continue
        if not x.num and not y.num:
            if x.v == y.v:
                continue
            if x.rank is not None and y.rank is not None:
                if x.rank == y.rank:
                    if x.patch and y.patch:
                        return Cmp(-1 if x.v < y.v else 1, certain)
                    continue
                return Cmp(-1 if x.rank < y.rank else 1, certain)
            ex = x.rank
            ey = y.rank
            if ex is not None or ey is not None:
                known = ex if ex is not None else ey
                sign = 1 if ex is not None else -1
                return Cmp(-sign if known < 0 else sign, False)  # type: ignore[operator]
            return Cmp(-1 if x.v < y.v else 1, False)
        word = y if x.num else x
        sign = 1 if x.num else -1
        return Cmp(sign, word.rank is not None and word.rank < 0)
    return Cmp(0, certain)


def norm_update(s: str) -> str:
    """``sp1`` / ``SP-1`` / ``service_pack_1`` -> ``sp1``; ``u5`` / ``update_5`` -> ``update5``;
    ``a1`` -> ``alpha1``."""
    s = re.sub(r"[-_.\s]", "", str(s).lower())
    s = re.sub(r"^servicepack", "sp", s)
    s = re.sub(r"^releasecandidate", "rc", s)
    s = re.sub(r"^u(?=\d)", "update", s)
    s = re.sub(r"^upd(?=\d)", "update", s)
    s = re.sub(r"^a(?=\d)", "alpha", s)
    s = re.sub(r"^b(?=\d)", "beta", s)
    return s


def effective_version(t: Cpe, q: dict[str, int] | None = None) -> str:
    """The version a range is measured against: 7.4.0 with update alpha1 sits before 7.4.0."""
    q = QUALIFIERS if q is None else q
    if not t.update or t.update in (ANY, NA):
        return t.version
    m = re.match(r"^[a-z]+", t.update)
    if m and m.group(0) in q:
        return t.version + "-" + t.update
    return t.version


# --------------------------------------------------------------------------- matching


def attr_match(crit: str, tgt: str, crit_re: re.Pattern[str] | None = None) -> int:
    if crit == ANY:
        return T
    if tgt == ANY:
        return U
    if crit == NA:
        return T if tgt == NA else F
    if tgt == NA:
        return F
    if crit_re is not None:
        return T if crit_re.search(tgt) else F
    return T if crit == tgt else F


@dataclass
class VersionMatch:
    r: int
    how: str  # exact | range | any | wild
    certain: bool
    bounds: list[str]
    why: str = ""


RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")


def match_version(cm: dict[str, Any], crit: Cpe, tgt: Cpe, q: dict[str, int] | None = None) -> VersionMatch:
    q = QUALIFIERS if q is None else q
    has_range = any(cm.get(k) for k in RANGE_KEYS)
    if tgt.version == ANY:
        how = "range" if has_range else ("any" if crit.version == ANY else "exact")
        return VersionMatch(U, how, True, [], "version unspecified")
    if crit.version == NA:
        return VersionMatch(T if tgt.version == NA else F, "exact", True, [])
    if crit.version != ANY:
        if "version" in crit.wild:
            ok = bool(crit.wild["version"].search(tgt.version))
            return VersionMatch(T if ok else F, "wild", True, ["~ " + crit.version])
        c = vcmp(crit.version, tgt.version, q)
        if c.cmp != 0:
            return VersionMatch(
                F if c.certain else U,
                "exact",
                c.certain,
                ["= " + crit.version],
                "" if c.certain else f"cannot tell {tgt.version} from {crit.version}",
            )
        if not has_range:
            return VersionMatch(T, "exact", True, ["= " + crit.version])
    if not has_range:
        return VersionMatch(T, "any", True, ["any version"])

    eff = effective_version(tgt, q)
    certain = True
    bounds: list[str] = []
    whys: list[str] = []

    def in_range(v: str) -> bool:
        nonlocal certain
        ok = True
        for key, test, label in (
            ("versionStartIncluding", lambda c: c >= 0, ">="),
            ("versionStartExcluding", lambda c: c > 0, ">"),
            ("versionEndIncluding", lambda c: c <= 0, "<="),
            ("versionEndExcluding", lambda c: c < 0, "<"),
        ):
            bound = cm.get(key)
            if not bound:
                continue
            c = vcmp(v, bound, q)
            if v == eff:
                bounds.append(f"{label} {bound}")
            if not c.certain:
                certain = False
                whys.append(f"cannot order {v} against {bound}")
            if not test(c.cmp):
                ok = False
        return ok

    r = T if in_range(eff) else F
    if eff != tgt.version:
        plain = T if in_range(tgt.version) else F
        if plain != r:
            r = U
            whys.append(
                f"{tgt.version} {tgt.update} is {'inside' if plain == T else 'outside'} as {tgt.version} "
                f"and {'outside' if plain == T else 'inside'} as a pre-release of it"
            )
    if not certain:
        r = U
    return VersionMatch(r, "range", certain, bounds, "; ".join(whys))


@dataclass
class CriteriaMatch:
    r: int
    foreign: bool = False
    how: str = ""
    certain: bool = True
    bounds: list[str] = field(default_factory=list)
    why: str = ""
    notes: list[str] = field(default_factory=list)
    target: Cpe | None = None


def match_criteria(cm: dict[str, Any], tgt: Cpe, q: dict[str, int] | None = None) -> CriteriaMatch:
    """One ``cpeMatch`` entry against one target. ``foreign`` = a different product entirely
    (the platform in a running-on configuration), which is unknown, not false."""
    q = QUALIFIERS if q is None else q
    crit = parse_cpe(cm.get("criteria", ""))
    if crit is None:
        return CriteriaMatch(F, foreign=True)
    for a in ("part", "vendor", "product"):
        if attr_match(crit.get(a), tgt.get(a), crit.wild.get(a)) != T:
            return CriteriaMatch(F, foreign=True)
    v = match_version(cm, crit, tgt, q)
    if v.r == F:
        return CriteriaMatch(F, False, v.how, v.certain, v.bounds, f"version {tgt.version} is outside {' '.join(v.bounds)}")
    res = CriteriaMatch(v.r, False, v.how, v.certain, list(v.bounds), v.why if v.r == U else "")
    cu, tu = crit.update, tgt.update
    if cu != ANY:
        if tu == ANY:
            if cu != NA:
                res.r = U
                res.why = res.why or f"update unspecified; the record wants update {cu}"
                res.bounds.append("update " + cu)
        else:
            if cu == NA:
                um = T if tu == NA else F
            elif "update" in crit.wild:
                um = T if crit.wild["update"].search(tu) else F
            else:
                um = T if norm_update(cu) == norm_update(tu) else F
            if um == F:
                return CriteriaMatch(F, False, v.how, v.certain, v.bounds, f"update {tu} is not {cu}")
            res.bounds.append("update " + cu)
    for a in ("edition", "language", "sw_edition", "target_sw", "target_hw", "other"):
        ca = crit.get(a)
        if ca == ANY:
            continue
        ta = tgt.get(a)
        if ta != ANY:
            if attr_match(ca, ta, crit.wild.get(a)) == F:
                return CriteriaMatch(F, False, v.how, v.certain, v.bounds, f"{a} {ta} is not {ca}")
        else:
            res.notes.append(f"{a}={ca}")
    return res


RANK = {"EXACT": 7, "RANGE": 6, "ANY": 5, "COND": 4, "MAYBE": 3, "PLATFORM": 2, "NONE": 0}
CONFIRMED = ("EXACT", "RANGE", "ANY")


@dataclass
class Hit:
    cm: dict[str, Any]
    res: CriteriaMatch
    vulnerable: bool


@dataclass
class NodeEval:
    val: int
    hits: list[Hit]
    negate: bool
    criteria: list[str]


def eval_node(node: dict[str, Any], targets: list[Cpe], q: dict[str, int] | None = None) -> NodeEval:
    hits: list[Hit] = []
    any_t = any_u = any_f = False
    all_foreign = True
    for cm in node.get("cpeMatch") or []:
        best: CriteriaMatch | None = None
        for t in targets:
            r = match_criteria(cm, t, q)
            if best is None or r.r > best.r or (r.r == best.r and not r.foreign and best.foreign):
                r.target = t
                best = r
        if best is None:
            continue
        if not best.foreign:
            all_foreign = False
        if best.r == T:
            any_t = True
        elif best.r == U:
            any_u = True
        elif not best.foreign:
            any_f = True
        if best.r != F:
            hits.append(Hit(cm, best, cm.get("vulnerable", True) is not False))
    op = (node.get("operator") or "OR").upper()
    if all_foreign:
        val = U
    elif op == "AND":
        val = (F if any_f else U) if (any_f or any_u) else T
    else:
        val = T if any_t else (U if any_u else F)
    if node.get("negate"):
        val = F if val == T else (T if val == F else U)
    return NodeEval(val, hits, bool(node.get("negate")), [c.get("criteria", "") for c in node.get("cpeMatch") or []])


@dataclass
class Verdict:
    verdict: str = "NONE"
    rank: int = 0
    matched: list[Hit] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    why: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.verdict in CONFIRMED

    def explain(self) -> list[dict[str, Any]]:
        out = []
        for h in self.matched:
            out.append(
                {
                    "criteria": h.cm.get("criteria"),
                    "matchCriteriaId": h.cm.get("matchCriteriaId"),
                    "vulnerable": h.vulnerable,
                    "how": h.res.how,
                    "bounds": list(h.res.bounds),
                    "why": h.res.why,
                    "notes": list(h.res.notes),
                }
            )
        return out


def eval_cve(cve: dict[str, Any], targets: list[Cpe], q: dict[str, int] | None = None) -> Verdict:
    """The verdict for one CVE record against the targets: walk every configuration, the best
    hit wins, every equally-ranked distinct node is kept so the output can show them all."""
    best = Verdict()

    def consider(verdict: str, hit: Hit, platforms: list[str]) -> None:
        rk = RANK[verdict]
        if rk > best.rank:
            best.verdict, best.rank, best.matched = verdict, rk, [hit]
            best.platforms = list(platforms)
            best.why = hit.res.why or ""
            best.notes = list(hit.res.notes)
        elif (
            rk == best.rank
            and rk > 0
            and not any(h.cm.get("matchCriteriaId") == hit.cm.get("matchCriteriaId") for h in best.matched)
        ):
            best.matched.append(hit)

    for cfg in cve.get("configurations") or []:
        nodes = [eval_node(n, targets, q) for n in cfg.get("nodes") or []]
        op = (cfg.get("operator") or "OR").upper()
        for n in nodes:
            if n.negate:
                continue  # a negated node names what is NOT affected
            for h in n.hits:
                if not h.vulnerable:
                    consider("PLATFORM", h, [])
                    continue
                if h.res.r == U:
                    verdict = "MAYBE"
                elif h.res.how == "exact":
                    verdict = "EXACT"
                elif h.res.how == "any":
                    verdict = "ANY"
                else:
                    verdict = "RANGE"
                platforms: list[str] = []
                if op == "AND":
                    others = [m for m in nodes if m is not n]
                    if any(m.val == F for m in others):
                        continue
                    unknown = [m for m in others if m.val == U]
                    if unknown:
                        platforms = [c for m in unknown for c in m.criteria]
                        if verdict != "MAYBE":
                            verdict = "COND"
                consider(verdict, h, platforms)
    return best


def fixed_versions(cve: dict[str, Any], target: Cpe, q: dict[str, int] | None = None) -> list[str]:
    """Versions implied fixed for the target's product: every ``versionEndExcluding`` on a
    vulnerable node of that product whose range the target satisfies (sorted, unique)."""
    out: set[str] = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            if node.get("negate"):
                continue
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable") is False:
                    continue
                crit = parse_cpe(cm.get("criteria", ""))
                if crit is None or crit.vendor != target.vendor or crit.product != target.product:
                    continue
                end = cm.get("versionEndExcluding")
                if end and match_criteria(cm, target, q).r != F:
                    out.add(end)
    return sorted(out, key=lambda v: [(t.num, int(t.v) if t.num else t.v) for t in vtokens(v)])
