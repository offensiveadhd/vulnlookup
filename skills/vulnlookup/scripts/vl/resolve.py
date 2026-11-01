"""From what a person typed to a CPE the NVD knows, with a verification flow.

1. Parse ``"apache httpd 2.4.49"`` into a product text, a version and an update field.
2. The alias table (``references/aliases.json``) first: zero requests, every pair verified.
3. Otherwise the NVD CPE dictionary (``keywordSearch``), grouped by ``part:vendor:product`` and
   ranked. One answer is returned only when it is unambiguous: an exact product-token match
   with no equally exact rival. Anything else is a list of candidates with a confidence and a
   reason, and the caller (the model, or the person) picks.
4. The version is looked up in the dictionary (``cpeMatchString``); when the dictionary spells
   it differently (``u5`` -> ``update_5``) that spelling is used, when a deprecated entry points
   at a replacement the replacement is used, and when it is not there at all the typed version
   is kept as typed and flagged: only range criteria can then catch it. A version is never
   invented.
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import cpe as C

REFERENCES = Path(__file__).resolve().parents[2] / "references"

_ALIASES: dict[str, Any] | None = None


def aliases() -> dict[str, Any]:
    global _ALIASES
    if _ALIASES is None:
        with (REFERENCES / "aliases.json").open("r", encoding="utf-8") as fh:
            _ALIASES = json.load(fh)
        C.QUALIFIERS.update(_ALIASES.get("qualifiers", {}))
    return _ALIASES


def norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9+]+", " ", str(s).lower())).strip()


VERSION_RE = re.compile(r"^\d[\w.\-+~]*$", re.IGNORECASE)
UPD_WORDS = "alpha|beta|rc|pre|preview|dev|snapshot|milestone|sp|update|upd|u|p|patch|hotfix|build|ga|final|release|esr|cu"
UPD_RE = re.compile(rf"^({UPD_WORDS})[-_.]?\d*$", re.IGNORECASE)
GLUED_RE = re.compile(rf"^(\d[\d.]*?)[-_.]?((?:{UPD_WORDS})[-_.]?\d*)$", re.IGNORECASE)


@dataclass
class Query:
    text: str  # the product words, normalised
    version: str = C.ANY
    update: str = C.ANY
    raw: str = ""

    @property
    def has_version(self) -> bool:
        return self.version != C.ANY


def parse_product(text: str, version: str | None = None) -> Query:
    """Split ``"php 7.4.0 alpha1"`` / ``"jdk 1.8.0 update 5"`` / ``"openssl 1.1.1k"``.
    A separate ``version`` argument wins over anything found in the text."""
    raw = str(text).strip()
    s = re.sub(r"^(server|x-powered-by|via)\s*:\s*", "", raw, flags=re.IGNORECASE)
    s = re.sub(r"\([^)]*\)", " ", s)
    s = re.sub(r"\bversion\b", " ", s, flags=re.IGNORECASE)
    toks = [re.sub(r"^v(?=\d)", "", t, flags=re.IGNORECASE) for t in re.split(r"[\s/]+", s) if t]
    if version:
        q = Query(norm_text(" ".join(toks)), raw=raw)
        v, u = split_version(version)
        q.version, q.update = v, u
        return q
    for i in range(len(toks) - 1, 0, -1):
        rest = toks[i:]
        if not VERSION_RE.match(rest[0]):
            continue
        product = norm_text(" ".join(toks[:i]))
        if not product:
            continue
        # "jdk 1.8.0 update 5": the trailing 5 is the update's number, not the version
        if (
            re.fullmatch(r"\d+", rest[0])
            and i >= 2
            and re.fullmatch(r"(update|upd|u|sp|service|pack|patch|p|build|hotfix|cu)", toks[i - 1], re.IGNORECASE)
        ):
            continue
        upd = C.ANY
        tail = rest[1:]
        if tail:
            j = " ".join(tail)
            if UPD_RE.match(j.replace(" ", "")):
                upd = re.sub(r"\s+", "_", j.lower())
            elif re.fullmatch(r"service\s*pack\s*(\d+)", j, re.IGNORECASE):
                upd = "sp" + re.search(r"(\d+)$", j).group(1)  # type: ignore[union-attr]
            else:
                continue
        v, u = split_version(rest[0])
        if upd != C.ANY and u == C.ANY:
            u = upd
        return Query(product, v, u, raw)
    return Query(norm_text(" ".join(toks)), raw=raw)


def split_version(tok: str) -> tuple[str, str]:
    """``7.4.0alpha1`` -> (7.4.0, alpha1); ``1.1.1k`` stays whole (a patch letter)."""
    tok = re.sub(r"^v(?=\d)", "", tok.strip(), flags=re.IGNORECASE)
    m = GLUED_RE.match(tok)
    if m:
        return re.sub(r"[.\-_]+$", "", m.group(1)), m.group(2).lower()
    return tok.lower(), C.ANY


# ---------------------------------------------------------------------- resolution


@dataclass
class Candidate:
    cpe: str  # part:vendor:product
    confidence: float
    reason: str
    title: str = ""
    entries: int = 0
    deprecated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpe": self.cpe,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
            "title": self.title,
            "entries": self.entries,
            "deprecated": self.deprecated,
        }


@dataclass
class Resolution:
    status: str  # ok | ambiguous | none
    query: Query
    pairs: list[str] = field(default_factory=list)  # part:vendor:product, when ok
    via: str = ""  # alias | dictionary | cpe
    candidates: list[Candidate] = field(default_factory=list)
    family: list[str] = field(default_factory=list)

    def targets(self) -> list[C.Cpe]:
        out = []
        for pair in self.pairs:
            part, vendor, product = pair.split(":", 2)
            out.append(C.make_cpe(part, vendor, product, self.query.version, self.query.update))
        for pair in self.family:  # windows_10_1809 carries its own build numbers: every version of it
            part, vendor, product = pair.split(":", 2)
            out.append(C.make_cpe(part, vendor, product))
        return out


def resolve_alias(q: Query) -> Resolution | None:
    text = q.text
    best = None
    for a in aliases()["aliases"]:
        for form in a["q"]:
            nf = norm_text(form)
            if nf == text and (best is None or len(nf) > len(best[0])):
                best = (nf, a)
    if best is None:
        return None
    a = best[1]
    res = Resolution("ok", q, list(a["cpe"]), "alias")
    fam = a.get("family")
    if fam and q.has_version and re.fullmatch(r"\d{4}|[0-9a-z]{2,6}", q.version):
        res.family = [fam.replace("{v}", q.version)]
    return res


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9+]+", s.lower()) if t]


def rank_groups(q: Query, entries: list[dict[str, Any]]) -> list[Candidate]:
    """Group dictionary entries by part:vendor:product and score each group against the query."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        p = C.parse_cpe(e["cpeName"])
        if p is None:
            continue
        groups.setdefault(p.short(), []).append(e)
    qtoks = _tokens(q.text)
    qset = set(qtoks)
    qjoined = "".join(qtoks)
    out: list[Candidate] = []
    for key, ents in groups.items():
        part, vendor, product = key.split(":", 2)
        ptoks = _tokens(product)
        vtoks = _tokens(vendor)
        pset, vset = set(ptoks), set(vtoks)
        score = 0.0
        reason = ""
        if qset == pset or "".join(ptoks) == qjoined:
            score, reason = 1.0, "product name is exactly what you typed"
        elif qset == pset | vset or qset == (pset | vset) - {"project", "software", "foundation"}:
            score, reason = 0.95, "vendor and product are exactly what you typed"
        elif qset and qset <= (pset | vset) and pset <= qset | vset:
            score, reason = 0.85, "every word you typed is in vendor + product"
        elif qset and qset <= pset:
            score, reason = 0.6, "your words are part of a longer product name"
        elif qset and pset <= qset:
            score, reason = 0.55, "the product name is part of what you typed"
        else:
            title = next((e["title"] for e in ents if e.get("title")), "").lower()
            ttoks = set(_tokens(title))
            if qset and qset <= ttoks:
                score, reason = 0.4, "matches the dictionary title only"
            else:
                overlap = len(qset & (pset | vset | ttoks)) / max(1, len(qset))
                if overlap <= 0:
                    continue
                score, reason = 0.2 * overlap, "partial word overlap"
        if vendor and vset & qset and score < 0.95:
            score += 0.05
        n = len(ents)
        score += min(0.08, 0.02 * math.log10(max(1, n)))
        dep = all(e.get("deprecated") for e in ents)
        if dep:
            score -= 0.3
            reason += "; every entry is deprecated"
        title = next((e["title"] for e in sorted(ents, key=lambda x: x["cpeName"]) if e.get("title")), "")
        title = re.sub(r"\s+\d[\w.\-]*(\s.*)?$", "", title) if title else ""
        out.append(Candidate(key, min(1.0, score), reason, title, n, dep))
    out.sort(key=lambda c: (-round(c.confidence, 4), c.cpe))
    return out


def decide(q: Query, cands: list[Candidate]) -> Resolution:
    if not cands:
        return Resolution("none", q, via="dictionary")
    top = cands[0]
    second = cands[1].confidence if len(cands) > 1 else 0.0
    exact = [c for c in cands if c.confidence >= 0.95]
    if len(exact) == 1 and top.confidence >= 0.95 and not top.deprecated:
        return Resolution("ok", q, [top.cpe], "dictionary", cands[:8])
    if top.confidence >= 0.85 and top.confidence - second >= 0.3 and not top.deprecated:
        return Resolution("ok", q, [top.cpe], "dictionary", cands[:8])
    return Resolution("ambiguous", q, [], "dictionary", cands[:8])


def resolve(q: Query, sources: Any) -> Resolution:
    """Alias table, then the dictionary. ``sources`` needs ``cpe_keyword(text)``."""
    hit = None if os.environ.get("VULNLOOKUP_NO_ALIAS") else resolve_alias(q)  # the env var is for demos and tests
    if hit:
        return hit
    if not q.text:
        return Resolution("none", q)
    entries = sources.cpe_keyword(q.text)
    return decide(q, rank_groups(q, entries))


# ---------------------------------------------------------------------- version snap


@dataclass
class Snap:
    in_dictionary: bool
    version: str
    update: str
    cpe_name: str = ""
    note: str = ""


def snap_version(pair: str, q: Query, sources: Any, entries: list[dict[str, Any]] | None = None) -> Snap:
    """Is the typed version in the dictionary for this vendor:product? Returns the dictionary's
    own spelling (and follows a ``deprecatedBy`` chain) or the typed version flagged."""
    if not q.has_version:
        return Snap(False, C.ANY, C.ANY, note="no version given")
    part, vendor, product = pair.split(":", 2)
    if entries is None:
        prefix = C.prefix_match_string(C.make_cpe(part, vendor, product, q.version.split("-")[0].split("_")[0]))
        entries = sources.cpe_match(prefix)
    want_u = C.norm_update(q.update) if q.update != C.ANY else None
    chosen = None
    for e in sorted(entries, key=lambda x: x["cpeName"]):
        p = C.parse_cpe(e["cpeName"])
        if p is None or p.vendor != vendor or p.product != product:
            continue
        if C.vcmp(p.version, q.version).cmp != 0:
            continue
        if want_u is None:
            if p.update in (C.ANY, C.NA):
                chosen = (e, p)
                break
            continue
        if p.update not in (C.ANY, C.NA) and C.norm_update(p.update) == want_u:
            chosen = (e, p)
            break
    if chosen is None:
        return Snap(
            False, q.version, q.update, note="version not in the NVD dictionary; typed as given, only range criteria can match it"
        )
    e, p = chosen
    name = e["cpeName"]
    note = "exact dictionary entry"
    if e.get("deprecated") and e.get("deprecatedBy"):
        name = sorted(e["deprecatedBy"])[0]
        p2 = C.parse_cpe(name)
        same_shape = (
            p2
            and p2.vendor == vendor
            and p2.product == product
            and all(p2.get(a) == C.ANY for a in ("edition", "language", "sw_edition", "target_sw", "target_hw", "other"))
        )
        if same_shape:
            p = p2
            note = f"deprecated entry; replaced by {name}"
        else:  # the replacements are platform-specific (an arm64 edition): keep the typed version
            name = e["cpeName"]
            note = "deprecated entry; its replacements add a platform, so the version is kept as typed"
    update = C.ANY if p.update == C.NA else p.update  # the dictionary's "no update" is a plain version
    return Snap(True, p.version, update, name, note)
