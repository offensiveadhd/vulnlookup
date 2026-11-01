"""The command line. One entry point, subcommands, composable filters, five formats, three
styles, stable exit codes:

    0  done
    1  error (network, bad input)
    2  usage
    3  ambiguous product: candidates were printed, pick one with --pick or resolve first
    4  nothing found (unknown CVE / product, or no CVE survived the filters)
    5  --offline and the cache had no answer
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__, enrich, keystore, render, resolve
from . import cpe as C
from .cache import Cache
from .http import Client, HttpError, OfflineError, have_network_override
from .sources import Sources

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_AMBIGUOUS, EXIT_NOTHING, EXIT_OFFLINE = 0, 1, 2, 3, 4, 5

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# ---------------------------------------------------------------------- arguments


def add_common(p: argparse.ArgumentParser, suppress: bool) -> None:
    """The output, filter and network options. They are accepted before *and* after the
    subcommand (a model or a person should not have to remember argparse's order), so every
    subparser gets the same set with SUPPRESS defaults, and the main parser's defaults win."""
    d: Any = argparse.SUPPRESS if suppress else None
    f_ = argparse.SUPPRESS if suppress else False

    def dflt(v: Any) -> Any:
        return argparse.SUPPRESS if suppress else v

    g = p.add_argument_group("output")
    g.add_argument("--format", "-f", choices=render.FORMATS, default=dflt("table"))
    g.add_argument(
        "--style",
        "-s",
        choices=render.STYLES,
        default=dflt("analyst"),
        help="terse: one line per CVE; analyst: everything incl. matched criteria (default); executive: summary first",
    )
    g.add_argument(
        "--sort",
        choices=("id", "cvss", "epss", "published"),
        default=dflt("id"),
        help="row order; ties always break on the CVE id, so the output is stable",
    )
    g.add_argument("--limit", type=int, default=dflt(0), help="keep the first N rows after sorting")
    g.add_argument(
        "--poc", action="store_true", default=f_, help="classify exploit evidence from the references (evidence, not a verdict)"
    )
    g.add_argument("--recommend", action="store_true", default=f_, help="a remediation checklist per CVE")
    g.add_argument(
        "--include-unverified",
        action="store_true",
        default=f_,
        help="also show records the local check could not confirm (COND, MAYBE, NVD-only), flagged",
    )
    g.add_argument("--verbose", "-v", action="store_true", default=f_, help="log every request to stderr")
    f = p.add_argument_group("filters (composable)")
    f.add_argument("--min-cvss", type=float, default=d)
    f.add_argument("--severity", choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"), default=d, help="this severity and above")
    f.add_argument("--min-epss", type=float, default=d)
    f.add_argument("--kev", action="store_true", default=f_, help="only CVEs in CISA's Known Exploited Vulnerabilities catalogue")
    f.add_argument("--ransomware", action="store_true", default=f_, help="only KEV entries with known ransomware campaign use")
    f.add_argument("--cwe", action="append", default=d, help="keep this CWE (repeatable), e.g. --cwe CWE-79")
    f.add_argument("--years", default=d, help="published in this range, e.g. 2019-2024 or 2023")
    f.add_argument(
        "--version-from",
        default=d,
        help="product queries without a version: keep CVEs whose vulnerable criteria reach this version or later",
    )
    n = p.add_argument_group("network and cache")
    n.add_argument("--offline", action="store_true", default=f_, help="answer from the cache only")
    n.add_argument("--no-cache", action="store_true", default=f_)
    n.add_argument("--ttl", action="append", default=dflt([]), metavar="SOURCE=HOURS", help="override a TTL: kev, epss, cpe, cve")
    n.add_argument("--cache-dir", default=d, help="override the cache directory")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnlookup",
        description="Passive CVE / CPE / EPSS / KEV lookups against the NVD, FIRST and CISA. Scans nothing; asks.",
    )
    p.add_argument("--version", action="version", version=f"vulnlookup {__version__}")
    add_common(p, suppress=False)

    sub = p.add_subparsers(dest="cmd", metavar="command")

    def add(name: str, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        add_common(sp, suppress=True)
        return sp

    s = add("cve", "one or more CVE ids")
    s.add_argument("ids", nargs="*")
    s.add_argument("--file", help="a file with one CVE id per line (or any text; ids are extracted)")

    s = add("cpe", "one or more CPE 2.3 names, verbatim")
    s.add_argument("cpes", nargs="*")
    s.add_argument("--file")

    s = add("product", 'a product, optionally a version: product "apache httpd" 2.4.49')
    s.add_argument("text", help='what is running, e.g. "openssl", "apache httpd 2.4.49", "php 7.4.0 alpha1"')
    s.add_argument("version", nargs="?", help="the version, if not part of the text")
    s.add_argument("--on", help='the platform it runs on, e.g. "windows 10" (resolves running-on configurations)')
    s.add_argument("--on-cpe", help="the platform as a CPE name")
    s.add_argument("--pick", help="when the product is ambiguous: the part:vendor:product to use")

    s = add("resolve", "resolve a product name to a CPE, or list the candidates")
    s.add_argument("text")
    s.add_argument("version", nargs="?")

    s = add("bulk", "many subjects from files")
    s.add_argument("--products", help='file: one "name [version]" per line')
    s.add_argument("--cpes", help="file: one CPE per line")
    s.add_argument("--cves", help="file: CVE ids")

    s = add("kev", "the CISA KEV catalogue")
    s.add_argument("ids", nargs="*", help="check these CVE ids against KEV")
    s.add_argument("--recent", type=int, metavar="N", help="the N most recently added entries")
    s.add_argument("--search", help="entries whose vendor/product/name contains this text")

    s = add("epss", "EPSS scores for CVE ids")
    s.add_argument("ids", nargs="+")

    s = add("key", "the optional NVD API key (raises the rate limit from 5 to 50 requests per 30 s)")
    s.add_argument("action", choices=("set", "status", "clear"))
    s.add_argument("value", nargs="?", help="the key (set); omit to read it from stdin")
    s.add_argument("--file", action="store_true", help="store in the config file even when an OS store exists")

    s = add("cache", "the local cache")
    s.add_argument("action", choices=("stats", "clear", "path"))
    s.add_argument("--source", choices=("kev", "epss", "cpe", "cve"))
    return p


# ---------------------------------------------------------------------- plumbing


def make_sources(a: argparse.Namespace, fetch: Any = None) -> Sources:
    ttl: dict[str, int] = {}
    for item in a.ttl:
        k, _, v = item.partition("=")
        if k not in ("kev", "epss", "cpe", "cve") or not v:
            raise SystemExit(f"--ttl wants SOURCE=HOURS with SOURCE in kev, epss, cpe, cve; got {item!r}")
        ttl[k] = int(float(v) * 3600)
    cache = Cache(Path(a.cache_dir) if a.cache_dir else None, ttl, enabled=not a.no_cache)
    key, _where = keystore.get_key()
    offline = a.offline or have_network_override()
    client = Client(cache.root, key, offline=offline, fetch=fetch, verbose=a.verbose)
    return Sources(client, cache)


def read_ids(values: list[str], file: str | None) -> list[str]:
    text = " ".join(values or [])
    if file:
        text += " " + Path(file).read_text("utf-8")
    ids = sorted({m.group(0).upper() for m in CVE_RE.finditer(text)})
    return ids


def read_lines(file: str) -> list[str]:
    out = []
    for line in Path(file).read_text("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def parse_years(spec: str | None) -> tuple[int, int] | None:
    if not spec:
        return None
    m = re.fullmatch(r"(\d{4})(?:\s*-\s*(\d{4}))?", spec.strip())
    if not m:
        raise SystemExit(f"--years wants YYYY or YYYY-YYYY, got {spec!r}")
    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    return (min(a, b), max(a, b))


# ---------------------------------------------------------------------- the pipeline


def version_reaches(cve: dict[str, Any], targets: list[C.Cpe], floor: str) -> bool:
    """Does some vulnerable criteria of the target's product cover ``floor`` or anything above?"""
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            if node.get("negate"):
                continue
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable") is False:
                    continue
                crit = C.parse_cpe(cm.get("criteria", ""))
                if crit is None or not any(crit.vendor == t.vendor and crit.product == t.product for t in targets):
                    continue
                if crit.version not in (C.ANY, C.NA) and "version" not in crit.wild:
                    if C.vcmp(crit.version, floor).cmp >= 0:
                        return True
                    continue
                end_i, end_e = cm.get("versionEndIncluding"), cm.get("versionEndExcluding")
                if not end_i and not end_e:
                    return True
                if end_i and C.vcmp(end_i, floor).cmp >= 0:
                    return True
                if end_e and C.vcmp(end_e, floor).cmp > 0:
                    return True
    return False


def passes_filters(row: dict[str, Any], a: argparse.Namespace, years: tuple[int, int] | None) -> bool:
    m = row.get("cvss") or {}
    if a.min_cvss is not None and (m.get("score") is None or m["score"] < a.min_cvss):
        return False
    if a.severity and enrich.SEVERITY_ORDER.get(m.get("severity", ""), -1) < enrich.SEVERITY_ORDER[a.severity]:
        return False
    if a.min_epss is not None and ((row.get("epss") or {}).get("epss") is None or row["epss"]["epss"] < a.min_epss):
        return False
    if a.kev and not row.get("kev"):
        return False
    if a.ransomware and (not row.get("kev") or (row["kev"].get("knownRansomwareCampaignUse") or "").lower() != "known"):
        return False
    if a.cwe and not {c.upper() for c in a.cwe} & set(row.get("cwe") or []):
        return False
    if years:
        y = row.get("published", "")[:4]
        if not y.isdigit() or not (years[0] <= int(y) <= years[1]):
            return False
    return True


def sort_rows(rows: list[dict[str, Any]], how: str) -> None:
    if how == "cvss":
        rows.sort(key=lambda r: (-((r.get("cvss") or {}).get("score") or 0), r["id"]))
    elif how == "epss":
        rows.sort(key=lambda r: (-((r.get("epss") or {}).get("epss") or 0), r["id"]))
    elif how == "published":
        rows.sort(key=lambda r: (r.get("published") or "", r["id"]))
    else:
        rows.sort(key=lambda r: r["id"])


def finish_rows(
    records: list[dict[str, Any]],
    verdicts: dict[str, C.Verdict | None],
    target: C.Cpe | None,
    src: Sources,
    a: argparse.Namespace,
) -> list[dict[str, Any]]:
    ids = [c["id"] for c in records]
    epss = src.epss(ids) if ids else {}
    kev = src.kev() if ids else {}
    years = parse_years(a.years)
    rows = []
    for c in records:
        row = enrich.build_row(c, verdicts.get(c["id"]), epss.get(c["id"].upper()), enrich.kev_of(c, kev), target)
        if a.poc or a.recommend:
            enrich.add_poc(row, c)
        if a.recommend:
            row["recommend"] = enrich.recommend(row, c)
        if passes_filters(row, a, years):
            rows.append(row)
    sort_rows(rows, a.sort)
    if a.limit:
        rows = rows[: a.limit]
    return rows


def lookup_targets(
    targets: list[C.Cpe], platforms: list[C.Cpe], subject: str, src: Sources, a: argparse.Namespace
) -> dict[str, Any]:
    """The core: every CVE the NVD files for the targets, re-checked locally, enriched, filtered."""
    seen: dict[str, dict[str, Any]] = {}
    for t in targets:
        for c in src.cves_matching(C.prefix_match_string(t)):
            seen.setdefault(c["id"], c)
    has_version = any(t.version != C.ANY for t in targets)
    confirmed: list[dict[str, Any]] = []
    verdicts: dict[str, C.Verdict | None] = {}
    excluded: dict[str, int] = {"COND": 0, "MAYBE": 0, "PLATFORM": 0, "NVD-only": 0}
    unverified: list[dict[str, Any]] = []
    for cid in sorted(seen):
        c = seen[cid]
        v = C.eval_cve(c, targets + platforms)
        if not has_version and v.verdict == "MAYBE" and all(h.res.why == "version unspecified" for h in v.matched):
            v.verdict = "LISTED"  # the product is named vulnerable; no version was given to check
            v.why = ""
        if a.version_from and not has_version and not version_reaches(c, targets, a.version_from):
            continue
        verdicts[cid] = v
        if v.confirmed or v.verdict == "LISTED":
            confirmed.append(c)
        else:
            key = v.verdict if v.verdict in excluded else "NVD-only"
            excluded[key] += 1
            if a.include_unverified and v.verdict != "PLATFORM":
                if v.verdict == "NONE":
                    v.verdict = "NVD-only"
                    v.why = "the NVD's matcher returned it; no configuration node fits the target locally"
                unverified.append(c)
    records = confirmed + (unverified if a.include_unverified else [])
    rows = finish_rows(records, verdicts, targets[0] if len(targets) == 1 else None, src, a)
    notes = []
    if src.stale:
        notes.append(f"{len(src.stale)} answer(s) came from a stale cache (offline or network failure)")
    return {
        "subject": subject,
        "targets": [str(t) for t in targets],
        "platforms": [str(p) for p in platforms],
        "nvd_returned": len(seen),
        "confirmed": len(confirmed),
        "excluded": {k: v for k, v in excluded.items() if v},
        "rows": rows,
        "notes": notes,
    }


def print_candidates(res: resolve.Resolution) -> None:
    q = res.query
    print(
        f"ambiguous: {q.text!r} matches {len(res.candidates)} products in the NVD dictionary. "
        f"Pick one with --pick part:vendor:product, or ask which was meant:",
        file=sys.stderr,
    )
    for c in res.candidates:
        print(f"  {c.confidence:4.2f}  {c.cpe:48s} {c.title[:40]:40s} {c.reason}", file=sys.stderr)


def resolve_or_exit(text: str, version: str | None, src: Sources, pick: str | None, out: Any) -> resolve.Resolution:
    q = resolve.parse_product(text, version)
    if pick:
        pair = pick if pick.count(":") == 2 else "a:" + pick
        return resolve.Resolution("ok", q, [pair], "pick")
    res = resolve.resolve(q, src)
    if res.status == "ok":
        return res
    payload = {
        "status": res.status,
        "query": {"text": q.text, "version": q.version, "update": q.update},
        "candidates": [c.as_dict() for c in res.candidates],
    }
    if res.status == "ambiguous":
        print_candidates(res)
        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
        raise SystemExit(EXIT_AMBIGUOUS)
    print(f"no product in the NVD dictionary matches {q.text!r}", file=sys.stderr)
    print(json.dumps(payload, indent=2, sort_keys=True), file=out)
    raise SystemExit(EXIT_NOTHING)


def subject_line(res: resolve.Resolution, snaps: list[resolve.Snap]) -> str:
    q = res.query
    s = q.text + (f" {q.version}" if q.has_version else "") + (f" {q.update}" if q.update != C.ANY else "")
    s += " -> " + ", ".join(res.pairs + res.family) + f" (via {res.via})"
    if snaps:
        found = [pair for pair, x in zip(res.pairs, snaps) if x.in_dictionary]
        if found and len(found) == len(snaps):
            s += "; version in the NVD dictionary"
        elif found:  # a product filed under several vendors: the dictionary knows the version for some of them
            s += "; version in the NVD dictionary for " + ", ".join(found) + " (typed as given for the rest)"
        else:
            s += "; version NOT in the NVD dictionary (typed as given; only range criteria can match it)"
    return s


# ---------------------------------------------------------------------- commands


def cmd_product(a: argparse.Namespace, src: Sources, out: Any) -> int:
    res = resolve_or_exit(a.text, a.version, src, a.pick, out)
    snaps: list[resolve.Snap] = []
    if res.query.has_version:
        for pair in res.pairs:
            snaps.append(resolve.snap_version(pair, res.query, src))
        snapped = next((s for s in snaps if s.in_dictionary), None)
        if snapped and (snapped.version != res.query.version or snapped.update != res.query.update):
            res.query.version, res.query.update = snapped.version, snapped.update
    platforms: list[C.Cpe] = []
    if a.on_cpe:
        p = C.parse_cpe(a.on_cpe)
        if p is None:
            raise SystemExit(f"--on-cpe is not a CPE 2.3 name: {a.on_cpe!r}")
        platforms.append(p)
    elif a.on:
        pres = resolve_or_exit(a.on, None, src, None, out)
        platforms.extend(pres.targets())
    result = lookup_targets(res.targets(), platforms, subject_line(res, snaps), src, a)
    result["resolution"] = {
        "status": res.status,
        "via": res.via,
        "pairs": res.pairs,
        "family": res.family,
        "snap": [s.__dict__ for s in snaps],
    }
    out.write(render.render(result, a.format, a.style))
    return EXIT_OK if result["rows"] else EXIT_NOTHING


def cmd_resolve(a: argparse.Namespace, src: Sources, out: Any) -> int:
    q = resolve.parse_product(a.text, a.version)
    res = resolve.resolve(q, src)
    payload: dict[str, Any] = {
        "status": res.status,
        "via": res.via,
        "query": {"text": q.text, "version": q.version, "update": q.update},
        "pairs": res.pairs,
        "candidates": [c.as_dict() for c in res.candidates],
    }
    if res.status == "ok" and q.has_version:
        payload["snap"] = [resolve.snap_version(p, q, src).__dict__ for p in res.pairs]
        payload["cpe"] = [str(t) for t in res.targets()]
    elif res.status == "ok":
        payload["cpe"] = [str(t) for t in res.targets()]
    if a.format == "json" or res.status != "ok":
        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
    else:
        for c in payload["cpe"]:
            print(c, file=out)
        for s in payload.get("snap", []):
            print(f"  {s['note']}" + (f" ({s['cpe_name']})" if s.get("cpe_name") else ""), file=out)
    if res.status == "ambiguous":
        print_candidates(res)
        return EXIT_AMBIGUOUS
    return EXIT_OK if res.status == "ok" else EXIT_NOTHING


def cmd_cpe(a: argparse.Namespace, src: Sources, out: Any) -> int:
    names = list(a.cpes or []) + (read_lines(a.file) if a.file else [])
    if not names:
        raise SystemExit("give at least one CPE name")
    results = []
    rc = EXIT_NOTHING
    for name in names:
        t = C.parse_cpe(name)
        if t is None or t.vendor == C.ANY or t.product == C.ANY:
            raise SystemExit(f"not a CPE 2.3 name with a vendor and a product: {name!r}")
        r = lookup_targets([t], [], str(t), src, a)
        results.append(r)
        if r["rows"]:
            rc = EXIT_OK
    emit_many(results, a, out)
    return rc


def cmd_cve(a: argparse.Namespace, src: Sources, out: Any) -> int:
    ids = read_ids(a.ids, a.file)
    if not ids:
        raise SystemExit("give at least one CVE id (CVE-YYYY-NNNN)")
    records = []
    missing = []
    for i in ids:
        c = src.cve(i)
        (records if c else missing).append(c or i)
    rows = finish_rows(records, {}, None, src, a)
    result = {
        "subject": ", ".join(ids) if len(ids) <= 5 else f"{len(ids)} CVE ids",
        "rows": rows,
        "not_found": missing,
        "notes": [f"not in the NVD: {', '.join(missing)}"] if missing else [],
    }
    out.write(render.render(result, a.format, a.style))
    return EXIT_OK if rows else EXIT_NOTHING


def cmd_bulk(a: argparse.Namespace, src: Sources, out: Any) -> int:
    results: list[dict[str, Any]] = []
    rc = EXIT_NOTHING
    if a.cves:
        a.ids, a.file = [], a.cves
        return cmd_cve(a, src, out)
    if a.cpes:
        a.cpes, a.file = [], a.cpes
        return cmd_cpe(a, src, out)
    if not a.products:
        raise SystemExit("bulk wants --products, --cpes or --cves")
    for line in read_lines(a.products):
        q = resolve.parse_product(line)
        res = resolve.resolve(q, src)
        if res.status != "ok":
            results.append(
                {
                    "subject": line,
                    "rows": [],
                    "resolution": {"status": res.status, "candidates": [c.as_dict() for c in res.candidates]},
                    "notes": [f"{res.status}: {len(res.candidates)} candidate(s); resolve this line separately"],
                }
            )
            continue
        snaps = [resolve.snap_version(p, q, src) for p in res.pairs] if q.has_version else []
        r = lookup_targets(res.targets(), [], subject_line(res, snaps), src, a)
        results.append(r)
        if r["rows"]:
            rc = EXIT_OK
    emit_many(results, a, out)
    return rc


def emit_many(results: list[dict[str, Any]], a: argparse.Namespace, out: Any) -> None:
    if a.format == "json":
        out.write(render.render_json({"subjects": results}, a.style))
        return
    if a.format == "csv":
        text = ""
        for i, r in enumerate(results):
            rows = render.render_csv(r, a.style).splitlines()
            if i == 0:
                text += "subject," + rows[0] + "\n"
            text += "".join(_csv_quote(r["subject"]) + "," + line + "\n" for line in rows[1:])
        out.write(text)
        return
    for i, r in enumerate(results):
        if i:
            out.write("\n")
        if a.format in ("table", "brief"):
            out.write(f"== {r['subject']}\n")
        out.write(render.render(r, a.format, a.style))


def _csv_quote(s: str) -> str:
    return '"' + s.replace('"', '""') + '"'


def cmd_kev(a: argparse.Namespace, src: Sources, out: Any) -> int:
    kev = src.kev()
    by = kev.get("byId") or {}
    if a.ids:
        ids = read_ids(a.ids, None)
        hits = {i: by.get(i) for i in ids}
        if a.format == "json":
            print(json.dumps({"catalogVersion": kev.get("catalogVersion"), "kev": hits}, indent=2, sort_keys=True), file=out)
        else:
            for i in ids:
                e = hits[i]
                print(
                    f"{i}  "
                    + (
                        f"KEV added {e['dateAdded']} due {e['dueDate']} "
                        f"ransomware {e['knownRansomwareCampaignUse']}  {e['vulnerabilityName']}"
                        if e
                        else "not in KEV"
                    ),
                    file=out,
                )
        return EXIT_OK if any(hits.values()) else EXIT_NOTHING
    entries = sorted(by.items(), key=lambda kv: (kv[1].get("dateAdded") or "", kv[0]), reverse=True)
    if a.search:
        s = a.search.lower()
        entries = [
            kv
            for kv in entries
            if s in " ".join(str(kv[1].get(k) or "") for k in ("vendorProject", "product", "vulnerabilityName")).lower()
        ]
    if a.recent:
        entries = entries[: a.recent]
    if a.format == "json":
        print(
            json.dumps(
                {
                    "catalogVersion": kev.get("catalogVersion"),
                    "count": len(entries),
                    "entries": [dict(cveID=k, **v) for k, v in entries],
                },
                indent=2,
                sort_keys=True,
            ),
            file=out,
        )
    else:
        print(
            f"CISA KEV catalogue {kev.get('catalogVersion')}: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}", file=out
        )
        for k, v in entries:
            print(
                f"{v.get('dateAdded')}  {k:18s} {(v.get('vendorProject') or '')[:18]:18s} {(v.get('product') or '')[:24]:24s} "
                f"due {v.get('dueDate')}  ransomware {v.get('knownRansomwareCampaignUse')}",
                file=out,
            )
    return EXIT_OK if entries else EXIT_NOTHING


def cmd_epss(a: argparse.Namespace, src: Sources, out: Any) -> int:
    ids = read_ids(a.ids, None)
    scores = src.epss(ids)
    if a.format == "json":
        print(json.dumps({"epss": {i: scores.get(i) for i in ids}}, indent=2, sort_keys=True), file=out)
    else:
        for i in ids:
            e = scores.get(i)
            print(
                f"{i}  "
                + (
                    f"EPSS {render.fmt_prob(e['epss'])}  percentile {render.fmt_prob(e['percentile'])}  ({e['date']})"
                    if e
                    else "no EPSS score"
                ),
                file=out,
            )
    return EXIT_OK if scores else EXIT_NOTHING


def cmd_key(a: argparse.Namespace, out: Any) -> int:
    if a.action == "status":
        st = keystore.status()
        if a.format == "json":
            print(json.dumps(st.as_dict(), sort_keys=True), file=out)
        else:
            print(
                f"NVD API key: {'present' if st.present else 'none'}"
                + (
                    f" (…{st.hint}, from {st.where})"
                    if st.present
                    else "; requests are paced at 5 per 30 s. Get one at https://nvd.nist.gov/developers/request-an-api-key"
                ),
                file=out,
            )
        return EXIT_OK
    if a.action == "clear":
        where = keystore.clear_key()
        print("cleared: " + (", ".join(where) if where else "nothing stored"), file=out)
        return EXIT_OK
    value = a.value
    if not value:
        if sys.stdin.isatty():
            print("paste the key and press Enter (it is not echoed back):", file=sys.stderr)
        value = sys.stdin.readline().strip()
    try:
        kind = keystore.set_key(value, force_file=a.file)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    print(f"stored in the {kind}. Keyed requests are paced at 50 per 30 s.", file=out)
    return EXIT_OK


def cmd_cache(a: argparse.Namespace, out: Any) -> int:
    cache = Cache(Path(a.cache_dir) if a.cache_dir else None)
    if a.action == "path":
        print(cache.root, file=out)
    elif a.action == "stats":
        print(json.dumps(cache.stats(), indent=2, sort_keys=True), file=out)
    else:
        n = cache.clear(a.source)
        print(f"removed {n} cached file(s)" + (f" from {a.source}" if a.source else ""), file=out)
    return EXIT_OK


# ---------------------------------------------------------------------- main


def main(argv: list[str] | None = None, out: Any = None, fetch: Any = None) -> int:
    out = out or sys.stdout
    parser = build_parser()
    a = parser.parse_args(argv)
    if not a.cmd:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        if a.cmd == "key":
            return cmd_key(a, out)
        if a.cmd == "cache":
            return cmd_cache(a, out)
        src = make_sources(a, fetch)
        rc = {
            "cve": cmd_cve,
            "cpe": cmd_cpe,
            "product": cmd_product,
            "resolve": cmd_resolve,
            "bulk": cmd_bulk,
            "kev": cmd_kev,
            "epss": cmd_epss,
        }[a.cmd](a, src, out)
        if a.verbose:
            print(f"[{src.client.requests} request(s), waited {src.client.waited:.1f}s for the rate limit]", file=sys.stderr)
        return rc
    except OfflineError as e:
        print(f"offline: no cached answer for {e}", file=sys.stderr)
        return EXIT_OFFLINE
    except HttpError as e:
        print(f"error: {e}" + (f": {e.body}" if e.body else ""), file=sys.stderr)
        return EXIT_ERROR
    except SystemExit as e:
        if isinstance(e.code, str):
            print(f"error: {e.code}", file=sys.stderr)
            return EXIT_USAGE
        return int(e.code or 0)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
