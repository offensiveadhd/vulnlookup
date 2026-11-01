"""Output. Five formats (table, json, md, csv, brief) times three styles (terse, analyst,
executive). Every renderer is a pure function of the rows, sorted by the caller, so two runs
on the same data print the same bytes. No run timestamps appear in the body; the dates shown
(published, KEV added, EPSS date) are data.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

FORMATS = ("table", "json", "md", "csv", "brief")
STYLES = ("terse", "analyst", "executive")


def fmt_prob(v: float | None, dp: int = 3) -> str:
    """A probability shown truncated, never rounded up: 0.99992 reads 0.999, not 1.000."""
    if v is None:
        return "-"
    f = 10**dp
    if v <= 0:
        return f"{0:.{dp}f}"
    t = int(v * f) / f
    if t < 1 / f:
        return f"<{1 / f:.{dp}f}"
    if t >= 1:
        return f"{1 - 1 / f:.{dp}f}"
    return f"{t:.{dp}f}"


def _score(row: dict[str, Any]) -> str:
    m = row.get("cvss")
    if not m or m.get("score") is None:
        return "-"
    return f"{m['score']:.1f} {m.get('severity', '')[:4]}".rstrip()


def _kev(row: dict[str, Any]) -> str:
    k = row.get("kev")
    if not k:
        return "-"
    r = (k.get("knownRansomwareCampaignUse") or "").lower()
    return "KEV" + ("+ransomware" if r == "known" else "")


def _epss(row: dict[str, Any]) -> str:
    e = row.get("epss")
    return fmt_prob(e["epss"]) if e else "-"


def _pct(row: dict[str, Any]) -> str:
    e = row.get("epss")
    return f"{e['percentile'] * 100:.0f}%" if e else "-"


def _poc(row: dict[str, Any]) -> str:
    ev = row.get("exploit_evidence")
    if not ev:
        return ""
    return {"exploited-in-the-wild": "ITW", "public-exploit": "PoC", "no-public-evidence": "none"}[ev["level"]]


def _matched_line(row: dict[str, Any]) -> str:
    ms = row.get("matched") or []
    if not ms:
        return ""
    parts = []
    for m in ms[:3]:
        b = " ".join(m.get("bounds") or [])
        parts.append(f"{m['criteria']}" + (f" [{b}]" if b else ""))
    return "; ".join(parts)


# ---------------------------------------------------------------------- table


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()
    out = [line, "  ".join("-" * w for w in widths)]
    for r in rows:
        out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    return "\n".join(out)


def _columns(rows: list[dict[str, Any]], style: str) -> tuple[list[str], list[list[str]]]:
    has_verdict = any("verdict" in r for r in rows)
    has_poc = any("exploit_evidence" in r for r in rows)
    headers = ["CVE", "CVSS", "EPSS", "KEV"]
    if has_poc:
        headers.append("Exploit")
    if style != "terse":
        headers += ["Published", "CWE"]
    if has_verdict:
        headers.append("Match")
    if style == "analyst":
        headers.append("Matched criteria")
    body = []
    for r in rows:
        cells = [r["id"], _score(r), _epss(r), _kev(r)]
        if has_poc:
            cells.append(_poc(r))
        if style != "terse":
            cells += [r.get("published", ""), ",".join(r.get("cwe") or [])[:24]]
        if has_verdict:
            cells.append(r.get("verdict", ""))
        if style == "analyst":
            cells.append(_matched_line(r)[:110])
        body.append(cells)
    return headers, body


def render_table(result: dict[str, Any], style: str) -> str:
    rows = result["rows"]
    out: list[str] = []
    if style == "executive":
        out.append(_executive_summary(result))
        out.append("")
    if not rows:
        out.append("No matching CVEs.")
    else:
        h, b = _columns(rows, style)
        out.append(_table(h, b))
    if style == "analyst":
        for r in rows:
            out.append("")
            out.append(_analyst_block(r))
    out.extend(_footer(result, style))
    return "\n".join(out).rstrip() + "\n"


def _analyst_block(r: dict[str, Any]) -> str:
    lines = [f"{r['id']}  {r['url']}"]
    m = r.get("cvss")
    if m:
        lines.append(f"  CVSS {m.get('version')} {m.get('score')} {m.get('severity')}  {m.get('vector') or ''}".rstrip())
    e = r.get("epss")
    if e:
        lines.append(f"  EPSS {fmt_prob(e['epss'])} (percentile {fmt_prob(e['percentile'])}, {e['date']})")
    k = r.get("kev")
    if k:
        lines.append(
            f"  KEV added {k.get('dateAdded')} due {k.get('dueDate')} ransomware {k.get('knownRansomwareCampaignUse') or 'n/a'}"
        )
    if r.get("cwe"):
        lines.append("  CWE " + ", ".join(r["cwe"]))
    for mm in r.get("matched") or []:
        b = " ".join(mm.get("bounds") or [])
        lines.append(f"  matched {mm['criteria']}" + (f"  [{b}]" if b else "") + (f"  ({mm['why']})" if mm.get("why") else ""))
    if r.get("platforms"):
        lines.append("  only when running on: " + ", ".join(r["platforms"]))
    if r.get("fixed_versions"):
        lines.append("  fixed in " + ", ".join(r["fixed_versions"]))
    for fp in r.get("fixed_versions_by_product") or []:
        lines.append(f"  {fp['product']} ranges end before " + ", ".join(fp["versions"]))
    ev = r.get("exploit_evidence")
    if ev:
        lines.append(f"  exploit evidence: {ev['level']}" + (" (weaponised tooling)" if ev.get("weaponised_tooling") else ""))
        for x in ev["evidence"][:6]:
            lines.append(f"    {x['kind']}: {x['url']}")
    if r.get("recommend"):
        lines.append("  remediation:")
        for s in r["recommend"]:
            lines.append(f"    - {s}")
    desc = r.get("description", "")
    if desc:
        lines.append("  " + (desc[:300] + ("..." if len(desc) > 300 else "")))
    return "\n".join(lines)


def _executive_summary(result: dict[str, Any]) -> str:
    rows = result["rows"]
    n = len(rows)
    kev = sum(1 for r in rows if r.get("kev"))
    crit = sum(1 for r in rows if (r.get("cvss") or {}).get("severity") == "CRITICAL")
    high = sum(1 for r in rows if (r.get("cvss") or {}).get("severity") == "HIGH")
    hot = sum(1 for r in rows if (r.get("epss") or {}).get("epss", 0) >= 0.1)
    poc = sum(1 for r in rows if (r.get("exploit_evidence") or {}).get("level") in ("public-exploit", "exploited-in-the-wild"))
    lines = [
        f"Subject: {result.get('subject', '')}".rstrip(),
        f"{n} CVE(s) confirmed against the subject: {crit} critical, {high} high; {kev} in CISA KEV; "
        f"{hot} with EPSS >= 0.1"
        + (f"; {poc} with exploit evidence (public PoC or in the wild)" if any("exploit_evidence" in r for r in rows) else "")
        + ".",
    ]
    top = sorted(rows, key=lambda r: (0 if r.get("kev") else 1, -((r.get("cvss") or {}).get("score") or 0), r["id"]))[:5]
    if top:
        lines.append("Act first:")
        for r in top:
            fx = r.get("fixed_versions") or []
            lines.append(
                f"  - {r['id']} ({_score(r)}, EPSS {_epss(r)}{', KEV' if r.get('kev') else ''})"
                + (f": upgrade to {fx[0]}" if fx else "")
            )
    return "\n".join(lines)


def _footer(result: dict[str, Any], style: str) -> list[str]:
    out: list[str] = []
    notes = result.get("notes") or []
    excl = result.get("excluded") or {}
    if excl and style != "terse":
        parts = [f"{k} {v}" for k, v in sorted(excl.items()) if v]
        if parts:
            out.append("")
            out.append("Not counted (shown with --include-unverified): " + ", ".join(parts))
    if notes and style != "terse":
        out.append("")
        out.extend(f"note: {n}" for n in notes)
    return out


# ---------------------------------------------------------------------- md / csv / brief / json


def render_md(result: dict[str, Any], style: str) -> str:
    rows = result["rows"]
    out: list[str] = []
    if result.get("subject"):
        out.append(f"## {result['subject']}")
        out.append("")
    if style == "executive":
        summary = _executive_summary(result).replace("Act first:", "**Act first:**")
        out.append(summary.split(chr(10), 1)[1] if result.get("subject") else summary)  # the heading already names the subject
        out.append("")
    if rows:
        h, b = _columns(rows, "terse" if style == "terse" else "analyst" if style == "analyst" else "executive")
        out.append("| " + " | ".join(h) + " |")
        out.append("|" + "|".join("---" for _ in h) + "|")
        for r in b:
            out.append("| " + " | ".join(c.replace("|", "\\|") for c in r) + " |")
    else:
        out.append("No matching CVEs.")
    if style == "analyst":
        for r in rows:
            out.append("")
            out.append(f"### {r['id']}")
            out.append("")
            for line in _analyst_block(r).split("\n")[1:]:
                item = line.strip()
                out.append("  " + item if item.startswith("- ") else "- " + item)  # remediation steps nest
    for line in _footer(result, style):
        out.append(line)
    return "\n".join(out).rstrip() + "\n"


def render_csv(result: dict[str, Any], style: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    cols = [
        "cve",
        "cvss_version",
        "cvss_score",
        "severity",
        "vector",
        "epss",
        "epss_percentile",
        "kev_added",
        "kev_due",
        "ransomware",
        "cwe",
        "published",
        "last_modified",
        "verdict",
        "matched",
        "fixed_versions",
        "exploit_evidence",
        "url",
    ]
    w.writerow(cols)
    for r in result["rows"]:
        m = r.get("cvss") or {}
        e = r.get("epss") or {}
        k = r.get("kev") or {}
        w.writerow(
            [
                r["id"],
                m.get("version", ""),
                m.get("score", ""),
                m.get("severity", ""),
                m.get("vector", ""),
                e.get("epss", ""),
                e.get("percentile", ""),
                k.get("dateAdded", ""),
                k.get("dueDate", ""),
                k.get("knownRansomwareCampaignUse", ""),
                " ".join(r.get("cwe") or []),
                r.get("published", ""),
                r.get("lastModified", ""),
                r.get("verdict", ""),
                _matched_line(r),
                " ".join(r.get("fixed_versions") or []),
                (r.get("exploit_evidence") or {}).get("level", ""),
                r["url"],
            ]
        )
    return buf.getvalue()


def render_brief(result: dict[str, Any], style: str) -> str:
    rows = result["rows"]
    out: list[str] = []
    if style == "executive":
        out.append(_executive_summary(result))
    elif not rows:
        out.append(f"{result.get('subject', '')}: no matching CVEs.".strip())
    else:
        for r in rows:
            bits = [r["id"], _score(r), f"EPSS {_epss(r)}"]
            if r.get("kev"):
                bits.append(_kev(r))
            p = _poc(r)
            if p:
                bits.append(f"exploit:{p}")
            if r.get("verdict"):
                bits.append(r["verdict"])
            if style == "analyst" and r.get("fixed_versions"):
                bits.append("fix " + r["fixed_versions"][0])
            out.append("  ".join(bits))
    out.extend(_footer(result, style))
    return "\n".join(out).rstrip() + "\n"


def render_json(result: dict[str, Any], style: str) -> str:
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render(result: dict[str, Any], fmt: str = "table", style: str = "analyst") -> str:
    return {"table": render_table, "json": render_json, "md": render_md, "csv": render_csv, "brief": render_brief}[fmt](
        result, style
    )
