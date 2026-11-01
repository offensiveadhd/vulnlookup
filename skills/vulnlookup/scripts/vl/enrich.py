"""Reading an NVD record into a result row, and the two evidence-based passes over it:
exploit evidence (``--poc``) and a remediation checklist (``--recommend``).

Everything here is a deterministic function of the record, the KEV entry and the EPSS score.
The exploit classification is *evidence found in the references*, never a verdict about
exploitability, and the output says so.
"""

from __future__ import annotations

import re
from typing import Any

from . import cpe as C

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "": -1}


def severity_of(score: float | None) -> str:
    if score is None:
        return ""
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def metrics(cve: dict[str, Any]) -> dict[str, Any] | None:
    m = cve.get("metrics") or {}

    def pick(arr: list[dict[str, Any]] | None) -> dict[str, Any] | None:
        if not arr:
            return None
        return next((x for x in arr if x.get("type") == "Primary"), arr[0])

    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        x = pick(m.get(key))
        if x:
            d = x.get("cvssData") or {}
            score = d.get("baseScore")
            return {
                "version": d.get("version") or ver,
                "score": score,
                "severity": (d.get("baseSeverity") or x.get("baseSeverity") or severity_of(score) or "").upper(),
                "vector": d.get("vectorString"),
                "source": x.get("source"),
            }
    return None


def cwes(cve: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if re.fullmatch(r"CWE-\d+", v) and v not in out:
                out.append(v)
    return sorted(out, key=lambda s: int(s.split("-")[1]))


def description(cve: dict[str, Any]) -> str:
    ds = cve.get("descriptions") or []
    d = next((x for x in ds if x.get("lang") == "en"), ds[0] if ds else None)
    return (d or {}).get("value", "").strip()


def kev_of(cve: dict[str, Any], kev: dict[str, Any]) -> dict[str, Any] | None:
    e = (kev.get("byId") or {}).get(cve["id"].upper())
    if e:
        return {
            "dateAdded": e.get("dateAdded"),
            "dueDate": e.get("dueDate"),
            "knownRansomwareCampaignUse": e.get("knownRansomwareCampaignUse"),
            "vulnerabilityName": e.get("vulnerabilityName"),
            "requiredAction": e.get("requiredAction"),
        }
    if cve.get("cisaExploitAdd"):
        return {
            "dateAdded": cve.get("cisaExploitAdd"),
            "dueDate": cve.get("cisaActionDue"),
            "knownRansomwareCampaignUse": None,
            "vulnerabilityName": cve.get("cisaVulnerabilityName"),
            "requiredAction": cve.get("cisaRequiredAction"),
        }
    return None


# ---------------------------------------------------------------------- references

# Hosts and paths that publish working exploit code. Deterministic; extend in one place.
POC_HOSTS = (
    (re.compile(r"(^|\.)exploit-db\.com$"), "Exploit-DB"),
    (re.compile(r"(^|\.)packetstormsecurity\.(com|net|org)$"), "Packet Storm"),
    (re.compile(r"(^|\.)packetstorm\.news$"), "Packet Storm"),
    (re.compile(r"(^|\.)0day\.today$"), "0day.today"),
    (re.compile(r"(^|\.)vulncheck\.com$"), "VulnCheck"),
    (re.compile(r"(^|\.)seebug\.org$"), "Seebug"),
)
GITHUB_POC_PATH = re.compile(r"github\.com/[^/]+/[^/]*(poc|exploit|cve-\d{4}-\d+|rce|0day)[^/]*", re.IGNORECASE)
METASPLOIT = re.compile(r"(rapid7\.com/db/modules|github\.com/rapid7/metasploit-framework)", re.IGNORECASE)
NUCLEI = re.compile(r"github\.com/projectdiscovery/nuclei-templates", re.IGNORECASE)


def classify_references(refs: list[dict[str, Any]], kev: dict[str, Any] | None) -> dict[str, Any]:
    """Three evidence levels, from the reference tags and known exploit hosts:

    * ``exploited-in-the-wild``: CISA KEV lists it (an observed exploitation, not a PoC).
    * ``public-exploit``: a reference tagged ``Exploit`` by the NVD, or a URL on a host that
      publishes exploit code (Exploit-DB, Packet Storm, Metasploit, nuclei, a GitHub repo
      whose name says PoC / exploit / the CVE id).
    * ``no-public-evidence``: none of the above in the references the NVD lists.
    """
    evidence: list[dict[str, str]] = []
    for r in refs or []:
        url = r.get("url", "")
        tags = r.get("tags") or []
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        kind = ""
        if METASPLOIT.search(url):
            kind = "Metasploit module"
        elif NUCLEI.search(url):
            kind = "nuclei template"
        else:
            for pat, name in POC_HOSTS:
                if pat.search(host):
                    kind = name
                    break
        if not kind and GITHUB_POC_PATH.search(url):
            kind = "GitHub PoC repository"
        if not kind and "Exploit" in tags:
            kind = "NVD tag: Exploit"
        if kind and not any(e["url"] == url and e["kind"] == kind for e in evidence):
            evidence.append({"url": url, "kind": kind, "tags": ",".join(sorted(tags))})
    evidence.sort(key=lambda e: (e["kind"], e["url"]))
    if kev:
        level = "exploited-in-the-wild"
    elif evidence:
        level = "public-exploit"
    else:
        level = "no-public-evidence"
    weaponised = [e for e in evidence if e["kind"] in ("Metasploit module", "nuclei template")]
    return {
        "level": level,
        "evidence": evidence,
        "weaponised_tooling": bool(weaponised),
        "basis": "references the NVD lists, their tags, known exploit hosts, and the CISA KEV catalogue; "
        "evidence of what is public, not a judgement of exploitability",
    }


def tagged(refs: list[dict[str, Any]], *want: str, without: tuple[str, ...] = ()) -> list[str]:
    return sorted(
        {
            r.get("url", "")
            for r in refs or []
            if set(r.get("tags") or []) & set(want) and not set(r.get("tags") or []) & set(without)
        }
    )


def fixed_versions_by_product(cve: dict[str, Any], limit: int = 3) -> list[tuple[str, list[str]]]:
    """For a CVE looked up without a target: the ``versionEndExcluding`` bounds per vendor:product
    over every vulnerable criteria, for the products with the most criteria (the subject of the
    record, not the long tail of platforms that embed it)."""
    per: dict[str, set[str]] = {}
    count: dict[str, int] = {}
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            if node.get("negate"):
                continue
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable") is False:
                    continue
                crit = C.parse_cpe(cm.get("criteria", ""))
                if crit is None:
                    continue
                key = f"{crit.vendor}:{crit.product}"
                count[key] = count.get(key, 0) + 1
                if cm.get("versionEndExcluding"):
                    per.setdefault(key, set()).add(cm["versionEndExcluding"])
    top = sorted(per, key=lambda k: (-count[k], k))[:limit]
    return [(k, sorted(per[k], key=lambda v: [(t.num, int(t.v) if t.num else t.v) for t in C.vtokens(v)])) for k in top]


# ---------------------------------------------------------------------- rows


def build_row(
    cve: dict[str, Any], verdict: C.Verdict | None, epss: dict[str, Any] | None, kev: dict[str, Any] | None, target: C.Cpe | None
) -> dict[str, Any]:
    m = metrics(cve)
    refs = cve.get("references") or []
    row: dict[str, Any] = {
        "id": cve["id"],
        "published": (cve.get("published") or "")[:10],
        "lastModified": (cve.get("lastModified") or "")[:10],
        "status": cve.get("vulnStatus"),
        "cvss": m,
        "epss": epss,
        "kev": kev,
        "cwe": cwes(cve),
        "description": description(cve),
        "references": [
            {"url": r.get("url"), "tags": sorted(r.get("tags") or [])} for r in sorted(refs, key=lambda r: r.get("url", ""))
        ],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }
    if verdict is not None:
        row["verdict"] = verdict.verdict
        row["matched"] = verdict.explain()
        row["platforms"] = list(verdict.platforms)
        row["why"] = verdict.why
    if target is not None:
        row["target"] = str(target)
        row["fixed_versions"] = C.fixed_versions(cve, target)
    else:
        row["fixed_versions_by_product"] = [{"product": k, "versions": v} for k, v in fixed_versions_by_product(cve)]
    return row


def add_poc(row: dict[str, Any], cve: dict[str, Any]) -> None:
    row["exploit_evidence"] = classify_references(cve.get("references") or [], row.get("kev"))


def recommend(row: dict[str, Any], cve: dict[str, Any]) -> list[str]:
    """A remediation checklist from the record: the fixed versions the ranges imply, the
    patch and vendor-advisory references, the KEV deadline and required action."""
    steps: list[str] = []
    refs = cve.get("references") or []
    fixed = row.get("fixed_versions") or []
    if fixed:
        prod = ""
        if row.get("target"):
            t = C.parse_cpe(row["target"])
            prod = f"{t.vendor} {t.product} " if t else ""
        steps.append(f"Upgrade {prod}to {' or '.join(fixed)} or later (the first version the NVD's vulnerable ranges exclude).")
    for fp in row.get("fixed_versions_by_product") or []:
        steps.append(f"{fp['product']}: the vulnerable ranges end before {', '.join(fp['versions'])}; upgrade to those or later.")
    for u in tagged(refs, "Patch"):
        steps.append(f"Apply the patch: {u}")
    for u in tagged(refs, "Vendor Advisory"):
        steps.append(f"Follow the vendor advisory: {u}")
    if not fixed and not row.get("fixed_versions_by_product") and not tagged(refs, "Patch", "Vendor Advisory"):
        for u in tagged(refs, "Mitigation", "Third Party Advisory", without=("Exploit", "VDB Entry"))[:3]:
            steps.append(f"No vendor fix is tagged; see the advisory: {u}")
    kev = row.get("kev")
    if kev:
        due = kev.get("dueDate")
        steps.append(
            f"CISA KEV since {kev.get('dateAdded')}"
            + (f", federal due date {due}" if due else "")
            + (": " + kev["requiredAction"].strip() if kev.get("requiredAction") else ".")
        )
        if (kev.get("knownRansomwareCampaignUse") or "").lower() == "known":
            steps.append("Known ransomware campaign use: treat as an active incident risk, not a backlog item.")
    ev = row.get("exploit_evidence")
    if ev and ev["level"] == "public-exploit":
        steps.append(f"Public exploit material exists ({len(ev['evidence'])} reference(s)); prioritise above CVSS alone.")
    if not steps:
        steps.append("No patch, advisory or fixed version is recorded in the NVD references; check the vendor directly.")
    return steps
