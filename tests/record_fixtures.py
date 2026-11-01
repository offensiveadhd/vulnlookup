#!/usr/bin/env python3
"""Re-record the offline fixtures from the live APIs (development only; needs the network).

    python tests/record_fixtures.py

Writes tests/fixtures/responses.json: a map of request URL -> response body, slimmed the way
the tool slims records (so the fixtures stay small) but wrapped back in the APIs' envelopes so
the client code path is the one exercised. KEV is trimmed to the entries the tests use plus
the newest fifty. Re-recording changes EPSS scores and may add CVEs; update the expectations
in test_cli.py deliberately when you do.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "skills" / "vulnlookup" / "scripts"))

from vl import sources  # noqa: E402
from vl.http import _default_fetch, build_url  # noqa: E402

OUT = HERE / "fixtures" / "responses.json"

CVES = ["CVE-2021-44228", "CVE-2021-41773", "CVE-2007-4723", "CVE-2014-0160", "CVE-2024-3094"]
KEYWORDS = ["log4j", "struts", "gitlab", "openssl", "exchange server"]
MATCH_STRINGS = [
    "cpe:2.3:a:apache:http_server:2.4.49",
    "cpe:2.3:a:openssl:openssl:1.1.1",
    "cpe:2.3:a:apache:log4j:2.14.1",
    "cpe:2.3:a:apache:log4j:2.99",
    "cpe:2.3:a:php:php:7.4.0",
]
VMS = [
    "cpe:2.3:a:apache:http_server:2.4.49",
    "cpe:2.3:a:openssl:openssl:1.1.1",
    "cpe:2.3:a:apache:log4j:2.14.1",
    "cpe:2.3:a:apache:log4j:2.99",
    "cpe:2.3:a:apache:http_server",
]
EPSS_BATCHES = [
    CVES,
]
KEEP_KEV = {
    "CVE-2021-44228",
    "CVE-2021-41773",
    "CVE-2021-42013",
    "CVE-2024-38475",
    "CVE-2014-0160",
    "CVE-2024-3094",
    "CVE-2023-25690",
    "CVE-2022-22963",
}


def get(url: str) -> dict:
    status, body = _default_fetch(url, {"User-Agent": "vulnlookup-fixtures", "Accept": "application/json"})
    if status != 200:
        raise SystemExit(f"{status} for {url}")
    return json.loads(body)


def slim_cve_envelope(j: dict) -> dict:
    return {
        "format": j.get("format"),
        "version": j.get("version"),
        "totalResults": j.get("totalResults"),
        "resultsPerPage": j.get("resultsPerPage"),
        "startIndex": j.get("startIndex"),
        "vulnerabilities": [{"cve": sources.slim(v["cve"])} for v in j.get("vulnerabilities", [])],
    }


def slim_cpe_envelope(j: dict) -> dict:
    return {
        "totalResults": j.get("totalResults"),
        "resultsPerPage": j.get("resultsPerPage"),
        "products": [
            {
                "cpe": {
                    "cpeName": p["cpe"]["cpeName"],
                    "deprecated": p["cpe"].get("deprecated", False),
                    "deprecatedBy": p["cpe"].get("deprecatedBy", []),
                    "titles": p["cpe"].get("titles", []),
                }
            }
            for p in j.get("products", [])
        ],
    }


def trim(out: dict) -> None:
    """Keep the fixture file small: 40 dictionary entries per vendor:product for keyword searches,
    400 for match strings, 12 references and a 400-character description per CVE."""
    import collections

    for u, j in out.items():
        if "cpes/2.0" in u:
            per = 40 if "keywordSearch" in u else 400
            seen: collections.Counter = collections.Counter()
            kept = []
            for x in j["products"]:
                g = ":".join(x["cpe"]["cpeName"].split(":")[2:5])
                if seen[g] < per:
                    kept.append(x)
                    seen[g] += 1
            j["products"] = kept
            j["resultsPerPage"] = len(kept)
        if "cves/2.0" in u:
            for v in j["vulnerabilities"]:
                c = v["cve"]
                # keep the tagged references the tool reasons about, then the rest, 12 in all
                want = ("Patch", "Vendor Advisory", "Exploit", "Mitigation")
                refs = sorted(
                    c["references"], key=lambda r: (not any(t in (r.get("tags") or []) for t in want), r.get("url", ""))
                )
                c["references"] = refs[:12]
                for dsc in c["descriptions"]:
                    dsc["value"] = dsc["value"][:400]
                c["metrics"] = {k: m for k, m in c["metrics"].items() if k.startswith("cvss")}


def main() -> None:
    out: dict[str, dict] = {}
    pace = 6.5  # public limit: 5 per 30 s

    def nvd(url: str) -> dict:
        time.sleep(pace)
        print("GET", url)
        return get(url)

    for cve in CVES:
        url = build_url(sources.NVD_CVES, {"cveId": cve})
        out[url] = slim_cve_envelope(nvd(url))
    for kw in KEYWORDS:
        url = build_url(sources.NVD_CPES, {"keywordSearch": kw, "resultsPerPage": sources.CPE_PAGE})
        out[url] = slim_cpe_envelope(nvd(url))
    for ms in MATCH_STRINGS:
        url = build_url(sources.NVD_CPES, {"cpeMatchString": ms, "resultsPerPage": sources.CPE_PAGE})
        out[url] = slim_cpe_envelope(nvd(url))
    for vms in VMS:
        url = build_url(sources.NVD_CVES, {"virtualMatchString": vms, "resultsPerPage": sources.CVE_PAGE, "startIndex": 0})
        j = slim_cve_envelope(nvd(url))
        if vms == "cpe:2.3:a:apache:http_server":
            # keep the fixture small: only the records the tests reason about
            keep = {
                "CVE-2021-41773",
                "CVE-2021-42013",
                "CVE-2024-38475",
                "CVE-2006-20001",
                "CVE-2007-4723",
                "CVE-2023-25690",
                "CVE-2017-7679",
                "CVE-2011-3192",
            }
            j["vulnerabilities"] = [v for v in j["vulnerabilities"] if v["cve"]["id"] in keep]
            j["totalResults"] = len(j["vulnerabilities"])
            j["resultsPerPage"] = len(j["vulnerabilities"])
        out[url] = j
    for batch in EPSS_BATCHES:
        url = build_url(sources.EPSS, {"cve": ",".join(sorted(batch))})
        print("GET", url)
        out[url] = get(url)
    # EPSS for every CVE the matched fixtures contain, in the batches the tool will form
    ids = sorted({v["cve"]["id"] for u, j in out.items() if "cves/2.0" in u for v in j["vulnerabilities"]})
    for n in range(0, len(ids), sources.EPSS_BATCH):
        batch = ids[n : n + sources.EPSS_BATCH]
        url = build_url(sources.EPSS, {"cve": ",".join(batch)})
        print("GET", url)
        out[url] = get(url)
    print("GET", sources.KEV)
    kev = get(sources.KEV)
    vulns = kev["vulnerabilities"]
    keep = [v for v in vulns if v["cveID"] in KEEP_KEV or v["cveID"] in ids]
    newest = sorted(vulns, key=lambda v: v["dateAdded"], reverse=True)[:50]
    seen = set()
    trimmed = []
    for v in keep + newest:
        if v["cveID"] not in seen:
            seen.add(v["cveID"])
            trimmed.append(v)
    kev["vulnerabilities"] = trimmed
    kev["count"] = len(trimmed)
    out[sources.KEV] = kev
    trim(out)
    OUT.write_text(json.dumps(out, indent=0, sort_keys=True), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(out)} responses)")


if __name__ == "__main__":
    main()
