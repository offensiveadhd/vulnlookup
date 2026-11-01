"""The three data sources behind the tool, each read through the cache.

* NVD CVE API 2.0        services.nvd.nist.gov/rest/json/cves/2.0
* NVD CPE API 2.0        services.nvd.nist.gov/rest/json/cpes/2.0
* FIRST EPSS             api.first.org/data/v1/epss
* CISA KEV catalogue     www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Only CVE ids, CPE strings and product keywords ever leave the machine, as query parameters to
those hosts. ``--offline`` answers from the cache and marks stale entries.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any

from .cache import Cache
from .http import Client, OfflineError, build_url

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVE_PAGE = 2000
CPE_PAGE = 10000
EPSS_BATCH = 100


@dataclass
class Fetched:
    value: Any
    source: str  # "network" | "cache" | "stale-cache"
    age_s: float = 0.0


@dataclass
class Sources:
    client: Client
    cache: Cache
    stale: list[str] = field(default_factory=list)  # cache keys answered stale under --offline

    # ------------------------------------------------------------------ plumbing
    def _get(self, source: str, key: str, url: str, reduce: Any = None) -> Fetched:
        hit = self.cache.get(source, key)
        if hit and hit.fresh:
            return Fetched(hit.value, "cache", hit.age)
        if self.client.offline:
            if hit:
                self.stale.append(key)
                return Fetched(hit.value, "stale-cache", hit.age)
            raise OfflineError(key)
        try:
            raw = self.client.get_json(url)
        except Exception:
            if hit:  # network failed but we have something: say so and go on
                self.stale.append(key)
                print(f"warning: network failed for {source}; using cache from {hit.age / 3600:.1f} h ago", file=sys.stderr)
                return Fetched(hit.value, "stale-cache", hit.age)
            raise
        value = reduce(raw) if reduce else raw
        self.cache.put(source, key, value)
        return Fetched(value, "network")

    # ------------------------------------------------------------------ CVEs
    def cve(self, cve_id: str) -> dict[str, Any] | None:
        cve_id = cve_id.upper()
        url = build_url(NVD_CVES, {"cveId": cve_id})
        got = self._get("cve", f"cveId={cve_id}", url, lambda j: [slim(v["cve"]) for v in j.get("vulnerabilities", [])])
        return got.value[0] if got.value else None

    def cves_matching(self, match_string: str, **params: Any) -> list[dict[str, Any]]:
        """Every CVE whose applicability statements match ``match_string`` (the NVD applies the
        version ranges server side; the caller re-checks every record locally)."""
        base = {"virtualMatchString": match_string, "resultsPerPage": CVE_PAGE}
        base.update({k: v for k, v in params.items() if v is not None})
        key = "vms:" + "&".join(f"{k}={base[k]}" for k in sorted(base))
        return self._paged(key, base)

    def _paged(self, key: str, base: dict[str, Any]) -> list[dict[str, Any]]:
        hit = self.cache.get("cve", key)
        if hit and hit.fresh:
            return hit.value
        if self.client.offline:
            if hit:
                self.stale.append(key)
                return hit.value
            raise OfflineError(key)
        out: list[dict[str, Any]] = []
        start = 0
        while True:
            params = dict(base, startIndex=start)
            j = self.client.get_json(build_url(NVD_CVES, params))
            out.extend(slim(v["cve"]) for v in j.get("vulnerabilities", []))
            total = int(j.get("totalResults", 0))
            start += int(j.get("resultsPerPage", CVE_PAGE)) or CVE_PAGE
            if start >= total or not j.get("vulnerabilities"):
                break
        out.sort(key=lambda c: c["id"])
        self.cache.put("cve", key, out)
        return out

    # ------------------------------------------------------------------ CPE dictionary
    def cpe_keyword(self, text: str) -> list[dict[str, Any]]:
        url = build_url(NVD_CPES, {"keywordSearch": text, "resultsPerPage": CPE_PAGE})
        return self._get("cpe", f"kw={text.lower()}", url, lambda j: [slim_cpe(p["cpe"]) for p in j.get("products", [])]).value

    def cpe_match(self, match_string: str) -> list[dict[str, Any]]:
        url = build_url(NVD_CPES, {"cpeMatchString": match_string, "resultsPerPage": CPE_PAGE})
        return self._get("cpe", f"ms={match_string}", url, lambda j: [slim_cpe(p["cpe"]) for p in j.get("products", [])]).value

    # ------------------------------------------------------------------ EPSS
    def epss(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        ids = sorted({i.upper() for i in ids})
        out: dict[str, dict[str, Any]] = {}
        missing: list[str] = []
        for i in ids:
            hit = self.cache.get("epss", i)
            if hit and (hit.fresh or self.client.offline):
                if not hit.fresh:
                    self.stale.append("epss:" + i)
                if hit.value:
                    out[i] = hit.value
            else:
                missing.append(i)
        if missing and self.client.offline:
            return out
        for n in range(0, len(missing), EPSS_BATCH):
            batch = missing[n : n + EPSS_BATCH]
            try:
                j = self.client.get_json(build_url(EPSS, {"cve": ",".join(batch)}))
            except Exception as e:  # EPSS is enrichment; a failure must not hide the CVEs
                print(f"warning: EPSS unavailable ({e}); scores left blank", file=sys.stderr)
                return out
            got = {
                d["cve"].upper(): {"epss": float(d["epss"]), "percentile": float(d["percentile"]), "date": d["date"]}
                for d in j.get("data", [])
            }
            for i in batch:
                self.cache.put("epss", i, got.get(i))
                if i in got:
                    out[i] = got[i]
        return out

    # ------------------------------------------------------------------ KEV
    def kev(self) -> dict[str, dict[str, Any]]:
        def reduce(j: dict[str, Any]) -> dict[str, Any]:
            return {
                "catalogVersion": j.get("catalogVersion"),
                "count": j.get("count"),
                "byId": {
                    v["cveID"].upper(): {
                        "dateAdded": v.get("dateAdded"),
                        "dueDate": v.get("dueDate"),
                        "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
                        "vulnerabilityName": v.get("vulnerabilityName"),
                        "requiredAction": v.get("requiredAction"),
                        "vendorProject": v.get("vendorProject"),
                        "product": v.get("product"),
                        "notes": v.get("notes", ""),
                    }
                    for v in j.get("vulnerabilities", [])
                },
            }

        try:
            return self._get("kev", "feed", KEV, reduce).value
        except OfflineError:
            raise
        except Exception as e:
            print(f"warning: KEV feed unavailable ({e}); falling back to the NVD's cisaExploitAdd field", file=sys.stderr)
            return {"catalogVersion": None, "count": 0, "byId": {}}


# ---------------------------------------------------------------------- slimming


def slim(c: dict[str, Any]) -> dict[str, Any]:
    """Keep what the rows, the matching and the recommendations need; a full record is 4-90 KB."""
    return {
        "id": c["id"],
        "published": c.get("published"),
        "lastModified": c.get("lastModified"),
        "vulnStatus": c.get("vulnStatus"),
        "descriptions": [d for d in c.get("descriptions", []) if d.get("lang") == "en"][:1],
        "metrics": c.get("metrics", {}),
        "weaknesses": c.get("weaknesses", []),
        "configurations": c.get("configurations", []),
        "references": _dedupe_refs(c.get("references", [])),
        "cisaExploitAdd": c.get("cisaExploitAdd"),
        "cisaActionDue": c.get("cisaActionDue"),
        "cisaRequiredAction": c.get("cisaRequiredAction"),
        "cisaVulnerabilityName": c.get("cisaVulnerabilityName"),
        "cveTags": c.get("cveTags", []),
    }


def _dedupe_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The NVD lists the same URL once per source that cited it; one copy, union of tags."""
    out: dict[str, dict[str, Any]] = {}
    for r in refs:
        url = r.get("url", "")
        if url in out:
            out[url]["tags"] = sorted(set(out[url]["tags"]) | set(r.get("tags") or []))
        else:
            out[url] = {"url": url, "source": r.get("source"), "tags": sorted(r.get("tags") or [])}
    return list(out.values())


def slim_cpe(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "cpeName": p["cpeName"],
        "deprecated": bool(p.get("deprecated")),
        "deprecatedBy": [d["cpeName"] for d in p.get("deprecatedBy", [])],
        "title": next((t["title"] for t in p.get("titles", []) if t.get("lang") == "en"), ""),
    }
