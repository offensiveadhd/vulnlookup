# The three APIs, as the tool uses them

Verified against live responses on 2026-11-01. Nothing else is called.

## NVD CVE API 2.0 — `https://services.nvd.nist.gov/rest/json/cves/2.0`

| Parameter | Used for | Notes |
|---|---|---|
| `cveId=CVE-YYYY-NNNN` | `cve` | one id per request; no bulk form exists |
| `virtualMatchString=cpe:2.3:a:vendor:product[:version]` | `product`, `cpe` | the NVD compares it against every CVE's match criteria **including version ranges**, so `…:http_server:2.4.49` returns the `versionEndExcluding: 2.4.52` records too. Every record is re-checked locally afterwards |
| `resultsPerPage` (max 2000), `startIndex` | pagination | a product with > 2000 CVEs takes several requests |
| `pubStartDate` / `pubEndDate`, `lastModStartDate` / `lastModEndDate` | not used for queries | the window is capped at 120 consecutive days, so year filters are applied locally on `published` instead of spending requests |
| `hasKev`, `cvssV3Severity`, `keywordSearch` | not used | all filtering is local, after verification, so filtered counts are consistent with unfiltered ones |

Header `apiKey: <key>` when a key is configured. Limits: 5 requests per rolling 30 s without a
key, 50 with one (nvd.nist.gov/developers/start-here). The NVD answers **403** (sometimes 429
or 503) when the window is exceeded; the client backs off 6 s, 12 s, 24 s, 48 s.

Record shape (`vulnerabilities[].cve`): `id`, `published`, `lastModified`, `vulnStatus`
(`Analyzed`, `Modified`, `Awaiting Analysis`, `Received`, `Deferred`, `Rejected`),
`descriptions[{lang,value}]`, `metrics{cvssMetricV40?, cvssMetricV31?, cvssMetricV30?,
cvssMetricV2?}` each a list of `{source, type: Primary|Secondary, cvssData{version,
vectorString, baseScore, baseSeverity}}`, `weaknesses[].description[{value: CWE-n}]`,
`configurations[{operator?: AND|OR, nodes[{operator, negate, cpeMatch[{vulnerable, criteria,
versionStartIncluding?, versionStartExcluding?, versionEndIncluding?, versionEndExcluding?,
matchCriteriaId}]}]}]`, `references[{url, source, tags[]}]`, and when CISA lists it:
`cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName`.

Reference tags seen: `Exploit`, `Patch`, `Vendor Advisory`, `Third Party Advisory`,
`Mitigation`, `VDB Entry`, `Mailing List`, `Issue Tracking`, `Release Notes`, `Product`,
`Technical Description`, `US Government Resource`, `Press/Media Coverage`, `Broken Link`.

## NVD CPE API 2.0 — `https://services.nvd.nist.gov/rest/json/cpes/2.0`

| Parameter | Used for |
|---|---|
| `keywordSearch=<words>` | `resolve`: every dictionary entry whose title or name contains all the words (`log4j` → 278 entries across `apache:log4j`, `log4js_project:log4js`, `amazon:hotpatch`) |
| `cpeMatchString=cpe:2.3:a:vendor:product:version` | the version snap: is this version in the dictionary, and under which spelling |
| `resultsPerPage` (max 10000) | one page is enough for a product |

Entry shape (`products[].cpe`): `cpeName`, `cpeNameId`, `deprecated`, `deprecatedBy[{cpeName}]`,
`titles[{title, lang}]`, `refs`, `created`, `lastModified`. Deprecated entries point at their
replacement; the snap follows one hop when the replacement is the same vendor:product.

The CPE Match API (`/cpematch/2.0`, `cveId=` or `matchStringSearch=`) returns the match
criteria of a CVE with the dictionary names each resolves to. Not needed here: the
configurations inside the CVE record carry the same criteria and the tool evaluates them
itself.

## FIRST EPSS — `https://api.first.org/data/v1/epss`

`?cve=CVE-A,CVE-B,…` (up to 100 per call; the tool batches 100), optional `date=YYYY-MM-DD`
and `scope=time-series` (not used). Response: `data[{cve, epss, percentile, date}]`, the
numbers as strings. A CVE without a score is simply absent. Scores are recomputed daily, so
the `date` is shown with the score.

## CISA KEV — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

One file (~1.8 MB, ~1,800 entries), cached 24 h. Entry: `cveID`, `vendorProject`, `product`,
`vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`,
`knownRansomwareCampaignUse` (`Known` | `Unknown`), `notes`, `cwes[]`. The tool keeps
`catalogVersion` and `dateReleased` from the header and indexes entries by id. When the feed
cannot be fetched, the NVD record's `cisaExploitAdd` / `cisaActionDue` fields stand in
(they lack the ransomware flag).

## CPE 2.3 (NISTIR 7695 / 7696) in two paragraphs

A name is `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`.
`part` is `a` (application), `o` (OS) or `h` (hardware). `*` is ANY, `-` is NA ("no update").
Everything outside `[A-Za-z0-9_.-]` is `\`-escaped (`notepad\+\+`). `*` and `?` inside a
component are wildcards (`2.4.*`). Matching is tri-state: a criteria `*` matches anything; a
criteria value against a target the user did not specify is *unknown*; otherwise equality
(or the wildcard pattern).

A CVE's applicability is a list of configurations, each a list of nodes. A node is an `OR`
over `cpeMatch` criteria; a configuration whose `operator` is `AND` requires every node
(typically "the vulnerable product" AND "the platform it runs on", the platform node's criteria
carrying `vulnerable: false`). `negate: true` names what is *not* affected. A criteria with a
`*` version plus `versionStart…`/`versionEnd…` bounds is a range; the bounds are compared as
versions, not strings.
