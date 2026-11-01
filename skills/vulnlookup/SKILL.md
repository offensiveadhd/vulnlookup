---
name: vulnlookup
description: Passive vulnerability lookup - CVE, CPE, EPSS and CISA KEV - against the NVD, FIRST and CISA, with no scanning and no guessing. Use it whenever the user names a CVE id, asks what is known or filed against a product or a version ("is nginx 1.18 vulnerable", "CVEs for openssl 1.1.1", "what hits Apache httpd 2.4.49"), pastes a CPE string or a Server header, asks for EPSS scores, exploit probability, whether something is in KEV / actively exploited / has a public PoC, wants a remediation or patch checklist for a CVE list, or wants vulnerabilities filtered by severity, year, CWE or exploitation. Also use it for bulk jobs (a file of CVEs, CPEs or products) and for resolving a product name to its CPE. Scripts do the lookups deterministically; you only classify the request and, when the dictionary is ambiguous, pick or ask.
license: MIT
metadata:
  version: 1.0.0
  author: TikoTikTok
  hermes:
    tags: [cve, cpe, epss, kev, nvd, vulnerability-management, passive, security]
    category: security
---

# vulnlookup

A passive lookup. It scans nothing and asks nothing of the target: every request goes to
`services.nvd.nist.gov`, `api.first.org` and `www.cisa.gov`, carrying only CVE ids, CPE
strings and product keywords. The script (`scripts/vulnlookup.py`, Python 3.10+, standard
library only) does the work; your job is to decide **what was asked** and run exactly one
command for it. Do not compute scores, ranges or verdicts yourself: the script re-checks every
NVD configuration node locally, names the node that matched and its bounds, and drops anything
it cannot confirm. Two identical commands print identical output, so you can quote it as is.

```
S=skills/vulnlookup/scripts/vulnlookup.py        # path relative to this skill's parent; adjust
python $S --help
```

## 1. Classify the request, then run one command

| The user asks for | Kind | Command |
|---|---|---|
| One CVE: "what is CVE-2021-44228", "is X in KEV", "EPSS of CVE-…" | `cve` | `python $S cve CVE-2021-44228` |
| Several CVE ids in the text or a file | `cve` (bulk) | `python $S cve CVE-… CVE-… ` or `python $S cve --file list.txt` |
| A product **and** version: "apache httpd 2.4.49", "nginx/1.18.0", a `Server:` header | `product+version` | `python $S product "apache httpd 2.4.49"` |
| A product, no version: "what's filed against openssl" | `product` | `python $S product openssl` |
| Product + the OS / platform it runs on | `product+os` | `python $S product "ragnarok online control panel 4.3.4a" --on "apache http server"` |
| A product over a time range: "openssl CVEs 2019-2024" | `product+years` | `python $S product openssl --years 2019-2024` |
| "Everything above 2.x", a version floor with no exact version | `product+floor` | `python $S product "apache httpd" --version-from 2.0` |
| A CPE 2.3 string, verbatim | `cpe` | `python $S cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"` |
| Many CPEs / many products / many CVEs from files | `bulk` | `python $S bulk --cpes cpes.txt` · `--products products.txt` · `--cves cves.txt` |
| Many products × many versions ("these 5 packages at these versions") | `bulk` (many-to-many) | write one `name version` per line, then `python $S bulk --products file` |
| "Which CPE is this", "resolve log4j to a CPE" | `resolve` | `python $S resolve "log4j 2.14.1"` |
| KEV only: "what did CISA add this week", "is this in KEV" | `kev` | `python $S kev --recent 20` · `python $S kev CVE-…` · `python $S kev --search ivanti` |
| EPSS only | `epss` | `python $S epss CVE-… CVE-…` |
| Key / cache housekeeping | `key`, `cache` | `python $S key status` · `python $S cache stats` |

Then compose the **mission** with filters and modes; they stack in one command and apply after
the local verification, so the counts stay honest:

| Ask | Flag |
|---|---|
| "critical only", "CVSS 9+" | `--severity CRITICAL` / `--min-cvss 9` |
| "actively exploited", "in KEV", "ransomware" | `--kev`, `--ransomware` |
| "likely to be exploited", "EPSS above 10 %" | `--min-epss 0.1` |
| "published 2019 to 2024" | `--years 2019-2024` |
| "only XSS / only CWE-79" | `--cwe CWE-79` (repeatable) |
| "is there a PoC / exploit", "weaponised?" | `--poc` (evidence from references + KEV, never a verdict) |
| "what do we patch", "remediation", "fix versions" | `--recommend` |
| "the worst first", "top 10" | `--sort cvss` or `--sort epss`, `--limit 10` |
| "show me the ones you dropped" | `--include-unverified` |

Example mission, one command: *"Apache httpd above 2.0 that is in KEV, with PoC evidence and
what to do about each"*:

```
python $S product "apache httpd" --version-from 2.0 --kev --poc --recommend --format md
```

## 2. Pick the output for the audience

`--format table|json|md|csv|brief` × `--style terse|analyst|executive`. Defaults: `table`,
`analyst`. Choose by who will read it, and say which you used when it is not the default:

| Style | For | What it prints |
|---|---|---|
| `terse` | a quick answer, a chat reply, a pipeline | one row per CVE: id, CVSS, EPSS, KEV, verdict |
| `analyst` | an engineer who will act on it | the table, then per CVE: vector, EPSS percentile and date, KEV dates, CWE, the **matched criteria and bounds**, fixed versions, exploit evidence, remediation, description |
| `executive` | a manager, a ticket summary | a one-paragraph summary (counts, KEV, EPSS, PoC) and "act first" (KEV, then CVSS), then the table |

`json` is for programs and for you when you need to reason over fields (`sort_keys`, stable).
`md` pastes into tickets and reports. `csv` is for spreadsheets. `brief` is the terse table
without the box. The user can switch at any time ("make that executive"): rerun with the
new style, nothing else changes, the rows are the same.

## 3. The ambiguity protocol (the one place you decide)

`product` and `resolve` try the alias table first (`references/aliases.json`, 250+ products
in the spellings people type, every pair verified against the NVD), then the NVD CPE
dictionary. They return a single CPE **only** when the product-name match is exact and
unrivalled. Otherwise the script prints candidates to stderr and JSON to stdout and exits
**3**:

```
ambiguous: 'exchange server' matches 3 products in the NVD dictionary. Pick one ...
  0.95  a:microsoft:exchange_server      Microsoft Exchange Server      vendor and product are exactly what you typed
  0.60  a:microsoft:exchange_server_2019 ...                           your words are part of a longer product name
```

When that happens:

1. If the user's wording settles it (they said the vendor, the edition, the platform), rerun
   with `--pick part:vendor:product`, and say which you picked and why in one line.
2. Otherwise ask the user, quoting the candidates with their confidence. Do not pick by
   popularity, do not guess.

The version is never guessed either. If the typed version is not in the dictionary the
subject line says so (`version NOT in the NVD dictionary; typed as given`) and only range
criteria can match it; pass that sentence on. When the dictionary spells it differently
(`u5` → `update_5`, a deprecated entry replaced by its successor) the script uses the
dictionary's spelling and says so.

## 4. What the verdicts mean (read before you summarise)

Each row of a product / CPE query carries the verdict of the local re-check against the
NVD configuration tree, and the matched criteria with its bounds:

| Verdict | Shown by default | Meaning |
|---|---|---|
| `EXACT` | yes | a vulnerable criteria names this exact version |
| `RANGE` | yes | inside a `versionStart…`/`versionEnd…` range the comparator can prove |
| `ANY` | yes | the vulnerable criteria is `*` with no range: every version. True more often than not; say "the NVD lists every version" rather than "confirmed for this version" |
| `LISTED` | yes | product query without a version: the product is named vulnerable; nothing was checked against a version |
| `COND` | no (counted) | matches, but the configuration is an `AND` with a platform the user did not name ("vulnerable when running on Windows"). Offer `--on "<platform>"` |
| `MAYBE` | no (counted) | the comparator will not guess: an unknown word in the version, a pre-release on a range boundary, an update the record wants that the user did not give. The reason is in `why` |
| `PLATFORM` | never | the product appears only as `vulnerable: false`, the thing the real bug runs on. This is where most CPE false positives come from |
| `NVD-only` | no (counted) | the NVD's matcher returned it, no node fits locally. Kept countable so a comparator disagreement never hides a finding |

The footer `Not counted (shown with --include-unverified): COND 3` is part of the answer:
mention it when it is non-zero. Never promote a COND / MAYBE / NVD-only row to "vulnerable" in
your own words.

## 5. Facts to carry into your answer, unchanged

- CVSS is whichever the record has, newest first (4.0, 3.1, 3.0, 2.0), with the vector.
- EPSS is a probability shown truncated to three decimals (0.999 is not 1.000) with its
  percentile and date; it changes daily, so the date matters.
- KEV carries `dateAdded`, `dueDate` (the federal deadline) and `knownRansomwareCampaignUse`.
  "KEV" means observed exploitation, not "has a PoC".
- `--poc` levels: `exploited-in-the-wild` (KEV), `public-exploit` (an `Exploit`-tagged
  reference or a known exploit host: Exploit-DB, Packet Storm, Metasploit, nuclei, a PoC
  GitHub repository), `no-public-evidence`. Repeat the script's own line: this is **evidence
  found in the references, not a judgement of exploitability**.
- `--recommend` lists the first fixed version implied by `versionEndExcluding`, the
  `Patch` and `Vendor Advisory` references, and the KEV deadline and required action. It is
  a checklist from the record, not vendor guidance.
- Exit codes: 0 done · 1 error · 2 usage · 3 ambiguous · 4 nothing found · 5 offline and
  not cached. On 4 for a `cve`, the id is not in the NVD (typo, or reserved / rejected).

## 6. Speed, cache, the key

- The NVD allows 5 requests per 30 s without a key, 50 with one; the script paces itself
  and shares the window across processes. A product with hundreds of CVEs is one or two
  requests; a list of 40 CVE ids is 40 requests (about four minutes unkeyed). Say so
  before running a long one, or suggest a key.
- Cache: KEV 24 h, EPSS 24 h, CPE dictionary 7 d, CVE results 6 h, under the user's cache
  dir (`cache path`). `--offline` answers from it and marks stale rows. `--ttl cve=1`
  overrides. `--no-cache` bypasses.
- Key: `python $S key set` (reads from stdin; stored in Windows Credential Manager, macOS
  Keychain or the Secret Service, else a 0600 file with a warning), `key status` shows
  presence and the last four characters only, `key clear`. `NVD_API_KEY` in the environment
  wins. Never ask the user to paste the key into the chat; point them at `key set`.

## 7. Files

- `scripts/vulnlookup.py` the entry point; `scripts/vl/` the engine (`cpe.py` strings,
  versions, matching; `resolve.py` aliases, ranking, the snap; `sources.py` the three APIs;
  `enrich.py` rows, exploit evidence, remediation; `render.py` formats and styles;
  `keystore.py`; `cache.py`; `http.py` pacing and backoff).
- `references/aliases.json` the product aliases and qualifier ranks. Add a product = add
  an entry.
- `references/api-notes.md` the three APIs as used (parameters, limits, field shapes).
- `references/cpe-matching.md` how a version is compared and a configuration tree walked,
  with the cases that produce false positives elsewhere.
- `references/output-styles.md` the formats and styles, with samples.
- `assets/products.example.txt`, `assets/cpes.example.txt` input files for `bulk`.
