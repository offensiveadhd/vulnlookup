# Test cases

Two layers. **The prompt layer** is what a person says to an agent and the one command the
skill must turn it into (`skills/vulnlookup/SKILL.md` §1). **The script layer** is
`tests/`: every query kind, the guards, the formats, the key store, run offline against
`tests/fixtures/responses.json` (recorded from the live APIs on 2026-11-01; re-record with
`python tests/record_fixtures.py`). CI runs the script layer on Ubuntu, Windows and macOS with
Python 3.10 to 3.13.

## 1. Prompt → command (the model's part)

| # | Prompt (as a user would type it) | Kind | Expected command | Expected shape |
|---|---|---|---|---|
| P1 | "what's CVE-2021-44228" | one CVE | `cve CVE-2021-44228` | 1 row, CVSS 10.0, KEV 2021-12-10 ransomware Known, EPSS ≈ 0.999, CWE-20/400/502/917 |
| P2 | "give me the epss for CVE-2021-44228 and CVE-2021-41773" | EPSS only | `epss CVE-2021-44228 CVE-2021-41773` | two lines, score + percentile + date |
| P3 | "is CVE-2014-0160 in KEV?" | KEV only | `kev CVE-2014-0160` | one line: `KEV added 2022-05-04 …` |
| P4 | "we run apache httpd 2.4.49, what hits us?" | product+version | `product "apache httpd 2.4.49"` | subject line via alias, version in dictionary; CVE-2021-41773 `EXACT [= 2.4.49]`, CVE-2021-44224 `RANGE [>= 2.4.7 < 2.4.52]`; footer `COND n`; no CVE-2007-4723 |
| P5 | "Server: Apache/2.4.49 (Ubuntu)" (a pasted header) | product+version | `product "Server: Apache/2.4.49 (Ubuntu)"` | same as P4 (the parser strips the header name and the parenthesis) |
| P6 | "openssl 1.1.1 - anything critical and exploited?" | product+version, filters | `product "openssl 1.1.1" --severity CRITICAL --kev` | rows only where both hold; `excluded: PLATFORM 1` never shown |
| P7 | "what is filed against openssl at all" | product only | `product openssl` | every row `LISTED`; three vendor pairs queried (openssl, openssl_project, …) |
| P8 | "openssl CVEs between 2019 and 2024, markdown please" | product+years | `product openssl --years 2019-2024 --format md` | Markdown table, published 2019…2024 only |
| P9 | "apache httpd above 2.x that is in KEV, with PoC evidence and what to do" | product+floor, mission | `product "apache httpd" --version-from 2.0 --kev --poc --recommend` | KEV rows whose criteria reach 2.0+, `Exploit` column, `remediation:` lists |
| P10 | "ragnarok online control panel 4.3.4a on apache" | product+os | `product "ragnarok online control panel 4.3.4a" --on "apache http server"` | COND resolves to EXACT when the platform is named (engine-level test; the panel is not in the alias table so this goes through the dictionary) |
| P11 | "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" | one CPE | `cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"` | as P4 without the resolution step |
| P12 | "check these" + a file of 40 CVE ids | bulk CVEs | `cve --file ids.txt` (warn: 40 NVD requests ≈ 4 min unkeyed) | one table, `not in the NVD: …` note for typos |
| P13 | "run this list of packages at these versions" | many-to-many | `bulk --products list.txt` | one section per line; ambiguous lines reported, not guessed |
| P14 | "which CPE is log4j" | resolve | `resolve log4j` | `cpe:2.3:a:apache:log4j:*:…` via alias |
| P15 | "resolve gitlab" (alias table disabled, dictionary only) | resolve, ambiguous | `resolve gitlab` → exit 3 | candidates `a:gitlab:gitlab` 1.00 and `a:jenkins:gitlab` 0.99: the model asks or picks on wording |
| P16 | "log4j 2.99" | version not in dictionary | `product "log4j 2.99"` | 0 rows, exit 4, subject says `version NOT in the NVD dictionary; typed as given` |
| P17 | "the five worst for httpd 2.4.49, for my manager" | style | `product "apache httpd 2.4.49" --sort cvss --limit 5 --style executive` | summary paragraph + "Act first" |
| P18 | "same but as a one-liner each" | style switch | rerun with `--style terse --format brief` | identical rows, one line each |
| P19 | "store my NVD key" | key | `key set` (stdin) | `stored in the credential-manager` (Windows) / keychain / secret-service / file + warning; never echo |
| P20 | "do I have a key configured?" | key | `key status` | `present (…abcd, from credential-manager)` or `none` |
| P21 | "work offline from what you have" | offline | add `--offline` | cached answers, `note: n answer(s) came from a stale cache`; exit 5 when nothing cached |

## 2. Script layer (`python -m pytest -q`)

### `tests/test_cpe.py` — the engine (72 tests)

| Area | Cases |
|---|---|
| Version ordering | 29 pairs: numeric, `2.4 == 2.4.0`, patch letters (`1.0.2k`), glued qualifiers (`1.0a1`), rc/beta/alpha, `update_5`, `9.3p1`, `-r1`, `v` prefix, leading zeros, build numbers, dates, `esr`, `sp1` |
| Certainty | `4.av4` vs `4.1` uncertain; `4.av4 == 4.av4` certain; unknown vs unknown uncertain |
| Update normalisation | `update_5` = `u5`, `Service Pack 1` = `sp1`, `a1` → `alpha1` |
| CPE strings | parse, escapes (`joomla\!`, `notepad\+\+`), round trip, wildcard versions, short names padded, junk rejected, prefix match strings |
| Tri-state attributes | the six NISTIR 7696 cases |
| Criteria | exact hit/miss, range edges incl/excl, `1.0.2k` vs `< 1.0.2k`, foreign product, any-version, pre-release on both boundaries → unknown, update rules (`:-`, `alpha1`, `update_5` = `u5`), uncertain → unknown, `target_sw` is a note |
| Whole configurations | Ragnarok/Apache: `PLATFORM` for Apache, `COND` for the panel, `EXACT` when the platform is given; Log4Shell ranges for 9 versions; the matched node id and bounds; `2.0:-` vs `2.0:beta9`; fixed versions; negated nodes; AND with a failing sibling |

### `tests/test_resolve.py` — parsing and resolution (24 tests)

Query parsing for 13 spellings (header, slash, glued update, `update 5`, `p1`); alias hits
(nginx's three vendors), the Windows 10 family; dictionary ranking: log4j beats log4js,
struts, **gitlab ambiguous** (gitlab:gitlab vs jenkins:gitlab) and settled by "jenkins
gitlab", exchange server; version snap: exact entry, deprecated `openssl 1.1.1:*` → `1.1.1:-`
without restricting the query, not-in-dictionary kept as typed, `alpha1` spelling; the alias
file is well formed and no spelling is claimed twice.

### `tests/test_cli.py` — end to end (≈ 55 tests)

| Group | What is pinned |
|---|---|
| CVE | brief/terse exact bytes for CVE-2021-44228; JSON fields; ids extracted from a file; unknown id → exit 4 and `not_found`; no id → exit 2 |
| Product + version | httpd 2.4.49: targets, alias, snap, `EXACT`/`RANGE` with bounds, fixed version 2.4.52, Ragnarok absent, every shown verdict confirmed, `nvd_returned == confirmed + excluded`; COND hidden by default and shown flagged with `--include-unverified`; openssl 1.1.1: 55 returned, 54 shown, `PLATFORM 1`; log4j 2.14.1 `RANGE [>= 2.13.0 < 2.15.0]` fixed 2.15.0; log4j 2.99 → nothing invented |
| Product only / floors / years | `LISTED`; `--version-from 2.4.55` keeps `<= 2.4.55` and `< 2.4.60`, drops `< 2.4.55` and exact 2.4.49; `--years 2021`, `2022-2023` |
| Filters and modes | `--kev --min-cvss 9 --poc --recommend` → exactly the three KEV criticals, evidence `exploited-in-the-wild` with Packet Storm, remediation steps incl. KEV deadline and ransomware; `--cwe`, `--severity`, `--min-epss`; `--sort cvss --limit 3` |
| CPE / bulk / resolve | verbatim CPE; junk rejected; products file with comments → `[3, 2, 0]` KEV rows; CSV gains a `subject` column; resolve ok; ambiguous → exit 3 + candidates; `--pick`; nothing → exit 4 |
| KEV / EPSS | ids, `--recent`, `--search`; EPSS for two ids |
| Formats × styles | all 15 combinations render and contain the KEV CVE; executive has "Act first"; analyst shows `[= 2.4.49]` and the evidence line; footer counts; terse has no footer |
| **Determinism** | four commands run twice (cache) and once more `--no-cache`: byte-identical; the second run makes zero requests |
| Offline | cached → answers; not cached → exit 5 |
| Options order | before and after the subcommand give the same bytes |
| Key | file store set/status/clear with the warning; junk rejected; env wins and reaches only `services.nvd.nist.gov`; key never in output or cache |
| Cache | stats, clear by source, path |

### `tests/test_http_cache.py` — plumbing (13 tests)

URL encoding; the rolling-window pacer (waits, persists, shared); backoff 6/12 s then success;
gives up after retries; 404 not retried; keyed window = 50; TTL fresh/stale/clear; disabled
cache; atomic hashed files; key file fallback mode 0600 (POSIX); validation; a real
Credential Manager round trip when `VULNLOOKUP_TEST_CREDMAN=1` (Windows).

### `tests/test_live.py` — opt-in (`VULNLOOKUP_LIVE=1`)

Log4Shell record shape; httpd 2.4.49 still `EXACT` with no platform rows; resolve + snap;
version-not-in-dictionary wording. About a dozen requests.

### `tests/check_skill.py` — the skill-format gate

Frontmatter (name = folder, description 60–1024 chars, license, metadata.version =
`vl.__version__`), body under 500 lines, every `scripts/ references/ assets/` path in SKILL.md
exists, every command in SKILL.md parses with the real argument parser, the three plugin
manifests agree, the example input files are valid.

## 3. Live checks run during development (2026-11-01)

| Query | Result |
|---|---|
| `cve CVE-2021-44228 --format brief --style terse` | `CVE-2021-44228  10.0 CRIT  EPSS 0.999  KEV+ransomware` |
| `product "apache httpd" 2.4.49 --poc --recommend` | 88 returned by the NVD, 61 confirmed (3 `EXACT`, 58 `RANGE`), `COND 3` not counted, 0 `PLATFORM` rows shown; CVE-2021-41773 / 42013 / 2024-38475 in KEV |
| `product "openssl 1.1.1"` | 55 returned, 54 confirmed (4 `EXACT`, 50 `RANGE`), 1 `PLATFORM` dropped; the deprecated `1.1.1:*` → `1.1.1:-` snap handled (a first cut asked only for `-` criteria and saw 2 CVEs: fixed, pinned) |
| `resolve "log4j 2.14.1"` | `cpe:2.3:a:apache:log4j:2.14.1:*:…`, exact dictionary entry |
| `resolve jenkins`, `resolve "struts 2.3.5"`, `resolve spring` | alias / dictionary, unambiguous |
| `resolve gitlab` with the alias table bypassed | ambiguous: gitlab:gitlab vs jenkins:gitlab |
| `product "log4j 2.99"` | 0 rows, "version NOT in the NVD dictionary" |
