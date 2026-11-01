# Output formats and styles

`--format` picks the container, `--style` picks how much is said. Any pair works. Rows are
always sorted by `--sort` (default the CVE id; `cvss`, `epss`, `published` also available),
ties on the id, so the same command prints the same bytes twice. No run timestamps appear
in the body; the dates shown are data (published, KEV added, the EPSS score's date).

| format | what it is | for |
|---|---|---|
| `table` (default) | fixed-width columns, then (analyst) one block per CVE, then the footer | a terminal, a chat reply in a code block |
| `md` | the same as a Markdown table + `###` sections | tickets, reports, PR descriptions |
| `csv` | one header, one row per CVE, every field flat (`subject` column added by `bulk`) | spreadsheets, diffing two runs |
| `brief` | one line per CVE, no header, no columns | a quick answer, grepping |
| `json` | the whole result (`subject`, `targets`, `nvd_returned`, `confirmed`, `excluded`, `rows[]`, `notes`), `sort_keys` | programs, and the model when it must reason over fields |

| style | rows | per-CVE detail | summary first | footer |
|---|---|---|---|---|
| `terse` | id, CVSS, EPSS, KEV, (Exploit), verdict | no | no | no |
| `analyst` (default) | + published, CWE, matched criteria | yes: vector, EPSS percentile + date, KEV dates, CWE, matched nodes and bounds, platforms, fixed versions, exploit evidence, remediation, description | no | yes |
| `executive` | + published, CWE | no | yes: counts, KEV, EPSS, PoC, "act first" | yes |

## Samples (recorded 2026-11-01; EPSS values move daily)

### `product "apache httpd 2.4.49" --kev --format brief --style terse`

```
CVE-2021-41773  9.8 CRIT  EPSS 0.999  KEV+ransomware  EXACT
CVE-2021-42013  9.8 CRIT  EPSS 0.999  KEV+ransomware  EXACT
CVE-2024-38475  9.1 CRIT  EPSS 0.999  KEV  RANGE
```

### `product "apache httpd 2.4.49" --kev --style executive --format brief`

```
Subject: apache httpd 2.4.49 -> a:apache:http_server (via alias); version in the NVD dictionary
3 CVE(s) confirmed against the subject: 3 critical, 0 high; 3 in CISA KEV; 3 with EPSS >= 0.1.
Act first:
  - CVE-2021-41773 (9.8 CRIT, EPSS 0.999, KEV)
  - CVE-2021-42013 (9.8 CRIT, EPSS 0.999, KEV)
  - CVE-2024-38475 (9.1 CRIT, EPSS 0.999, KEV): upgrade to 2.4.60

Not counted (shown with --include-unverified): COND 3
```

### `product "apache httpd 2.4.49" --kev --poc --recommend` (table, analyst), one block

```
CVE             CVSS      EPSS   KEV             Exploit  Published   CWE     Match  Matched criteria
--------------  --------  -----  --------------  -------  ----------  ------  -----  -----------------------------------------------------------
CVE-2021-41773  9.8 CRIT  0.999  KEV+ransomware  ITW      2021-10-05  CWE-22  EXACT  cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:* [= 2.4.49]
...

CVE-2021-41773  https://nvd.nist.gov/vuln/detail/CVE-2021-41773
  CVSS 3.1 9.8 CRITICAL  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  EPSS 0.999 (percentile 0.999, 2026-11-01)
  KEV added 2021-11-03 due 2021-11-17 ransomware Known
  CWE CWE-22
  matched cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*  [= 2.4.49]
  exploit evidence: exploited-in-the-wild
    NVD tag: Exploit: http://www.openwall.com/lists/oss-security/2021/10/08/1
    Packet Storm: http://packetstormsecurity.com/files/164418/Apache-HTTP-Server-2.4.49-Path-Traversal-Remote-Code-Execution.html
  remediation:
    - Apply the patch: https://lists.apache.org/thread.html/r17a4c6ce9aff662efd9459e9d1850ab4a611cb23392fc68264c72cb3%40%3Ccvs.httpd.apache.org%3E
    - Follow the vendor advisory: https://httpd.apache.org/security/vulnerabilities_24.html
    - CISA KEV since 2021-11-03, federal due date 2021-11-17: Apply updates per vendor instructions.
    - Known ransomware campaign use: treat as an active incident risk, not a backlog item.
  A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. ...
```

The `Exploit` column: `ITW` = in CISA KEV (exploited in the wild), `PoC` = public exploit
material in the references, `none` = no public evidence in the references the NVD lists.

### `cve CVE-2021-44228 --format json` (trimmed)

```json
{
  "notes": [],
  "not_found": [],
  "rows": [
    {
      "cvss": {"score": 10.0, "severity": "CRITICAL", "source": "nvd@nist.gov", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "version": "3.1"},
      "cwe": ["CWE-20", "CWE-400", "CWE-502", "CWE-917"],
      "epss": {"date": "2026-11-01", "epss": 0.99999, "percentile": 1.0},
      "fixed_versions_by_product": [{"product": "apache:log4j", "versions": ["2.3.1", "2.12.2", "2.15.0"]}],
      "id": "CVE-2021-44228",
      "kev": {"dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", ...},
      "published": "2021-12-10",
      "references": [{"tags": ["Exploit", "Third Party Advisory", "VDB Entry"], "url": "..."}, ...],
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    }
  ],
  "subject": "CVE-2021-44228"
}
```

A product / CPE row adds `target`, `verdict`, `matched[]` (`criteria`, `matchCriteriaId`,
`vulnerable`, `how`, `bounds`, `why`, `notes`), `platforms[]`, `fixed_versions[]`; `--poc` adds
`exploit_evidence` (`level`, `evidence[]`, `weaponised_tooling`, `basis`); `--recommend` adds
`recommend[]`.

### The ambiguous case (`resolve` or `product`, exit code 3)

stderr:
```
ambiguous: 'gitlab' matches 6 products in the NVD dictionary. Pick one with --pick part:vendor:product, or ask which was meant:
  1.00  a:gitlab:gitlab                                  GitLab                                   product name is exactly what you typed
  0.99  a:jenkins:gitlab                                 Jenkins GitLab Plugin                    product name is exactly what you typed
  0.60  a:gitlab:runner                                  ...
```
stdout: the same as JSON (`status`, `query`, `candidates[]` with `cpe`, `confidence`, `reason`,
`title`, `entries`, `deprecated`).
