# Security audit of vulnlookup 1.0.0

Self-audit performed while building the tool (2026-11-01), by reading every module and
tracing every path that leaves the process. It is a statement of what the code does, with
file references, so a reviewer can check each claim in minutes. It is not a third-party
audit.

## 1. Surface

| Item | Finding |
|---|---|
| Language, runtime | Python 3.10+; CPython standard library only. `pyproject.toml` declares no dependencies; CI installs only `pytest` and `ruff` for testing and linting |
| Network | outbound HTTPS GET only, three hosts (`scripts/vl/sources.py` constants `NVD_CVES`, `NVD_CPES`, `EPSS`, `KEV`). No listener, no other protocol |
| Process execution | `scripts/vl/keystore.py` only, `subprocess.run` with argument lists (`security`, `secret-tool`); `shell=False` by default, never overridden. Inputs to those commands are fixed constants plus the key the user typed |
| Files written | the cache directory and the config directory (`scripts/vl/paths.py`), both overridable with `VULNLOOKUP_CACHE_DIR` / `VULNLOOKUP_CONFIG_DIR`. Cache writes are atomic (`tmp` + `os.replace`) |
| Files read | the cache, the config key file, and files the user names on the command line (`--file`, `--products`, `--cpes`, `--cves`), read as UTF-8 text and parsed for CVE ids / lines |
| Code loading | none from data. `json.loads` only. No `eval`, `exec`, `pickle`, `yaml`, `importlib` on data |

## 2. Data flows

### 2.1 Outbound

Every request is built by `vl.http.build_url(base, params)`, which URL-encodes each
parameter with `urllib.parse.urlencode` (`safe=":*"` so CPE strings stay readable; both
characters are legal in a query string). Parameters are:

- `cveId` — a string matched by `CVE-\d{4}-\d{4,}` (`vl.cli.CVE_RE`) and upper-cased.
- `virtualMatchString`, `cpeMatchString` — a CPE 2.3 prefix produced by `vl.cpe.format_cpe`
  / `prefix_match_string`, which escapes every character outside `[A-Za-z0-9_.-]`.
- `keywordSearch` — the user's product text after `norm_text` (lower-case alphanumerics and
  spaces).
- `resultsPerPage`, `startIndex` — integers.
- `cve` (EPSS) — a comma-joined list of ids as above.

The only header beyond `User-Agent` / `Accept` is `apiKey`, added in `Client.get_json` when
`urlsplit(url).netloc == "services.nvd.nist.gov"` (`vl/http.py`). Test
`test_key_env_wins_and_is_sent_only_to_nvd` asserts this.

### 2.2 Inbound

Responses are decoded as UTF-8 and parsed with `json.loads`. Fields are read by key; unknown
fields are ignored; the record is slimmed (`vl.sources.slim`) before caching. Reference URLs
are matched against regular expressions for classification and printed; they are never
fetched. Text fields (descriptions, titles) are printed with `[:N]` truncation in the table
styles and in full in JSON. Nothing is passed to a shell or interpolated into code.

A malicious or compromised API could therefore only: return wrong data (the local
verification limits the damage of wrong *applicability* data; wrong scores are reported as
received), or return a very large body (bounded by the API's own page limits; parsing is
in-memory and would fail loudly, not silently).

### 2.3 Stored

Cache files hold `{"t": epoch, "k": key, "v": value}` where `key` is the request's logical
key (contains the same CVE / CPE / keyword strings as the URL, never the API key) and `value`
the slimmed response. The rate-limit window file holds a list of epoch floats. The key file
holds the key alone.

## 3. The API key

`vl/keystore.py`:

- **Read order**: `NVD_API_KEY` env → OS store → file. The first hit wins; the key is held in
  memory for the process only.
- **Windows**: `CredReadW` / `CredWriteW` / `CredDeleteW` through `ctypes`, generic
  credential, target `vulnlookup/nvd-api-key`, persist `LOCAL_MACHINE` (the current user's
  roaming-free profile). Blob stored UTF-16-LE as Credential Manager expects.
- **macOS**: `security add-generic-password -U -a nvd-api-key -s vulnlookup -w <key>`. The
  Keychain CLI has no stdin mode for `add`, so the key is a process argument for the duration
  of the call. Documented in `SECURITY.md`; `NVD_API_KEY` or `--file` avoid it.
- **Linux**: `secret-tool store … service vulnlookup account nvd-api-key`, key on **stdin**.
- **File fallback**: `os.open(..., 0o600)` then `chmod 0600`; a warning on stderr every time.
- **Validation**: 20–128 characters of `[A-Za-z0-9_-]` (`_valid`), so a pasted shell line or
  a path cannot become a "key".
- **Never printed**: `status` returns the last four characters only; `--verbose` logs URLs
  (which do not carry the key) and status codes. Tests: `test_key_never_in_cache_or_output`,
  `test_key_set_status_clear_file_store`.

## 4. Determinism and false positives as security properties

For a lookup tool the security property that matters most is that it does not lie:

- **No false positives by construction.** Every record the NVD returns is re-evaluated
  against the NVD's own configuration tree locally (`vl.cpe.eval_cve`). Only `EXACT`,
  `RANGE`, `ANY` (and `LISTED` for a version-less query) are counted. `PLATFORM` records (the
  product named as the thing a bug runs on) are never shown; `COND` / `MAYBE` / `NVD-only`
  are counted in the footer and shown only with `--include-unverified`, flagged. The version
  comparator refuses to order strings it does not understand instead of guessing
  (`vcmp(...).certain`). Regression vectors: `tests/test_cpe.py`.
- **No invented versions.** `resolve.snap_version` uses the NVD dictionary's spelling when
  the version exists there and otherwise keeps the typed version and says so. It never
  substitutes a "closest" version.
- **No silent ambiguity.** `resolve.decide` returns one CPE only for an exact, unrivalled
  product-name match; otherwise exit code 3 with ranked candidates and reasons.
- **Same input, same bytes.** Rows are sorted by a total order (the chosen key, then the CVE
  id); JSON is dumped with `sort_keys`; no run timestamps appear in the body. Tests:
  `test_identical_input_identical_output` (cached and `--no-cache`),
  `test_second_run_makes_no_nvd_requests`.

## 5. Denial of service and rate limits

The pacer (`vl.http.Pacer`) enforces 5 / 50 requests per rolling 30 s and persists the
window on disk, so a user cannot accidentally hammer the NVD by running the tool in a loop.
Backoff on 403 / 429 / 503 is 6, 12, 24, 48 s and then a clean error. One `product` query is
one or two NVD requests plus one EPSS request and one KEV fetch per day. A list of N CVE ids
is N NVD requests (the API has no bulk id lookup); the tool says so in `SKILL.md` so the model
warns before a long run.

## 6. Dependency and supply chain

None at runtime. Development: `pytest` and `ruff`, pinned by major version in the workflows.
CI uses `actions/checkout@v4`, `actions/setup-python@v5`, `github/codeql-action@v3`. No
third-party GitHub Actions beyond GitHub's own.

## 7. Findings and residual risks

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Low | macOS: key visible in the process list during `security add-generic-password` | documented; alternatives offered |
| 2 | Low | the file fallback on Windows cannot be 0600 (no POSIX mode); it is only reached when `ctypes` / Credential Manager fail | the fallback warns; Credential Manager is the default path and is tested |
| 3 | Info | the cache contains the queries a user made (which products / CVEs they looked up) in plain text | cache is local, per user; `cache clear` removes it; documented in SECURITY.md |
| 4 | Info | `ANY` criteria (`*`, no range) are trusted as the NVD wrote them | reported with the `ANY` verdict so the reader can weigh it; documented in SKILL.md §4 |
| 5 | Info | the exploit-evidence classifier is a list of hosts and tags | labelled as evidence, never a verdict, in every output |

No high or critical findings. Nothing in the tool executes, writes outside its two
directories, or sends data anywhere but the three documented hosts.
