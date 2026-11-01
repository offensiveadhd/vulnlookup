# Security

vulnlookup is a passive lookup tool. It never touches the system it is asked about. This file
says what it does touch, what it stores, and how to report a problem. The full audit is in
[docs/security-audit.md](docs/security-audit.md).

## What leaves the machine

Three hosts, HTTPS only, GET only:

| Host | What is sent | Why |
|---|---|---|
| `services.nvd.nist.gov` | CVE ids, CPE 2.3 strings, product keywords, paging parameters; the `apiKey` header when a key is configured | the CVE and CPE dictionaries |
| `api.first.org` | CVE ids | EPSS scores |
| `www.cisa.gov` | nothing but the GET for the public KEV JSON | the KEV catalogue |

No hostnames, IPs, file paths, user names or scan data are ever sent anywhere. The tool
does not phone home; there is no "ours" to phone.

## What is stored

- **Cache** (public API responses only) under the user's cache directory
  (`vulnlookup cache path`): Windows `%LOCALAPPDATA%\vulnlookup\cache`, macOS
  `~/Library/Caches/vulnlookup`, Linux `$XDG_CACHE_HOME/vulnlookup`. Safe to delete at any
  time. The API key is never written there.
- **The NVD API key**, optional, in this order: `NVD_API_KEY` from the environment; the OS
  credential store (Windows Credential Manager via `CredWriteW`, macOS Keychain via
  `security`, Linux Secret Service via `secret-tool`); only when none exists, a file under the
  user config directory with mode 0600, and the tool warns each time it writes one. `key
  status` shows presence and the last four characters only. The key is sent to
  `services.nvd.nist.gov` and nowhere else.
- **The rate-limit window**: timestamps of recent NVD requests in the cache directory, so
  several processes share one window.

## What the code does not do

- No shell. Every subprocess (`security`, `secret-tool`) is an argument list; nothing the user
  or an API returns is ever interpolated into a command.
- No string-built URLs. Every parameter goes through `urllib.parse.urlencode`.
- No dependencies. Python 3.10+ standard library only, so there is no supply chain to audit
  beyond CPython.
- No code from the network. Responses are parsed as JSON and read as data. Reference URLs
  are printed, never fetched.
- No writes outside the cache and config directories.

## Threat model for the key

An NVD API key only raises a rate limit; it grants no access to anything private. Losing it
costs the owner a key rotation. The store still treats it as a secret because habits matter:

| Threat | Mitigation |
|---|---|
| Key committed to a repository | never written inside the repository; `.gitignore` excludes the key file name and caches as belt and braces |
| Key in shell history | `key set` reads from stdin when no value is given |
| Key in logs or output | never printed; `--verbose` logs URLs and status codes only; `key status` shows the last four characters |
| Key readable by other local users | OS store first; file fallback is 0600 and announced |
| Key sent to the wrong host | the header is added only when the URL's host is exactly `services.nvd.nist.gov` |
| macOS `security add-generic-password` shows the key in the process list for an instant | documented limitation of the Keychain CLI; use `NVD_API_KEY` or the file store if that matters on a shared Mac |

## Reporting

Please report security issues privately through GitHub's private vulnerability reporting on
this repository (Security → Report a vulnerability), or by email to the maintainer listed on
the [offensiveadhd](https://github.com/offensiveadhd) organisation page. Expect an
acknowledgement within a week. Fixes are released as a tagged version with a note in the
changelog; credit is given unless you prefer otherwise.

Things that are **in scope**: anything that makes the tool send data where this document says
it does not, store the key where it says it does not, execute anything, report a CVE as
confirmed against a version it does not affect (a false positive), or silently drop one it
does (a false negative). Things that are **not**: the correctness of the NVD, FIRST or CISA
data itself, and rate limiting by those services.
