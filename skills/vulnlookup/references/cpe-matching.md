# How a version is compared and a configuration tree is walked

This is `scripts/vl/cpe.py`, in words. It is the part that makes "zero false positives" more
than a slogan: the NVD's own matcher answers *yes or no*; this answers *why*, and refuses to
answer when it cannot order two strings.

## Versions: tokens, ranks, certainty

Split on `. - _ + ~ space`, then at every digit/letter boundary (rpmvercmp's idea). Compare
token by token:

- numbers numerically, as strings with leading zeros dropped (`10.0.17763.1234`, `20240101`);
- a missing trailing token counts as `0` (`2.4 == 2.4.0`) unless the longer side continues
  with a pre-release word, which sorts it below (`1.0-rc1 < 1.0`), or a post-release word,
  which sorts it above (`1.0-sp1 > 1.0`);
- words are ranked (`references/aliases.json` → `qualifiers`): `dev < snapshot < pre <
  alpha/a < beta/b < milestone/m < rc/cr < release/final/ga/esr (= 0) < build < p/patch/r <
  sp < update/u`;
- a single letter glued to digits with nothing after it is a **patch letter**
  (`1.0.2k > 1.0.2j > 1.0.2`); the same letter with digits after it is a qualifier (`1.0a1`
  is alpha 1). OpenSSL versus Python pre-releases, decided by position, not by a list;
- a number beats a word (`1.0.1 > 1.0.rc1`);
- anything that rests on a word the table does not know (`4.av4` against `4.1`) is
  **uncertain**. `4.av4` against `4.av3` is still ordered; `4.av4 == 4.av4` is certain.

Updates are normalised before comparison: `sp1` = `SP-1` = `Service Pack 1`; `u5` =
`update_5` = `Update 5`; `a1` = `alpha1`.

## A criteria against a target

1. `part`, `vendor`, `product` must match (`*` in the criteria matches anything). A different
   product is **foreign**, which is "unknown" in an AND, not "false".
2. Version:
   - target version unspecified → unknown ("version unspecified");
   - criteria names a version: equal → hit (`exact`); different and certain → miss;
     different and uncertain → unknown;
   - criteria is `*` with no bounds → hit (`any`);
   - bounds: the target is tested against each (`>=`, `>`, `<=`, `<`). The bounds that were
     tested are recorded (`[>= 2.13.0 < 2.15.0]`) and shown in the output.
3. Pre-release updates: `7.4.0 alpha1` is measured as `7.4.0-alpha1`, below `7.4.0`. The
   range is tested both with and without the update; when the two readings disagree the
   result is unknown with the disagreement spelled out ("inside as 7.4.0 and outside as a
   pre-release of it"). The NVD quietly picks one.
4. The `update` field: a criteria that wants an update the user did not give is unknown
   (`7.4.0:alpha1` vs a plain `7.4.0`); `-` (no update) matches a plain version and rejects
   an update; otherwise normalised equality.
5. `edition`, `language`, `sw_edition`, `target_sw`, `target_hw`, `other`: a specified target
   value must match; an unspecified one is a **note** (`target_sw=node.js`), never a miss.

## A configuration tree against the targets

For every configuration, every node, every criteria: the best match over all targets (the
product and any `--on` platforms). A node's value: `OR` → any hit; `AND` → every criteria
must hit, a miss wins over unknown; a node whose criteria are all foreign is unknown;
`negate` inverts. Then for every **vulnerable** hit in a non-negated node:

| Situation | Verdict |
|---|---|
| exact version | `EXACT` |
| inside a range | `RANGE` |
| `*`, no range | `ANY` |
| hit, but a sibling node in an `AND` configuration is unknown (the platform) | `COND`, with the platform criteria listed |
| hit, but a sibling node is a definite miss | nothing (the configuration does not apply) |
| unknown (any of the uncertain cases above) | `MAYBE`, with the reason |
| the only hits are `vulnerable: false` | `PLATFORM` |
| nothing | `NONE`; when the NVD returned the record anyway, reported as `NVD-only` |

The best verdict across the tree wins (`EXACT > RANGE > ANY > COND > MAYBE > PLATFORM`);
equally ranked distinct nodes are all kept so the output can list them. Only `EXACT`,
`RANGE`, `ANY` (and `LISTED` for version-less product queries) are counted as confirmed.

## The cases that produce false positives elsewhere

- **Running-on platforms.** CVE-2007-4723 (Ragnarok Online Control Panel) has an `AND`
  configuration with `apache:http_server:*` as `vulnerable: false`. A naive CPE search for
  Apache finds it; here it is `PLATFORM` and never shown.
- **Letters in versions.** `openssl 1.0.2k` must not fall inside `< 1.0.2k`, and must fall
  inside `< 1.0.2l`. `1.0.2a` is after `1.0.2`, not an alpha.
- **Pre-releases on a boundary.** `php 7.4.0 alpha1` against `>= 7.4.0 < 7.4.5`: inside as a
  version, outside as a pre-release. Reported `MAYBE`, not silently included or dropped.
- **The dictionary's `-`.** `cpe:2.3:a:apache:log4j:2.0:-:…` is the plain 2.0 release;
  `2.0:beta9` is a different thing. A typed `2.0` matches the first and not the second.
- **Negated nodes.** A `negate: true` node lists what is *not* affected; it never produces a
  hit.
- **Unknown words.** `4.av4` against `< 4.1` cannot be ordered; `MAYBE` with "cannot order".
- **Deprecated dictionary entries.** `openssl:openssl:1.1.1:*` is deprecated in favour of
  `1.1.1:-`; the snap follows the pointer and then treats `-` as "no update", so the query
  does not accidentally restrict itself to criteria with a `-` update.
- **Version not in the dictionary.** The NVD still applies range criteria to a version it
  has no entry for; exact criteria cannot match it. The subject line says so.

## Fixed versions

`--recommend` reads every `versionEndExcluding` on a vulnerable criteria of the target's
product whose range the target satisfies, and reports the smallest as "upgrade to X or
later". `versionEndIncluding` does not imply a fix version and is not used for this.
