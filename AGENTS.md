# vulnlookup for agents that are not Claude Code

This repository is an [Agent Skill](https://agentskills.io): one folder,
`skills/vulnlookup/`, with a `SKILL.md` that tells a model when and how to use the scripts
in `skills/vulnlookup/scripts/`. Hermes Agent, OpenAI Codex, Grok and any other agent that can
run a shell command can use it. The scripts are Python 3.10+ with the standard library only.

## The contract

1. **Decide the kind of request** (one CVE, several, product + version, product only,
   product + platform, product over years, a CPE, bulk, resolve, KEV, EPSS). The table in
   `skills/vulnlookup/SKILL.md` §1 maps each kind to exactly one command.
2. **Run that command** with `python skills/vulnlookup/scripts/vulnlookup.py …`. Add filters
   (`--kev --min-cvss 7 --years 2019-2024 --cwe CWE-79`), modes (`--poc`, `--recommend`) and
   the output (`--format table|json|md|csv|brief --style terse|analyst|executive`) in the same
   command.
3. **Exit code 3 means ambiguous**: the script printed candidate CPEs with confidences. Pick
   with `--pick part:vendor:product` only when the user's wording settles it; otherwise show
   the candidates and ask. Never guess a product or a version.
4. **Report the script's words.** The verdict per row (`EXACT`, `RANGE`, `ANY`, `LISTED`), the
   matched criteria and bounds, the "Not counted" footer, and the "evidence, not a verdict"
   line of `--poc` all go into the answer unchanged. Do not recompute scores or re-rank.

## A prompt block to paste into another agent's system prompt

```
You have the vulnlookup skill at <path>/skills/vulnlookup. For any question about a CVE,
a product's vulnerabilities, a CPE, EPSS or CISA KEV, read <path>/skills/vulnlookup/SKILL.md
and run exactly one command from its table with
`python <path>/skills/vulnlookup/scripts/vulnlookup.py …`. Exit code 3 = ambiguous product:
show the candidates and ask instead of guessing. Quote the script's verdicts and footers as
printed. Never compute CVSS, EPSS or version ranges yourself.
```

## Install

```bash
git clone https://github.com/offensiveadhd/vulnlookup
bash vulnlookup/install.sh                 # Claude Code, Hermes, Codex: detected and copied
pwsh vulnlookup/install.ps1                # Windows
hermes skills install offensiveadhd/vulnlookup/skills/vulnlookup --category security
npx skills add offensiveadhd/vulnlookup --agent '*' -g -y
```

Hermes: `/vulnlookup <request>`. Codex: `$vulnlookup`. Claude Code: `/vulnlookup` or let it
trigger on CVE / CPE / EPSS / KEV wording.

## Rate limits and the key

The NVD allows 5 requests per 30 s without a key and 50 with one; the script paces itself
and shares the window between processes. An agent running many lookups should set a key
once: `python skills/vulnlookup/scripts/vulnlookup.py key set` (stdin), or export
`NVD_API_KEY`. The key never appears in output or in the cache.
