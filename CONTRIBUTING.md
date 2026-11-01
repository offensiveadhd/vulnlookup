# Contributing

Thanks for looking. The bar is simple: the tool must never report a CVE against a version
it does not affect, and two identical commands must print identical bytes. Everything else
is negotiable.

## Set up

```bash
git clone https://github.com/offensiveadhd/vulnlookup
cd vulnlookup
python -m pip install pytest ruff
python -m pytest -q            # offline, ~30 s, no network
python -m ruff check .
```

Python 3.10 or newer. No runtime dependencies, and please keep it that way: the whole point
of the standard-library-only rule is that an agent can run the scripts anywhere without an
install step and a reviewer can audit the surface in an afternoon.

## Where things live

```
skills/vulnlookup/SKILL.md         what the model reads: the intent table, the ambiguity protocol
skills/vulnlookup/scripts/         vulnlookup.py (entry) and vl/ (the engine)
skills/vulnlookup/references/      aliases.json, api-notes.md, cpe-matching.md, output-styles.md
tests/                             pytest; fixtures/responses.json is recorded from the live APIs
docs/                              test-cases.md, security-audit.md, the demo recording
```

## The rules that matter

- **Every false positive or false negative becomes a test.** Add the recorded configuration
  (trimmed) and the expected verdict to `tests/test_cpe.py`, or the recorded response to the
  fixtures and the expectation to `tests/test_cli.py`. Fix the engine until it passes. The
  comparator (`vl/cpe.py`) is deterministic and documented in
  `references/cpe-matching.md`; change the document with the code.
- **Never guess.** If the comparator cannot order two strings, return `certain=False`. If the
  dictionary has two exact product matches, return `ambiguous`. If the version is not in the
  dictionary, say so. A clever heuristic that is right 95 % of the time is a bug here.
- **Determinism.** Sort with a total order (always end on the CVE id). No `time.time()`,
  `datetime.now()`, random or dictionary-order dependence in anything that reaches the
  output. `sort_keys=True` on every `json.dumps` that is printed.
- **Only the three hosts.** Adding a data source means updating `SECURITY.md`,
  `docs/security-audit.md`, `references/api-notes.md` and the fixtures recorder.
- **No shell, no string-built URLs.** `subprocess.run([...])`, `build_url(base, params)`.
- **The key is a secret.** It never reaches stdout, stderr, the cache or a test fixture.

## Adding a product alias

`skills/vulnlookup/references/aliases.json`: add `{"q": ["spellings", "people", "type"],
"cpe": ["a:vendor:product", ...]}`. List every `vendor:product` the NVD has filed the product
under (the NVD renamed nginx twice). Check each pair exists:

```bash
python skills/vulnlookup/scripts/vulnlookup.py resolve "vendor product"
python skills/vulnlookup/scripts/vulnlookup.py cpe "cpe:2.3:a:vendor:product" --limit 1 --format brief
```

`tests/test_resolve.py::test_aliases_file_is_well_formed` rejects a spelling claimed by two
entries.

## Re-recording fixtures

`python tests/record_fixtures.py` (about three minutes at the public rate limit) rewrites
`tests/fixtures/responses.json`. EPSS scores change daily and the NVD adds CVEs, so some
expectations in `tests/test_cli.py` will need a deliberate update. Do this in its own commit.

## Commits and pull requests

One concern per commit; describe the change, not the file list. CI runs ruff, the tests on
three operating systems and four Python versions, a skill-format check and CodeQL; all must
be green. If a change touches what the model sees (`SKILL.md`), paste the command you expect
the model to run for one or two example prompts into the PR so a reviewer can judge the
mapping, and add them to `docs/test-cases.md`.
