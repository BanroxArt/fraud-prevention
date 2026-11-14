# Contributing

Bug reports and patches are welcome. For anything larger than a small fix, open an issue first so we can agree on the shape before you write it.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

`make check` runs ruff (lint and format), the content lint in `scripts/check.py`, mypy in strict mode over `src/`, and pytest including the Hypothesis property tests. CI runs the same steps on Python 3.11 to 3.13.

## What a good patch looks like

- One change per pull request, with a test that fails before it and passes after.
- A bug fix gets a regression test named after the behaviour, not the ticket.
- New state in the engine needs a bound: a time-based prune and a hard cap. Say which in the docstring.
- New reason codes need a default weight in `default_rules.yaml` (0 is fine for explain-only codes) and a line in the README or `docs/threat-model.md` saying what they catch.
- Update `CHANGELOG.md` under "Unreleased".

## Things we will not merge

- Techniques for getting around fraud controls, or rules tuned to a specific real company.
- Real event data, real phone numbers, emails or card fingerprints in tests or examples. Use the RFC 2606 domains, the NANP 555-01xx range and documentation IP ranges. `scripts/check.py` enforces this.
- Vendored IP reputation lists. They go stale and their licences vary.

## Commit messages

Short imperative subject in lower case (`engine: dedup on event_id`), a blank line, then why. Sign-off is not required.

## Conduct

Everyone taking part in issues, pull requests and reviews is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Reports go to opensource@banrox.com and are read by the maintainers only.
