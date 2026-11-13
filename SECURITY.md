# Security policy

## Reporting a problem

Please report security problems privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for anything that could help someone get around a deployed fraud control or crash a scorer.

Include what you ran, what you expected, what happened, and the smallest event stream or rules file that shows it. Synthetic data only, please; do not send real customer events.

You should get an acknowledgement within five working days. Fixes land on `main` with a regression test and a CHANGELOG entry that credits you unless you ask not to be named.

## Supported versions

This is a 0.x project. Only the latest commit on `main` gets fixes.

## In scope

- Anything that makes `fraudkit` score the same event differently depending on input it should ignore: replays, field ordering, oversized or malformed fields.
- Memory or CPU growth driven by event content (keys, late events, linking).
- Rules-file parsing that executes code or reads files it was not pointed at.

## Out of scope

- Evasion of the shipped example rules by an attacker who knows them. The rules are a starting point and are public on purpose; tune your own.
- Weaknesses in your event pipeline, such as client-supplied device ids. See [docs/threat-model.md](docs/threat-model.md) for the assumptions the engine makes.
