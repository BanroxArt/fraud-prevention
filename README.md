# fraud-prevention

A defensive first-pass fraud program review for a product, payments, lending, onboarding, or account-security team. It helps you map abuse cases, walk a public checklist, and leave with a 30/60/90-day workflow. It will not help anyone evade controls.

Author: Art Akopian, CEO of [Banrox](https://banrox.com)

## What it does

This repository is an agent skill. After you install it, ask your coding agent for a fraud-program review or a first-pass abuse design. The agent should:

- Stay on the defensive side and refuse requests to bypass controls
- Map assets and abuse cases before recommending tools
- Separate identity proofing, fraud risk, and credit risk
- Walk a baseline checklist covering accounts, identity, money movement, case handling, and vendors
- Return a short report: scope, top abuse cases, checklist status, prioritized gaps, a 30/60/90-day plan, and open questions for counsel

It is a preparation aid, not a substitute for legal counsel, a bank sponsor's program policy, or a licensed investigator.

## Install

Copy `SKILL.md` into your agent's skills folder, for example:

```text
.cursor/skills/fraud-prevention/SKILL.md
```

or the equivalent path your agent documents. Restart or reload skills if your agent requires it.

## Use

Ask for a first-pass fraud review of a product you own or are clearly authorized to review. Say what the product actually does (accounts, payments, cards, credit, marketplaces, promo credits) and what, if anything, has already gone wrong. If you do not know yet, say so; the skill starts from the baseline rather than inventing a theater of controls.

## Example

See [examples/sample-review.md](examples/sample-review.md) for a fictional worked example of the expected report shape. The company in that file is made up. It is not a review of Banrox or of any real bank.

## Limitations

- Not legal advice, a certification, an audit, or a guarantee of loss rates.
- Not a vendor recommendation engine. The skill may name categories (device intelligence, identity, case management) and leaves vendor choice to the company.
- It will not invent benchmarks or present guessed loss rates as facts.
- If you work with a regulated partner (a bank or a processor), their program policy controls; this checklist is only a preparation aid.

## License

The `LICENSE` file currently contains the MIT License text, with copyright holder Banrox Inc. and year 2026. This is a placeholder. The public licence is pending a final pick by Banrox and may change before the repository is published. Do not treat MIT as final until that decision is recorded.

## Checks

From the repository root:

```text
python3 scripts/check.py
```

This validates skill frontmatter, required sections, example files, local links, and a lint that public files do not include internal names or unsupported certification or traction claims.

## Contributing

Issues and patches are welcome after a public repository exists. Do not send exploit proof-of-concepts or requests to evade fraud or account-security controls.

## Related skills

Sibling skills from the same author, each in its own repository:

- `cybersecurity-baseline` — small-company security baseline (not a certification)
- `live-codebase` — two-week plan to make one service shippable, observable, and safely connected to live data
- `calling-bot-twilio` — consent-gated Twilio calling pattern (not a dialer)
