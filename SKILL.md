---
name: fraud-prevention
description: Run a defensive fraud-prevention review, or design and stand up first-pass fraud rules, for a product with accounts, payments, payouts, lending, onboarding or promo credit. Use when the user asks for a fraud checklist, an abuse review, account takeover or promo-abuse controls, velocity rules, or a first fraud program for a startup. Includes a working rules engine (fraudkit) the agent can configure against the team's own event data. Do not use this to design ways around controls, to social-engineer third parties, or against a system the user does not own.
---

# Fraud prevention review and first rules

You are helping a team protect its own product. Stay on the defensive side. If asked how to get around a control, decline that part and keep going with the defence.

There are two halves. The review is a conversation and a short report. The rules half is code: this repo ships `fraudkit`, a small engine that scores JSONL events against a YAML rule file. Do the review first; only write rules once you know what is being abused.

## 1. Facts first

Ask what the product does and what has already gone wrong. Concretely:

- Which value can leave or be granted: withdrawals, payouts, refunds, promo credit, referral bonuses, free trials, credit lines.
- Which events the backend already records, and whether device id and client IP are set server-side.
- Who looks at alerts today, if anyone, and how many cases a week they can handle.
- Any regulated partner (sponsor bank, processor, lender). Their program policy wins over anything here.

If they do not know, say so in the report. Do not fill gaps with invented loss rates or benchmarks.

## 2. Abuse cases before tools

List the cases that apply and rank them by likely cost for this product: fake signups, synthetic identity, account takeover, first-party or friendly fraud, promo and referral abuse, card testing, mule accounts, authorised push payment scams against users, insider abuse.

For each: the signal the team can observe today, the decision (allow, step-up, hold, deny), who owns the case, and what the user is told. Prefer step-up over silent rejection.

Keep three questions apart and say so if a design merges them: is this a real person (identity proofing), is this action abusive (fraud risk), will they repay (credit risk).

## 3. Baseline checklist

Mark each: in place, partial, missing, not applicable.

Accounts and access
- Verified contact before risky actions
- MFA on password change, payout destination change and large transfers
- Device and session list, sign out elsewhere
- Rate limits and bot resistance on login and signup
- Recovery no weaker than login

Onboarding and identity
- Written rule for when identity verification is required
- Data sources listed with the consent or legal basis for each
- Human review for high-stake synthetic or stolen identity hits
- Clear, explainable eligibility rules (age, geography)

Money and value
- Limits by account age, verification and destination newness
- Holds on first withdrawal and first referral payout
- Promo and referral rules capped and enforced server-side
- Owner and record for refunds, chargebacks and disputes

Detection and cases
- One place alerts become cases
- Each case records time, user, signal, decision, reason, decider
- Scheduled false positive review
- Written incident path: who can lock accounts, who talks to users and partners

People and vendors
- Least privilege and audit logs on support tools
- Vendor list with data shared and offboarding steps
- Social engineering drills for support

## 4. Standing up rules with fraudkit

Only if the team has event data or can export it.

1. Map their events to the fraudkit schema (`ts`, `type`, `account_id`, plus `device_id`, `ip`, `email`, `phone`, `card_fp`, `address`, `amount`, `promo_code`). Phones and addresses should be keyed hashes. Never ask them to paste raw customer data into the chat; work from the schema and a synthetic sample.
2. Start from `src/fraudkit/default_rules.yaml`. Remove rules for events they do not have. Set thresholds from their own volumes, for example the 99th percentile of signups per device per day, not from the defaults.
3. Run `fraudkit synth` and `fraudkit score` to show the team what each reason code looks like before touching real data.
4. Run in shadow mode for at least two weeks. Use `fraudkit eval` on labelled outcomes to tune (see `docs/tuning.md`).
5. Only then wire `deny`. Keep `review` going to a person.

Call out the engine's limits when they matter: in-memory state, no shared store across workers, no device fingerprinting, no IP reputation data included.

## 5. Privacy

Collect what a control needs and no more. Say when a vendor would receive personal data. Reason codes are for analysts; users get a generic message and an appeal path.

## Output format

A short report:

1. Scope and the product facts relied on, plus what was unknown
2. Top abuse cases, ranked for this product
3. Checklist with status
4. Gaps in priority order
5. Rules plan: which fraudkit rules to enable, starting thresholds and why, shadow-mode period (skip if no event data)
6. 30/60/90 day plan with owners
7. Open legal and compliance questions for counsel, especially for payments, credit, or multi-state U.S. operation

If a regulated partner is involved, say their policy controls and this review is preparation only. See `examples/sample-review.md` for the shape.
