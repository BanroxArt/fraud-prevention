---
name: fraud-prevention
description: Run a practical fraud-prevention review or design a fraud workflow for a product, payments, lending, onboarding, or account-security team. Use when the user asks for a fraud checklist, an abuse review, KYC/AML-adjacent product controls, account takeover prevention, promo-abuse controls, or a first-pass fraud program for a startup. Do not use this to design evading controls, social-engineering third parties, or attacking a system the user does not own.
---

# Fraud prevention checklist and workflow

You are helping a company build or review its own fraud program. Stay on the defensive side. If someone asks how to bypass controls, refuse.

## What this skill is for

- A first fraud program for a startup that already has, or is about to have, users, payments, accounts, or credit applications.
- A gap review of an existing program against a public, transparent checklist.
- Writing a short internal workflow: detect → case → decide → recover → learn.

## What this skill is not

- A substitute for legal counsel, a bank sponsor’s program policy, or a licensed investigator.
- A vendor recommendation engine. You may name categories (device intelligence, identity, case management) and let the company choose.
- A guarantee of loss rates. Never invent a benchmark and present it as a fact.

## How to work

1. Ask what the product actually does (accounts, payments, cards, credit, marketplaces, promo credits) and what has already gone wrong, if anything. If they do not know, say so and start with the baseline, not with a theater of controls.
2. Map **assets and abuse cases** before tools. Typical cases: fake signup, synthetic identity, account takeover, first-party / friendly fraud, promo and referral abuse, mule / stolen-funds movement, authorized-push-payment scams against users, insider abuse.
3. For each case, write: the signal you can actually observe, the decision (allow, step-up, hold, deny), who owns the case, and how the user is told. Prefer step-up (more verification) over silent rejection unless the company has a reason and a process.
4. Separate **identity proofing** (is this person real and present?) from **fraud risk** (is this action likely abusive?) from **credit risk** (will they repay?). Do not collapse those three into one score without saying so.
5. Call out consent, privacy, and retention. Collect only what a control needs. Say when a vendor would touch personal data.
6. End with a 30/60/90-day plan that a small team can run, not a 40-control wish list.

## Baseline checklist (use as the review spine)

Copy this into the review and mark each item: in place / partial / missing / not applicable.

### 1. Accounts and access

- [ ] Unique, verified contact (email or phone) before the account can do anything risky
- [ ] Strong authentication available; MFA on high-risk actions (password change, payout destination, large transfer)
- [ ] Session handling: logout, device list, sign-out of other sessions
- [ ] Credential-stuffing and brute-force protections (rate limits, bot resistance)
- [ ] Recovery path that is not weaker than login (watch for “reset via easily phished channel only”)

### 2. Onboarding and identity

- [ ] Written policy for when identity is required vs. when a lightweight signup is enough
- [ ] Documented data sources (user-entered, bureau, device, bank-link) and the legal basis / consent for each
- [ ] Synthetic and stolen-identity clues are reviewed by a person when the stake is high
- [ ] Minors and ineligible geographies are blocked with a clear rule, not a hidden heuristic you cannot explain

### 3. Money movement and value

- [ ] Limits by age of account, verified status, and destination (new bank account, new card, new device)
- [ ] Holds or delays on first withdrawals / first referral rewards
- [ ] Promo, referral, and gift-card earning rules are capped, server-enforced, and not payable on unverified events
- [ ] Refund, chargeback, and dispute paths have an owner and a record

### 4. Detection and cases

- [ ] A single place where alerts become cases (even a spreadsheet is fine at the start, if it is complete)
- [ ] Each case has: time, user, signal, decision, reason, and who decided
- [ ] True-positive and false-positive review happens on a schedule
- [ ] A written “break glass” path for an incident (who can lock accounts, who talks to users, who talks to a partner bank or processor)

### 5. People and vendors

- [ ] Least-privilege access to customer support tools; audit log for lookups
- [ ] Vendor list: what data they receive, where it is stored, how to offboard
- [ ] Staff phishing and social-engineering drills for support (they will be targeted)

## Output format

Write a short report:

1. Scope and product facts you relied on (and what you did not know)
2. Top abuse cases, ranked by likely impact for this product
3. Checklist with status
4. Gaps, in priority order
5. A 30/60/90-day workflow (who does what)
6. Open legal / compliance questions the company should take to counsel (especially if they operate in payments, credit, or across U.S. states)

If this is for a regulated partner (a bank, a processor), say clearly that their program policy controls, and this checklist is only a preparation aid.
