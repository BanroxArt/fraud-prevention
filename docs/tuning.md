# Tuning and false positives

The default weights are starting guesses. Plan on changing them in the first month.

## Loop

1. Run in shadow mode. Score everything, act on nothing, log decisions next to outcomes (chargebacks, confirmed takeovers, support tickets, manual review verdicts).
2. Every week, build a labelled file: the scored rows plus a `label` field (`legit` or the abuse type). `fraudkit eval scored.jsonl` prints precision and recall for the review and deny bands and precision for each reason code.
3. Change one thing at a time. A reason code with low precision either needs a higher threshold, a lower weight, or a `where` clause that narrows it.
4. Move to acting on `deny` only when its precision is high enough that you would defend each case to the customer. Keep `review` going to a person.

## Reading the eval

```text
 review: flagged   164  precision 0.872  recall 0.888  fp 21
   deny: flagged     6  precision 1.0    recall 0.037  fp 0

reason code               accounts  precision
EMAIL_PLUS_TAG                  82      0.671
PROMO_LINKED_REDEMPTION        148      0.858
```

That is synthetic data, so the absolute numbers mean little. The shape is typical though: `deny` is precise and catches very little, `review` catches most things and needs people. `EMAIL_PLUS_TAG` has poor precision because plenty of real people use plus addressing. Its default weight is 5 for that reason; it is there to add context to other reasons, not to decide anything.

## Usual false positive sources

- **Households and offices.** Shared devices and cards inside a family trip linking and identity reuse. Raise `promo_max_accounts_per_cluster` to 2 if your product allows family accounts, or lower `max_attribute_degree` for devices.
- **Corporate and mobile NAT.** Many real users behind one IPv4 address. Keep IP rules on `ip_prefix` with high thresholds, never on linking.
- **Travel.** New device plus new country looks like takeover. The sequence rule needs a credential change and a cash-out as well, which travellers rarely do together.
- **QA and load test accounts.** Put them in `allowlist.accounts`. Their reasons are still recorded so you can see if the allowlist is hiding something.
- **Legit password resets.** People forget passwords and then update bank details. The partial `ATO_CRED_CHANGE_CASHOUT` (25) is deliberately well below the full sequence (85).

## Weights versus thresholds

Raise a velocity `threshold` when the rule fires on normal behaviour. Lower its `weight` when it fires on the right behaviour but is weak evidence on its own. Mixing those up is the most common tuning mistake.

## Combining

Because scores combine as noisy-OR, adding a new weak signal (10) to an event already at 60 moves it to 64, not 70. Correlated signals (three email checks that all fire on the same throwaway address) still stack somewhat. If two codes always fire together, give one of them weight 0 and keep it for explanation.
