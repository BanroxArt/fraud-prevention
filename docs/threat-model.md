# Threat model

What fraudkit tries to catch, what it assumes, and where it is weak.

## Assets

Money leaving the platform (withdrawals, payouts, refunds), value granted by the platform (promo credit, referral bonuses, free trials), and accounts themselves (an account with history and a verified payout destination is worth stealing).

## Attackers and what the engine looks at

| Attack | Typical shape | Signals |
| --- | --- | --- |
| Device or emulator farm | Many signups from one device or a small IP prefix, throwaway emails | `VEL_SIGNUPS_PER_DEVICE`, `VEL_LOGIN_IP_PREFIX`, `EMAIL_*` |
| Promo and referral rings | Several accounts that share a card, device or mailbox each take the new-user offer | `PROMO_LINKED_REDEMPTION`, `PROMO_REPEAT_ACCOUNT`, `ID_CARD_REUSE_AT_SIGNUP` |
| Synthetic identity | Made-up identities built on a reused phone, address or card | `ID_PHONE_REUSE`, `ID_ADDRESS_REUSE`, `ID_CARD_REUSE_AT_SIGNUP` |
| Account takeover | Phished or stuffed credentials, then reset, then redirect payouts | `ATO_SEQUENCE` and its partial forms |
| Card testing | Bursts of small charges across many cards | `VEL_CARD_ATTEMPTS`, `VEL_CARDS_PER_ACCOUNT`, `VEL_CARD_SPEND` |
| Credential stuffing | Many failed logins per account or per IP prefix | `VEL_FAILED_LOGIN_ACCOUNT`, `VEL_LOGIN_IP_PREFIX` |

## Assumptions

- Event fields are set by your backend, not by the client. A `device_id` the client invents is a hint, not an identifier. If an attacker controls it, every device rule degrades to an IP rule.
- Client IP is read from the right proxy header. `IP_NON_ROUTABLE` exists to tell you when it is not.
- Events arrive roughly in time order and the scorer sees all of them for an account. Sharding by anything other than account breaks the takeover and velocity logic.
- Events carry a unique `event_id`, so redelivery can be detected.
- For accounts that predate the pipeline, the first device the engine sees is treated as the baseline, the same as a signup device. The alternative, flagging every account's first observed login as a new device, buries real takeovers in noise on day one. The cost is that a takeover device seen before any genuine one is trusted.
- Phone and address are keyed hashes. A plain SHA-256 of a phone number can be reversed by brute force in minutes.

## Attacks on the engine itself

- **Replay.** Queues redeliver and clients retry. Without dedup, one payment seen eight times counts as eight card attempts. The engine returns the first decision for a repeated `event_id` inside `state.dedup_window` and leaves state untouched. Events with no id are not protected.
- **State exhaustion.** Device ids, card fingerprints and free-form fields become dictionary keys. A sender who rotates them can try to grow memory without limit. The parser caps field lengths and the number of extra fields, and every in-memory structure has a time-based prune plus a hard cap (see "State and memory" in the README). At the cap the oldest keys are dropped, which loses signal for them; that is the trade for staying up.
- **Linking poisoning.** Linking on a normalised email means `victim+anything` at the victim's provider lands in the same node as the victim's real address. Someone who registers that address can drag the victim into their cluster and make the victim's later promo use look linked. Plus-tag stripping applies to every domain, which also merges distinct mailboxes on the few providers where `+` is a literal character. If that matters for your traffic, link on a verified email only, or drop `email_norm` from `link_on`.
- **Cluster growth.** The supernode cap is per attribute; `max_cluster_size` bounds the whole cluster so a long chain through different attributes cannot merge unrelated people.

## Known gaps

- Patient attackers. Anything spaced out wider than the windows is invisible. Longer windows cost memory and raise false positives.
- Attribute rotation. A ring that uses a fresh card, device and mailbox per account does not link. Linking then has to come from data this engine does not have (bank account, shipping address, behaviour).
- Supernode capping means a ring that hides behind a genuinely shared attribute is not linked through it. That is the trade for not merging unrelated customers.
- Insider abuse and support social engineering. Those show up in admin and support tool logs, not in customer events.
- Authorised push payment scams, where the real customer is tricked into sending money. The customer's own device and credentials are used, so takeover signals stay quiet. That needs payee risk and in-flow warnings.

## Abuse of the tool itself

Reason codes are shown to analysts, not end users. Telling a declined user "VEL_SIGNUPS_PER_DEVICE" teaches the attacker the threshold. Give users a generic message and a way to appeal.
