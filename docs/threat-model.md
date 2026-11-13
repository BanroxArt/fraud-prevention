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
- Phone and address are keyed hashes. A plain SHA-256 of a phone number can be reversed by brute force in minutes.

## Known gaps

- Patient attackers. Anything spaced out wider than the windows is invisible. Longer windows cost memory and raise false positives.
- Attribute rotation. A ring that uses a fresh card, device and mailbox per account does not link. Linking then has to come from data this engine does not have (bank account, shipping address, behaviour).
- Supernode capping means a ring that hides behind a genuinely shared attribute is not linked through it. That is the trade for not merging unrelated customers.
- Insider abuse and support social engineering. Those show up in admin and support tool logs, not in customer events.
- Authorised push payment scams, where the real customer is tricked into sending money. The customer's own device and credentials are used, so takeover signals stay quiet. That needs payee risk and in-flow warnings.

## Abuse of the tool itself

Reason codes are shown to analysts, not end users. Telling a declined user "VEL_SIGNUPS_PER_DEVICE" teaches the attacker the threshold. Give users a generic message and a way to appeal.
