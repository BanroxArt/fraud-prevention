# fraud-prevention

`fraudkit` is a small fraud scoring engine for account and payment events, plus an agent skill (`SKILL.md`) for running a first-pass fraud program review.

The engine takes a stream of events (signups, logins, password resets, payout changes, payments, promo redemptions), keeps a little state in memory, and returns a score, an action (`allow`, `review`, `deny`) and the list of reasons that fired. Every point of score maps to a reason code you can show an analyst. There is no model to train.

It is meant for teams that need something better than nothing in week one, and want the rules in a file they can review, not buried in a vendor console.

Author: Art Akopian ([Banrox](https://banrox.com))

## What's in it

| Module | Does |
| --- | --- |
| `windows.py` | Trailing count, sum and distinct-value windows keyed by any field |
| `signals.py` | Email checks (disposable domain, plus tags, digit-heavy and random-looking local parts), email normalisation, IP range checks |
| `ato.py` | Account takeover sequence: new device, then credential change, then payout change or withdrawal |
| `linking.py` | Union-find over accounts and shared attributes, used to catch promo and referral rings |
| `rules.py` | YAML rule loading and validation |
| `engine.py` | Ties it together and combines weights into one score |
| `synth.py` | Labelled synthetic event generator |
| `cli.py` | `fraudkit score`, `fraudkit synth`, `fraudkit eval` |

## Install and run

Python 3.11 or newer. The only runtime dependency is PyYAML.

```sh
python -m pip install -e '.[dev]'
make check        # ruff, content lint, pytest
make demo         # synth 300 accounts, score them, print precision/recall
```

Score your own events:

```sh
fraudkit score events.jsonl --rules my-rules.yaml -o scored.jsonl
fraudkit score - --min-score 40 < events.jsonl     # only print what needs a look
```

Events are one JSON object per line. `ts` (epoch seconds or ISO 8601 with an offset), `type` and `account_id` are required. Optional fields: `device_id`, `ip`, `email`, `phone`, `card_fp`, `address`, `amount`, `promo_code`. Anything else is kept and can be used in a rule's `where` clause.

Running the bundled example (`fraudkit score examples/events.jsonl`) gives, trimmed:

```text
e3  allow   24.0  IP_HOSTING, ATO_NEW_DEVICE_LOGIN
e4  allow   30.0  ATO_CRED_CHANGE_AFTER_NEW_DEVICE
e5  deny    88.0  ATO_SEQUENCE, IP_HOSTING
e8  review  72.8  VEL_SIGNUPS_PER_DEVICE, ID_CARD_REUSE_AT_SIGNUP, IP_HOSTING, EMAIL_PLUS_TAG
e10 review  60.0  PROMO_LINKED_REDEMPTION
```

From Python:

```python
from fraudkit import Engine, load_rules, parse_event

engine = Engine(load_rules("rules.yaml"))
decision = engine.score(parse_event(raw_dict))
if decision.action != "allow":
    open_case(decision.account_id, [r.code for r in decision.reasons])
```

## Rules

Rules are YAML. The packaged defaults are in `src/fraudkit/default_rules.yaml` and are a starting point, not a recommendation for your traffic.

```yaml
velocity:
  - code: VEL_SIGNUPS_PER_DEVICE
    events: [signup]
    key: device_id
    distinct: account_id     # count distinct accounts, not events
    window: 24h
    threshold: 3
    weight: 45
  - code: VEL_FAILED_LOGIN_ACCOUNT
    events: [login]
    key: account_id
    where: {success: false}
    window: 15m
    threshold: 10
    weight: 20
weights:
  ATO_SEQUENCE: 85
  EMAIL_DISPOSABLE: 30
```

Velocity keys can be any event field plus two derived ones: `ip_prefix` (/24 for v4, /64 for v6) and `email_norm`. The loader rejects unknown fields, duplicate codes, weights outside 0..100 and linking on IP.

## Design notes

**Scores combine as noisy-OR.** `score = 100 * (1 - prod(1 - w/100))`. One strong signal (85) outranks three weak ones (30 each come to 65.7), and the total cannot pass 100. A capped sum lets a pile of weak, correlated signals look like certainty. The cost is that weights are not independent probabilities in practice, so treat the score as a ranking, not a calibrated probability.

**Linking uses union-find with a degree cap.** Accounts and attribute values are nodes; sharing a card or device merges clusters. Promo redemptions are tracked per cluster, so five accounts on one card redeeming `WELCOME10` is caught even if every email is different. An attribute that has already linked `max_attribute_degree` accounts stops merging and emits `LINK_SUPERNODE` instead. Without the cap, one shared office tablet or a wallet's generic card fingerprint merges thousands of unrelated people into one ring. IP is never a linking key for the same reason (carrier NAT).

**Takeover is a sequence, not a signal.** A new device, a password reset and a payout change are each normal. In that order inside 24 hours they are the common takeover cash-out. `ato.py` keeps per-account deques of new-device logins and credential changes and grades the cash-out event by how much of the sequence it saw. The device used at signup does not count as new.

**Bring your own IP lists.** No hosting, VPN or proxy ranges ship with this. They go stale in weeks and the good ones are licensed. `IP_NON_ROUTABLE` fires on private client addresses because that almost always means your proxy header is not being read, which silently breaks every IP rule.

**Hash PII before it gets here.** Phone and address are only compared for equality, so pass a keyed hash (HMAC with a secret you rotate) rather than the raw value. Email is the exception because the checks read the domain and local part.

## Limitations

- State is in memory and per process. Restarting loses windows and links. For more than one worker, shard by account and accept that cross-account signals (shared devices, rings) need a shared store such as Redis. That is not built here.
- Late events are inserted in order but cost O(n) for that key. Badly ordered input should be sorted first (`--sort`).
- The synthetic generator is blunt. `make demo` numbers show the engine does what the rules say. They say nothing about catch rates on real traffic.
- No device fingerprinting, no consortium data, no ML. Those are worth buying once you know what you are losing money to.
- This is a decision aid. Denying someone money or access has legal and fairness consequences; keep a human in the loop for `deny` until you have reviewed outcomes.

More: [docs/threat-model.md](docs/threat-model.md), [docs/tuning.md](docs/tuning.md).

## The agent skill

`SKILL.md` is a skill file for coding agents that support them. Copy it to `.cursor/skills/fraud-prevention/SKILL.md` (or your agent's equivalent). It walks an agent through a defensive fraud program review and, where the team has event data, through standing up `fraudkit` against it. [examples/sample-review.md](examples/sample-review.md) shows the report shape on a made-up company.

## License

MIT. See [LICENSE](LICENSE). Copyright 2026 Banrox Inc.

Issues and patches are welcome. Please do not send techniques for evading fraud controls.
