# fraud-prevention

`fraudkit` is a small fraud scoring engine for account and payment events, plus an agent skill (`SKILL.md`) for running a first-pass fraud program review.

The engine takes a stream of events (signups, logins, password resets, payout changes, payments, promo redemptions), keeps a little state in memory, and returns a score, an action (`allow`, `review`, `deny`) and the list of reasons that fired. Every point of score maps to a reason code you can show an analyst. There is no model to train.

It is meant for teams that need something better than nothing in week one, and want the rules in a file they can review, not buried in a vendor console.

Built and maintained by Art Akopian, CEO of [Banrox](https://banrox.com). Banrox builds consumer credit and fraud-prevention software and publishes the general-purpose pieces.

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
| `cli.py` | `fraudkit score`, `fraudkit synth`, `fraudkit eval`, `fraudkit validate` |

## Install and run

Python 3.11 or newer. The only runtime dependency is PyYAML.

```sh
python -m pip install -e '.[dev]'
make check        # ruff, content lint, mypy, pytest
make demo         # synth 300 accounts, score them with the demo rules, print precision/recall
```

Score your own events:

```sh
fraudkit score events.jsonl --rules my-rules.yaml -o scored.jsonl
fraudkit score - --min-score 40 < events.jsonl     # only print what needs a look
fraudkit validate my-rules.yaml                     # load and check a rules file
```

Events are one JSON object per line. `ts` (epoch seconds or ISO 8601 with an offset), `type` and `account_id` are required. Optional fields: `event_id`, `device_id`, `ip`, `email`, `phone`, `card_fp`, `address`, `amount`, `promo_code`. Anything else is kept and can be used in a rule's `where` clause. Identifier fields are capped at 256 characters, extra fields at 32 per event, and amounts must be finite; lines that break those limits are rejected and reported, not truncated.

Send an `event_id`. A repeated id inside `state.dedup_window` (24h by default) returns the first decision again with `"duplicate": true` and does not touch any counters, so queue redelivery and client retries cannot push an account over a velocity threshold. Without an id there is nothing to deduplicate on.

Running the bundled example with the packaged rules (`fraudkit score examples/events.jsonl`) gives, trimmed:

```text
e3  allow    5.0  ATO_NEW_DEVICE_LOGIN
e4  allow   30.0  ATO_CRED_CHANGE_AFTER_NEW_DEVICE
e5  deny    85.0  ATO_SEQUENCE
e8  review  66.0  VEL_SIGNUPS_PER_DEVICE, ID_CARD_REUSE_AT_SIGNUP, EMAIL_PLUS_TAG
e10 review  60.0  PROMO_LINKED_REDEMPTION
```

`examples/demo-rules.yaml` is the same file with a documentation IP range filled in as the hosting list, so `IP_HOSTING` shows up in the demo too. The packaged rules ship with empty IP lists.

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

Velocity keys can be any event field plus two derived ones: `ip_prefix` (/24 for v4, /64 for v6) and `email_norm`. The loader rejects unknown fields, duplicate codes, weights outside 0..100, non-positive windows and caps, and linking on IP. `fraudkit validate rules.yaml` runs the same checks without scoring anything.

## Design notes

**Scores combine as noisy-OR.** `score = 100 * (1 - prod(1 - w/100))`. One strong signal (85) outranks three weak ones (30 each come to 65.7), and the total cannot pass 100. A capped sum lets a pile of weak, correlated signals look like certainty. The cost is that weights are not independent probabilities in practice, so treat the score as a ranking, not a calibrated probability.

**Linking uses union-find with a degree cap.** Accounts and attribute values are nodes; sharing a card or device merges clusters. Promo redemptions are tracked per cluster, so five accounts on one card redeeming `WELCOME10` is caught even if every email is different. An attribute that has already linked `max_attribute_degree` accounts stops merging and emits `LINK_SUPERNODE` instead. Without the cap, one shared office tablet or a wallet's generic card fingerprint merges thousands of unrelated people into one ring. The per-attribute cap does not stop a chain through different attributes (card to device to phone to ...), so there is also `max_cluster_size`: a merge that would push a cluster past it is refused and reported the same way. IP is never a linking key for the same reason (carrier NAT). Links and redemptions age out after `linking.window` (90 days by default); a card two people shared in January does not tie them together in June.

**Takeover is a sequence, not a signal.** A new device, a password reset and a payout change are each normal. In that order inside 24 hours, on the same device, they are the common takeover cash-out. `ato.py` keeps per-account deques of new-device logins and credential changes, each with the device it came from. `ATO_SEQUENCE` needs a credential change made from a device after that device's first login, and a cash-out from the same device (or with no device, for server-side payout jobs). A reset from the owner's usual phone plus an unrelated new-device login earlier that day only gets the weaker `ATO_CRED_AND_NEW_DEVICE`. The device used at signup does not count as new.

**Bring your own IP lists.** No hosting, VPN or proxy ranges ship with this. They go stale in weeks and the good ones are licensed. `IP_NON_ROUTABLE` fires on private client addresses because that almost always means your proxy header is not being read, which silently breaks every IP rule.

**Hash PII before it gets here.** Phone and address are only compared for equality, so pass a keyed hash (HMAC with a secret you rotate) rather than the raw value. Email is the exception because the checks read the domain and local part.

## State and memory

Every structure the engine keeps is bounded, because nearly every key in it comes from event data:

| State | Aged out by | Hard cap (`state:` in the rules file) |
| --- | --- | --- |
| Velocity and identity windows | their own `window` | `max_keys_per_window`, least recently updated key dropped first |
| Takeover tracker (devices, recent logins and credential changes) | `ato.device_ttl` for idle accounts | `max_accounts` |
| Linking graph and promo redemptions | `linking.window` | `max_link_edges`, oldest tenth dropped when hit |
| Dedup cache | `state.dedup_window` | `dedup_max_ids` |

`Engine.prune(now)` runs every 10,000 events against the newest timestamp seen so far and returns what it dropped. `Engine.state_size()` gives the current counts if you want to export them as metrics. Hitting a hard cap means some signal is lost for the evicted keys; if it happens under normal traffic, raise the cap rather than live with it.

## Late and out-of-order events

Windows run on event time. Queues redeliver out of order, mobile clients batch events from a flight, and a consumer that restarts may replay an hour behind, so arrival order cannot be trusted. Three settings in `state:` cover it:

| Setting | Default | Effect |
| --- | --- | --- |
| `allowed_lateness` | `1h` | An event older than (newest timestamp seen minus this) is behind the watermark. It is not scored against state, gets `late: true`, a `LATE_EVENT` reason with how far behind it was, and `late_action`. |
| `late_action` | `review` | `allow`, `review` or `deny` for refused events. `review` is the safe choice: a late event is unusual, and refusing to look at it silently is how replay abuse goes unnoticed. |
| `max_future_skew` | off | An event this far ahead of the newest one seen gets `CLOCK_AHEAD` and `late_action`, and does not move the watermark. Without it, one event stamped next year makes every later event late. Turn it on for live streams; leave it off for batch replays with gaps. |

An event inside `allowed_lateness` is scored, and every window answers as of its own timestamp. Three card attempts at 10:15 do not count against a payment that happened at 10:00 and arrived at 10:20. To make that answer exact, each window keeps the last `allowed_lateness` of expired entries, so memory per key grows by roughly that fraction of the window. The property tests check the window answers against a brute-force count for arbitrary arrival orders inside the bound.

`allowed_lateness` has to be shorter than `dedup_window`. Otherwise an event delivered once, then redelivered after its dedup entry expired but while still inside the lateness bound, would be scored twice.

`fraudkit score` prints how many events it refused on stderr.

## Limitations

- State is in memory and per process. Restarting loses windows and links. For more than one worker, shard by account and accept that cross-account signals (shared devices, rings) need a shared store such as Redis. That is not built here.
- Dedup keys on `event_id` alone. Two different events sent with the same id get one decision; make ids unique upstream.
- Late events cost O(n) for their key, and the takeover tracker and linker see events in arrival order even inside `allowed_lateness`, so a sequence delivered backwards is not reassembled. Badly ordered input should be sorted first (`--sort`).
- A late event is answered as of its own time, but the decisions already made for the events after it are not revisited. If a late payment would have pushed a later one over a threshold, that later one stays scored as it was.
- The synthetic generator is blunt. `make demo` numbers show the engine does what the rules say. They say nothing about catch rates on real traffic.
- No device fingerprinting, no consortium data, no ML. Those are worth buying once you know what you are losing money to.
- This is a decision aid. Denying someone money or access has legal and fairness consequences; keep a human in the loop for `deny` until you have reviewed outcomes.

More: [docs/threat-model.md](docs/threat-model.md), [docs/tuning.md](docs/tuning.md), [CHANGELOG.md](CHANGELOG.md).

## The agent skill

`SKILL.md` is a skill file for coding agents that support them. Copy it to `.cursor/skills/fraud-prevention/SKILL.md` (or your agent's equivalent). It walks an agent through a defensive fraud program review and, where the team has event data, through standing up `fraudkit` against it. [examples/sample-review.md](examples/sample-review.md) shows the report shape on a made-up company.

## Benchmarks

Per-operation timings and how to reproduce them: [docs/benchmarks.md](docs/benchmarks.md).

## License

MIT. See [LICENSE](LICENSE). Copyright 2026 Banrox Inc.

Issues and patches are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as described in [SECURITY.md](SECURITY.md). Please do not send techniques for evading fraud controls.
