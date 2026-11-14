"""Scoring engine.

``Engine.score`` takes one event, updates in-memory state, and returns a
decision with every reason that fired. State is process-local; for more than
one worker, shard by account and accept that cross-shard signals (shared
devices, rings) need a shared store. See docs/threat-model.md.

Scoring is idempotent per ``event_id``. Queues redeliver, clients retry, and
without this a payment redelivered eight times would count as eight card
attempts. A repeated id inside ``dedup_window`` gets the original decision
back, marked ``duplicate``, and touches no state. Events without an id cannot
be deduplicated; set one upstream.

Every piece of state has a bound: windows cap their keys, the takeover
tracker caps accounts and ages them out, the linker ages out edges, and the
dedup cache is capped by count and age. ``prune`` runs every ``PRUNE_EVERY``
events against the newest timestamp seen so far, so one late event cannot
drag pruning back in time.

Event time, not arrival time, drives every window, so ordering matters. The
engine tracks a watermark: the newest timestamp seen minus
``allowed_lateness``. An event at or above the watermark is scored normally,
and the windows answer as of its own timestamp. An event below it is not
scored against state at all: by then pruning may have dropped what it should
be compared with, and inserting it would rewrite history that later decisions
already relied on. It gets ``late: true``, a ``LATE_EVENT`` reason and
``late_action``. ``max_future_skew`` does the mirror image for timestamps too
far ahead of the newest one seen; without it, one event stamped next year
moves the watermark and turns the whole stream late.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from fraudkit.ato import AtoTracker
from fraudkit.events import Event
from fraudkit.linking import Linker
from fraudkit.rules import RuleConfig, VelocityRule
from fraudkit.signals import IpClassifier, email_hits, ip_prefix, normalize_email
from fraudkit.windows import CountWindow, DistinctWindow, SumWindow

EMAIL_EVENTS = frozenset({"signup", "email_change"})
IP_EVENTS = frozenset({"signup", "login", "payment", "payout_change", "withdrawal"})
LINK_EVENTS = frozenset({"signup", "login", "payment", "payout_change", "promo_redeem"})

PRUNE_EVERY = 10_000


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    weight: float
    detail: str


@dataclass(slots=True)
class Decision:
    event_id: str
    account_id: str
    ts: float
    score: float
    action: str
    reasons: list[Reason] = field(default_factory=list)
    duplicate: bool = False
    late: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["score"] = round(self.score, 2)
        return d


def combine(weights: list[float]) -> float:
    """Noisy-OR of per-signal weights, on a 0..100 scale.

    ``1 - prod(1 - w/100)``. One 85 is worse than three 30s (85 vs 65.7),
    which matches how reviewers think about it better than a capped sum does,
    and the result can never exceed 100.
    """
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - min(max(w, 0.0), 100.0) / 100.0
    return 100.0 * (1.0 - remaining)


class Engine:
    def __init__(self, config: RuleConfig) -> None:
        self.cfg = config
        self.ips = IpClassifier(config.hosting_cidrs, config.blocked_cidrs)
        self.ato = AtoTracker(
            window_s=config.ato_window_s,
            device_ttl_s=config.device_ttl_s,
            max_accounts=config.max_accounts,
        )
        self.linker = Linker(
            max_degree=config.max_attribute_degree,
            max_cluster=config.max_cluster_size,
            ttl_s=config.link_window_s,
            max_edges=config.max_link_edges,
        )
        max_keys = config.max_keys_per_window
        # Windows keep expired entries this long so late events get as-of answers.
        grace = config.allowed_lateness_s
        self._windows: dict[str, CountWindow] = {}
        for rule in config.velocity:
            cls = {"count": CountWindow, "sum": SumWindow, "distinct": DistinctWindow}[rule.kind]
            self._windows[rule.code] = cls(rule.window_s, max_keys, grace)
        reuse = config.identity_reuse_window_s
        self._phone_accounts = DistinctWindow(reuse, max_keys, grace)
        self._address_accounts = DistinctWindow(reuse, max_keys, grace)
        self._card_accounts = DistinctWindow(reuse, max_keys, grace)
        # account -> promo code -> last redemption ts, aged with the link window
        self._promo_by_account: OrderedDict[str, dict[str, float]] = OrderedDict()
        self._decisions: OrderedDict[str, Decision] = OrderedDict()
        self._seen = 0
        self._high_water = float("-inf")
        self.late_events = 0

    @staticmethod
    def _field(ev: Event, name: str) -> str | None:
        if name == "ip_prefix":
            return ip_prefix(ev.ip)
        if name == "email_norm":
            return normalize_email(ev.email) if ev.email else None
        value = ev.get(name)
        return None if value is None else str(value)

    def _velocity(self, ev: Event, rule: VelocityRule) -> Reason | None:
        if ev.type not in rule.events:
            return None
        if any(ev.get(k) != v for k, v in rule.where):
            return None
        key = self._field(ev, rule.key)
        if key is None:
            return None
        win = self._windows[rule.code]
        if isinstance(win, DistinctWindow):
            value = self._field(ev, rule.distinct or "")
            if value is None:
                return None
            observed: float = win.add(key, ev.ts, value)
        elif isinstance(win, SumWindow):
            observed = win.add(key, ev.ts, ev.amount)
        else:
            observed = win.add(key, ev.ts)
        if observed >= rule.threshold:
            detail = f"{rule.kind} {observed:g} >= {rule.threshold:g} by {rule.key}"
            return Reason(rule.code, rule.weight, detail)
        return None

    def _identity(self, ev: Event) -> list[tuple[str, str]]:
        if ev.type != "signup":
            return []
        out = []
        th = self.cfg.identity_reuse_threshold
        for win, value, code in (
            (self._phone_accounts, ev.phone, "ID_PHONE_REUSE"),
            (self._address_accounts, ev.address, "ID_ADDRESS_REUSE"),
            (self._card_accounts, ev.card_fp, "ID_CARD_REUSE_AT_SIGNUP"),
        ):
            if not value:
                continue
            n = win.add(value.strip().lower(), ev.ts, ev.account_id)
            limit = self.cfg.card_reuse_threshold if code == "ID_CARD_REUSE_AT_SIGNUP" else th
            if n >= limit:
                out.append((code, f"{n} accounts in reuse window"))
        return out

    def _promo(self, ev: Event) -> list[tuple[str, str]]:
        if ev.type != "promo_redeem" or not ev.promo_code:
            return []
        out = []
        used = self._promo_by_account.pop(ev.account_id, None) or {}
        self._promo_by_account[ev.account_id] = used
        while len(self._promo_by_account) > self.cfg.max_accounts:
            self._promo_by_account.popitem(last=False)
        if ev.promo_code in used:
            out.append(("PROMO_REPEAT_ACCOUNT", ev.promo_code))
        used[ev.promo_code] = max(ev.ts, used.get(ev.promo_code, ev.ts))
        n = self.linker.redeem(ev.account_id, ev.promo_code, ev.ts)
        if n > self.cfg.promo_max_accounts_per_cluster:
            out.append(("PROMO_LINKED_REDEMPTION", f"{n} linked accounts used {ev.promo_code}"))
        return out

    def _replayed(self, ev: Event) -> Decision | None:
        if not ev.event_id:
            return None
        prior = self._decisions.get(ev.event_id)
        if prior is None:
            return None
        if max(self._high_water, ev.ts) - prior.ts >= self.cfg.dedup_window_s:
            # Too old to be a redelivery we can vouch for; score it fresh.
            del self._decisions[ev.event_id]
            return None
        return replace(prior, reasons=list(prior.reasons), duplicate=True)

    def _remember(self, decision: Decision) -> None:
        if not decision.event_id:
            return
        self._decisions[decision.event_id] = decision
        self._decisions.move_to_end(decision.event_id)
        while len(self._decisions) > self.cfg.dedup_max_ids:
            self._decisions.popitem(last=False)

    @property
    def watermark(self) -> float:
        """Events older than this are refused by ``score``. ``-inf`` before the first event."""
        return self._high_water - self.cfg.allowed_lateness_s

    def _out_of_order(self, ev: Event) -> Decision | None:
        if self._high_water == float("-inf"):
            return None
        if ev.ts < self.watermark:
            code = "LATE_EVENT"
            detail = f"{self._high_water - ev.ts:g}s behind newest event"
        else:
            skew = self.cfg.max_future_skew_s
            if skew is None or ev.ts - self._high_water <= skew:
                return None
            code = "CLOCK_AHEAD"
            detail = f"{ev.ts - self._high_water:g}s ahead of newest event"
        self.late_events += 1
        reason = Reason(code, self.cfg.weight(code), detail)
        return Decision(
            ev.event_id, ev.account_id, ev.ts, 0.0, self.cfg.late_action, [reason], late=True
        )

    def score(self, ev: Event) -> Decision:
        replayed = self._replayed(ev)
        if replayed is not None:
            return replayed
        refused = self._out_of_order(ev)
        if refused is not None:
            # Remembered, so a redelivery of the same late event gets the same answer.
            self._remember(refused)
            return refused
        self._high_water = max(self._high_water, ev.ts)
        self._seen += 1
        if self._seen % PRUNE_EVERY == 0:
            self.prune(self._high_water)
        decision = self._score(ev)
        self._remember(decision)
        return decision

    def _score(self, ev: Event) -> Decision:
        hits: list[tuple[str, str]] = []
        reasons: list[Reason] = []

        for rule in self.cfg.velocity:
            r = self._velocity(ev, rule)
            if r:
                reasons.append(r)
        if ev.type in EMAIL_EVENTS:
            hits += [(h.code, h.detail) for h in email_hits(ev.email, self.cfg.disposable_domains)]
        if ev.type in IP_EVENTS:
            hits += [(h.code, h.detail) for h in self.ips.hits(ev.ip)]
        hits += [
            (h.code, h.detail)
            for h in self.ato.observe(ev.type, ev.account_id, ev.device_id, ev.ts)
        ]
        hits += self._identity(ev)
        if ev.type in LINK_EVENTS:
            attrs = {f: self._field(ev, f) for f in self.cfg.link_on}
            for attr in self.linker.link(ev.account_id, attrs, ev.ts):
                hits.append(("LINK_SUPERNODE", attr.split(":", 1)[0]))
        hits += self._promo(ev)

        reasons += [Reason(code, self.cfg.weight(code), detail) for code, detail in hits]
        reasons.sort(key=lambda r: (-r.weight, r.code))

        if ev.account_id in self.cfg.allow_accounts:
            # Keep the reasons so allowlisted traffic is still visible in review.
            return Decision(ev.event_id, ev.account_id, ev.ts, 0.0, "allow", reasons)

        total = combine([r.weight for r in reasons])
        if total >= self.cfg.deny_at:
            action = "deny"
        elif total >= self.cfg.review_at:
            action = "review"
        else:
            action = "allow"
        return Decision(ev.event_id, ev.account_id, ev.ts, total, action, reasons)

    def prune(self, now: float) -> dict[str, int]:
        """Age out state older than its window. Returns how much each part dropped."""
        dropped = {"windows": 0, "ato_accounts": 0, "link_edges": 0, "promo": 0, "dedup": 0}
        for win in self._windows.values():
            dropped["windows"] += win.prune(now)
        for win in (self._phone_accounts, self._address_accounts, self._card_accounts):
            dropped["windows"] += win.prune(now)
        dropped["ato_accounts"] = self.ato.prune(now)
        dropped["link_edges"] = self.linker.prune(now)
        cutoff = now - self.cfg.link_window_s
        for acct in list(self._promo_by_account):
            codes = self._promo_by_account[acct]
            for code in [c for c, ts in codes.items() if ts <= cutoff]:
                del codes[code]
                dropped["promo"] += 1
            if not codes:
                del self._promo_by_account[acct]
        dedup_cutoff = now - self.cfg.dedup_window_s
        for eid in [e for e, d in self._decisions.items() if d.ts <= dedup_cutoff]:
            del self._decisions[eid]
            dropped["dedup"] += 1
        return dropped

    def state_size(self) -> dict[str, int]:
        """Rough count of held entries per structure, for metrics and tests."""
        return {
            "window_keys": sum(len(w) for w in self._windows.values())
            + len(self._phone_accounts)
            + len(self._address_accounts)
            + len(self._card_accounts),
            "ato_accounts": len(self.ato),
            "link_edges": len(self.linker),
            "promo_accounts": len(self._promo_by_account),
            "dedup_ids": len(self._decisions),
        }
