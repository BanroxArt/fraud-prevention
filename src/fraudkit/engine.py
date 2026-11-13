"""Scoring engine.

``Engine.score`` takes one event, updates in-memory state, and returns a
decision with every reason that fired. State is process-local; for more than
one worker, shard by account and accept that cross-shard signals (shared
devices, rings) need a shared store. See docs/threat-model.md.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
        self.ato = AtoTracker(window_s=config.ato_window_s)
        self.linker = Linker(max_degree=config.max_attribute_degree)
        self._windows: dict[str, CountWindow] = {}
        for rule in config.velocity:
            cls = {"count": CountWindow, "sum": SumWindow, "distinct": DistinctWindow}[rule.kind]
            self._windows[rule.code] = cls(rule.window_s)
        reuse = config.identity_reuse_window_s
        self._phone_accounts = DistinctWindow(reuse)
        self._address_accounts = DistinctWindow(reuse)
        self._card_accounts = DistinctWindow(reuse)
        self._promo_by_account: dict[str, set[str]] = {}
        self._seen = 0

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
            limit = 2 if code == "ID_CARD_REUSE_AT_SIGNUP" else th
            if n >= limit:
                out.append((code, f"{n} accounts in reuse window"))
        return out

    def _promo(self, ev: Event) -> list[tuple[str, str]]:
        if ev.type != "promo_redeem" or not ev.promo_code:
            return []
        out = []
        used = self._promo_by_account.setdefault(ev.account_id, set())
        if ev.promo_code in used:
            out.append(("PROMO_REPEAT_ACCOUNT", ev.promo_code))
        used.add(ev.promo_code)
        n = self.linker.redeem(ev.account_id, ev.promo_code)
        if n > self.cfg.promo_max_accounts_per_cluster:
            out.append(("PROMO_LINKED_REDEMPTION", f"{n} linked accounts used {ev.promo_code}"))
        return out

    def score(self, ev: Event) -> Decision:
        self._seen += 1
        if self._seen % PRUNE_EVERY == 0:
            self.prune(ev.ts)

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
            for attr in self.linker.link(ev.account_id, attrs):
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

    def prune(self, now: float) -> None:
        for win in self._windows.values():
            win.prune(now)
        for win in (self._phone_accounts, self._address_accounts, self._card_accounts):
            win.prune(now)
