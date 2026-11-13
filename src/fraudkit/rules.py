"""Rule configuration.

Rules live in YAML so that risk and ops people can tune them in review
without touching code. Every weight is a number in [0, 100] read as "how
confident would I be this is abuse if this were the only thing I knew".
See docs/tuning.md for how the weights combine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from fraudkit.events import EVENT_TYPES

_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(s|m|h|d)?\s*$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}

KEY_FIELDS = {
    "account_id",
    "device_id",
    "ip",
    "ip_prefix",
    "email",
    "email_norm",
    "phone",
    "card_fp",
    "address",
}


class RuleError(ValueError):
    pass


def parse_duration(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    m = _DURATION.match(str(value))
    if not m:
        raise RuleError(f"bad duration {value!r}, expected e.g. 90s, 10m, 24h, 30d")
    return float(m.group(1)) * _UNITS[m.group(2)]


@dataclass(frozen=True, slots=True)
class VelocityRule:
    code: str
    events: frozenset[str]
    key: str
    window_s: float
    threshold: float
    weight: float
    distinct: str | None = None
    sum: str | None = None
    where: tuple[tuple[str, Any], ...] = ()

    @property
    def kind(self) -> str:
        if self.distinct:
            return "distinct"
        if self.sum:
            return "sum"
        return "count"


@dataclass(slots=True)
class RuleConfig:
    review_at: float = 40.0
    deny_at: float = 80.0
    velocity: list[VelocityRule] = field(default_factory=list)
    weights: dict[str, float] = field(default_factory=dict)
    disposable_domains: list[str] = field(default_factory=list)
    hosting_cidrs: list[str] = field(default_factory=list)
    blocked_cidrs: list[str] = field(default_factory=list)
    ato_window_s: float = 86_400.0
    link_on: list[str] = field(
        default_factory=lambda: ["device_id", "card_fp", "email_norm", "phone"]
    )
    max_attribute_degree: int = 25
    promo_max_accounts_per_cluster: int = 1
    identity_reuse_window_s: float = 30 * 86_400.0
    identity_reuse_threshold: int = 3
    allow_accounts: frozenset[str] = frozenset()

    def weight(self, code: str) -> float:
        return self.weights.get(code, 0.0)


def _weight(value: Any, where: str) -> float:
    try:
        w = float(value)
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{where}: weight must be a number") from exc
    if not 0 <= w <= 100:
        raise RuleError(f"{where}: weight must be within 0..100")
    return w


def _velocity(raw: dict[str, Any], idx: int) -> VelocityRule:
    loc = f"velocity[{idx}]"
    try:
        code = str(raw["code"])
        key = str(raw["key"])
        window = parse_duration(raw["window"])
        threshold = float(raw["threshold"])
    except KeyError as exc:
        raise RuleError(f"{loc}: missing {exc.args[0]}") from exc
    events = raw.get("events") or raw.get("event")
    if isinstance(events, str):
        events = [events]
    if not events:
        raise RuleError(f"{loc}: needs event or events")
    unknown = set(events) - EVENT_TYPES
    if unknown:
        raise RuleError(f"{loc}: unknown event types {sorted(unknown)}")
    if key not in KEY_FIELDS:
        raise RuleError(f"{loc}: key {key!r} not one of {sorted(KEY_FIELDS)}")
    distinct, total = raw.get("distinct"), raw.get("sum")
    if distinct and total:
        raise RuleError(f"{loc}: use distinct or sum, not both")
    if distinct and distinct not in KEY_FIELDS:
        raise RuleError(f"{loc}: distinct field {distinct!r} not supported")
    if total and total != "amount":
        raise RuleError(f"{loc}: only sum: amount is supported")
    where = raw.get("where") or {}
    if not isinstance(where, dict):
        raise RuleError(f"velocity[{idx}]: where must be a mapping")
    return VelocityRule(
        code=code,
        events=frozenset(events),
        key=key,
        window_s=window,
        threshold=threshold,
        weight=_weight(raw.get("weight", 0), loc),
        distinct=distinct,
        sum=total,
        where=tuple(sorted(where.items())),
    )


def build_rules(data: dict[str, Any]) -> RuleConfig:
    if not isinstance(data, dict):
        raise RuleError("rules file must be a mapping")
    if data.get("version") != 1:
        raise RuleError("rules file must declare version: 1")
    cfg = RuleConfig()
    decision = data.get("decision", {})
    cfg.review_at = float(decision.get("review_at", cfg.review_at))
    cfg.deny_at = float(decision.get("deny_at", cfg.deny_at))
    if not 0 < cfg.review_at <= cfg.deny_at <= 100:
        raise RuleError("decision: need 0 < review_at <= deny_at <= 100")
    cfg.velocity = [_velocity(r, i) for i, r in enumerate(data.get("velocity", []))]
    codes = [r.code for r in cfg.velocity]
    if len(codes) != len(set(codes)):
        raise RuleError("velocity: duplicate rule codes")
    cfg.weights = {str(k): _weight(v, f"weights.{k}") for k, v in data.get("weights", {}).items()}
    email = data.get("email", {})
    cfg.disposable_domains = [str(d).lower() for d in email.get("disposable_domains", [])]
    ip = data.get("ip", {})
    cfg.hosting_cidrs = list(ip.get("hosting_cidrs", []))
    cfg.blocked_cidrs = list(ip.get("blocked_cidrs", []))
    ato = data.get("ato", {})
    cfg.ato_window_s = parse_duration(ato.get("window", "24h"))
    link = data.get("linking", {})
    cfg.link_on = list(link.get("link_on", cfg.link_on))
    bad = set(cfg.link_on) - KEY_FIELDS
    if bad:
        raise RuleError(f"linking.link_on: unsupported fields {sorted(bad)}")
    if "ip" in cfg.link_on or "ip_prefix" in cfg.link_on:
        # Carrier NAT and office networks put unrelated people behind one IP.
        raise RuleError(
            "linking.link_on: linking on ip merges unrelated users; use velocity instead"
        )
    cfg.max_attribute_degree = int(link.get("max_attribute_degree", cfg.max_attribute_degree))
    cfg.promo_max_accounts_per_cluster = int(
        link.get("promo_max_accounts_per_cluster", cfg.promo_max_accounts_per_cluster)
    )
    ident = data.get("identity", {})
    cfg.identity_reuse_window_s = parse_duration(ident.get("reuse_window", "30d"))
    cfg.identity_reuse_threshold = int(ident.get("reuse_threshold", cfg.identity_reuse_threshold))
    cfg.allow_accounts = frozenset(str(a) for a in data.get("allowlist", {}).get("accounts", []))
    return cfg


def load_rules(path: str | Path | None = None) -> RuleConfig:
    """Load rules from a YAML file, or the packaged defaults when ``path`` is None."""
    if path is None:
        text = resources.files("fraudkit").joinpath("default_rules.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    return build_rules(yaml.safe_load(text))
