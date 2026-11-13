"""Event model and JSONL parsing.

Events are flat JSON objects. Only ``ts``, ``type`` and ``account_id`` are
required; everything else is optional because real event pipelines are
patchy and a missing device id should lower confidence, not crash scoring.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

EVENT_TYPES = frozenset(
    {
        "signup",
        "login",
        "password_reset",
        "email_change",
        "mfa_change",
        "payout_change",
        "payment",
        "withdrawal",
        "promo_redeem",
    }
)

_KNOWN = {
    "ts",
    "type",
    "account_id",
    "event_id",
    "device_id",
    "ip",
    "email",
    "phone",
    "card_fp",
    "address",
    "amount",
    "promo_code",
}


class EventError(ValueError):
    pass


@dataclass(frozen=True, slots=True, eq=False)
class Event:
    ts: float
    type: str
    account_id: str
    event_id: str = ""
    device_id: str | None = None
    ip: str | None = None
    email: str | None = None
    phone: str | None = None
    card_fp: str | None = None
    address: str | None = None
    amount: float = 0.0
    promo_code: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        if name in _KNOWN:
            return getattr(self, name)
        return self.extra.get(name)


def parse_ts(value: Any) -> float:
    """Epoch seconds, or an ISO 8601 string with an offset (``Z`` accepted)."""
    if isinstance(value, bool):
        raise EventError("ts must be a number or ISO 8601 string")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise EventError(f"bad ts {value!r}") from exc
        if dt.tzinfo is None:
            # Naive timestamps are ambiguous across regions; refuse them rather
            # than guess and silently shift every window by hours.
            raise EventError(f"ts {value!r} has no UTC offset")
        return dt.timestamp()
    raise EventError("ts must be a number or ISO 8601 string")


def _opt_str(raw: dict[str, Any], key: str) -> str | None:
    v = raw.get(key)
    if v is None or v == "":
        return None
    return str(v)


def parse_event(raw: dict[str, Any]) -> Event:
    if not isinstance(raw, dict):
        raise EventError("event must be a JSON object")
    for key in ("ts", "type", "account_id"):
        if key not in raw:
            raise EventError(f"missing {key}")
    etype = str(raw["type"])
    if etype not in EVENT_TYPES:
        raise EventError(f"unknown event type {etype!r}")
    try:
        amount = float(raw.get("amount") or 0.0)
    except (TypeError, ValueError) as exc:
        raise EventError("amount must be numeric") from exc
    extra = {k: v for k, v in raw.items() if k not in _KNOWN}
    return Event(
        ts=parse_ts(raw["ts"]),
        type=etype,
        account_id=str(raw["account_id"]),
        event_id=str(raw.get("event_id") or ""),
        device_id=_opt_str(raw, "device_id"),
        ip=_opt_str(raw, "ip"),
        email=_opt_str(raw, "email"),
        phone=_opt_str(raw, "phone"),
        card_fp=_opt_str(raw, "card_fp"),
        address=_opt_str(raw, "address"),
        amount=amount,
        promo_code=_opt_str(raw, "promo_code"),
        extra=extra,
    )


def read_jsonl(lines: Iterable[str]) -> Iterator[tuple[int, Event | EventError]]:
    """Yield ``(line_number, event_or_error)``. Bad lines are reported, not fatal."""
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield n, parse_event(json.loads(line))
        except json.JSONDecodeError as exc:
            yield n, EventError(f"invalid JSON: {exc.msg}")
        except EventError as exc:
            yield n, exc
