"""Synthetic event generator for demos, tests and threshold tuning.

The data is made up and labelled. Every account carries ``label`` in each
event so ``fraudkit eval`` can report precision and recall per reason code.
Patterns are simplified versions of what abuse usually looks like; they are
useful for checking the engine does what the rules say, not for estimating
real-world catch rates.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from typing import Any

DAY = 86_400.0
START = 1_767_225_600.0  # 2026-01-01T00:00:00Z


class Synth:
    def __init__(self, seed: int = 7, disposable_domain: str = "mailinator.com") -> None:
        self.rng = random.Random(seed)
        self.disposable = disposable_domain
        self._n = 0
        self.events: list[dict[str, Any]] = []

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}{self._n:06d}"

    def _hex(self, n: int = 12) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(n))

    def _ip(self, net: int | None = None) -> str:
        # Only documentation space (RFC 3849 for v6, RFC 5737 for v4), so the
        # output can never point at a real network.
        if net is None:
            net = self.rng.randrange(0, 65536)
        return (
            f"2001:db8:{net:x}:{self.rng.randrange(0, 65536):x}::{self.rng.randrange(1, 65535):x}"
        )

    def _bad_ip(self) -> str:
        return f"203.0.113.{self.rng.randrange(1, 255)}"

    def _token(self, kind: str) -> str:
        # Phones and addresses are emitted as opaque tokens, the way they should
        # reach a scoring service: keyed-hashed upstream, never raw.
        return f"{kind}_{self._hex(16)}"

    def _name_email(self, domain: str = "example.com") -> str:
        first = self.rng.choice(
            ["sam", "lee", "kim", "alex", "jo", "ana", "max", "eva", "ravi", "mia"]
        )
        last = self.rng.choice(
            ["park", "silva", "nguyen", "moreau", "kowal", "reyes", "ito", "baker"]
        )
        sep = self.rng.choice([".", "", "_"])
        # The counter keeps mailboxes unique; real collisions mean the same inbox.
        suffix = str(self._n % 1000)
        tag = "+shop" if self.rng.random() < 0.05 else ""
        return f"{first}{sep}{last}{suffix}{tag}@{domain}"

    def emit(self, ts: float, etype: str, acct: str, label: str, **fields: Any) -> None:
        ev = {"event_id": self._id("e"), "ts": round(ts, 3), "type": etype, "account_id": acct}
        ev.update({k: v for k, v in fields.items() if v is not None})
        ev["label"] = label
        self.events.append(ev)

    def legit(self, t0: float) -> None:
        acct = self._id("a")
        dev = self._hex()
        card = self._hex(16)
        ip = self._ip()
        self.emit(
            t0,
            "signup",
            acct,
            "legit",
            device_id=dev,
            ip=ip,
            email=self._name_email(),
            phone=self._token("ph"),
            card_fp=card,
            address=self._token("ad"),
        )
        t = t0
        for _ in range(self.rng.randrange(1, 6)):
            t += self.rng.uniform(0.2, 4) * DAY
            self.emit(t, "login", acct, "legit", device_id=dev, ip=ip, success=True)
            if self.rng.random() < 0.6:
                self.emit(
                    t + 120,
                    "payment",
                    acct,
                    "legit",
                    card_fp=card,
                    ip=ip,
                    amount=round(self.rng.uniform(5, 180), 2),
                )
        if self.rng.random() < 0.08:
            # Legit people reset passwords and change payouts too. Without this
            # the eval would make the ATO rules look better than they are.
            t += DAY
            self.emit(t, "password_reset", acct, "legit", device_id=dev)
            self.emit(t + 3 * DAY, "payout_change", acct, "legit", device_id=dev, ip=ip)
        if self.rng.random() < 0.3:
            self.emit(t + 60, "promo_redeem", acct, "legit", promo_code="WELCOME10", card_fp=card)

    def device_farm(self, t0: float, size: int = 6) -> None:
        dev = self._hex()
        net = self.rng.randrange(0, 65536)
        for i in range(size):
            acct = self._id("a")
            local = self._hex(14)
            self.emit(
                t0 + i * 400,
                "signup",
                acct,
                "device_farm",
                device_id=dev,
                ip=self._ip(net),
                email=f"{local}@{self.disposable}",
                phone=self._token("ph"),
            )
            self.emit(
                t0 + i * 400 + 90,
                "promo_redeem",
                acct,
                "device_farm",
                promo_code="WELCOME10",
                device_id=dev,
            )

    def promo_ring(self, t0: float, size: int = 5) -> None:
        card = self._hex(16)
        base = self.rng.choice(["deals", "promo", "freebie"])
        for i in range(size):
            acct = self._id("a")
            email = f"{base}+{i}@example.com"
            self.emit(
                t0 + i * 3 * 3600,
                "signup",
                acct,
                "promo_ring",
                device_id=self._hex(),
                ip=self._ip(),
                email=email,
                card_fp=card,
            )
            self.emit(
                t0 + i * 3 * 3600 + 300,
                "promo_redeem",
                acct,
                "promo_ring",
                promo_code="WELCOME10",
                card_fp=card,
            )

    def takeover(self, t0: float) -> None:
        acct = self._id("a")
        dev, ip = self._hex(), self._ip()
        self.emit(
            t0,
            "signup",
            acct,
            "legit",
            device_id=dev,
            ip=ip,
            email=self._name_email(),
            phone=self._token("ph"),
        )
        self.emit(t0 + 2 * DAY, "login", acct, "legit", device_id=dev, ip=ip, success=True)
        t = t0 + 10 * DAY
        bad_dev, bad_ip = self._hex(), self._bad_ip()
        self.emit(t, "login", acct, "ato", device_id=bad_dev, ip=bad_ip, success=True)
        self.emit(t + 300, "password_reset", acct, "ato", device_id=bad_dev, ip=bad_ip)
        self.emit(t + 900, "payout_change", acct, "ato", device_id=bad_dev, ip=bad_ip)
        self.emit(t + 1000, "withdrawal", acct, "ato", device_id=bad_dev, ip=bad_ip, amount=950.0)

    def card_testing(self, t0: float, attempts: int = 12) -> None:
        acct = self._id("a")
        dev, ip = self._hex(), self._ip()
        self.emit(
            t0,
            "signup",
            acct,
            "card_testing",
            device_id=dev,
            ip=ip,
            email=f"{self._hex(8)}{self.rng.randrange(1000, 9999)}@example.com",
        )
        card = self._hex(16)
        for i in range(attempts):
            if i % 3 == 0:
                card = self._hex(16)
            self.emit(
                t0 + 60 + i * 20,
                "payment",
                acct,
                "card_testing",
                card_fp=card,
                ip=ip,
                amount=round(self.rng.uniform(0.5, 2.0), 2),
            )

    def generate(self, accounts: int = 500, fraud_rate: float = 0.08) -> list[dict[str, Any]]:
        horizon = 30 * DAY
        for _ in range(accounts):
            t0 = START + self.rng.uniform(0, horizon)
            if self.rng.random() >= fraud_rate:
                self.legit(t0)
                continue
            pattern = self.rng.choice(
                [self.device_farm, self.promo_ring, self.takeover, self.card_testing]
            )
            pattern(t0)
        self.events.sort(key=lambda e: e["ts"])
        return self.events


def generate(
    seed: int = 7,
    accounts: int = 500,
    fraud_rate: float = 0.08,
    disposable_domain: str = "mailinator.com",
) -> Iterator[dict[str, Any]]:
    yield from Synth(seed, disposable_domain).generate(accounts, fraud_rate)
