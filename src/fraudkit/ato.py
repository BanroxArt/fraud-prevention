"""Account takeover sequence detection.

The pattern that matters most in practice is short: a login from a device
the account has never used, a credential change (password reset, email or
MFA change), then a change to where money goes. Any one of those is normal.
All three inside a day, in that order, is the classic takeover cash-out.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass

CREDENTIAL_EVENTS = frozenset({"password_reset", "email_change", "mfa_change"})
CASHOUT_EVENTS = frozenset({"payout_change", "withdrawal"})


@dataclass(frozen=True, slots=True)
class AtoHit:
    code: str
    detail: str


class AtoTracker:
    def __init__(self, window_s: float = 86_400, max_devices: int = 50) -> None:
        self.window_s = window_s
        self.max_devices = max_devices
        self._devices: dict[str, OrderedDict[str, float]] = defaultdict(OrderedDict)
        self._new_device_logins: dict[str, deque[float]] = defaultdict(deque)
        self._cred_changes: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

    def _remember_device(self, account_id: str, device_id: str, ts: float) -> bool:
        """Record the device. Returns True if the account had not used it before."""
        known = self._devices[account_id]
        is_new = device_id not in known
        known[device_id] = ts
        known.move_to_end(device_id)
        while len(known) > self.max_devices:
            known.popitem(last=False)
        return is_new

    def _trim(self, account_id: str, now: float) -> None:
        cutoff = now - self.window_s
        logins = self._new_device_logins[account_id]
        while logins and logins[0] <= cutoff:
            logins.popleft()
        creds = self._cred_changes[account_id]
        while creds and creds[0][0] <= cutoff:
            creds.popleft()

    def observe(
        self, etype: str, account_id: str, device_id: str | None, ts: float
    ) -> list[AtoHit]:
        hits: list[AtoHit] = []
        self._trim(account_id, ts)
        first_device = not self._devices[account_id]
        if device_id:
            is_new = self._remember_device(account_id, device_id, ts)
            # The device used at signup is not "new" for takeover purposes.
            if is_new and not first_device and etype == "login":
                self._new_device_logins[account_id].append(ts)
                hits.append(AtoHit("ATO_NEW_DEVICE_LOGIN", "login from unseen device"))
        if etype in CREDENTIAL_EVENTS:
            self._cred_changes[account_id].append((ts, etype))
            if self._new_device_logins[account_id]:
                hits.append(AtoHit("ATO_CRED_CHANGE_AFTER_NEW_DEVICE", etype))
        if etype in CASHOUT_EVENTS:
            new_login = bool(self._new_device_logins[account_id])
            creds = self._cred_changes[account_id]
            if new_login and creds:
                first_login = self._new_device_logins[account_id][0]
                ordered = any(t >= first_login for t, _ in creds)
                kinds = ",".join(sorted({k for _, k in creds}))
                if ordered:
                    hits.append(AtoHit("ATO_SEQUENCE", f"new device -> {kinds} -> {etype}"))
                else:
                    hits.append(AtoHit("ATO_CRED_AND_NEW_DEVICE", f"{kinds}; new device; {etype}"))
            elif new_login:
                hits.append(AtoHit("ATO_NEW_DEVICE_CASHOUT", etype))
            elif creds:
                hits.append(AtoHit("ATO_CRED_CHANGE_CASHOUT", etype))
        return hits

    def known_devices(self, account_id: str) -> list[str]:
        return list(self._devices.get(account_id, {}))
