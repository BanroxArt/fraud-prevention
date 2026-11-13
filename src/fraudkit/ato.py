"""Account takeover sequence detection.

The pattern that matters most in practice is short: a login from a device
the account has never used, a credential change (password reset, email or
MFA change) made from that same device, then a change to where money goes.
Any one of those is normal. All three inside a day, in that order and tied
to one device, is the classic takeover cash-out.

The tie to a device is what keeps this honest. A password reset from the
owner's usual phone and an unrelated login from a new laptop the day before
are two normal things, not a sequence, so they only get the weaker
``ATO_CRED_AND_NEW_DEVICE`` grade.

State is per account and bounded two ways: ``prune(now)`` drops accounts
idle for longer than ``device_ttl_s``, and ``max_accounts`` caps how many
accounts are held at all (least recently seen goes first).
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field

CREDENTIAL_EVENTS = frozenset({"password_reset", "email_change", "mfa_change"})
CASHOUT_EVENTS = frozenset({"payout_change", "withdrawal"})


@dataclass(frozen=True, slots=True)
class AtoHit:
    code: str
    detail: str


@dataclass(slots=True)
class _Account:
    last_seen: float
    devices: OrderedDict[str, float] = field(default_factory=OrderedDict)
    # (ts, device_id) for logins from a device the account had not used before
    new_logins: deque[tuple[float, str]] = field(default_factory=deque)
    # (ts, kind, device_id or None)
    cred_changes: deque[tuple[float, str, str | None]] = field(default_factory=deque)


class AtoTracker:
    def __init__(
        self,
        window_s: float = 86_400,
        max_devices: int = 50,
        *,
        device_ttl_s: float = 90 * 86_400,
        max_accounts: int = 1_000_000,
    ) -> None:
        if window_s <= 0 or device_ttl_s <= 0 or max_devices < 1 or max_accounts < 1:
            raise ValueError("window, ttl and caps must be positive")
        self.window_s = window_s
        self.max_devices = max_devices
        self.device_ttl_s = device_ttl_s
        self.max_accounts = max_accounts
        self._accounts: OrderedDict[str, _Account] = OrderedDict()

    def __len__(self) -> int:
        return len(self._accounts)

    def _account(self, account_id: str, ts: float) -> tuple[_Account, bool]:
        acct = self._accounts.get(account_id)
        if acct is None:
            acct = _Account(last_seen=ts)
            self._accounts[account_id] = acct
            while len(self._accounts) > self.max_accounts:
                self._accounts.popitem(last=False)
            return acct, True
        acct.last_seen = max(acct.last_seen, ts)
        self._accounts.move_to_end(account_id)
        return acct, False

    def _remember_device(self, acct: _Account, device_id: str, ts: float) -> bool:
        """Record the device. Returns True if the account had not used it before."""
        known = acct.devices
        is_new = device_id not in known
        known[device_id] = max(ts, known.get(device_id, ts))
        known.move_to_end(device_id)
        while len(known) > self.max_devices:
            known.popitem(last=False)
        return is_new

    def _trim(self, acct: _Account, now: float) -> None:
        cutoff = now - self.window_s
        while acct.new_logins and acct.new_logins[0][0] <= cutoff:
            acct.new_logins.popleft()
        while acct.cred_changes and acct.cred_changes[0][0] <= cutoff:
            acct.cred_changes.popleft()

    def observe(
        self, etype: str, account_id: str, device_id: str | None, ts: float
    ) -> list[AtoHit]:
        hits: list[AtoHit] = []
        acct, created = self._account(account_id, ts)
        self._trim(acct, ts)
        # The first device we ever see for an account is its baseline. For a
        # signup that is exactly right. For an account that predates the
        # pipeline it means the first device seen is trusted; see the threat
        # model for why that is the less bad choice.
        baseline = created or not acct.devices
        if device_id:
            is_new = self._remember_device(acct, device_id, ts)
            if is_new and not baseline and etype == "login":
                acct.new_logins.append((ts, device_id))
                hits.append(AtoHit("ATO_NEW_DEVICE_LOGIN", "login from unseen device"))

        if etype in CREDENTIAL_EVENTS:
            acct.cred_changes.append((ts, etype, device_id))
            if self._tied_login(acct, ts, device_id) is not None:
                hits.append(AtoHit("ATO_CRED_CHANGE_AFTER_NEW_DEVICE", etype))

        if etype in CASHOUT_EVENTS:
            hits.extend(self._grade_cashout(acct, etype, device_id))
        return hits

    @staticmethod
    def _tied_login(acct: _Account, ts: float, device_id: str | None) -> float | None:
        """Earliest new-device login from ``device_id`` at or before ``ts``."""
        if not device_id:
            return None
        for login_ts, dev in acct.new_logins:
            if dev == device_id and login_ts <= ts:
                return login_ts
        return None

    def _grade_cashout(self, acct: _Account, etype: str, device_id: str | None) -> list[AtoHit]:
        new_login = bool(acct.new_logins)
        creds = acct.cred_changes
        if not new_login and not creds:
            return []
        if not new_login:
            return [AtoHit("ATO_CRED_CHANGE_CASHOUT", etype)]
        if not creds:
            return [AtoHit("ATO_NEW_DEVICE_CASHOUT", etype)]
        kinds = ",".join(sorted({kind for _, kind, _ in creds}))
        # Full sequence: some credential change was made from a device whose
        # first (new-device) login came before it, and the cash-out comes from
        # that same device, or carries no device at all (server-side payout
        # jobs often do not).
        for cred_ts, _, cred_dev in creds:
            if cred_dev is None:
                continue
            if self._tied_login(acct, cred_ts, cred_dev) is None:
                continue
            if device_id is None or device_id == cred_dev:
                return [AtoHit("ATO_SEQUENCE", f"new device -> {kinds} -> {etype}")]
        return [AtoHit("ATO_CRED_AND_NEW_DEVICE", f"{kinds}; new device; {etype}")]

    def prune(self, now: float) -> int:
        """Forget accounts idle for longer than ``device_ttl_s``. Returns how many."""
        cutoff = now - self.device_ttl_s
        dead = [a for a, acct in self._accounts.items() if acct.last_seen <= cutoff]
        for a in dead:
            del self._accounts[a]
        for acct in self._accounts.values():
            self._trim(acct, now)
            stale = [d for d, ts in acct.devices.items() if ts <= cutoff]
            for d in stale:
                del acct.devices[d]
        return len(dead)

    def known_devices(self, account_id: str) -> list[str]:
        acct = self._accounts.get(account_id)
        return list(acct.devices) if acct else []
