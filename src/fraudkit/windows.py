"""Trailing time windows keyed by an arbitrary string.

All three window types share one rule: an observation at time ``t`` counts
for a query at ``now`` while ``now - window < t <= now``. Each key holds a
deque ordered by time, so eviction is amortised O(1) per event and the common
case (events arriving in time order) answers from a running aggregate.

Late events. A key's clock is the newest time it has been asked about. An
``add`` older than that clock is late, and it is answered as of its own
timestamp: only observations in ``(ts - window, ts]`` count, so a payment
that arrives five minutes late is not charged for the attempts that came after
it. To answer that honestly the window has to remember observations that
already left the live range, so each key also keeps a grace deque holding
the last ``grace_s`` seconds of expired entries. The engine sets ``grace_s``
to ``state.allowed_lateness`` and refuses anything later than that before it
gets here; a window asked about an even older time answers from what it still
has, which is an undercount. The late path scans the key, O(n), which is fine
when lateness is rare. If a stream is badly out of order, sort it first
(``--sort`` on the CLI).

Keys usually come from event data (device ids, card fingerprints), so a
sender that rotates them can grow a window without bound inside one time
span. ``max_keys`` caps the number of keys held; past it the least recently
updated key is dropped. ``prune(now)`` still does the time-based cleanup.
"""

from __future__ import annotations

import bisect
from collections import Counter, deque
from collections.abc import Iterable
from typing import Any

DEFAULT_MAX_KEYS = 1_000_000

Item = tuple[Any, ...]


def _insort(q: deque[Item], item: Item) -> None:
    if not q or item[0] >= q[-1][0]:
        q.append(item)
        return
    items = list(q)
    # bisect_right keeps equal timestamps in arrival order.
    bisect.insort_right(items, item, key=lambda x: x[0])
    q.clear()
    q.extend(items)


class CountWindow:
    """Number of events per key in the trailing window."""

    def __init__(
        self, window_s: float, max_keys: int = DEFAULT_MAX_KEYS, grace_s: float = 0.0
    ) -> None:
        if window_s <= 0:
            raise ValueError("window must be positive")
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        if grace_s < 0:
            raise ValueError("grace must not be negative")
        self.window_s = window_s
        self.max_keys = max_keys
        self.grace_s = grace_s
        self.evicted = 0
        # Insertion order of _q doubles as the LRU order for max_keys.
        self._q: dict[str, deque[Item]] = {}
        self._grace: dict[str, deque[Item]] = {}
        self._clock: dict[str, float] = {}

    # Hooks for the running aggregate over the live deque.
    def _enter(self, key: str, item: Item) -> None:
        pass

    def _expire(self, key: str, item: Item) -> None:
        pass

    def _forget(self, key: str) -> None:
        pass

    def _live_value(self, key: str) -> Any:
        return len(self._q[key])

    def _scan_value(self, items: Iterable[Item]) -> Any:
        return sum(1 for _ in items)

    def _touch(self, key: str) -> deque[Item]:
        """Return the deque for ``key`` and mark it most recently used."""
        q = self._q.pop(key, None)
        if q is None:
            q = deque()
        self._q[key] = q
        while len(self._q) > self.max_keys:
            oldest = next(iter(self._q))
            self._drop(oldest)
            self.evicted += 1
        return q

    def _drop(self, key: str) -> None:
        del self._q[key]
        self._grace.pop(key, None)
        self._clock.pop(key, None)
        self._forget(key)

    def _evict(self, key: str, now: float) -> deque[Item]:
        q = self._q[key]
        clock = max(now, self._clock.get(key, now))
        self._clock[key] = clock
        cutoff = clock - self.window_s
        grace = self._grace.get(key)
        while q and q[0][0] <= cutoff:
            item = q.popleft()
            self._expire(key, item)
            if self.grace_s > 0:
                if grace is None:
                    grace = self._grace[key] = deque()
                grace.append(item)
        if grace is not None:
            while grace and grace[0][0] <= cutoff - self.grace_s:
                grace.popleft()
            if not grace:
                del self._grace[key]
        return q

    def _value_at(self, key: str, ts: float) -> Any:
        if ts >= self._clock[key]:
            return self._live_value(key)
        lo = ts - self.window_s
        items = [*self._grace.get(key, ()), *self._q[key]]
        return self._scan_value(it for it in items if lo < it[0] <= ts)

    def _add(self, key: str, item: Item) -> Any:
        self._touch(key)
        ts = item[0]
        q = self._evict(key, ts)
        if ts > self._clock[key] - self.window_s:
            _insort(q, item)
            self._enter(key, item)
        elif ts > self._clock[key] - self.window_s - self.grace_s:
            _insort(self._grace.setdefault(key, deque()), item)
        return self._value_at(key, ts)

    def _query(self, key: str, now: float, empty: Any) -> Any:
        if key not in self._q:
            return empty
        self._evict(key, now)
        return self._value_at(key, now)

    def add(self, key: str, ts: float) -> int:
        n: int = self._add(key, (ts,))
        return n

    def count(self, key: str, now: float) -> int:
        n: int = self._query(key, now, 0)
        return n

    def prune(self, now: float) -> int:
        """Drop keys with nothing left in the window or its grace period."""
        dead = [k for k in self._q if not self._evict(k, now) and k not in self._grace]
        for k in dead:
            self._drop(k)
        return len(dead)

    def __len__(self) -> int:
        return len(self._q)


class SumWindow(CountWindow):
    """Sum of a numeric value per key, e.g. card spend in the last hour."""

    def __init__(
        self, window_s: float, max_keys: int = DEFAULT_MAX_KEYS, grace_s: float = 0.0
    ) -> None:
        super().__init__(window_s, max_keys, grace_s)
        self._sum: dict[str, float] = {}

    def _enter(self, key: str, item: Item) -> None:
        self._sum[key] = self._sum.get(key, 0.0) + item[1]

    def _expire(self, key: str, item: Item) -> None:
        self._sum[key] -= item[1]
        if not self._q[key]:
            # Reset so float drift does not accumulate on long-lived keys.
            self._sum[key] = 0.0

    def _forget(self, key: str) -> None:
        self._sum.pop(key, None)

    def _live_value(self, key: str) -> float:
        return self._sum.get(key, 0.0)

    def _scan_value(self, items: Iterable[Item]) -> float:
        return float(sum(it[1] for it in items))

    def add(self, key: str, ts: float, value: float = 1.0) -> float:  # type: ignore[override]
        total: float = self._add(key, (ts, value))
        return total

    def total(self, key: str, now: float) -> float:
        total: float = self._query(key, now, 0.0)
        return total


class DistinctWindow(CountWindow):
    """Distinct values per key, e.g. distinct accounts seen on one device in 24h."""

    def __init__(
        self, window_s: float, max_keys: int = DEFAULT_MAX_KEYS, grace_s: float = 0.0
    ) -> None:
        super().__init__(window_s, max_keys, grace_s)
        self._seen: dict[str, Counter[str]] = {}

    def _enter(self, key: str, item: Item) -> None:
        self._seen.setdefault(key, Counter())[item[1]] += 1

    def _expire(self, key: str, item: Item) -> None:
        seen = self._seen[key]
        seen[item[1]] -= 1
        if seen[item[1]] <= 0:
            del seen[item[1]]

    def _forget(self, key: str) -> None:
        self._seen.pop(key, None)

    def _live_value(self, key: str) -> int:
        return len(self._seen.get(key, ()))

    def _scan_value(self, items: Iterable[Item]) -> int:
        return len({it[1] for it in items})

    def add(self, key: str, ts: float, value: str = "") -> int:
        n: int = self._add(key, (ts, value))
        return n

    def distinct(self, key: str, now: float) -> int:
        n: int = self._query(key, now, 0)
        return n
