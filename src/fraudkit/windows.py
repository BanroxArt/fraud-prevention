"""Trailing time windows keyed by an arbitrary string.

All three window types share one rule: an observation at time ``t`` stays in
the window while ``now - t < window``. Each key holds a deque ordered by time,
so eviction is amortised O(1) per event.

Late events (older than the newest one already seen for that key) are
inserted in order. That costs O(n) for the key, which is fine when lateness is
rare. If your stream is badly out of order, sort it first (``--sort`` on the
CLI) instead of relying on this path.

Keys usually come from event data (device ids, card fingerprints), so a
sender that rotates them can grow a window without bound inside one time
span. ``max_keys`` caps the number of keys held; past it the least recently
updated key is dropped. ``prune(now)`` still does the time-based cleanup.
"""

from __future__ import annotations

import bisect
from collections import Counter, defaultdict, deque
from typing import Any

DEFAULT_MAX_KEYS = 1_000_000


def _insert(q: deque[Any], item: tuple[Any, ...]) -> None:
    if not q or item[0] >= q[-1][0]:
        q.append(item)
        return
    items = list(q)
    bisect.insort(items, item, key=lambda x: x[0])
    q.clear()
    q.extend(items)


class CountWindow:
    """Number of events per key in the trailing window."""

    def __init__(self, window_s: float, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        if window_s <= 0:
            raise ValueError("window must be positive")
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        self.window_s = window_s
        self.max_keys = max_keys
        self.evicted = 0
        self._q: dict[str, deque[Any]] = defaultdict(deque)

    def _touch(self, key: str) -> deque[Any]:
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

    def _evict(self, key: str, now: float) -> deque[Any]:
        q = self._q[key]
        cutoff = now - self.window_s
        while q and q[0][0] <= cutoff:
            q.popleft()
        return q

    def add(self, key: str, ts: float) -> int:
        self._touch(key)
        q = self._evict(key, ts)
        _insert(q, (ts,))
        return len(q)

    def count(self, key: str, now: float) -> int:
        if key not in self._q:
            return 0
        return len(self._evict(key, now))

    def prune(self, now: float) -> int:
        """Drop keys with nothing left in the window. Returns how many were dropped."""
        dead = [k for k in self._q if not self._evict(k, now)]
        for k in dead:
            self._drop(k)
        return len(dead)

    def __len__(self) -> int:
        return len(self._q)


class SumWindow(CountWindow):
    """Sum of a numeric value per key, e.g. card spend in the last hour."""

    def __init__(self, window_s: float, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        super().__init__(window_s, max_keys)
        self._sum: dict[str, float] = defaultdict(float)

    def _drop(self, key: str) -> None:
        super()._drop(key)
        self._sum.pop(key, None)

    def _evict(self, key: str, now: float) -> deque[Any]:
        q = self._q[key]
        cutoff = now - self.window_s
        while q and q[0][0] <= cutoff:
            _, value = q.popleft()
            self._sum[key] -= value
        if not q:
            # Reset so float drift does not accumulate on long-lived keys.
            self._sum[key] = 0.0
        return q

    def add(self, key: str, ts: float, value: float = 1.0) -> float:  # type: ignore[override]
        self._touch(key)
        q = self._evict(key, ts)
        _insert(q, (ts, value))
        self._sum[key] += value
        return self._sum[key]

    def total(self, key: str, now: float) -> float:
        if key not in self._q:
            return 0.0
        self._evict(key, now)
        return self._sum[key]

    def prune(self, now: float) -> int:
        dropped = super().prune(now)
        for k in [k for k in self._sum if k not in self._q]:
            del self._sum[k]
        return dropped


class DistinctWindow(CountWindow):
    """Distinct values per key, e.g. distinct accounts seen on one device in 24h."""

    def __init__(self, window_s: float, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        super().__init__(window_s, max_keys)
        self._seen: dict[str, Counter[str]] = defaultdict(Counter)

    def _drop(self, key: str) -> None:
        super()._drop(key)
        self._seen.pop(key, None)

    def _evict(self, key: str, now: float) -> deque[Any]:
        q = self._q[key]
        seen = self._seen[key]
        cutoff = now - self.window_s
        while q and q[0][0] <= cutoff:
            _, value = q.popleft()
            seen[value] -= 1
            if seen[value] <= 0:
                del seen[value]
        return q

    def add(self, key: str, ts: float, value: str = "") -> int:
        self._touch(key)
        q = self._evict(key, ts)
        _insert(q, (ts, value))
        self._seen[key][value] += 1
        return len(self._seen[key])

    def distinct(self, key: str, now: float) -> int:
        if key not in self._q:
            return 0
        self._evict(key, now)
        return len(self._seen[key])

    def prune(self, now: float) -> int:
        dropped = super().prune(now)
        for k in [k for k in self._seen if k not in self._q]:
            del self._seen[k]
        return dropped
