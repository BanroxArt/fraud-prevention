"""Entity linking with union-find, used for promo and referral rings.

Accounts and attribute values (device, card fingerprint, normalised email,
phone) are nodes. Each event unions the account with its attribute nodes, so
two accounts that shared a card inside the linking window end up in one
cluster.

Two failure modes are guarded against:

- The supernode. A shared office device or a payment wallet's generic
  fingerprint links thousands of unrelated people. An attribute that has
  already linked ``max_degree`` accounts stops merging and is reported
  instead.
- The chain. The degree cap is per attribute, so a long chain through
  *different* attributes (A-card-B-device-C-phone-D...) could still grow one
  cluster without limit. A merge that would push a cluster past
  ``max_cluster`` accounts is refused and reported the same way.

Union-find cannot delete, so state is aged out by rebuilding. Every link and
redemption is kept as an edge with its last-seen time; ``prune(now)`` drops
edges older than ``ttl_s`` and rebuilds the forest from what is left. That
is O(edges), which is fine at the engine's prune cadence. ``max_edges``
bounds memory between prunes: when it is exceeded the oldest tenth of edges
goes first.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict


class UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._size: dict[str, int] = {}

    def add(self, x: str) -> None:
        if x not in self._parent:
            self._parent[x] = x
            self._size[x] = 1

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression in a second pass keeps find iterative.
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> tuple[str, str | None]:
        """Merge the sets of ``a`` and ``b``. Returns ``(new_root, absorbed_root)``."""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra, None
        if self._size[ra] < self._size[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        self._size[ra] += self._size[rb]
        return ra, rb

    def __contains__(self, x: str) -> bool:
        return x in self._parent

    def __len__(self) -> int:
        return len(self._parent)


class Linker:
    def __init__(
        self,
        max_degree: int = 25,
        *,
        max_cluster: int = 500,
        ttl_s: float = 90 * 86_400,
        max_edges: int = 2_000_000,
    ) -> None:
        if max_degree < 1 or max_cluster < 1 or ttl_s <= 0 or max_edges < 1:
            raise ValueError("caps and ttl must be positive")
        self.max_degree = max_degree
        self.max_cluster = max_cluster
        self.ttl_s = ttl_s
        self.max_edges = max_edges
        # (account, attr) -> last seen; (account, promo code) -> last seen.
        self._links: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._redemptions: OrderedDict[tuple[str, str], float] = OrderedDict()
        self.saturated: set[str] = set()
        self._reset()

    def _reset(self) -> None:
        self.uf = UnionFind()
        self._accounts: dict[str, set[str]] = defaultdict(set)  # root -> accounts
        self._attr_accounts: dict[str, set[str]] = defaultdict(set)
        # root -> promo code -> accounts that redeemed it
        self._redeemed: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    def __len__(self) -> int:
        """Number of stored edges (links plus redemptions)."""
        return len(self._links) + len(self._redemptions)

    def _node(self, account_id: str) -> str:
        node = f"acct:{account_id}"
        if node not in self.uf:
            self.uf.add(node)
            self._accounts[node].add(account_id)
        return node

    def _merge(self, a: str, b: str) -> bool:
        ra, rb = self.uf.find(a), self.uf.find(b)
        if ra == rb:
            return True
        if len(self._accounts.get(ra, ())) + len(self._accounts.get(rb, ())) > self.max_cluster:
            return False
        root, absorbed = self.uf.union(a, b)
        if absorbed is None:
            return True
        self._accounts[root] |= self._accounts.pop(absorbed, set())
        src_promos = self._redeemed.pop(absorbed, {})
        dst = self._redeemed[root]
        for code, accts in src_promos.items():
            dst[code] |= accts
        return True

    def _apply_link(self, account_id: str, attr: str) -> bool:
        acct = self._node(account_id)
        seen = self._attr_accounts[attr]
        if account_id not in seen and len(seen) >= self.max_degree:
            return False
        self.uf.add(attr)
        if not self._merge(acct, attr):
            return False
        seen.add(account_id)
        return True

    def _apply_redeem(self, account_id: str, code: str) -> int:
        root = self.uf.find(self._node(account_id))
        users = self._redeemed[root][code]
        users.add(account_id)
        return len(users)

    @staticmethod
    def _touch(edges: OrderedDict[tuple[str, str], float], key: tuple[str, str], ts: float) -> None:
        edges[key] = max(ts, edges.get(key, ts))
        edges.move_to_end(key)

    def link(self, account_id: str, attrs: dict[str, str | None], ts: float = 0.0) -> list[str]:
        """Link an account to attribute values. Returns attributes that hit a cap."""
        self._node(account_id)
        capped: list[str] = []
        for kind, value in attrs.items():
            if not value:
                continue
            attr = f"{kind}:{value}"
            if self._apply_link(account_id, attr):
                self._touch(self._links, (account_id, attr), ts)
            else:
                self.saturated.add(attr)
                capped.append(attr)
        self._enforce_edge_cap()
        return capped

    def cluster_accounts(self, account_id: str) -> set[str]:
        return set(self._accounts.get(self.uf.find(self._node(account_id)), set()))

    def redeem(self, account_id: str, code: str, ts: float = 0.0) -> int:
        """Record a redemption; return how many accounts in the cluster used ``code``."""
        n = self._apply_redeem(account_id, code)
        self._touch(self._redemptions, (account_id, code), ts)
        self._enforce_edge_cap()
        return n

    def _enforce_edge_cap(self) -> None:
        if len(self) <= self.max_edges:
            return
        # Evict down to 90% so a stream sitting at the cap does not pay for a
        # rebuild on every event.
        target = max(0, self.max_edges - max(1, self.max_edges // 10))
        while len(self) > target:
            # Drop whichever edge type holds the older head.
            links_head = next(iter(self._links.values()), float("inf"))
            redeem_head = next(iter(self._redemptions.values()), float("inf"))
            if links_head <= redeem_head:
                self._links.popitem(last=False)
            else:
                self._redemptions.popitem(last=False)
        self._rebuild()

    def _rebuild(self) -> None:
        self._reset()
        self.saturated = set()
        # Replay in time order so caps resolve the same way they did live.
        for (account_id, attr), _ in sorted(self._links.items(), key=lambda kv: kv[1]):
            if not self._apply_link(account_id, attr):
                self.saturated.add(attr)
        for (account_id, code), _ in sorted(self._redemptions.items(), key=lambda kv: kv[1]):
            self._apply_redeem(account_id, code)

    def prune(self, now: float) -> int:
        """Drop links and redemptions not seen within ``ttl_s``. Returns edges dropped."""
        cutoff = now - self.ttl_s
        before = len(self)
        for edges in (self._links, self._redemptions):
            for key in [k for k, ts in edges.items() if ts <= cutoff]:
                del edges[key]
        dropped = before - len(self)
        if dropped:
            self._rebuild()
        return dropped
