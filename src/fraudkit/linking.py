"""Entity linking with union-find, used for promo and referral rings.

Accounts and attribute values (device, card fingerprint, normalised email,
phone) are nodes. Each event unions the account with its attribute nodes, so
two accounts that ever shared a card end up in one cluster.

The obvious failure mode is the supernode: a shared office device or a
payment wallet's generic fingerprint links thousands of unrelated people. We
cap how many accounts an attribute may link. Once an attribute has seen
``max_degree`` accounts it stops merging clusters and is reported instead.
"""

from __future__ import annotations

from collections import defaultdict


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


class Linker:
    def __init__(self, max_degree: int = 25) -> None:
        self.max_degree = max_degree
        self.uf = UnionFind()
        self._accounts: dict[str, set[str]] = defaultdict(set)  # root -> accounts
        self._attr_accounts: dict[str, set[str]] = defaultdict(set)
        # root -> promo code -> accounts that redeemed it
        self._redeemed: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.saturated: set[str] = set()

    def _node(self, account_id: str) -> str:
        node = f"acct:{account_id}"
        if node not in self.uf:
            self.uf.add(node)
            self._accounts[node].add(account_id)
        return node

    def _merge(self, a: str, b: str) -> None:
        root, absorbed = self.uf.union(a, b)
        if absorbed is None:
            return
        self._accounts[root] |= self._accounts.pop(absorbed, set())
        src_promos = self._redeemed.pop(absorbed, {})
        dst = self._redeemed[root]
        for code, accts in src_promos.items():
            dst[code] |= accts

    def link(self, account_id: str, attrs: dict[str, str | None]) -> list[str]:
        """Link an account to attribute values. Returns attributes that hit the cap."""
        acct = self._node(account_id)
        capped: list[str] = []
        for kind, value in attrs.items():
            if not value:
                continue
            attr = f"{kind}:{value}"
            seen = self._attr_accounts[attr]
            if account_id not in seen and len(seen) >= self.max_degree:
                self.saturated.add(attr)
                capped.append(attr)
                continue
            seen.add(account_id)
            self.uf.add(attr)
            self._merge(acct, attr)
        return capped

    def cluster_accounts(self, account_id: str) -> set[str]:
        return set(self._accounts.get(self.uf.find(self._node(account_id)), set()))

    def redeem(self, account_id: str, code: str) -> int:
        """Record a redemption; return how many accounts in the cluster used ``code``."""
        root = self.uf.find(self._node(account_id))
        users = self._redeemed[root][code]
        users.add(account_id)
        return len(users)
