from fraudkit.linking import Linker, UnionFind


def test_union_find_merges_and_compresses():
    uf = UnionFind()
    for a, b in [("a", "b"), ("c", "d"), ("b", "d")]:
        uf.union(a, b)
    assert len({uf.find(x) for x in "abcd"}) == 1
    assert uf.find("e") == "e"


def test_union_is_idempotent():
    uf = UnionFind()
    uf.union("a", "b")
    _, absorbed = uf.union("a", "b")
    assert absorbed is None


def test_accounts_sharing_card_cluster():
    ln = Linker()
    ln.link("a1", {"card_fp": "c1"})
    ln.link("a2", {"card_fp": "c1"})
    ln.link("a3", {"device_id": "d9"})
    assert ln.cluster_accounts("a1") == {"a1", "a2"}
    assert ln.cluster_accounts("a3") == {"a3"}


def test_transitive_linking_merges_promo_history():
    ln = Linker()
    ln.link("a1", {"card_fp": "c1"})
    assert ln.redeem("a1", "WELCOME") == 1
    ln.link("a2", {"device_id": "d1"})
    assert ln.redeem("a2", "WELCOME") == 1
    # a3 shares the card with a1 and the device with a2: one ring.
    ln.link("a3", {"card_fp": "c1", "device_id": "d1"})
    assert ln.cluster_accounts("a1") == {"a1", "a2", "a3"}
    assert ln.redeem("a3", "WELCOME") == 3


def test_supernode_cap_stops_merging():
    ln = Linker(max_degree=2)
    assert ln.link("a1", {"device_id": "kiosk"}) == []
    assert ln.link("a2", {"device_id": "kiosk"}) == []
    assert ln.link("a3", {"device_id": "kiosk"}) == ["device_id:kiosk"]
    assert ln.cluster_accounts("a3") == {"a3"}
    assert "device_id:kiosk" in ln.saturated


def test_empty_attributes_are_ignored():
    ln = Linker()
    ln.link("a1", {"phone": None, "card_fp": ""})
    ln.link("a2", {"phone": None, "card_fp": ""})
    assert ln.cluster_accounts("a1") == {"a1"}
