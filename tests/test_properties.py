"""Property tests for the pieces with simple invariants."""

from hypothesis import given, settings
from hypothesis import strategies as st

from fraudkit.engine import combine
from fraudkit.linking import UnionFind
from fraudkit.signals import normalize_email
from fraudkit.windows import CountWindow, DistinctWindow, SumWindow

weights = st.lists(st.floats(min_value=-50, max_value=150, allow_nan=False), max_size=12)


@given(weights)
def test_combine_is_bounded(ws):
    assert 0.0 <= combine(ws) <= 100.0


@given(weights, st.floats(min_value=0, max_value=100))
def test_combine_never_drops_when_a_reason_is_added(ws, extra):
    assert combine([*ws, extra]) >= combine(ws) - 1e-9


@given(weights)
def test_combine_ignores_order(ws):
    assert abs(combine(ws) - combine(list(reversed(ws)))) < 1e-9


events = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=500),
        st.sampled_from("abc"),
        st.integers(min_value=0, max_value=20),
    ),
    max_size=60,
)


@settings(max_examples=200)
@given(events, st.integers(min_value=1, max_value=120))
def test_windows_match_brute_force_under_any_arrival_order(evs, window):
    count, total, distinct = CountWindow(window), SumWindow(window), DistinctWindow(window)
    seen: list[tuple[int, str, int]] = []
    for ts, key, value in evs:
        seen.append((ts, key, value))
        newest = max(t for t, k, _ in seen if k == key)
        n = count.add(key, ts)
        s = total.add(key, ts, float(value))
        d = distinct.add(key, ts, str(value))
        # Eviction is driven by the newest event per key; anything older than
        # the window relative to it is gone, everything else is in.
        live = [(t, v) for t, k, v in seen if k == key and newest - t < window]
        if ts == newest:
            assert n == len(live)
            assert abs(s - sum(v for _, v in live)) < 1e-6
            assert d == len({v for _, v in live})


emails = st.from_regex(r"[a-z0-9.+_]{1,12}@(gmail|googlemail|example)\.com", fullmatch=True)


@given(emails)
def test_normalize_email_is_idempotent(addr):
    once = normalize_email(addr)
    if once is not None:
        assert normalize_email(once) == once


pairs = st.lists(st.tuples(st.sampled_from("abcdefgh"), st.sampled_from("abcdefgh")), max_size=20)


@given(pairs, st.randoms())
def test_union_find_partition_ignores_order(ps, rnd):
    def partition(order):
        uf = UnionFind()
        for a, b in order:
            uf.union(a, b)
        groups: dict[str, set[str]] = {}
        for x in "abcdefgh":
            groups.setdefault(uf.find(x), set()).add(x)
        return sorted(sorted(g) for g in groups.values())

    shuffled = list(ps)
    rnd.shuffle(shuffled)
    assert partition(ps) == partition(shuffled)
