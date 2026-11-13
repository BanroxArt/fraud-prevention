import pytest

from fraudkit.windows import CountWindow, DistinctWindow, SumWindow


def test_count_window_evicts_at_boundary():
    w = CountWindow(60)
    assert w.add("k", 0) == 1
    assert w.add("k", 30) == 2
    # An observation exactly one window old is out.
    assert w.add("k", 60) == 2
    assert w.count("k", 200) == 0


def test_count_window_keys_are_independent():
    w = CountWindow(60)
    w.add("a", 0)
    w.add("a", 1)
    w.add("b", 2)
    assert w.count("a", 10) == 2
    assert w.count("b", 10) == 1
    assert w.count("missing", 10) == 0


def test_late_event_is_inserted_in_order():
    w = CountWindow(100)
    w.add("k", 50)
    w.add("k", 10)  # late
    w.add("k", 120)
    # At t=120, the t=10 entry is gone and t=50 stays.
    assert w.count("k", 120) == 2


def test_sum_window_tracks_total_and_resets():
    w = SumWindow(3600)
    assert w.add("card", 0, 100.0) == 100.0
    assert w.add("card", 10, 50.5) == 150.5
    assert w.total("card", 3605) == 50.5
    assert w.total("card", 10_000) == 0.0


def test_distinct_window_counts_unique_values():
    w = DistinctWindow(100)
    assert w.add("dev", 0, "a1") == 1
    assert w.add("dev", 1, "a1") == 1
    assert w.add("dev", 2, "a2") == 2
    # t=100: the first a1 left, the second a1 (t=1) and a2 remain.
    assert w.distinct("dev", 100) == 2
    assert w.distinct("dev", 101) == 1
    assert w.distinct("dev", 102) == 0


def test_prune_drops_empty_keys():
    w = DistinctWindow(10)
    for i in range(50):
        w.add(f"k{i}", i, "x")
    assert w.prune(1_000) == 50
    assert len(w) == 0


def test_window_must_be_positive():
    with pytest.raises(ValueError):
        CountWindow(0)
