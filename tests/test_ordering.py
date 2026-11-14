"""Late and out-of-order events: as-of window answers, watermark, clock skew."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fraudkit.engine import Engine
from fraudkit.rules import RuleError, build_rules
from fraudkit.windows import CountWindow, DistinctWindow, SumWindow


def codes(decision):
    return [r.code for r in decision.reasons]


def test_late_add_sees_entries_that_already_left_the_live_range():
    w = CountWindow(100, grace_s=300)
    w.add("k", 0)
    w.add("k", 250)  # t=0 leaves the live range here
    assert w.add("k", 50) == 2  # as of t=50: t=0 and itself
    assert w.count("k", 250) == 1


def test_grace_is_trimmed_and_pruned():
    w = CountWindow(100, grace_s=50)
    w.add("k", 0)
    w.add("k", 120)
    assert "k" in w._grace
    w.count("k", 400)
    assert w.prune(400) == 1
    assert len(w) == 0 and not w._grace


def test_late_add_counts_only_what_came_before_it():
    w = CountWindow(600)
    for t in (100, 200, 300, 400):
        w.add("card", t)
    # Arrives after t=400 but happened at t=150: only t=100 and itself count.
    assert w.add("card", 150) == 2
    # The in-order path still sees everything inside the window.
    assert w.add("card", 500) == 6


def test_late_add_on_sum_and_distinct_windows():
    s = SumWindow(600)
    s.add("card", 100, 10.0)
    s.add("card", 300, 500.0)
    assert s.add("card", 200, 1.0) == 11.0
    assert s.total("card", 300) == 511.0

    d = DistinctWindow(600)
    d.add("dev", 100, "a1")
    d.add("dev", 300, "a2")
    d.add("dev", 400, "a3")
    assert d.add("dev", 200, "a1") == 1
    assert d.distinct("dev", 400) == 3


def test_equal_timestamps_keep_arrival_order():
    w = SumWindow(60)
    w.add("k", 10, 1.0)
    w.add("k", 20, 2.0)
    assert w.add("k", 10, 4.0) == 5.0


@settings(max_examples=200, deadline=None)
@given(
    st.lists(st.integers(min_value=0, max_value=5_000), min_size=1, max_size=60),
    st.integers(min_value=1, max_value=2_000),
    st.integers(min_value=0, max_value=1_500),
)
def test_count_window_matches_brute_force_in_any_order(times, window, lateness):
    w = CountWindow(window, grace_s=lateness)
    seen: list[int] = []
    newest = float("-inf")
    for t in times:
        if t < newest - lateness:
            # Behind the watermark: the engine refuses these before any window.
            continue
        seen.append(t)
        newest = max(newest, t)
        expected = sum(1 for s in seen if t - window < s <= t)
        assert w.add("k", t) == expected


@settings(max_examples=150, deadline=None)
@given(
    st.lists(
        st.tuples(st.integers(min_value=0, max_value=3_000), st.sampled_from("abcd")),
        min_size=1,
        max_size=40,
    ),
    st.integers(min_value=1, max_value=1_000),
    st.integers(min_value=0, max_value=800),
)
def test_distinct_window_matches_brute_force_in_any_order(items, window, lateness):
    w = DistinctWindow(window, grace_s=lateness)
    seen: list[tuple[int, str]] = []
    newest = float("-inf")
    for t, v in items:
        if t < newest - lateness:
            continue
        seen.append((t, v))
        newest = max(newest, t)
        expected = len({sv for st_, sv in seen if t - window < st_ <= t})
        assert w.add("k", t, v) == expected


def test_late_payment_is_not_charged_for_later_attempts(cfg, ev):
    # VEL_CARD_ATTEMPTS: 3 payments per card in 10 minutes.
    e = Engine(cfg)
    e.score(ev("payment", card_fp="c1", t=0, event_id="p1"))
    e.score(ev("payment", card_fp="c1", t=1_000, event_id="p2"))
    e.score(ev("payment", card_fp="c1", t=1_100, event_id="p3"))
    # Happened at t=10, delivered last. Before the fix it counted p2 and p3.
    late = e.score(ev("payment", card_fp="c1", t=10, event_id="p0"))
    assert not late.late
    assert "VEL_CARD_ATTEMPTS" not in codes(late)
    # And the next in-order attempt now sees four in its window.
    assert "VEL_CARD_ATTEMPTS" in codes(e.score(ev("payment", card_fp="c1", t=1_200)))


def test_event_behind_watermark_is_refused_and_leaves_state_alone(cfg, ev):
    e = Engine(cfg)
    e.score(ev("login", t=10_000))
    before = e.state_size()
    d = e.score(ev("payment", card_fp="c9", t=10_000 - 3_601, event_id="old"))
    assert d.late
    assert d.action == "review"
    assert d.score == 0.0
    assert codes(d) == ["LATE_EVENT"]
    assert "3601s behind" in d.reasons[0].detail
    after = e.state_size()
    # Only the dedup cache moves, so a redelivery gets the same answer.
    assert after.pop("dedup_ids") == before.pop("dedup_ids") + 1
    assert after == before
    assert e.late_events == 1
    assert d.to_dict()["late"] is True


def test_event_exactly_at_watermark_is_scored(cfg, ev):
    e = Engine(cfg)
    e.score(ev("login", t=10_000))
    assert not e.score(ev("login", t=10_000 - 3_600)).late


def test_redelivered_late_event_gets_the_same_answer(cfg, ev):
    e = Engine(cfg)
    e.score(ev("login", t=10_000))
    first = e.score(ev("payment", card_fp="c9", t=0, event_id="old"))
    again = e.score(ev("payment", card_fp="c9", t=0, event_id="old"))
    assert again.duplicate and again.late
    assert again.action == first.action
    assert e.late_events == 1


def test_late_action_and_lateness_come_from_rules(rules_dict, ev):
    rules_dict["state"] = {"allowed_lateness": "5m", "late_action": "allow"}
    e = Engine(build_rules(rules_dict))
    e.score(ev("login", t=1_000))
    assert not e.score(ev("login", t=1_000 - 300)).late
    d = e.score(ev("login", t=1_000 - 301))
    assert d.late and d.action == "allow"


def test_zero_lateness_refuses_anything_older_than_newest(rules_dict, ev):
    rules_dict["state"] = {"allowed_lateness": 0}
    e = Engine(build_rules(rules_dict))
    e.score(ev("login", t=100))
    assert not e.score(ev("login", t=100)).late
    assert e.score(ev("login", t=99)).late


def test_future_dated_event_does_not_move_the_watermark(rules_dict, ev):
    rules_dict["state"] = {"max_future_skew": "15m"}
    e = Engine(build_rules(rules_dict))
    e.score(ev("login", t=0))
    ahead = e.score(ev("login", t=365 * 86_400))
    assert ahead.late and codes(ahead) == ["CLOCK_AHEAD"]
    # Without the guard this would now be a year behind the watermark.
    assert not e.score(ev("login", t=60)).late
    assert not e.score(ev("login", t=60 + 900)).late


def test_future_skew_is_off_by_default(cfg, ev):
    e = Engine(cfg)
    e.score(ev("login", t=0))
    assert not e.score(ev("login", t=365 * 86_400)).late
    assert e.score(ev("login", t=60)).late


@pytest.mark.parametrize(
    "state",
    [
        {"late_action": "block"},
        {"allowed_lateness": "soon"},
        {"allowed_lateness": -5},
        {"max_future_skew": "0s"},
        {"allowed_lateness": "2d", "dedup_window": "24h"},
    ],
)
def test_bad_ordering_settings_are_rejected(rules_dict, state):
    rules_dict["state"] = state
    with pytest.raises(RuleError):
        build_rules(rules_dict)
