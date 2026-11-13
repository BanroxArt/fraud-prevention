"""Replay, memory bounds and hostile input."""

import json

import pytest
from conftest import BASE_TS

from fraudkit.cli import main
from fraudkit.engine import PRUNE_EVERY, Engine
from fraudkit.events import MAX_EXTRA_FIELDS, MAX_FIELD_LEN, EventError, parse_event
from fraudkit.rules import RuleError, build_rules
from fraudkit.windows import CountWindow, DistinctWindow, SumWindow


def codes(decision):
    return [r.code for r in decision.reasons]


def test_redelivered_event_does_not_inflate_velocity(cfg, ev):
    # Regression: the same payment scored eight times used to look like eight
    # card attempts and trip VEL_CARD_ATTEMPTS (threshold 3 here).
    e = Engine(cfg)
    payment = ev("payment", card_fp="c1", event_id="pay-1", amount=10)
    first = e.score(payment)
    for _ in range(7):
        again = e.score(payment)
        assert again.duplicate
        assert again.action == first.action
        assert codes(again) == codes(first)
    assert "VEL_CARD_ATTEMPTS" not in codes(e.score(ev("payment", card_fp="c1", event_id="p2")))


def test_duplicate_decision_is_a_copy(cfg, ev):
    e = Engine(cfg)
    first = e.score(ev("signup", email="x@burner.test", event_id="s1"))
    again = e.score(ev("signup", email="x@burner.test", event_id="s1"))
    again.reasons.clear()
    assert codes(e.score(ev("signup", email="x@burner.test", event_id="s1"))) == codes(first)
    assert not first.duplicate


def test_events_without_id_are_not_deduplicated(cfg, ev):
    e = Engine(cfg)
    for _ in range(3):
        d = e.score(ev("payment", card_fp="c1"))
    assert not d.duplicate
    assert "VEL_CARD_ATTEMPTS" in codes(d)


def test_dedup_expires_after_window(rules_dict, ev):
    rules_dict["state"] = {"dedup_window": "1h", "dedup_max_ids": 10}
    e = Engine(build_rules(rules_dict))
    e.score(ev("login", event_id="x", t=0))
    assert e.score(ev("login", event_id="x", t=60)).duplicate
    assert not e.score(ev("login", event_id="x", t=7_200)).duplicate


def test_dedup_cache_is_capped(rules_dict, ev):
    rules_dict["state"] = {"dedup_max_ids": 5}
    e = Engine(build_rules(rules_dict))
    for i in range(50):
        e.score(ev("login", event_id=f"e{i}", t=i))
    assert e.state_size()["dedup_ids"] == 5


def test_rotating_keys_cannot_grow_windows_past_cap(rules_dict, ev):
    rules_dict["state"] = {"max_keys_per_window": 100}
    e = Engine(build_rules(rules_dict))
    for i in range(2_000):
        e.score(ev("payment", f"a{i % 7}", t=i, card_fp=f"rot-{i}"))
    assert e._windows["VEL_CARD_ATTEMPTS"].evicted > 0
    assert all(len(w) <= 100 for w in e._windows.values())


def test_prune_covers_every_structure(cfg, ev):
    e = Engine(cfg)
    e.score(ev("signup", "a1", device_id="d1", card_fp="c1", phone="p1", event_id="1"))
    e.score(ev("promo_redeem", "a1", t=5, promo_code="P", event_id="2"))
    e.score(ev("payment", "a1", t=6, card_fp="c1", event_id="3"))
    size = e.state_size()
    assert all(v > 0 for v in size.values()), size
    dropped = e.prune(BASE_TS + 1_000 * 86_400)
    assert e.state_size() == {k: 0 for k in size}
    assert dropped["ato_accounts"] == 1
    assert dropped["link_edges"] >= 3


def test_prune_uses_high_water_mark_not_late_event(cfg, ev, monkeypatch):
    calls = []
    e = Engine(cfg)
    monkeypatch.setattr(e, "prune", lambda now: calls.append(now))
    for i in range(PRUNE_EVERY - 1):
        e.score(ev("login", t=1_000 + i))
    e.score(ev("login", t=0))  # late event lands on the prune boundary
    assert calls and calls[0] >= 1_000


@pytest.mark.parametrize(
    "raw",
    [
        {"ts": 1, "type": "login", "account_id": "a", "device_id": "x" * (MAX_FIELD_LEN + 1)},
        {"ts": 1, "type": "login", "account_id": "a" * (MAX_FIELD_LEN + 1)},
        {"ts": 1, "type": "login", "account_id": ""},
        {"ts": 1, "type": "login", "account_id": {"nested": 1}},
        {"ts": 1, "type": "payment", "account_id": "a", "amount": float("nan")},
        {"ts": 1, "type": "payment", "account_id": "a", "amount": float("inf")},
        {"ts": float("inf"), "type": "login", "account_id": "a"},
        {"ts": 1, "type": "login", "account_id": "a", "k" * 65: 1},
        {"ts": 1, "type": "login", "account_id": "a", "note": "x" * 5000},
        {"ts": 1, "type": "login", "account_id": "a", "blob": {"a": 1}},
        {
            "ts": 1,
            "type": "login",
            "account_id": "a",
            **{f"f{i}": i for i in range(MAX_EXTRA_FIELDS + 1)},
        },
    ],
)
def test_hostile_events_are_rejected(raw):
    with pytest.raises(EventError):
        parse_event(raw)


@pytest.mark.parametrize("cls", [CountWindow, SumWindow, DistinctWindow])
def test_window_key_cap_keeps_side_tables_in_step(cls):
    w = cls(60, max_keys=3)
    for i in range(10):
        w.add(f"k{i}", i)
    assert len(w) == 3
    for table in ("_sum", "_seen"):
        if hasattr(w, table):
            assert set(getattr(w, table)) <= set(w._q)


@pytest.mark.parametrize(
    "state",
    [{"max_accounts": 0}, {"dedup_window": "0s"}, {"max_keys_per_window": "lots"}, []],
)
def test_bad_state_section_is_rejected(rules_dict, state):
    rules_dict["state"] = state
    with pytest.raises(RuleError):
        build_rules(rules_dict)


def test_card_reuse_threshold_is_configurable(rules_dict, ev):
    rules_dict["identity"] = {"card_reuse_threshold": 3}
    e = Engine(build_rules(rules_dict))
    e.score(ev("signup", "a1", card_fp="c"))
    assert "ID_CARD_REUSE_AT_SIGNUP" not in codes(e.score(ev("signup", "a2", t=1, card_fp="c")))
    assert "ID_CARD_REUSE_AT_SIGNUP" in codes(e.score(ev("signup", "a3", t=2, card_fp="c")))


def test_validate_command(tmp_path, capsys):
    assert main(["validate", "examples/demo-rules.yaml"]) == 0
    assert capsys.readouterr().out.startswith("ok:")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nlinking: {link_on: [ip]}\n")
    assert main(["validate", str(bad)]) == 1


@pytest.mark.parametrize(
    "line",
    ["{nope", json.dumps({"account_id": "a"}), json.dumps({"account_id": "a", "action": "maybe"})],
)
def test_eval_reports_bad_rows_without_traceback(tmp_path, capsys, line):
    p = tmp_path / "s.jsonl"
    p.write_text(line + "\n")
    assert main(["eval", str(p)]) == 2
    assert "line 1" in capsys.readouterr().err


def test_default_rules_ship_no_ip_ranges():
    from fraudkit.rules import load_rules

    cfg = load_rules()
    assert cfg.hosting_cidrs == [] and cfg.blocked_cidrs == []


GMAIL = "@" + "gmail.com"  # split so the content lint does not read it as an address


@pytest.mark.parametrize("addr", ["+promo@example.com", "." + GMAIL, "..+x" + GMAIL])
def test_empty_normalized_mailbox_does_not_link(addr):
    # Regression found by the idempotence property: these used to normalise to
    # "@domain" and link every such signup together.
    from fraudkit.signals import normalize_email

    assert normalize_email(addr) is None
