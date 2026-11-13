import pytest

from fraudkit.engine import Engine, combine


def codes(decision):
    return [r.code for r in decision.reasons]


def test_combine_is_noisy_or():
    assert combine([]) == 0
    assert combine([100]) == 100
    assert combine([50, 50]) == pytest.approx(75)
    assert combine([85]) > combine([30, 30, 30])


def test_clean_signup_is_allowed(cfg, ev):
    d = Engine(cfg).score(
        ev("signup", email="maria.silva@example.com", device_id="d1", ip="198.51.100.2")
    )
    assert d.action == "allow"
    assert d.score == 0


def test_device_farm_trips_velocity_and_email(cfg, ev):
    e = Engine(cfg)
    decisions = [
        e.score(ev("signup", f"a{i}", t=i * 60, device_id="farm", email=f"x{i}@burner.test"))
        for i in range(3)
    ]
    last = decisions[-1]
    assert codes(last)[:2] == ["VEL_SIGNUPS_PER_DEVICE", "EMAIL_DISPOSABLE"]
    assert last.action == "review"
    assert decisions[0].action == "allow"


def test_reasons_are_sorted_by_weight(cfg, ev):
    e = Engine(cfg)
    for i in range(3):
        d = e.score(
            ev("signup", f"a{i}", t=i, device_id="farm", email="x@burner.test", ip="203.0.113.5")
        )
    weights = [r.weight for r in d.reasons]
    assert weights == sorted(weights, reverse=True)


def test_takeover_sequence_is_denied(cfg, ev):
    e = Engine(cfg)
    e.score(ev("signup", device_id="home", email="o@example.com"))
    e.score(ev("login", t=10, device_id="new"))
    e.score(ev("password_reset", t=20, device_id="new"))
    d = e.score(ev("payout_change", t=30, device_id="new"))
    assert "ATO_SEQUENCE" in codes(d)
    assert d.action == "deny"


def test_promo_ring_linked_by_card(cfg, ev):
    e = Engine(cfg)
    e.score(ev("signup", "a1", card_fp="c1", email="a@example.com"))
    e.score(ev("signup", "a2", t=5, card_fp="c1", email="b@example.com"))
    assert e.score(ev("promo_redeem", "a1", t=10, promo_code="P")).action == "allow"
    d = e.score(ev("promo_redeem", "a2", t=20, promo_code="P"))
    assert "PROMO_LINKED_REDEMPTION" in codes(d)
    assert d.action == "review"


def test_same_account_repeat_redemption(cfg, ev):
    e = Engine(cfg)
    e.score(ev("promo_redeem", promo_code="P"))
    assert "PROMO_REPEAT_ACCOUNT" in codes(e.score(ev("promo_redeem", t=1, promo_code="P")))


def test_where_filter_only_counts_failures(cfg, ev):
    e = Engine(cfg)
    for i in range(5):
        e.score(ev("login", t=i, success=True, device_id="d"))
    assert "VEL_FAILED_LOGIN" not in codes(e.score(ev("login", t=6, success=True, device_id="d")))
    for i in range(3):
        d = e.score(ev("login", t=10 + i, success=False, device_id="d"))
    assert "VEL_FAILED_LOGIN" in codes(d)


def test_identity_reuse_on_phone_and_card(cfg, ev):
    e = Engine(cfg)
    e.score(ev("signup", "a1", phone="ph_1", card_fp="c9"))
    d = e.score(ev("signup", "a2", t=1, phone="ph_1", card_fp="c9"))
    assert "ID_CARD_REUSE_AT_SIGNUP" in codes(d)
    assert "ID_PHONE_REUSE" not in codes(d)
    d = e.score(ev("signup", "a3", t=2, phone="ph_1"))
    assert "ID_PHONE_REUSE" in codes(d)


def test_allowlist_zeroes_score_but_keeps_reasons(rules_dict, ev):
    from fraudkit.rules import build_rules

    rules_dict["allowlist"] = {"accounts": ["qa-bot"]}
    e = Engine(build_rules(rules_dict))
    d = e.score(ev("signup", "qa-bot", email="x@burner.test"))
    assert d.action == "allow"
    assert d.score == 0
    assert "EMAIL_DISPOSABLE" in codes(d)


def test_unknown_weight_codes_score_zero(cfg, ev):
    d = Engine(cfg).score(ev("signup", email="a+b@example.com"))
    assert [(r.code, r.weight) for r in d.reasons] == [("EMAIL_PLUS_TAG", 0.0)]
