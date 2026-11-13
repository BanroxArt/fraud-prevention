from fraudkit.ato import AtoTracker


def codes(hits):
    return [h.code for h in hits]


def test_full_takeover_sequence():
    t = AtoTracker(window_s=86_400)
    assert codes(t.observe("signup", "a", "dev-home", 0)) == []
    assert codes(t.observe("login", "a", "dev-home", 100)) == []
    assert codes(t.observe("login", "a", "dev-x", 1_000)) == ["ATO_NEW_DEVICE_LOGIN"]
    assert "ATO_CRED_CHANGE_AFTER_NEW_DEVICE" in codes(
        t.observe("password_reset", "a", "dev-x", 1_200)
    )
    hits = t.observe("payout_change", "a", "dev-x", 1_500)
    assert codes(hits) == ["ATO_SEQUENCE"]
    assert "password_reset" in hits[0].detail


def test_sequence_expires_after_window():
    t = AtoTracker(window_s=3_600)
    t.observe("signup", "a", "d1", 0)
    t.observe("login", "a", "d2", 10)
    t.observe("password_reset", "a", "d2", 20)
    assert codes(t.observe("payout_change", "a", "d2", 10_000)) == []


def test_credential_change_before_new_device_is_weaker():
    t = AtoTracker()
    t.observe("signup", "a", "d1", 0)
    t.observe("email_change", "a", "d1", 10)
    t.observe("login", "a", "d2", 20)
    assert codes(t.observe("withdrawal", "a", "d2", 30)) == ["ATO_CRED_AND_NEW_DEVICE"]


def test_partial_patterns():
    t = AtoTracker()
    t.observe("signup", "a", "d1", 0)
    t.observe("login", "a", "d2", 10)
    assert codes(t.observe("payout_change", "a", "d2", 20)) == ["ATO_NEW_DEVICE_CASHOUT"]

    t.observe("signup", "b", "d1", 0)
    t.observe("password_reset", "b", "d1", 10)
    assert codes(t.observe("payout_change", "b", "d1", 20)) == ["ATO_CRED_CHANGE_CASHOUT"]


def test_signup_device_is_not_new_and_device_memory_is_bounded():
    t = AtoTracker(max_devices=2)
    t.observe("signup", "a", "d0", 0)
    assert codes(t.observe("login", "a", "d0", 1)) == []
    t.observe("login", "a", "d1", 2)
    t.observe("login", "a", "d2", 3)
    assert t.known_devices("a") == ["d1", "d2"]
