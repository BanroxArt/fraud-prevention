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


def test_known_device_reset_plus_unrelated_new_device_is_not_a_sequence():
    # Regression: the owner resets their password from their usual phone, and
    # a day earlier someone logged in from a new laptop. Those are not one
    # takeover, so the payout change must not grade as ATO_SEQUENCE.
    t = AtoTracker(window_s=2 * 86_400)
    t.observe("signup", "a", "phone", 0)
    t.observe("login", "a", "laptop", 100)
    hits = t.observe("password_reset", "a", "phone", 50_000)
    assert "ATO_CRED_CHANGE_AFTER_NEW_DEVICE" not in codes(hits)
    assert codes(t.observe("payout_change", "a", "phone", 50_100)) == ["ATO_CRED_AND_NEW_DEVICE"]


def test_sequence_allows_deviceless_server_side_cashout():
    t = AtoTracker()
    t.observe("signup", "a", "home", 0)
    t.observe("login", "a", "evil", 10)
    t.observe("mfa_change", "a", "evil", 20)
    assert codes(t.observe("payout_change", "a", None, 30)) == ["ATO_SEQUENCE"]
    # A cash-out from yet another device is not tied to the chain.
    assert codes(t.observe("withdrawal", "a", "third", 40)) == ["ATO_CRED_AND_NEW_DEVICE"]


def test_idle_accounts_are_pruned():
    t = AtoTracker(device_ttl_s=1_000)
    t.observe("signup", "a", "d1", 0)
    t.observe("signup", "b", "d1", 900)
    assert t.prune(1_500) == 1
    assert t.known_devices("a") == []
    assert t.known_devices("b") == ["d1"]


def test_account_count_is_capped():
    t = AtoTracker(max_accounts=3)
    for i in range(10):
        t.observe("login", f"acct{i}", "d", i)
    assert len(t) == 3
    assert t.known_devices("acct9") == ["d"]
    assert t.known_devices("acct0") == []


def test_reads_do_not_create_state():
    t = AtoTracker()
    assert t.known_devices("nobody") == []
    assert len(t) == 0
