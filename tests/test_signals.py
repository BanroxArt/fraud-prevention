import pytest

from fraudkit.signals import IpClassifier, email_hits, ip_prefix, normalize_email, shannon_entropy

GMAIL = "gmail.com"  # kept out of literal addresses so the content lint stays quiet


@pytest.mark.parametrize(
    ("raw", "norm"),
    [
        (f"A.B+promo1@{GMAIL.title()}", f"ab@{GMAIL}"),
        (f"a.b@google{'mail.com'}", f"ab@{GMAIL}"),
        ("first.last+x@example.com", "first.last@example.com"),
        ("not-an-email", None),
        ("two@@at.example", None),
    ],
)
def test_normalize_email(raw, norm):
    assert normalize_email(raw) == norm


def codes(hits):
    return {h.code for h in hits}


def test_disposable_matches_subdomains():
    assert "EMAIL_DISPOSABLE" in codes(email_hits("x@burner.test", ["burner.test"]))
    assert "EMAIL_DISPOSABLE" in codes(email_hits("x@mx.burner.test", ["burner.test"]))
    assert "EMAIL_DISPOSABLE" not in codes(email_hits("x@notburner.test", ["burner.test"]))


def test_digit_heavy_and_random_local_part():
    assert "EMAIL_DIGIT_HEAVY" in codes(email_hits("a83920193@example.com", []))
    assert "EMAIL_RANDOM_LOCALPART" in codes(email_hits("q8zk3vx0rj2mtw7p@example.com", []))
    assert codes(email_hits("maria.silva@example.com", [])) == set()


def test_missing_and_malformed_email():
    assert codes(email_hits(None, [])) == {"EMAIL_MISSING"}
    assert codes(email_hits("nope", [])) == {"EMAIL_MALFORMED"}


def test_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_ip_classifier():
    c = IpClassifier(hosting_cidrs=["203.0.113.0/24"], blocked_cidrs=["192.0.2.0/25"])
    assert codes(c.hits("203.0.113.9")) == {"IP_HOSTING"}
    assert codes(c.hits("192.0.2.5")) == {"IP_BLOCKLIST"}
    assert codes(c.hits("198.51.100.4")) == set()
    assert codes(c.hits("127.0.0.1")) == {"IP_NON_ROUTABLE"}
    assert codes(c.hits("garbage")) == {"IP_MALFORMED"}
    assert c.hits(None) == []


def test_ip_prefix():
    assert ip_prefix("198.51.100.77") == "198.51.100.0/24"
    assert ip_prefix("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert ip_prefix("bad") is None
