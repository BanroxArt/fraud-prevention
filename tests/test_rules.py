import pytest

from fraudkit.rules import RuleError, build_rules, load_rules, parse_duration


@pytest.mark.parametrize(
    ("raw", "secs"), [("90s", 90), ("10m", 600), ("24h", 86400), ("2d", 172800), (30, 30)]
)
def test_parse_duration(raw, secs):
    assert parse_duration(raw) == secs


def test_bad_duration():
    with pytest.raises(RuleError):
        parse_duration("ten minutes")


def test_packaged_defaults_load():
    cfg = load_rules()
    assert cfg.review_at < cfg.deny_at
    assert {r.code for r in cfg.velocity} >= {"VEL_SIGNUPS_PER_DEVICE", "VEL_CARD_ATTEMPTS"}
    assert all(0 <= w <= 100 for w in cfg.weights.values())


def test_where_clause_parsed(cfg):
    rule = next(r for r in cfg.velocity if r.code == "VEL_FAILED_LOGIN")
    assert rule.where == (("success", False),)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("version"),
        lambda d: d["decision"].update(review_at=90, deny_at=50),
        lambda d: d["velocity"][0].update(key="shoe_size"),
        lambda d: d["velocity"][0].update(events=["teleport"]),
        lambda d: d["velocity"][0].update(sum="amount"),
        lambda d: d["velocity"].append(dict(d["velocity"][0])),
        lambda d: d["weights"].update(X=150),
        lambda d: d.setdefault("linking", {}).update(link_on=["ip"]),
    ],
)
def test_invalid_configs_rejected(rules_dict, mutate):
    mutate(rules_dict)
    with pytest.raises(RuleError):
        build_rules(rules_dict)
