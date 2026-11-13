from __future__ import annotations

import pytest

from fraudkit.events import parse_event
from fraudkit.rules import build_rules

BASE_TS = 1_767_225_600  # 2026-01-01T00:00:00Z


@pytest.fixture
def ev():
    def make(etype: str, account: str = "a1", t: float = 0, **fields):
        return parse_event({"ts": BASE_TS + t, "type": etype, "account_id": account, **fields})

    return make


@pytest.fixture
def rules_dict():
    return {
        "version": 1,
        "decision": {"review_at": 40, "deny_at": 80},
        "velocity": [
            {
                "code": "VEL_SIGNUPS_PER_DEVICE",
                "events": ["signup"],
                "key": "device_id",
                "distinct": "account_id",
                "window": "24h",
                "threshold": 3,
                "weight": 45,
            },
            {
                "code": "VEL_CARD_ATTEMPTS",
                "events": ["payment"],
                "key": "card_fp",
                "window": "10m",
                "threshold": 3,
                "weight": 50,
            },
            {
                "code": "VEL_FAILED_LOGIN",
                "events": ["login"],
                "key": "account_id",
                "where": {"success": False},
                "window": "15m",
                "threshold": 3,
                "weight": 20,
            },
        ],
        "weights": {
            "EMAIL_DISPOSABLE": 30,
            "ATO_SEQUENCE": 85,
            "ATO_NEW_DEVICE_CASHOUT": 35,
            "PROMO_LINKED_REDEMPTION": 60,
            "PROMO_REPEAT_ACCOUNT": 40,
            "ID_PHONE_REUSE": 30,
            "ID_CARD_REUSE_AT_SIGNUP": 35,
            "IP_HOSTING": 20,
        },
        "email": {"disposable_domains": ["burner.test"]},
        "ip": {"hosting_cidrs": ["203.0.113.0/24"]},
        "linking": {"max_attribute_degree": 4},
        "identity": {"reuse_threshold": 3},
    }


@pytest.fixture
def cfg(rules_dict):
    return build_rules(rules_dict)
