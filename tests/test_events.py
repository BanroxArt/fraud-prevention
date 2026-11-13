import pytest

from fraudkit.events import Event, EventError, parse_event, parse_ts, read_jsonl


def test_parse_ts_forms():
    assert parse_ts(10) == 10.0
    assert parse_ts("2026-01-01T00:00:00Z") == 1_767_225_600.0
    assert parse_ts("2026-01-01T01:00:00+01:00") == 1_767_225_600.0


@pytest.mark.parametrize("bad", ["2026-01-01T00:00:00", "yesterday", True, None])
def test_parse_ts_rejects(bad):
    with pytest.raises(EventError):
        parse_ts(bad)


def test_unknown_fields_go_to_extra():
    e = parse_event({"ts": 1, "type": "login", "account_id": 42, "success": False})
    assert e.account_id == "42"
    assert e.get("success") is False
    assert e.get("device_id") is None


@pytest.mark.parametrize(
    "raw",
    [
        {"type": "login", "account_id": "a"},
        {"ts": 1, "type": "hack", "account_id": "a"},
        {"ts": 1, "type": "payment", "account_id": "a", "amount": "lots"},
        [],
    ],
)
def test_parse_event_rejects(raw):
    with pytest.raises(EventError):
        parse_event(raw)


def test_read_jsonl_reports_bad_lines():
    lines = ['{"ts":1,"type":"login","account_id":"a"}', "", "# comment", "{nope", '{"ts":1}']
    out = list(read_jsonl(lines))
    assert [n for n, _ in out] == [1, 4, 5]
    assert isinstance(out[0][1], Event)
    assert all(isinstance(x, EventError) for _, x in out[1:])
