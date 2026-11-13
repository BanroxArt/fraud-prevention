import itertools
import json

from fraudkit.cli import evaluate, main
from fraudkit.synth import generate


def test_synth_is_deterministic():
    a = list(generate(seed=3, accounts=50))
    b = list(generate(seed=3, accounts=50))
    assert a == b
    assert all(x["ts"] <= y["ts"] for x, y in itertools.pairwise(a))
    assert {e["label"] for e in a} >= {"legit"}


def test_score_and_eval_round_trip(tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    scored = tmp_path / "scored.jsonl"
    assert main(["synth", "--seed", "11", "--accounts", "300", "-o", str(events)]) == 0
    assert main(["score", str(events), "-o", str(scored)]) == 0
    rows = [json.loads(x) for x in scored.read_text().splitlines()]
    assert rows and {"score", "action", "reasons", "label"} <= rows[0].keys()
    assert main(["eval", str(scored), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    review = result["bands"]["review"]
    # Synthetic patterns are blunt; if the defaults stop catching most of them
    # something in the engine or rules regressed.
    assert review["recall"] >= 0.7
    assert review["precision"] >= 0.6


def test_score_reports_bad_lines(tmp_path, capsys):
    events = tmp_path / "e.jsonl"
    events.write_text('{"ts":1,"type":"login","account_id":"a"}\nnot json\n')
    assert main(["score", str(events), "--strict"]) == 1
    assert "line 2" in capsys.readouterr().err


def test_score_sort_and_min_score(tmp_path, capsys):
    events = tmp_path / "e.jsonl"
    events.write_text(
        '{"ts":20,"type":"login","account_id":"a"}\n{"ts":10,"type":"signup","account_id":"a"}\n'
    )
    assert main(["score", str(events), "--sort"]) == 0
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [r["ts"] for r in rows] == [10, 20]
    assert main(["score", str(events), "--min-score", "1"]) == 0
    assert capsys.readouterr().out == ""


def test_eval_needs_labels(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text('{"account_id":"a","action":"allow","reasons":[]}\n')
    assert main(["eval", str(p)]) == 2


def test_evaluate_counts_worst_action_per_account():
    rows = [
        {"account_id": "a", "action": "allow", "reasons": [], "label": "ato"},
        {"account_id": "a", "action": "deny", "reasons": [{"code": "X"}], "label": "ato"},
        {"account_id": "b", "action": "review", "reasons": [{"code": "X"}], "label": "legit"},
    ]
    r = evaluate(rows)
    assert r["bands"]["review"] == {
        "flagged": 2,
        "precision": 0.5,
        "recall": 1.0,
        "false_positives": 1,
    }
    assert r["bands"]["deny"]["flagged"] == 1
    assert r["codes"]["X"] == {"accounts": 2, "precision": 0.5}
