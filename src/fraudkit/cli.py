"""Command line entry point: ``fraudkit score|synth|eval``."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import IO

from fraudkit.engine import Engine
from fraudkit.events import Event, EventError, read_jsonl
from fraudkit.rules import RuleError, load_rules
from fraudkit.synth import generate


def _open_in(path: str) -> IO[str]:
    return sys.stdin if path == "-" else open(path, encoding="utf-8")


def _open_out(path: str | None) -> IO[str]:
    return sys.stdout if path in (None, "-") else open(path, "w", encoding="utf-8")


def cmd_score(args: argparse.Namespace) -> int:
    try:
        cfg = load_rules(args.rules)
    except (OSError, RuleError) as exc:
        print(f"rules: {exc}", file=sys.stderr)
        return 2
    engine = Engine(cfg)
    bad = 0
    with _open_in(args.events) as fh:
        parsed = list(read_jsonl(fh)) if args.sort else read_jsonl(fh)
        if args.sort:
            good = [(n, e) for n, e in parsed if isinstance(e, Event)]
            errs = [(n, e) for n, e in parsed if isinstance(e, EventError)]
            good.sort(key=lambda p: p[1].ts)
            parsed = errs + good
        out = _open_out(args.output)
        try:
            for n, item in parsed:
                if isinstance(item, EventError):
                    bad += 1
                    print(f"line {n}: {item}", file=sys.stderr)
                    continue
                decision = engine.score(item)
                if decision.score < args.min_score:
                    continue
                row = decision.to_dict()
                if "label" in item.extra:
                    row["label"] = item.extra["label"]
                out.write(json.dumps(row, separators=(",", ":")) + "\n")
        finally:
            if out is not sys.stdout:
                out.close()
    if bad and args.strict:
        return 1
    return 0


def cmd_synth(args: argparse.Namespace) -> int:
    out = _open_out(args.output)
    try:
        for ev in generate(args.seed, args.accounts, args.fraud_rate, args.disposable_domain):
            out.write(json.dumps(ev, separators=(",", ":")) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()
    return 0


def evaluate(rows: Iterable[dict]) -> dict:
    """Account-level eval: an account counts as flagged if any of its events reached the action."""
    worst: dict[str, str] = {}
    label: dict[str, bool] = {}
    codes_by_acct: dict[str, set[str]] = defaultdict(set)
    rank = {"allow": 0, "review": 1, "deny": 2}
    for row in rows:
        acct = row["account_id"]
        bad = row.get("label", "legit") != "legit"
        label[acct] = label.get(acct, False) or bad
        if rank[row["action"]] > rank.get(worst.get(acct, "allow"), 0):
            worst[acct] = row["action"]
        worst.setdefault(acct, "allow")
        for r in row.get("reasons", []):
            codes_by_acct[acct].add(r["code"])
    result: dict = {"accounts": len(label), "fraud_accounts": sum(label.values()), "bands": {}}
    for band in ("review", "deny"):
        flagged = {a for a, w in worst.items() if rank[w] >= rank[band]}
        tp = sum(1 for a in flagged if label[a])
        fp = len(flagged) - tp
        fn = sum(1 for a, b in label.items() if b and a not in flagged)
        result["bands"][band] = {
            "flagged": len(flagged),
            "precision": round(tp / len(flagged), 3) if flagged else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_positives": fp,
        }
    per_code: dict[str, Counter] = defaultdict(Counter)
    for acct, codes in codes_by_acct.items():
        for c in codes:
            per_code[c]["fraud" if label[acct] else "legit"] += 1
    result["codes"] = {
        c: {
            "accounts": cnt["fraud"] + cnt["legit"],
            "precision": round(cnt["fraud"] / (cnt["fraud"] + cnt["legit"]), 3),
        }
        for c, cnt in sorted(per_code.items())
    }
    return result


def cmd_eval(args: argparse.Namespace) -> int:
    with _open_in(args.scored) as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    if not any("label" in r for r in rows):
        print("no label field in scored rows; eval needs labelled input", file=sys.stderr)
        return 2
    res = evaluate(rows)
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    print(f"accounts {res['accounts']}  fraud {res['fraud_accounts']}")
    for band, m in res["bands"].items():
        print(
            f"{band:>7}: flagged {m['flagged']:>5}  precision {m['precision']}  "
            f"recall {m['recall']}  fp {m['false_positives']}"
        )
    print("\nreason code               accounts  precision")
    for code, m in res["codes"].items():
        print(f"{code:<26}{m['accounts']:>8}  {m['precision']:>9}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fraudkit", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("score", help="score a JSONL event stream")
    s.add_argument("events", help="JSONL file, or - for stdin")
    s.add_argument("--rules", type=Path, default=None, help="rules YAML (default: packaged rules)")
    s.add_argument("-o", "--output", default=None)
    s.add_argument("--sort", action="store_true", help="load everything and sort by ts first")
    s.add_argument("--min-score", type=float, default=0.0, help="only emit decisions at or above")
    s.add_argument("--strict", action="store_true", help="exit 1 if any line failed to parse")
    s.set_defaults(func=cmd_score)

    g = sub.add_parser("synth", help="write a labelled synthetic event stream")
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--accounts", type=int, default=500)
    g.add_argument("--fraud-rate", type=float, default=0.08)
    g.add_argument("--disposable-domain", default="mailinator.com")
    g.add_argument("-o", "--output", default=None)
    g.set_defaults(func=cmd_synth)

    e = sub.add_parser("eval", help="precision and recall from scored, labelled output")
    e.add_argument("scored")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_eval)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
