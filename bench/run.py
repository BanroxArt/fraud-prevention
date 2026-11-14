"""Micro-benchmarks. Run: PYTHONPATH=src python bench/run.py

Standard library timeit, best of five repeats. Numbers are per operation on
one CPU core; compare runs on the same machine, not across machines.
"""

from __future__ import annotations

import platform
import sys
import timeit
from collections.abc import Callable

from fraudkit.engine import Engine
from fraudkit.events import parse_event
from fraudkit.rules import load_rules
from fraudkit.synth import generate


def bench(name: str, fn: Callable[[], object], number: int, repeat: int = 5) -> None:
    best = min(timeit.repeat(fn, number=number, repeat=repeat)) / number
    print(f"| {name} | {best * 1e6:,.2f} | {1 / best:,.0f} |")


def header() -> None:
    print(f"Python {platform.python_version()} on {platform.machine()} ({sys.platform})\n")
    print("| case | µs/op | ops/s |")
    print("|---|---:|---:|")


def main() -> None:
    header()
    cfg = load_rules()
    events = [parse_event(r) for r in generate(seed=7, accounts=2000)]

    def stream() -> None:
        engine = Engine(cfg)
        for e in events:
            engine.score(e)

    per_event = min(timeit.repeat(stream, number=1, repeat=5)) / len(events)
    name = f"score, {len(events):,}-event synthetic stream, per event"
    print(f"| {name} | {per_event * 1e6:,.2f} | {1 / per_event:,.0f} |")
    warm = Engine(cfg)
    for e in events:
        warm.score(e)
    last = events[-1]
    bench("score one event (repeated) against warm state", lambda: warm.score(last), 2000)
    bench("parse_event (dict -> Event)", lambda: parse_event(dict(generate_one)), 20000)


generate_one = next(iter(generate(seed=1, accounts=1)))

if __name__ == "__main__":
    main()
