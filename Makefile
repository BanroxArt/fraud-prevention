PY ?= python3

.PHONY: bench install lint test check demo

install:
	$(PY) -m pip install -e '.[dev]'

lint:
	ruff check .
	ruff format --check .
	$(PY) scripts/check.py
	$(PY) -m mypy

test:
	$(PY) -m pytest -q

check: lint test

demo:
	$(PY) -m fraudkit synth --seed 7 --accounts 300 -o /tmp/fraudkit-events.jsonl
	$(PY) -m fraudkit score /tmp/fraudkit-events.jsonl --rules examples/demo-rules.yaml -o /tmp/fraudkit-scored.jsonl
	$(PY) -m fraudkit eval /tmp/fraudkit-scored.jsonl

bench:
	PYTHONPATH=src $(PY) bench/run.py
