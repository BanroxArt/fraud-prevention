# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Fixed

- A late event was charged for observations that happened after it. Windows now answer as of the event's own timestamp, and keep `allowed_lateness` of expired entries so that answer is exact.
- Replayed events no longer inflate velocity windows. A repeated `event_id` inside `state.dedup_window` returns the first decision with `duplicate: true` and leaves state alone.
- `ATO_SEQUENCE` now requires the credential change and the cash-out to come from the same new device, after that device's first login. Previously a reset from a known device plus an unrelated new-device login earlier in the window graded as a full takeover (weight 85).
- `AtoTracker`, `Linker` and the per-account promo map were never pruned. All three now age out with `Engine.prune` and have hard caps, so state no longer grows with the number of accounts or attribute values forever.
- Linking could grow one cluster without limit through a chain of different attributes. Merges that would exceed `linking.max_cluster_size` are refused and reported as `LINK_SUPERNODE`.
- `normalize_email` returned `@domain` for local parts that were empty after stripping (`+promo@x`, `.@gmail.com`), which linked every such signup into one cluster. It now returns `None`.
- Pruning used the current event's timestamp, so a late event on the prune boundary pruned against a stale clock. It now uses the newest timestamp seen.
- `fraudkit eval` printed a traceback on invalid JSON or rows without `action`; it now reports the line and exits 2.

### Added

- Visible author attribution, a `CITATION.cff` citation file, and `llms.txt`.

- Event-time ordering. `state.allowed_lateness` (default 1h) sets a watermark; events behind it are not scored against state and come back with `late: true`, a `LATE_EVENT` reason and `state.late_action`. Optional `state.max_future_skew` does the same for future-dated events (`CLOCK_AHEAD`) so one bad clock cannot move the watermark. `Engine.watermark` and `Engine.late_events` expose both.
- Input bounds in the event parser: 256-character identifiers, at most 32 extra fields, finite `amount` and `ts`.
- `state:` section in the rules file for dedup and memory caps; `linking.window`, `linking.max_cluster_size`, `ato.device_ttl` and `identity.card_reuse_threshold` (was hardcoded to 2).
- `Engine.state_size()` and a return value from `Engine.prune()` for monitoring.
- `fraudkit validate rules.yaml`.
- mypy (strict) in CI, a `py.typed` marker, and Hypothesis property tests for score combination, windows, email normalisation and union-find.
- SECURITY.md, CONTRIBUTING.md and this file.

### Changed

- The packaged rules ship with empty `hosting_cidrs`. The documentation range that used to be there moved to `examples/demo-rules.yaml`, which `make demo` uses.
- `Decision` has `duplicate` and `late` fields, so scored JSON output has two more keys.
- Window constructors take an optional `grace_s`.

## [0.1.0] - 2026-11-12

First public version: velocity, sum and distinct windows, email and IP signals, takeover sequence tracking, union-find linking for promo rings, YAML rules, CLI with synthetic data and evaluation.
