# Benchmarks

Run them yourself:

```
make bench
```

or `PYTHONPATH=src python bench/run.py`. The script uses `timeit` from the
standard library and reports the best of five repeats, so the numbers are a
floor for one CPU core, not a throughput promise. Compare runs on the same
machine only.

Last recorded run, Nov 14, 2026, on a shared cloud VM (Intel Xeon, 1 core in use):

Python 3.13.5 on x86_64 (linux)

| case | µs/op | ops/s |
|---|---:|---:|
| score, 12,852-event synthetic stream, per event | 42.77 | 23,380 |
| score one event (repeated) against warm state | 1.42 | 703,667 |
| parse_event (dict -> Event) | 3.16 | 316,466 |
