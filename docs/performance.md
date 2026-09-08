# Performance & evaluation

## Detection quality
Run against the labeled lab corpus:

```bash
uv run python -m evaluation.evaluate
```

Result (per-flow, strict):

| threat | precision | recall | note |
|--------|-----------|--------|------|
| dga_dns | 1.00 | 1.00 | |
| exfil | 1.00 | 1.00 | |
| tls_malware | 1.00 | 1.00 | |
| portscan | 1.00 | 0.68 | recall < 1 because the alert only fires once the window fills |
| flood | 1.00 | 0.35 | same — first ~40 flows of the burst warm up the window |
| beaconing | 1.00 | 0.17 | fires after ≥6 beacons observed |

- **Precision 1.00 across all six** — zero false positives on benign traffic.
- **Detection-level recall: 6/6** — every threat class is caught. Per-flow recall < 1 for
  scan/flood/beaconing is expected and correct: those threats span many flows and alert once
  their detection window accumulates enough evidence, so early flows in the burst are (rightly)
  not yet alertable.

## Throughput
```bash
uv run python -m bench.throughput --flows 10000
```
**~630 flows/sec sustained, single worker** (macOS + Docker Desktop; Redis over the mapped port).
The bottleneck is the detection stack: pipelined Redis round-trips (~5–6/flow) plus gated model
inference. Two engineering choices got here from an initial 68 flows/sec:
1. **Redis pipelining** — every state primitive batches its commands into one round-trip.
2. **Gated model inference with `n_jobs=1`** — the RandomForests only run on candidate flows
   (small-packet TLS / high-entropy domains), and single-threaded to avoid per-call threadpool
   overhead (~10 ms → ~0.3 ms per call).

Scale-out is linear: workers are stateless (state is shared Redis), so N workers in the Kafka
consumer group give ≈ N × throughput. On Linux with a co-located Redis, single-worker throughput
is materially higher (round-trip latency drops from ~150 µs to ~30 µs).
