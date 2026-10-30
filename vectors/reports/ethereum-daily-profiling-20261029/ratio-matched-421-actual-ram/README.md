# Ratio-matched mixed421 complete original proof

One clean CPU ReleaseSafe run on Apple M5 Max, with four workers, canonical q70/PoW26 and four native windows. This is a synthetic Ethereum-profile workload, not a full Ethereum block. It includes 1,726,115 cycles, 421 Keccak calls, one recovery call, 215,552 first-touch native words, 452,200 RAM events and 1,726,118 program fetches.

The complete original STARK was serialized, decoded and independently verified after all producer owners were destroyed. No recursive proof or checkpoint I/O is included. The benchmark explicitly admits up to 1,048,576 events, uses 65,536 events per RAM cohort, and retains the prior 8GiB memory-stage, 24GiB request and 8GiB retained-PCS limits.

| Measurement | Result |
|---|---:|
| Input to independently verified proof | 113.412 s |
| Setup | 7.437 s |
| Complete producer API | 105.112 s |
| Independent verification | 0.804 s |
| Process peak RSS | 8,718,729,216 B |
| Tracked cumulative allocation peak | 9,047,532,314 B |
| Complete proof envelope | 21,906,041 B |
| Raw STARK payload | 21,742,610 B |

## Measured bottlenecks

The DEEP quotient and FRI construction/commitment stage took 42.974 s (37.9% of the request); composition evaluation took 37.522 s (33.1%); native interaction generation/preparation took 17.054 s (15.0%). These three exclusive costs account for approximately 86% of the request. Caller preparation took 3.002 s, native access commitments 2.580 s and memory preparation 1.649 s. Core commitment/evaluation work dominates this case, not input execution or serialization. Optimize these measured stages before drawing conclusions from the much smaller basket.

The actual-event RAM layout fixed an honest high-clock completeness failure without weakening the receiver's zero-residual guard. The failed event-cap and old clock-layout attempts remain in sibling directories. The diagnostic JSON is explicitly unauthenticated; only the subsequent full proof establishes successful complete verification. This single run is neither a latency distribution nor a full-block extrapolation. See `summary.json`, the untouched per-run report and stage CSVs for exact provenance and all measurements.
