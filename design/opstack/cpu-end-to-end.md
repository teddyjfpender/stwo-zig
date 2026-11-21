# CPU proof latency for OP Mainnet and Mantle

The November 21 cohort measures native production, recursive production and
fresh root verification on an Apple M5 Max with 18 cores and 64 GiB. It used
16 native workers in one lane and a 1,048,575-step shard limit. Each row is one
observation. Archive commit d1934ae1ecd35a6952069d267acce696e8c460c5
provides the qualified D2 native and M7 recursive benchmark route. The proof
profile targets 128-bit security under documented assumptions. The maintained
OP product currently exposes native proving.

| Chain and block | RV64 steps | Native s | Recursion s | Root verification s | Total s |
|---|---:|---:|---:|---:|---:|
| OP 120,794,432 | 796,520 | 7.21 | 50.83 | 4.08 | 62.11 |
| OP 121,049,889 | 5,501,937 | 31.85 | 186.59 | 17.17 | 235.61 |
| OP 121,057,303 | 5,928,533 | 36.12 | 237.56 | 19.24 | 292.92 |
| OP 121,003,241 | 15,681,272 | 97.94 | Disk guard | — | — |
| OP 121,135,704 | 20,087,994 | 129.99 | Time cap | — | — |
| Mantle 103,132,217 | 3,237,854 | 15.82 | 83.60 | 6.49 | 105.91 |
| Mantle 103,132,921 | 3,264,567 | 17.02 | 136.57 | 10.63 | 164.22 |
| Mantle 103,133,561 | 3,279,437 | 17.01 | 138.56 | 6.23 | 161.81 |
| Mantle 103,133,753 | 10,253,419 | 47.84 | 200.12 | 17.27 | 265.22 |
| Mantle 103,133,433 | 11,534,260 | 60.57 | Time cap | — | — |

All ten native proofs and seven recursive roots passed fresh verification.
The two time-capped recursive producers ran for five minutes. The disk
guard retained a 10 GiB floor. The receipts, per-stage and guest data, and
shareable report remain in the operator evidence bundle
`opstack-cpu-benchmark.zip`, outside the source tree.

Recursion accounted for a median 81.1% of accepted wall time. Leaf wraps
and parent folds summed to 572.1 s and 411.2 s respectively. Across the
native cohort, lookup GKR took 102.1 s and composition evaluation 75.6 s.
Gas alone gave 54.1 s leave-one-block-out error for native wall time, versus
7.9 s for RV64 steps and 4.5 s after adding SHA-256 and Keccak counters.
The richer fit transferred poorly in whole-chain holdouts.

## Larger shard results

The larger-shard arm uses the same D2/M7 executables, inputs, guests, workers
and watchdogs. It raises the limit to 4,194,303 steps. The optional
one-proof-per-service-family arm uses the existing geometry planner. Each
row includes fresh root verification.

| Chain and block | Service grouping | CPU / service shards | Native s | Recursion s | Root verification s | Total s |
|---|---|---:|---:|---:|---:|---:|
| OP 121,049,889 | One per family | 2 / 4 | 33.32 | 99.48 | 10.12 | 142.92 |
| OP 121,057,303 | Baseline | 2 / 7 | 28.57 | 111.17 | 11.50 | 151.24 |
| OP 121,057,303 | One per family | 2 / 5 | 33.94 | 107.85 | 10.12 | 151.91 |
| OP 121,135,704 | Baseline | 5 / 6 | 121.22 | 205.26 | 23.82 | 350.30 |
| OP 121,135,704 | One per family | 5 / 4 | 105.60 | 159.80 | 18.84 | 284.25 |
| Mantle 103,133,753 | Baseline | 3 / 2 | 38.27 | 75.72 | 9.04 | 123.02 |

The Mantle contract-creation block took 53.6% less time through its fresh
receiver. OP 121,057,303 took 48.4% less time. On OP 121,135,704 service
grouping saved another 18.9% relative to the matching 4M-step run. Its
capped 1M-step control already spent 430 s before root verification, so
it provides a lower bound on the elapsed work and no completed baseline.
Grouping also reduced the number of service shards on 121,057,303 but its
native producer took longer and overall latency did not improve.

The opt-in [16-worker preset](../../tools/opstack/presets/cpu-16workers-single-lane.json)
uses the trial's component admissions and native schedule. Native and
recursive producers were separately guarded at 24 and 46 GiB RSS and a
10 GiB free-disk floor. The largest accepted 4M-step grouped run peaked at
35.71 GiB sampled RSS during recursion. The preset is a native resource
configuration. The recursive runs retain their archive binary provenance.

## Performance gates

Start with independently pinned OP and Mantle inputs from this cohort. Keep
the security profile and expected execution output fixed. Measure changes
in segment size separately from changes to guest instructions or recursion
kernels. Record native and recursive proof counts, peak memory, proof bytes,
and cold receiver time. Every successful arm needs fresh root verification
and the selected corruption controls. Compare common inputs through the same
stages including failures. Establish a bounded complete result for the large
inputs before extrapolating the speedup to them.

These measurements cover L2 execution. An SP1 replacement also needs anchored
L1 derivation, chain-specific data availability, adjacent range aggregation,
and a practical settlement verifier. Track the performance work and acceptance
criteria in [issue 491](https://github.com/starknet-innovation/stwo-zig/issues/491).
