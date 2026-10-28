# Cairo CUDA managed-capacity qualification on an L40S

This experiment tests whether the opt-in managed-capacity placement can prove
two Pedersen/EC-heavy canonical PIEs on an actual smaller GPU, then measures
the effect of putting trace-writer scratch in host-preferred managed memory
**before its first GPU write**. The GPU was an NVIDIA L40S with 46,068 MiB of
reported physical memory (48 GB decimal). Both runs used CUDA architecture
89, Zig ReleaseFast, pinned canonical preprocessing, 70 queries, and 26 query
PoW bits. The only source difference between the paired runs was the early
scratch-placement call in `proof_session.zig`.

| PIE | Policy | Publication (s) | Full command (s) | Sampled whole-device peak (GiB) | Exact proof / Rust verifier |
| --- | --- | ---: | ---: | ---: | --- |
| `15590913_15590913` | Coefficients before first write | 194.468 | 200.388 | 30.726 | match / pass |
| `15590913_15590913` | Plus writer scratch before first write | 219.442 | 225.772 | **19.474** | match / pass |
| `15582797_15582797` | Coefficients before first write | 207.825 | 212.847 | 26.849 | match / pass |
| `15582797_15582797` | Plus writer scratch before first write | 221.068 | 223.887 | **17.349** | match / pass |

Within the same card and inputs, early scratch placement cut the sampled HBM
peak by 36.6% and 35.4%, with publication time increases of 12.8% and 6.4%.
The earlier H100 capacity reference was 56.487/48.362 GiB before first-write
coefficient placement; cross-device times and memory peaks are **not** used as
an apples-to-apples speed comparison. This result establishes a real
less-than-48-GB-card proof for both PIEs. It does not establish the minimum
card size, an instantaneous peak bound, or performance on a consumer GPU.

The dense input SHA-256 is
`9d503fa0c6c818d8de84d3d71208df641bb62ec93e480687252128f698294bc3`;
its saved proof SHA-256 is
`23ef11f1f7bbf0b31d6ede197bd67d2548975b951283c4cedc0fb6148e443af9`.
The second input SHA-256 is
`319b538ff50ad8e04735886a7844de300198194a4cc2128dcb57bc625ec4e4cb`;
its saved proof SHA-256 is
`fcc457fee3bcaca85efd97d308daa1a16e849c633b4571144417543158eb1eeb`.
All four proof files matched these hashes and passed the pinned independent
Rust verifier. The large proof JSON files are not checked in; each run's
`summary.json`, `memory.csv`, `report.json`, `process.log`, and
`official-verdict.json` are retained here. The baseline runs are under each
PIE ID; the experimental runs are under `scratch-host/`.

The trace-writer scratch slot has 13,317,680,068 logical bytes for the dense
geometry and is live only during trace generation. The scratch policy raised
that stage from 12.01 to 43.30 seconds on the dense case, but avoided much
larger HBM residency. Physical arena addresses are reused across stages, so
the measured end-to-end impact, rather than the isolated writer time, governs
the decision to keep this capacity-only mode. The ordinary/throughput policy
does not set this host preference.

Device usage was sampled by the memory-trial helper, approximately every
250 ms; observed peaks are lower bounds on instantaneous maxima. Dense process
RSS reached about 85.38 GiB in both L40S runs. Managed-memory RSS is a host
accounting indicator, not a bound on required system RAM; the second PIE's
reported RSS changed sharply between runs even though its proof and input did
not. Host-memory capacity must therefore be qualified separately before
deploying this policy on a smaller-memory server. The Runpod pod was deleted
after collecting these receipts.
