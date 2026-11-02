# GKR route: compact decode + conjectured128 profile, measured

Block 24,628,607, V3 GKR route (`rv64-word16-ethereum-gkr produce-candidate`),
evmone v3 client, native jobs from the #310 GKR driver recipe
(`request-gkr.json`, `resources.json`: 2 lanes x 8 workers, park MAIN,
deferred local binding, 12 GiB fixed setup). 14-core M4 Max, 36 GB, AC power,
memguard, no other heavy job running. Binary: this branch at `16f9fc378`
(ReleaseFast), `STWO_ZIG_PROFILE_OM_DOMAIN=1`, `profile_stages=true`.
Single runs; wall deltas below ~5% are noise, core-seconds are the stable metric.
Phase split: `vectors/reports/rv64-v3-gkr-perf-20261102/gkr_phases.py RUN LOG`.

| | `pv4`: proven beta2/q256/P0 + compact | `cj4`: conjectured128 b2/q108/P20 + compact | delta | `cjfull`: complete block, conjectured128 |
|---|---:|---:|---:|---:|
| Packets / steps | 4 / 16,777,212 | 4 / 16,777,212 | | 7 / 26,894,777 |
| CPU + truth proofs | 4 + 8 | 4 + 8 | | 7 + 11 |
| **Prove (wall)** | **59.30 s** | **50.64 s** | **-14.6%** | **73.98 s** |
| Process wall / user-s | 68.82 / 556.2 | 57.69 / 455.3 | -16% / -18.1% | 84.08 / 682.3 |
| Recorded stage core-s | 462.1 | 389.8 | -15.6% | 582.3 |
| Committed trace cells (MAIN + INTER) | 1,741 M + 1,229 M | same | 0 | 2,695 M + 1,863 M |
| LDE cells (x blowup) | 11.88 G | 5.94 G | -50% | 9.12 G |
| Proof bytes (CPU + truth + stage-one) | 68.80 MB | 31.33 MB | **-54%** | 51.45 MB |
| Peak RSS (max resident / footprint) | 22.96 / 26.64 GB | 22.95 / 26.51 GB | ~0 | 24.39 / 27.83 GB |
| Fresh verify (verify_ns) | 0.929 s | 0.665 s | -28% | 0.865 s |
| Fresh receiver process wall / setup | 8.11 / 7.14 s | 5.65 / 4.96 s | | 8.19 / 7.29 s |

`cells.bin` (41.9 MB public cell file) is the same in both prefix runs and is
not a proof. Peak RSS does not drop: it is set by the CPU-side GKR/global
budgets and retained-frontend buffers, not by the LDE (see the GPU plan).

Per-phase core-seconds (recorded stages):

| Phase | pv4 | cj4 | cjfull |
|---|---:|---:|---:|
| CPU witness | 6.8 | 6.8 | 11.0 |
| Local GKR prove | 80.0 | 80.6 | 133.2 |
| MAIN LDE / Merkle | 22.6 / 35.1 | 13.9 / 15.8 | 21.2 / 24.6 |
| GKR binding finalize | 5.3 | 5.3 | 9.4 |
| Interaction gen / LDE / Merkle | 16.7 / 15.7 / 25.8 | 17.2 / 9.6 / 12.1 | 25.4 / 14.2 / 17.9 |
| Composition evaluation | 130.4 | 129.1 | 196.5 |
| Composition interpolate / commit | 1.3 / 15.0 | 1.3 / 7.9 | 1.8 / 10.9 |
| OODS sampled values | 11.0 | 11.3 | 17.2 |
| DEEP quotients + FRI commit | 75.4 | 67.9 | 83.0 |
| Proof of work | 0.0 | 0.0 (0.15 s wall) | 0.0 (0.11 s wall) |
| FRI / trace decommit | 4.1 / 16.7 | 2.0 / 8.8 | 3.0 / 13.1 |
| Retained-MAIN spill (wall, ~0 core) | 5.65 s | 5.00 s | 8.71 s |

DEEP/FRI falls only 10%: the CPU proofs' DEEP/FRI halves (62.1 -> 35.6 core-s),
but the Keccak truth's lazy quotient build rose from 6.6 to 27.8 core-s on the
prefix (16.8 on the complete block). The Keccak truth is the critical-path proof
(22.3 s wall in both prefix runs); this regression at rate 1/2 is the first
thing to investigate.

Files: `*.phases.json`, `*.report.json`, `*.time`, `*.fresh-receiver.{json,time}`,
`*.sha256` (artifact hashes; proofs not committed), `*.candidate-source-bounds.json`,
`cjfull.bundle.json`, `conjectured128-model.json` (exact-rational conjectured
accounting on the complete compact conjectured bundle; `model.py ... --security-profile
conjectured128_b2_q108_p20_fold4`), `conjectured128-model-parameters-only.json`
(same on the #310 reviewed envelope), `profile-compatibility.log`.

Profile compatibility (`profile-compatibility.log`): each fresh receiver accepts only
its own profile's bundle (cross-profile receivers reject with
`GlobalGkrManifestExecution`). The proven profile is byte-identical to the
pre-change merged binary (`bcdc06b7e`): all 13 proof files, `cells.bin` and
`bundle.json` equal on the same jobs, and that binary accepts this branch's proven
bundle. The unmerged experiment bundle `gkrperf/cmp4` (branch
`codex/rv64-ge-gkr-v3perf` on #310) is rejected by both the pre-change merged binary
and this branch (`InvalidSumcheck`), and the v3perf binary rejects `pv4`: the merged
compact-on-GKR transcript differs from that experiment's. This does not come from
the profile change, and no main-line compact-on-GKR bundle exists from before this branch.

Security: see `design/riscv-proving-stack/rv64-gkr-conjectured128-profile.md`.
Conjectured FRI bits 128 (1·108 + 20); OM31 algebraic union 2^-196.9; per-RO-query
success 2^-127.6 for T <= 2^120. `security_qualified=false` for both profiles.
