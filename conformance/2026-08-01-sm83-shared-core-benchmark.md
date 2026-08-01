# SM83 shared-core benchmark diagnostic

**Captured:** 2026-08-01

**Host:** Apple M5 Max, 18 cores, 64 GiB, macOS

**Power:** battery, discharging, Low Power Mode enabled

**Mode:** `ReleaseFast`, warm Zig cache, `-j1`, three alternating samples

**Baseline:** `a20eb1e8923a10c049f19d0b2b6f5302951c7936` (SM83 merge, PR #172)

**Candidate:** `7e2a418974b64fb4085eb55a40f42b36e783f1dc` (optimized main, PR #177)

This is a local diagnostic, not a publishable performance receipt. It answers
whether the shared prover and Metal changes merged after the SM83 frontend also
benefit SM83 without changing SM83-owned source. The two revisions have no diff
under `src/frontends/sm83`, `src/integrations/sm83_cpu`, or
`src/integrations/sm83_metal`; all measured changes therefore come from shared
dependencies or runtime behavior.

Every warmup and measured command passed.

## Results

Lower is better. Delta compares each backend and test portfolio only with its
identical baseline portfolio.

| Portfolio | Baseline samples (s) | Candidate samples (s) | Median | Delta |
| :--- | :--- | :--- | ---: | ---: |
| CPU/SIMD package proof suite | 32.44, 32.28, 32.65 | 32.44, 32.63, 32.80 | 32.44 → 32.63 | +0.6% |
| Metal package proof suite | 8.54, 8.63, 8.69 | 7.73, 7.87, 7.82 | 8.63 → 7.82 | **−9.4%** |
| CPU/SIMD v7 machine-environment gate, 16 rows | 22.91, 23.00, 23.03 | 23.04, 23.13, 23.08 | 23.00 → 23.08 | +0.3% |
| Metal v7 machine-environment gate, 16 rows | 1.60, 1.58, 1.61 | 1.27, 1.27, 1.28 | 1.60 → 1.27 | **−20.6%** |

The CPU movement is within local run-to-run noise. The Metal gains are large
and consistent across all three samples, including the same 16-row v7 trace
geometry.

## Interpretation boundary

The CPU and Metal wall times in different rows must not be divided to claim a
backend speedup. The package suites contain different test portfolios. The v7
CPU gate also performs two additional forged-proof verifications and a
poisoned-prepared-witness constraint check, while the Metal gate performs one
honest prove/verify and cheaper pre-proof mutations. The valid comparisons are
horizontal within a row: baseline versus candidate.

A publishable CPU-versus-Metal result needs one backend-neutral SM83 benchmark
driver that supplies the same prepared trace, PCS profile, prove count, verify
count, mutation policy, and receipt schema to both engines. That is the same
discipline already used by the RISC-V CSP matrix.

The external PE-AGI corpus was not present on this host, so this diagnostic does
not replace the pinned Pokémon checkpoint or battle receipts. In particular it
does not change the documented high-memory Metal frontier for the full battle.

## Commands

```sh
zig build test --build-file src/integrations/sm83_cpu/build.zig \
  -Doptimize=ReleaseFast -j1
zig build test --build-file src/integrations/sm83_metal/build.zig \
  -Doptimize=ReleaseFast -j1
zig build test-machine-environment \
  --build-file src/integrations/sm83_cpu/build.zig \
  -Doptimize=ReleaseFast -Dmachine-environment-log=4 -j1
zig build test-machine-environment \
  --build-file src/integrations/sm83_metal/build.zig \
  -Doptimize=ReleaseFast -j1
```
