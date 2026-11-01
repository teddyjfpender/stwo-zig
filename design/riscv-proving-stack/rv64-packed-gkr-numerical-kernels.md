# Packed GKR numerical kernels

This slice reuses the numerical organization of Stwo's SIMD backend at upstream commit `826591c6c`, especially `backend/simd/lookups/{gkr,mle}.rs`. The earlier Zig lookup implementation followed the CPU reference, with scalar arithmetic inside pooled ranges. The new helper applies the existing native-width `PackedQM31` and `PackedOM31` field authorities across independent rows.

The packed paths cover GrandProduct and all three LogUp layer kinds, adjacent-pair tree reduction, the oracle's eq-weighted evaluations at zero and two, half-split MLE challenge folds, and Eq-table scaling. M31 multiplicities retain their signed/canonical base-field encoding and use packed secure-by-base products. Helpers transpose one native pack from the existing scalar owners, so this does not introduce a new column representation or a full-sized transpose buffer. AArch64 has four native row lanes; this is not a claim of16-lane hardware.

The original allocator ownership and output buffers remain. Existing scoped-pool partitions and nonblocking lease/fallback rules remain; next-layer destinations now use the same bounded range helper. Packed arithmetic consumes only a prefix of any requested range; the original scalar formulas cover short ranges and the tail. Inputs are immutable and outputs separate, including MLE folds, so no adjacent-pair in-place aliasing is introduced. No new heap scratch, cache or pool is created.

The tests compare packed numerical results against independent scalar formulas for every gate kind, secure and M31 numerators, zero/negative/count weights, misaligned starts and partial packs. The full lookup ownership/allocation-failure suite passes in Safe and Fast. A pinned archive of the pre-change source proves the same four mixed-height gate instances: complete Q/OM proof serializations and the next transcript draw are exact under1/2/4/8worker schedules, with fresh terminal-MLE binding checks. The direct capture passes32tests.

A shared-host micro run of five65,536-term LogUp-multiplicity oracle evaluations measured3.67× for Q and3.89× for OM. The small complete-proof fixture remained approximatelyflat at one worker. Therefore these results qualify the hot numerical kernels and byte parity, not a block-level speedup. Production prefix/full-block profiling is required after integration.

There is a separate constant-cost issue: the current generic four-point Lagrange interpolation performs12secure divisions and heap polynomial construction per sumcheck round, in addition to two inversions in the correction formula. That can hide numerical-loop improvements in small fixtures. It is deliberately left unchanged here so the packed slice has a narrow correctness boundary.

Raw commands, logs and the exact qualification scope are in `vectors/reports/rv64-packed-gkr-20261101/`.
