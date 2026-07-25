---
title: Native CUDA wide-Fibonacci throughput baseline
author: Teddy Pender
created_utc: 2026-07-25T07:15:13Z
---

# Locked `log22 x 100` Native CUDA baseline

## What the number means

The locked architecture verdict records `79.473593 ms` for the candidate's
warm verified request on `extreme_wf_log22x100`: a `2^22`-row,
100-committed-column Native wide-Fibonacci proof. Thus:

```text
trace rows       = 2^22 = 4,194,304
committed cells  = 4,194,304 * 100 = 419,430,400
row MHz          = 4,194,304 / 0.079473593 / 1,000,000
                 = 52.776071
committed cells/s = 419,430,400 / 0.079473593
                  = 5,277,607,117
```

Rounded for reporting, the baseline is **52.78 row-MHz** and **5.277 billion
committed cells/s** (equivalently 5,277.61 committed-Mcells/s). Here MHz means
millions of workload units per second, not GPU clock frequency. Wide Fibonacci
uses one trace row as its native useful unit, so useful/native MHz and row-MHz
are numerically equal for this regular single-height workload. For Cairo, useful
MHz normally means adapted Cairo cycles per verified second; that is a different
unit and cannot be compared numerically without a complete per-component work
model.

The `79.473593 ms` field is specifically `candidate_verified_ms`. It is a
verified-request latency produced by the resident proving architecture, not a
device-critical-path or resident-only timer. The retained qualified verdict
does not expose a separate resident-only value for that same run, so the number
must not be relabelled as kernel time.

## Eligibility and provenance

The authoritative repository record is
[`autoresearch/notes/2026-07-24-cuda-system-architecture/verdict.json`](2026-07-24-cuda-system-architecture/verdict.json),
added by evidence commit
`8c865721985e74265e018ac0183088bf97365a4f`. It binds:

- candidate source `a49a389de5cf9c40305b521b9f18747bdb999887`;
- candidate binary SHA-256
  `b7115a64c116c21f70b8f48e4d038ed658441b56babed3819c24b5e27f222d51`;
- RTX 4090 / SM89 / driver `580.126.09`;
- seven same-host counterbalanced A-B-B-A rounds, with ten warmups and five
  verified samples per process;
- canonical proof SHA-256
  `2c0ca9f7a73ea80f4cc32f2e27785f9ccf6b11dc460a133ebc8f5cc441e76205`;
- byte-identical arms, independent Zig verification, pinned Rust verification,
  zero CPU fallbacks, one terminal D2H, and graph/direct parity.

The raw judge report is not checked into this tree. The verdict binds it by
SHA-256
`e796fa27e01d636c06bc2c0f1e43cbba5bffac9b32872ac1bba90549a61e5ebd`;
consequently the repository supports the qualified median and aggregate gates,
but not a fresh audit of that report's per-sample or per-stage data.

Do not substitute
[`conformance/evidence/cuda/system-architecture-sm89/structural-screen.json`](../../conformance/evidence/cuda/system-architecture-sm89/structural-screen.json).
That source-bound artifact was added by
`d07abb6bddd61c1d591c9db33a312b2fd2c3ee23` and records an earlier diagnostic
checkpoint at about `322.76 ms` verified. It is useful evidence for the timing
boundary and residency counters, but it is not the source of the locked
`79.47 ms` result.

## Why this is not an SN PIE latency estimate

This row is a shared-prover throughput canary: 100 uniform columns over a large
domain heavily exercise the reusable circle-transform, commitment/Merkle,
quotient, FRI, opening, transcript, and proof-publication path. A nearby
`log20 x 100` diagnostic profile in
[`conformance/evidence/cuda/system-architecture-sm89/profiling/receipt.json`](../../conformance/evidence/cuda/system-architecture-sm89/profiling/receipt.json),
retained by `c2a3c65112705a7809bbb10afdae6e1db5c65b59`, confirms that shared
transform and hash kernels dominate that geometry. That profile is explicitly
diagnostic and is not used to alter the locked result.

The baseline is not a pure PCS microbenchmark: it still includes Native
wide-Fibonacci witness and constraint work. More importantly, an SN PIE request
also includes PIE decode and validation, public-statement binding, construction
of many Cairo components at distinct heights, interaction witnesses and
lookups, Cairo-specific constraints and hashes, proof encoding, independent
verification, and publication. The Native verdict proves none of the four
canonical SN PIEs and supplies no Cairo adapted-cycle latency.

Therefore `79.47 ms`, `52.78 row-MHz`, and `5.277 billion committed cells/s`
are a locked shared-backend capacity reference and Native regression canary.
SN PIE performance becomes eligible only after its own complete exact-proof,
pinned stwo-cairo oracle, authenticated-AOT, zero-fallback, one-terminal-D2H,
and warm verified-request gates pass. No SN PIE latency should be extrapolated
from this baseline alone.
