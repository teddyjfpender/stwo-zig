# Build-monorepo performance baseline epoch 2 amendment

**Status:** DEFERRED; this is a future autoresearch goal and is not an
architecture BG-14 or BG-15 prerequisite.

**Scope:** This document preserves the proposed evidence contract for a later
autoresearch goal. The operative
[Zig build-monorepo delivery goal](2026-07-19-zig-build-monorepo-delivery-goal.md)
requires only static, fail-closed performance-harness readiness. It does not
require this capture, a performance comparison, or a performance threshold.

## Reason

The immutable v1 receipt at `conformance/build-monorepo-baseline-v1.json`
correctly preserves the pre-migration build surface, aggregate artifact,
proofs, and one three-sample smoke comparison. It does not contain all of the
denominators proposed for the future autoresearch promotion gate:

- focused-equivalent Native CPU and Metal performance samples;
- paired Hodges-Lehmann confidence intervals;
- peak proof memory;
- RISC-V cold and warm build measurements;
- focused binary and link-surface comparisons; and
- the complete reference-host and trusted-bundle state for the RISC-V gate.

The smoke row is explicitly non-promotion evidence. Treating it as a formal
performance baseline, or manufacturing missing fields from the migrated tree,
would be invalid. The future autoresearch goal remains `NO-GO` until the epoch
defined here has been captured and validated; the architecture goal does not.

## Unchanged authority

The historical baseline remains immutable:

```text
repository: https://github.com/teddyjfpender/stwo-zig
commit:     c1c70db5d8846183e36edcfd9a21c28fafc1c098
tree:       7bbe343342db578dc5ff8e1d9ed2ebec3d2ed06e
receipt:    conformance/build-monorepo-baseline-v1.json
```

Epoch 2 re-executes that exact commit from a detached clean worktree. It does
not substitute the current implementation, rewrite v1, or infer measurements
from old dashboard summaries. The candidate is a second clean worktree at the
single commit seeking independent performance-promotion approval.

The v1 statistical authority remains unchanged:

- round-level alternating `AB`/`BA` pairing;
- Hodges-Lehmann Walsh-average location;
- deterministic 95% percentile-bootstrap confidence interval;
- 4,000 bootstrap resamples;
- workload-ID-derived seed; and
- at least three paired rounds.

`A` always means the exact historical commit. `B` always means the candidate.
The role assignment is never selected from observed timing.

## Required artifact

The capture writes one immutable
`build-monorepo-performance-baseline-v2` receipt and a content-addressed raw
bundle. The receipt is committed only after independent validation. It binds:

- this amendment and the v1 receipt by SHA-256;
- baseline and candidate repository, commit, tree, and clean state;
- exact ordered commands and executable SHA-256 values;
- Zig, Python, Rust, SDK, OS, kernel, CPU, GPU, memory, filesystem, power,
  thermal, and runner identities;
- local and global cache directories and their initially empty state;
- raw stdout, stderr, proof, verifier, timing, and resource artifacts;
- every workload descriptor, numerator, trace shape, protocol, and security
  parameter;
- per-round execution order and samples;
- comparator source and policy digests;
- calculated ratios, confidence bounds, and budget verdicts; and
- all excluded, failed, retried, or interrupted attempts.

Unknown fields, duplicate JSON keys, missing raw artifacts, non-finite values,
or a digest mismatch fail validation. A failed attempt remains in the bundle
and cannot be silently replaced.

## Host sessions

### macOS session

One macOS Metal reference session captures:

- baseline aggregate Native CPU and Metal binaries;
- candidate focused Native CPU and explicit Native Metal binaries;
- candidate aggregate CPU compatibility binary;
- CPU and Metal benchmark baskets;
- cold and warm build measurements;
- peak proof memory;
- final binary sizes and `otool -L` surfaces; and
- Metal device, SDK, runtime, shader-source, and AOT identities.

The session is invalid if either worktree is dirty, the machine changes power
source, meaningful thermal throttling is observed, a profiler is attached, or
unrelated sustained work overlaps a measured round.

### Linux session

One Linux reference session captures:

- baseline aggregate Native and RISC-V CPU paths where the old tree supports
  them;
- candidate focused Native CPU and RISC-V CPU host/static products;
- cold and warm focused build measurements;
- final ELF, dynamic-link, and static `PT_INTERP` surfaces;
- peak proof memory; and
- the exact trusted Stark-V bundle identity used by the bounded challenge.

The absolute RISC-V requirements remain at most 60 seconds for a cold static
focused build, at most 2 seconds for a warm no-op build, and at most 180
seconds for the complete hosted challenge. An unavailable historical focused
step is recorded as `not_present_in_baseline`; it is not converted to zero or
used as a relative denominator.

## Build capture

Baseline and candidate use separate initially empty local and global Zig cache
directories. Every measured product records:

1. one cold build from empty caches;
2. one immediate warm no-op build using only that product's caches;
3. the installed-file manifest;
4. executable or library-object digest and bytes;
5. dynamic or static link closure; and
6. whether any unrelated product source was compiled.

The candidate Native CPU and RISC-V CPU focused cold builds must not be slower
than the comparable historical aggregate build. The absolute RISC-V limits
apply even when no focused historical denominator exists. Warm builds must not
construct or rebuild an unrelated product.

## Proof-performance basket

The Native basket is the six canonical functional workloads from
`scripts/native_proof_matrix_lib/model.py`:

| AIR | Parameters |
| --- | --- |
| `wide_fibonacci` | `log_n_rows=10`, `sequence_len=8` |
| `xor` | `log_size=10`, `log_step=2`, `offset=3` |
| `plonk` | `log_n_rows=10` |
| `state_machine` | `log_n_rows=10`, `initial_x=9`, `initial_y=3` |
| `blake` | `log_n_rows=8`, `n_rounds=2` |
| `poseidon` | `log_n_instances=13` |

Each lane uses the functional protocol, at least 10 excluded verified warmups,
and at least 10 measured verified proofs. Every measured proof must be locally
verified, byte-stable within its lane, equal across CPU and Metal where the
protocol promises deterministic bytes, and accepted by the pinned Rust Stwo
oracle.

The historical aggregate executable and candidate focused executable may have
different identity envelope schemas. The comparison normalizes only the
documented ownership provenance. It does not normalize proof bytes, statement,
trace geometry, security parameters, timing stages, runtime preparation, or
verification policy.

Metal fallback counters are recorded for both revisions. Historical fallback
does not invalidate the timing denominator, but the candidate cannot publish a
Metal headline or pass the future Metal performance lane with any CPU fallback
in a Metal-labelled warmup or sample.

Runtime modes are compared only like for like. If the historical executable
supports source JIT but has no equivalent authenticated AOT path, the
non-regression ratio uses source JIT on both revisions. Candidate AOT receives
separate correctness, identity, no-runtime-compilation, and absolute timing
evidence; it does not claim a speed ratio against historical source JIT. AOT
becomes a relative performance epoch only after an overlapping AOT calibration
receipt exists.

## Paired execution

For each host, backend, and workload:

1. perform the declared warmups outside measurement;
2. derive the first order from the workload ID;
3. alternate complete `AB` and `BA` rounds;
4. collect at least three paired rounds and the policy sample count per round;
5. cool down for the fixed policy interval between invocations;
6. independently verify every proof before accepting its timing; and
7. record process wall time, complete proof-request stages, and peak RSS.

No early stopping rule is introduced by this amendment. Retries are permitted
only for a classified infrastructure failure and are retained in evidence.
Timing out, proof failure, oracle failure, nonzero Metal fallback in the
candidate, or resource-collector failure is a product failure.

## Verdicts

For every unchanged CPU and Metal row, compute the paired ratio:

```text
candidate throughput / baseline throughput
```

The lower bound of its 95% Hodges-Lehmann confidence interval must be at least
`0.97`. Candidate peak proof memory must be no more than `1.05` times baseline
for the same row. Candidate link and binary surfaces must contain no unrelated
frontend/backend growth.

The receipt also reports request-time throughput and cold initialization, but
those diagnostics do not replace the complete proving-throughput verdict.
Every row passes independently; averages cannot hide a regression.

## Enforcing gates

The implementation must add one repository-owned capture controller and one
independent validator. The validator must test at least these mutations:

- replace baseline or candidate commit/tree;
- swap `A` and `B` after observing results;
- delete or reorder a paired round;
- alter a workload descriptor or numerator;
- change a proof, verifier, executable, or raw timing digest;
- omit a failed attempt;
- substitute host, SDK, Metal runtime, or trusted bundle;
- convert a CPU fallback into a Metal dispatch;
- change the comparator source or statistical policy; and
- recompute the unkeyed receipt digest after any mutation.

The future autoresearch promotion runner consumes the validated epoch-2
receipt. It does not implement a second statistical policy. Missing macOS or
Linux evidence, any mutation, or any failed budget keeps that future
performance promotion `NO-GO`; it does not block architecture BG-14 or BG-15.

## Completion

After a separate autoresearch goal explicitly activates this amendment, that
goal is complete only when:

- the exact historical commit and candidate were measured on their allocated
  hosts;
- the raw evidence bundle and v2 receipt pass the independent validator;
- every build, throughput, memory, and link budget passes;
- the protected autoresearch workflow binds the receipt digest; and
- the same candidate receives its independent performance-promotion receipt.

Until then, v1 remains valid historical evidence and performance promotion
remains `NO-GO`. Repository-architecture completion is decided independently.
