# Canonical tree CPU leaf pool — 2026-09-24

## Change

The canonical four-leaf fixture now explicitly admits a CPU worker pool for each
pair's two leaf proofs and recursive witness preparation. Previously this helper
passed no pool, while only its Metal aggregate workers received the configured
worker count. The pool is scoped and destroyed before proving the aggregate; this
is sequential branch execution, not concurrent tree scheduling. Configured worker
count is not a measurement of continuous worker utilization.

Ownership transfers only after fallible pool initialization and binding succeed.
Failures before transfer retain the existing cleanup owners. The diagnostic q8/PoW0
branch is unchanged. Phase receipts now separate leaf-pair proof/preparation,
aggregate proof with independent artifact checks, and root preparation. These
phase clocks exclude some fixture setup, negative checks and cleanup, so their sum
is not complete end-to-end latency.

This is a qualification/benchmark harness correction using the existing production
pool interface. It does not introduce a new scheduler default or change proving
parameters. Four compact-range CPU leaves and three Metal aggregates all retain
70 queries and 26 PoW bits, covering four adjacent segments and six guest cycles.

## Verification and measurement

The targeted ReleaseFast authenticated-AOT tree target passes all seven checks.
Each aggregate undergoes independent fresh-codec verification. Wrong-key, alias,
span adjacency, consuming-owner failure and lifetime checks remain enabled.
Node artifact sizes remain 918,746 / 911,657 / 904,156 bytes. Size equality is not a
claim of byte-for-byte proof identity.

`measure.py` runs frozen executables sequentially in control/candidate/candidate/
control order, with the SMP allocator and eight configured workers. The control is
`../2026-09-24-canonical-aggregation-tree/tree-test`; both executables use the archived
AOT bundle in `../2026-09-24-canonical-parent-pipeline/core`. The driver asserts all
canonical parameter, verified-node, root-span and routed allocation-budget receipts.
It records executable SHA-256, process wall time, physical peak and maximum RSS.
No sample is discarded. This is a small two-sample-per-arm fixture comparison,
including initialization, negative checks, verification and cleanup, not the CSP
suite or bare root proving latency.

## Measured result

M5 Max, ReleaseFast, two runs per arm in ABBA order:

| Run | Arm | Complete fixture seconds | Peak physical GB |
|---|---|---:|---:|
| 1 | control | 127.002 | 45.187 |
| 2 | candidate | 72.384 | 44.892 |
| 3 | candidate | 72.181 | 45.153 |
| 4 | control | 129.426 | 45.187 |

Median complete fixture time falls **128.214 to 72.282 seconds**:
**43.6% less time, 1.77× speedup**. Both candidate samples are
faster than both controls. This measures explicit leaf pool admission in this tree
fixture; it is not an independent speedup of the recursive proof algorithm.
All four runs pass all seven checks and independently verify all three aggregates
(12 measured aggregate artifacts total), with unchanged canonical parameters and
artifact sizes. Routed peak is unchanged at 30,309,734,580 bytes under 48 GiB.
The maximum observed physical peak is essentially flat, 45.187 vs 45.153 GB.
These process peaks include backend/system allocations outside the routed budget.

Candidate phase medians:

| Phase | Seconds |
|---|---:|
| Left leaf pair + preparation | 9.636 |
| Left aggregate + checks | 12.826 |
| Right leaf pair + preparation | 9.612 |
| Right aggregate + checks | 13.107 |
| Root preparation | 12.110 |
| Root aggregate + checks | 14.309 |

The control predates phase receipts, so no matched per-phase attribution is claimed.
The aggregate phases include key derivation, worker setup, proof, encoding and
independent checks. They are not bare proof times. Remaining recursive cost is
substantial despite correcting leaf parallelism.

## Evidence and reproduction

`qualified.log` contains the successful qualification. `tree-test-source.zig` and
`changes.patch` pin this change against the preceding tree checkpoint. The archived
executables and AOT bundle enable rerunning the comparison with:

```sh
python3 autoresearch/notes/2026-09-24-tree-leaf-pool/measure.py
```

This is a dirty-worktree checkpoint; its source snapshot alone is not a complete
clean-checkout reproduction of all dependencies. The evidence manifest covers the
local files; the control and AOT dependencies have their own earlier manifests.

Full CSP baseline recovery, materially faster recursive parents, persistent bounded
tree scheduling, further effective fusion/direct emission, and the separately
reviewed recursion parameter experiment remain open. Neither a tenfold speedup
nor subsecond recursion is established.

## Next bottleneck investigation

Root preparation includes two child-verifier witness preparations, namespace
planning/rebasing, final column joining, and temporary-owner teardown. The current
phase receipt cannot attribute its cost between those operations. The join writes
columns through committed-row permutations and the rebase performs repeated
identifier passes; both are candidates to measure, not established bottlenecks.
The existing `STWO_RISCV_PARENT_PREPARATION_PROFILE` can separate each child's
preparation from the encompassing root phase without changing the protocol.
Further changes should retain disjoint namespace admission, preflight-before-write
failure behavior, exact logical/padded row equivalence, and next-level qualification.
