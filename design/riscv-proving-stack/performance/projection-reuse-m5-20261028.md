# Eliminate exact duplicate relation batches: implementation and limit

The optional B6JP-v2 joint prover now proves identical native/companion relation
batches once. It omits the companion interaction columns and constraint when
the **entire signed rational function** is already proved by one native physical
batch. The independently selected verifier derives the same alias and requires
the transported companion claim to equal that native physical claim. Original
native equations, both physical-claim transcript bindings, other projections,
RAM integer/byte bridges and scoped global accounting remain unchanged.

Code: `ef3a97c218c076edbf6c8fd4829edc084a5adde2`, on
`codex/ethereum-block-fast-lab`. Default standalone and B6JP-v1 routes are
unchanged. This is an experimental local joint proof, not a new accepted block
root, recursive key, artifact codec or CUDA implementation.

## Measurements and decision

Apple M5 Max, 64 GiB, eight workers, ReleaseFast; matched 5,123-cycle fixture,
two transcript seeds. Median of two observations is descriptive, not a stable
latency distribution. Diagnostic q8/PoW0 avoids random proof-of-work dominating
the comparison:

| Register custody / access | Separate proof phase | Joint v1 | Pruned joint v2 | Removed projection equations | Removed base-field interaction cells |
|---|---:|---:|---:|---:|---:|
| Global registers, RAM | 202.127 ms | 190.305 ms | 186.392 ms | 3 / 21 | 24,584 |
| Local registers, RAM | 135.275 ms | 129.530 ms | 120.190 ms | 6 / 29 | 45,072 |
| Local registers, no RAM | 92.089 ms | 86.636 ms | 79.689 ms | 6 / 29 | 40,976 |

That is approximately **2–8%** versus the unpruned joint proof and **8–13%**
versus the separate proof phase. It is not another order of magnitude.
The canonical q70/PoW26 cases also verify, but individual pruned timings span
0.104–1.020 seconds and include regressions; do not select their fastest seed
as a production speedup. Query sampling can also change serialized size, so
fewer interaction columns do not guarantee smaller bytes in every sample.

The [CSV](block-v6-projection-reuse-m5-20261028.csv) and
[JSON](block-v6-projection-reuse-m5-20261028.json) retain all 36 observations,
verification time, STARK-body bytes, seed, geometry and raw-log hashes.
`alias_cells` is eligible area; `removed_interaction_cells` is zero for
unpruned arms. No peak-memory measurement was taken. STARK bytes exclude
transported claims. Timers exclude runner/initial commitments, serialization,
hostile probes and teardown; this is not full-command or block latency.

**Decision:** retain as an explicit tested optimization, but stop spending the
architectural campaign on this limited intersection. Most native batches mix
relation kinds, whereas companion partitions preserve separate scopes. Full
elimination needs a single partitioned relation layout at initial AIR
construction, not heuristically dropping more companion equations.

That larger replacement must independently establish exact coverage of every
typed entry, including program requests, state changes, all table demands,
register and ordinary RAM effects, clock-gap terms and external callers.
Conditional load/store weights must be polynomial identities. Local-x0 custody
changes three weights per access and cannot inherit an unweighted alias.
Keep the integer/byte memory bridge and per-window register closure. One global
aggregate replacing those scoped checks is not an acceptable shortcut.

## Evidence and limitations

- Two 16-test selected runs passed, including standalone fused regressions and
  all three proof arms in both security profiles, both register modes and
  RAM/no-RAM cases. All exported native and companion receipts match exactly.
- Every opcode family is checked against original typed rational functions at
  extension-field points. Partial batches, duplicate ordinals, mixed domains
  and nonconstant register selectors cannot be aliased.
- Altered alias claims, cancelling changes to native physical claims,
  cancelling companion claims and the wrong independently selected protocol
  version are rejected by fresh verification.
- A final 11-test focused run passed after adding the explicit fail-closed
  guard for an all-aliased roster. Such a roster needs a new owner for the
  companion interaction tree; it is unsupported rather than silently omitted.
- Global providers remain open in this fixture. These checks do not qualify a
  complete Ethereum proof or transfer acceptance to existing recursive keys.

Reproduce the current three-arm qualification:

```sh
STWO_JOINT_ITERATIONS=1024 STWO_JOINT_SEED=2 \
  python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_joint_native_test_root.zig -OReleaseFast \
  --test-filter 'block-v6 pruned native and companion' \
  --test-filter 'block-v5 full fused' \
  --test-filter 'block-v6 projection aliases' > projection-reuse.log 2>&1
```

`projection-reuse-results.py` accepts the old seed-one diagnostic format and
the final seed-two format. It requires the complete matched basket and test
success; missing completion, duplicate arms and false global-closure labels
are rejected. Original joint-proof benchmark commands remain available under
their original test names and log format.
