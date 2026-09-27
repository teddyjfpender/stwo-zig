# Canonical four-leaf aggregation tree — 2026-09-24

## Qualified

The previous goal turn made progress: two dependent parent levels were qualified,
and a fusion that increased next-level work without a speed benefit was removed.
This checkpoint extends the existing real-segment tree fixture to canonical parameters
and an injected parent backend. **Four canonical CPU leaf proofs and three canonical
Metal aggregate proofs now independently verify**, combining two pairs and then their
root. All levels use 70 queries / 26 PoW bits.

The guest runs four adjacent segments covering six executed cycles, including memory
stores. Runner boundaries, admitted job/program/I/O, segment spans, namespace rebasing
and aggregation identities are preserved. The root asserts four segments, six cycles
and height two; both intermediate nodes validate after their captures have been used
to prepare the root. Leaf proofs are verified into captures. Each aggregate is encoded,
its original storage is released, and a fresh decoded artifact independently verifies
under the admitted key and span. Wrong-key decoded artifacts are rejected and consumed.

The canonical branch explicitly uses `Owner.initCompact` and the matching compact
prepared verifier, matching the current typed compact-range execution path. Existing
diagnostic q8/PoW0 CPU tree behavior and its overlapping-root pipeline remain separate.
This change does not migrate the diagnostic test to weaker/stronger parameters silently.

`test-blake3-native-tree-aot` initializes the authenticated Metal runtime and runs this
canonical branch. Its missing/invalid-bundle wiring matches the other native qualification
targets. Parent workers are explicitly bounded and destroyed before artifact decoding.
The same test also preserves negative checks for wrong child keys, aliased children,
wrong phase/commitment admission, consuming-owner failure, and reversed adjacency.

## Result and limits

M5 Max, ReleaseFast, SMP allocator, eight workers for each parent:

| Aggregate | Height | Proof bytes | Queries / PoW bits |
|---|---:|---:|---:|
| Left pair | 1 | 918,746 | 70 / 26 |
| Right pair | 1 | 911,657 | 70 / 26 |
| Root | 2 | 904,156 | 70 / 26 |

**7/7 harness tests pass.** The successful test command reports approximately two
minutes for the run, with compilation reported separately, and `MaxRSS:42G`.
This is one qualification observation, including setup, negative checks, witness
preparation, proof and verification. It is not a warmed benchmark median or bare
root-proving latency. No prior-version speed comparison or artifact-hash equality
claim is made.

Tracked allocations peak at **30,309,734,580 bytes** under the whole-fixture
48 GiB (51,539,607,552-byte) routed allocation limit. Each parent worker additionally
has a 32 GiB routed allocation cap. Retained root rows total 5,110,278,888 bytes.
These caps exclude backend/system allocation overhead and do not enforce process RSS.
A live process sample is retained; it observed active Merkle witness generation,
not a blocked test.

This qualification proves aggregates sequentially to bound residency. It does not
establish concurrent branch proving, bounded-tree scheduling throughput, cross-job
plan reuse, or speed scaling. CPU leaf preparation still uses the existing helper's
unbound pool path; eight workers refers specifically to the parent workers. Explicit
leaf pool admission and phase profiling are useful next work before interpreting
this run as a performance baseline. The earlier chain and repeated-job pipeline
qualifications remain distinct evidence. This tiny tree does not qualify Ethereum
blocks or arbitrary large programs.

## Implementation and evidence

The shared tree fixture now takes a parent backend and an explicit canonical mode.
It derives canonical parent keys and uses bounded workers in that branch; the original
diagnostic path retains its existing plan/pipeline behavior. No production cryptographic
parameter or scheduler default is changed. The named Metal target calls the canonical
mode directly rather than inferring it from an environment variable.

The initial compile needed an explicit optional budget-pointer type. A subsequent
noncompact run was deliberately terminated after inspection showed it would qualify
the older noncompact leaf path. Both logs are retained and excluded from success.
The final compact qualification completed normally. Its binary, three changed source
snapshots, node receipts, live sample and raw log are retained and checksummed.
The archived binary uses the preceding canonical-pipeline checkpoint's authenticated
AOT bundle. This is a dirty-worktree checkpoint; these changed-source snapshots are
not a complete clean-checkout reproduction of every dependency.

```sh
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
```

Canonical four-leaf correctness is now demonstrated for this fixture. The full goal
still requires effective persistent/bounded scheduling, materially faster recursion,
further fusion/direct witness emission, full CPU/Metal CSP recovery, and the separately
reviewed recursion-parameter experiment. No subsecond or 10x result is established.
