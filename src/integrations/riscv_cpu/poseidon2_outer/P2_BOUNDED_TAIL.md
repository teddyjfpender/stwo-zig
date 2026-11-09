# Native P2 bounded-tail dispatch repair

The heavy conditional CPU profile identified MAIN+INTER commitment as the
largest stage. Source inspection found two independent implementation gaps:

- `pcs/scheme_family.zig` enabled `reuse_bounded_merkle_tail` by default only
  for Blake3 and supported Blake2 hashers. The native P2v2 workers did not set
  an override. Once the final state layer exceeded the unchanged 96MiB cap,
  `tree_builders.zig` therefore selected the non-reusing bounded-prefix route.
  Low-height tail columns were replayed at final-height multiplicity.
- Both `finalizeBoundedTailRange` and the reused path's final-height batch
  dispatched four independent messages only through `blake2_stream4`. P2's
  existing `H.updateM31Columns4` and `H.finalize4` APIs were unused there,
  although the ordinary `leaves.zig` path already supported them.

The fix uses those existing native-four APIs in both bounded tails. The
non-reusing path gathers at most64 columns ×4 rows, preserving the exact
lifted parity/source-index mapping in temporary column views. The reused path
continues its existing two-parity cache at each lower height and sends its
final-height adjacent rows directly through native-four updates. Remainders
keep the scalar path. No full-height hasher or complete-row slab is allocated.
The explicit caller workspace is included in the separate stack-cache telemetry
(which does not bound helper call frames or compiler spills);
the existing leaf-phase metric remains heap-only.

The default predicate now adds only the exact `Poseidon2M31MerkleHasherV2`
type. Other generic hashers, the older P2 suite and all existing Blake defaults
retain their previous choices. Hash arithmetic, domain, field/profile, roots,
wire, transcript, constraints, source authority and the 96MiB cap do not change.
Protected R5 files and core Poseidon implementations are untouched.

Focused ReleaseSafe gates compare every Merkle layer with an independent
scalar hasher, using equal-height and three-height mixed columns, one/three
worker pools, seed-only/partial/full prefix budgets, and instrumented four-lane
update/finalize calls. Three workers exercise non-four-aligned ranges on the
qualification host. A separate 4MiB shared-heap test checks prefix-cap refusal,
bounded state/leaf accounting and final zero heap/external ownership.

A single-worker log16 microprobe uses66 columns at logs10/12/16 (31/19/16
columns) and a208-byte seed-only prefix budget. The scalar control preserves
packed internal-node hashing so the comparison isolates leaf dispatch/replay.
The source data and36-byte root are identical:

| Path | Wall | Tail absorptions | Repeated tail absorptions |
|---|---:|---:|---:|
| Scalar bounded tail | 489.1ms | 4,325,376 | 3,167,232 |
| Native-four bounded tail | 165.2ms | 4,325,376 | 3,167,232 |
| Native-four with prefix reuse | 93.85ms | 1,158,144 | 0 |

This is about2.96×/5.21× for this **synthetic microprobe**, not a quiet matched
heavy/native proof benchmark. The heap-only leaf peak stays exactly2,359,504
bytes; bounded stack telemetry is3,632/19,760 bytes for packed/reused paths.
The actual same-source four-million-instruction heavy CPU fragment now passes
independent verification with byte-identical PCS and GKR proofs. Native seal
plus complete falls74.732→23.931 seconds (3.123×); MAIN Merkle39.245→5.792
and INTER Merkle20.095→3.828 seconds. Requested peak remains exactly
10,093,072,140 bytes, with zero major faults and zero final heap/external retention.
See `vectors/reports/rv64-opstack-cpu-20261109/heavy-conditional-prefix-p2-tail-v1.json`.
This remains a conditional component proof: RAM/Wire obligations are outstanding.
No complete heavy-block rerun, full-root speedup or hard10× achievement is claimed.

Add `p2_bounded_tail_test.zig` to the OP native test root and run:

```sh
zig build test-riscv64-op-native-join -Doptimize=ReleaseSafe \
  -Driscv-test-filter='OP P2' -j1
STWO_OP_P2_BOUNDED_TAIL_BENCH=1 \
zig build test-riscv64-op-native-join -Doptimize=ReleaseSafe \
  -Driscv-test-filter='OP P2 bounded tail tiny benchmark' -j1
```
