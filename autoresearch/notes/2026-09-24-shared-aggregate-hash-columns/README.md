# Shared aggregate hash columns

This implements direct final-layout G/XOR emission for pairing two verified
native recursive nodes. Both child plans determine one combined layout; one
owner allocates its columns and generated hash metadata. Disjoint logical views
let each child emit into that final domain. No per-child G/XOR main-column
allocations or subsequent G/XOR main-column copy are used on this path.

## Ownership and admission

- Ordinary prepared rows remain a prover input. An assembly-only `Partition`
  instead borrows G/XOR main columns and owns other columns and fixed metadata.
  Its destructor cannot free the shared buffers.
- Namespace reads/writes account for each partition's logical base. Rebase plans
  and namespace identities retain their original admission checks.
- Shared joining checks column identity, complete active-row coverage, disjoint
  offsets, exact final geometry and namespaces before destructive assembly.
  It copies other cohorts and fixed metadata using the existing bounded join.
- G/XOR backing transfers exactly once, after every fallible join operation.
  The final result uses the backing owner's allocator; cross-allocator source
  partitions free their own storage. Failure leaves shared backing owned by its
  original owner and consumes the partial children through existing cleanup.
- All workers drain before any shared storage can be destroyed. Rejected emission
  destinations also consume their plan, preserving the plan lifecycle contract.

No AIR, semantic digest, shader, proof parameter, or transcript encoding changes.
The default recursive-node pairing route uses this implementation. Single-child
preparation and execution-leaf pairing retain their existing ownership paths.

## Qualification

`final-tree.log`: seven canonical tree checks pass. Three aggregate artifacts
independently verify at 70 queries/26 PoW bits, sizes 845993/849496/889364 bytes;
8/8 hash-device coverage and bounded-worker failure/reuse checks pass.

`join.log`: five focused ReleaseSafe checks pass. The new shared case covers
empty, unequal and domain-crossing child sizes, every main value and fixed field,
zero padding, invalid partition offsets, and exact pointer retention at transfer.
Every allocation failure in shared backing and join output construction is
injected; independently owned source storage also cleans up. An initial overly
broad injection run was stopped because it repeatedly injected into unrelated
AIR-definition construction. `join-initial-aborted.log` is not passing evidence.
The narrowed complete ownership test finishes with the rest of the gate in 39s.

`lifecycle.log`: seven canonical parent checks pass. Two additional borrowed-emission
failure points preserve every shared backing allocation until its owner destroys
it, while releasing all emission/planning storage. Existing abandonment, repeated
use and four ordinary-emission failure checks also pass.

## Measurement

`binaries.json` pins frozen current/control canonical tree binaries. `measure.py`
runs ABBA, two samples per arm, with eight workers, SMP allocator, ReleaseFast and
the same ABI-24 authenticated Metal bundle. It checks independent verification,
canonical parameters, artifact sizes, allocation bounds and device hash coverage.
The measurement holds the build lock, so compilation does not compete with it.
Raw timings and summaries are in `results.json` and `summary.json`.

## Remaining work

This removes the G/XOR main-column join copy for recursive-node pairing, not all
host copies. Fixed metadata and other AIR cohorts still use the checked join.
Execution-leaf pairing also appends public-memory custody hash rows after native
preparation. Applying shared emission there requires planning those extra rows
before allocation and retaining verified captures until deferred emission; simply
reusing the current native-only counts would under-size those partitions.

No new CSP or peer-prover benchmark result is claimed by this change. Full-tree
10x improvement, broader effective fusion and the reviewed parameter experiment
remain open. Source snapshots cover changed files in the dirty workspace, not a
complete clean-checkout reproduction.

## Matched results

Four serial runs, control/candidate/candidate/control, two samples per arm:

| Metric | Control | Shared columns |
|---|---:|---:|
| Complete fixture median | 38.41448s | 37.64372s |
| Root preparation median | 4.26672s | 3.45793s |
| Routed peak | 26,459,992,736 B | 26,459,992,736 B |
| Physical peak | 39,162,765,336 B | 39,160,848,120 B |

Root preparation improves 18.95%, about 0.809s. Complete fixture improves 2.01%,
about 0.771s. Peak memory is effectively unchanged: the later proving peak still
dominates. All twelve timed aggregate artifacts independently verify at q70/PoW26
with unchanged sizes. These are local two-sample medians, not production latency
distributions or Ethereum block throughput. The implementation is retained.
