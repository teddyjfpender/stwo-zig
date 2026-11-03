# Bounded ready lanes for native OM31 recursion

`execution_wrap.runWithFactories` is an explicit candidate API. The existing
`run` entry remains the default serial streaming binary-carry implementation.
This foundation has host qualification; it does not admit production multi-GPU
recursion or claim hardware throughput.

The plan assigns every leaf and parent its original serial node ID before any
thread starts. Leaves retain their ordinal filenames; parent filenames and
factory scope ordinals retain the serial node ID. Finalization combines the
rightmost incomplete blocks first. Scheduling changes neither the ordered
Merkle digest nor the native proof statement, geometry or transcript.

Callers supply one to four `Lane` records: a unique physical device ID, atomic
trace-only device factory and stable caller-owned `WorkPool`. Aliased devices,
factory contexts or pools are rejected. The sum of pool widths must fit the
explicit CPU worker budget. Native proving must be drained before this phase.
Each lane thread installs `ScopedPoolBinding`; there is no implicit proof pool
or CPU proving fallback.

The allocator must come from `SharedHostBudget`. All graph, proof and retired
child-key storage uses that synchronized allocator. A separate external
reservation charges 8 MiB per lane for coordinator thread stacks. Pool helper
stacks are also reserved from their measured pool count and stack size. A caller
may supply an already live helper-stack reservation from the same budget; it is
validated and borrowed without double charging. Each lane owns at most one
active graph/proof. The ready queue counts completed child authorities plus
in-flight output reservations, prioritizes ready parents and reserves headroom
against filling the budget with unmatched leaves. The minimum slot cap is
`9 + 2 * lanes`; the default 17 admits up to four lanes. Heap byte admission
remains independently enforced by the shared allocator.

A child remains live through parent graph construction, proof generation and
fresh independent reception. The parent is serialized into its own pending
file, file-synced, renamed and directory-synced before the queue publishes it or
releases either child. Readable directory handles avoid Linux O_PATH/fsync
failures. On failure dispatch stops; all active lanes join before live proofs
and their allocator are released. A failed run cannot publish an accepted root
report. Partially published node files can subsequently be freshly revalidated.

Host checks cover exact binary-carry IDs, all 1–256 leaf counts with 1–4 lanes,
adversarial completion order, bounded active/retained custody, failure draining,
deterministic lowest submitted-node failure, duplicated device/factory/pool,
CPU worker over-admission, stale pending-file replacement and publication
failure cleanup. The actual blocking dispatcher is also tested by real threads:
out-of-order completion publishes before parent release, cancellation drains all
active work, and simultaneous failures retain deterministic lowest-node errors.
`zig build --build-file src/integrations/riscv_cuda/build.zig test-rv64-recursion-ready -Doptimize=ReleaseFast`
runs the scheduler/publication checks plus a direct call to the actual
`runWithFactories` API, forcing its full semantic reachability, and budget tests
for owned, borrowed, foreign, undersized and failure-atomic stack reservations.

The recursion allocator must be the direct shared-budget allocator. Existing
native capture/keys/bundles may remain under a recycler backed by that same
budget. Passing its unidentifiable recycler wrapper to this API is rejected;
there is no ancestry guessing or unbounded allocator fallback.

Remaining gates: run the candidate with one physical GPU and compare every
leaf, fold, root proof and tree against the serial control; independently verify
the root; then run actual two- and four-device gates with memory and pool
telemetry before enabling a driver option. The measured recursive trace is
roughly 48.7 billion MAIN+INTER cells across 33 nodes versus roughly 4.56 billion
native cells. Multi-device scheduling addresses this measured workload; it does
not remove that representation amplification.
