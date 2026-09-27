# Native-v3 CPU driver integration

The callable planning seam now collects actual native physical commitments
before global admissions exist. Its two-pass parity gate passed 8/8 under
ReleaseFast with three real Ethereum-SHA-profile release-ELF segments and a
pinned output oracle. The fixture proves no STARKs or complete block: its ROM
and lookup plans are real, while its remaining global digests are explicitly
scoped planning placeholders. See
[qualification JSON](block-v5-cpu-driver-two-pass-admission-q8.json).

`block_v5_cpu_native_root_proposal_v1.ForBackend.commitPhysical` is the shared
fixed/main commitment kernel used by both census proposals and
`NativeV3.commitFirstRound`. It retains the existing transcript recipe,
configuration, native-only phase, exact geometry and genuine caller-only Frame
checks. `collect` immediately destroys its PCS scheme and returns an owned
Proposal containing only roots, template and public/shape metadata. No native
trace, runner result, Merkle tree or LDE survives.

`Proposal.bind(actual Context)` computes the existing lightweight public
Admission and native instance ID once the ROM, memory and public-source plans
exist. Its output is a proposed roster entry, not an accepted receipt.
`requireReplay(actual NativeV3 FirstRound)` compares roots, template and admitted
instance during the second execution pass. Global receivers retain every
existing fresh-verification and catalog/source-seal check.

`block_v5_cpu_driver_admission_v1.Planning.initFromSource` requires independently
pinned source ELF/input/oracle hashes and exact JobContext, plus explicit source,
ROM, execution, aggregate metadata and field-safe lookup limits. Explicit
schedule JSON is independently hash-checked and compared to parsed source
budgets. The adapter owns the real decoded-ROM Census and canonical per-segment
fetch multiplicities. It validates contiguous PCs/global cycles, keeps input
only on the first segment and output only on the last, and rejects metadata
growth before copying. Its late `bind` builds the real smallest ROM plan,
contiguous lookup groups, lightweight admissions and template catalog. Binding
arrays and worst-case groups also count against the metadata cap.

The input arrays are copied once for the first public segment, and output once
for the terminal segment. Public metadata for other segments is sparse.
Planning's borrowed ROM plan must not outlive Planning; Bound's owned admission,
entry, catalog and lookup arrays have separate explicit teardown. No accepted
block authority is exposed by either type.

The smallest genuine block-driver entrypoint remains a new callable module,
followed by CLI wiring after actual qualification:

1. Use the existing pinned runner `Source.openPass(.first)` to produce one
   segment at a time. Build owned public data with the full declared ELF ROM
   root; construct `Owner` and `sealNativeOnly`; collect the physical proposal,
   canonical fetches and ordinary/caller lookup demand. Append real transitions
   to the immutable `block_memory_replay.Replay` spool. Collect caller arithmetic
   and memory-sidecar physical/witness-root proposals before releasing the
   segment.
2. Finish sorted replay and collect packed36/range16 memory roots/counters.
   Write independently matched initial/RW/first-touch/final/register source
   files; commit ROM and six-table provider roots. Late-bind native and caller
   proposals, then build the exact catalog/family roster and B5SS.
3. Feed `Source.openPass(.second)` through
   `block_v5_block_producer_v1.ForLightweightBackend.proveWithHooks`. Reproduce
   every root before proving. Compose native lookup, ordinary memory sidecar,
   caller arithmetic/program/table/memory stages and cached genuine recursive
   leaf publication while the same single segment is live.
4. Stage all typed proofs and compact public policy metadata. Run the versioned
   exact OpenV2 pair/quartet ready queue and hash-pinned outer file publication.
   Final acceptance must invoke `Global.verifyCompleteDetached`, which fresh
   verifies all globals and internally reconstructs native recursive policies.

Existing production pieces include native lookup/recursive-leaf warm hooks,
the bounded one-entry recursive setup cache, program extension/caller lookup
hooks, packed replay and its owning `TraceLease`, and the exact detached stage
and receiver. The source writer is being integrated separately.

Remaining engineering includes family11 late physical-root binding and checked
one-record warm proving, ordinary/external memory warm adapters, actual global
plan collection in the driver, and all-family staged codec/loader orchestration.
The old v4 bundle/materializer is incompatible proof transport and must not be
used as native-v3 authority. The existing runner's 1024-segment host cap remains
an upstream resource limit; this adapter adds only explicit configured caps.

There is no mandatory third execution replay in this design. Physical roots
have no dependency on global admission digests. An optional verification replay
may reconstruct compact policy metadata, but it is a nonsuccinct host step and
does not replace proof verification.
