# Block-v5 open orchestration API

The current producer and receiver APIs connect real native-v5 proof entrypoints
to global ROM and sorted-memory families without relabeling any v4 recursive
leaf. They deliberately expose an open core, not `CompleteBlock`.

`block_v5_block_producer_v1.ForBackend.prove` takes independent B5SS pins,
ordered roots, a native template catalog, completed two-pass program/memory
planners, and a replay loader. Each execution replay yields one native-only
owner and its admitted public plan; the producer recommits native roots and
leases those immutable fixed/main trees into the request proof, checks both
against pass one, proves and stages both, then releases the
owner. It proves the global ROM table and replays sorted-memory shards to the
caller sink. It rejects legacy request identities and precompile stages that
have not been connected. A producer result grants no verified authority.

`block_v5_program_native_batch_receiver_v1` fresh-verifies native-v5 proofs via
`verifyOwnedWithCatalog`, checks canonical native instance and program request
IDs, opens request columns at those native roots, derives public terminal
fetches, and closes the authenticated global ROM table. Its optional sparse
companion loader internally fresh-verifies family11 arithmetic and uses that
receipt's binding for fresh family12 request verification. A caller cannot
supply a precomputed program/arithmetic receipt as authority. The current
per-execution precompile companion is a qualification bridge; globally batched
provider arithmetic remains a separate planner change.

`block_v5_block_artifact_v1.Pins` holds independently supplied source/seal,
program plan, native shapes/public admissions, catalog and initial/memory pins.
Proof loaders are separate, so file-backed storage can reopen one proof at a
time. Candidate/proof metadata must not be copied into expected policy.
`block_v5_block_receiver_v1.verifyOpen` invokes the fresh program receiver and
fresh sorted-memory/initial/range receiver. When independent final endpoint
pins and proofs are provided it uses the endpoint receiver too.

The returned scalars stay separate: native open sum, precompile open sum,
program provider sum and sorted transition sum. No accidental cancellation of
different bus partitions can produce complete authority. The remaining
obligations are explicit:

- Fresh global providers for the six shared native lookup tables. Native-only
  witnesses export these requests and contain no local table providers.
- Fresh opcode and external memory projections, their byte table closure,
  and cancellation of the sorted transition bus with exact access counts.
- Universal native/precompile memory requests and the independently admitted
  public/provider compensation partitions.
- The ordered native-to-precompile caller/retirement bus, including clocks,
  control flow, caller counts and register claims.
- Independently pinned final RW endpoints when absent from this open call.
- A genuine native-v5 leaf plus exact-count recursive forest/outer receiver.

`Plan.Admission` remains the old public pin shape at the native-v5 seam.
Production must not reconstruct per-leaf custody hashes/trees solely to build
that identity; the lightweight global source/span pin migration is separate.
Native witness shared lookup counters must include external callers before
`sealNativeOnly`; this producer currently rejects that unfinished mode.

The family11/12 quotient and global ROM gate passed 6/6 at q8/PoW0. It includes
fresh arithmetic admission and program count/instance tampering, but its native
retirement roster is scaffolding. The new concrete producer/open receiver
entrypoint compile gate is separate from a full coherent proof qualification.

The ordinary native-v5/program batch gate now passed 12/12 at q8/PoW0.
It leases both original first-round trees, compares all source trace logs,
proves the request first, checks the surviving native roots, then proves and
freshly verifies native/request/global-ROM together. It closes exactly three
fetches with four native fixed and 70 main columns; no custody hash columns
were allocated. Wrong request count and canonical request ID are rejected;
`std.testing.allocator` teardown is clean. The leased tree logs must subtract
FRI blowup, and request quotient evaluation recovers only opened coefficient
columns when native commitment retention is `.never`. Neither correction
changes proof format or roots. This gate still returns an open native residual.
See `block-v5-native-program-shared-prefix-q8.json` for the exact command.
