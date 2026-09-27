# Caller pipeline from a live segment

`block_v5_caller_pipeline_v1.ForBackend.collectSegment` takes the driver's
already-live Ethereum/SHA segment, ordinal, exact clock frame, security
configuration, metadata/slot limits, and a caller-owned six-table counter set.
It generates the arithmetic matrix once for the physical family11 commitment.
The external stage leases those fixed/main trees and commits only its integer
witness tree. Collection returns fully value-owned `Proposal` metadata;
no runner slices, witness matrices or PCS trees survive.

`Proposal.lateBind(allocator, native_instance_id)` derives a `Bound` record and
the family11 arithmetic, family12 program and family13 packed-memory roster
entries. The native identity does not enter physical commitment construction.
Changing it changes all three instance IDs without changing the physical roots.
These entries are proposals; they issue no receipt or block authority.

`proveSegment` accepts the same live segment in the second pass. It validates
the independent B5SS roster and frame, regenerates one physical commitment,
and matches the arithmetic roots/key, external witness root, byte census and
all six physical counter snapshots before publishing proofs. It composes the
packed-memory, table/state and program warm callbacks, then proves family11.
An optional hook borrows the real arithmetic proof before its final sink.
There is no execution replay callback and no full `Profile.mainWitness`
generation inside a warm stage.

`Sink` exports `put_caller`, `put_program`, `put_state`, `put_tables`, and
`put_memory` with typed owned proof pointers and execution ordinals. Success
transfers ownership; error leaves cleanup with the producer. Durable transport
and fresh global verification remain the driver's responsibilities.

The counter set supplied to collection must belong to the caller's independently
planned field-safe execution/group policy. Collection merges arithmetic caller
requests plus 14 range88 byte requests per real external memory event only
after physical setup/census validation succeeds. Native six-table requests are
supplied separately. Proposals expose arithmetic `caller_max_requests` and
`byte_demand` so the global planner can combine these with admitted native
shape demands. Second-pass production checks local snapshots and does not
merge them into the global counter set again.

The existing SHA2/Keccak1 and signer1/Keccak1 fixtures now use this actual
collection/late-binding/production API and freshly verify arithmetic plus all
four warm side proofs. Changed proposal/bound roots and changed packed-memory
claims are included. The focused ReleaseFast/native gate passed **13/13** at
diagnostic q8/PoW0, with clean `std.testing.allocator` teardown. Both cases
freshly verified family11 and all four same-root side proofs. The three
authentic memory tuple regressions passed as well. The exact command and
scope are recorded in [block-v5-caller-pipeline-q8.json](block-v5-caller-pipeline-q8.json).

Qualification exposed two warm-source assumptions. `Trace.initSelected` now
checks complete descriptor geometry and every column actually read, while
leaving unused Keccak arithmetic columns unmaterialized. Packed external
quotient evaluation now uses the existing full-LDE recovery helper: it
interpolates the complete retained domain, rejects coefficients above the
admitted trace degree, and reuses the quotient buffer. Keccak's +27 state
shift and the default v2 quotient path are unchanged.

The diagnostic native/program/memory roster entries remain placeholders;
this gate qualifies caller production and fresh scoped verification. It
makes no complete block, canonical q70, detached transport or mainnet claim.
