# RISC-V long-execution proof boundary

The released SegmentV2 statement uses one global clock and admits at most
2^24 retired instructions. Splitting an execution into more SegmentV2 leaves
does not remove that global limit. A long execution needs bounded leaf-local
clocks and a recursively verified 64-bit global span.

## Implemented ingress

`recursion/segment_execution_campaign_v3.zig` executes a real ELF in leaf-local,
segment-owned chunks. A consumer receives the complete profile-specific leaf
before that leaf's trace is released. Continuation capabilities, segment order,
global cycle continuity, the V3 leaf budget, and a finite leaf limit are
checked. This is an execution source, not proof acceptance.

`integrations/riscv_cpu/recursive_segment_v3_native_ingress.zig` takes an
admitted V3 source for one leaf, projects it into the bounded V2 AIR, creates
and serializes its Poseidon2 proof, destroys the producer, freshly verifies the
decoded proof, and joins the verifier-owned receipt to the V3 metadata. Its
`VerifiedLinkV3` is checked by the host. It is not yet a recursive proof of
the global position.

`recursion/segment_execution_plan_v3.zig` runs the ELF once to size every
leaf, records the exact total, ELF/input hashes, guest policy, and compact
per-leaf CPU, sparse-memory, clock and I/O boundary records. Replay checks
these records before exposing a leaf to the proof consumer, so equal-sized but
different executions cannot silently reuse a plan. Replay also passes each
measured leaf count as that leaf's reservation budget, avoiding an oversized
terminal-leaf trace allocation. It rejects host and
retirement callbacks until their behavior has an authenticated replay
contract. Planning is advisory and does not authenticate a proof.

`recursion/temporal_pair_candidate_v3.zig` checks the exact two-child V3
metadata preimages and the folded parent statement, including 64-bit positions
past the V2 clock cap. It is a native preflight for a future parent AIR, with
mutation gates; it does not accept either child as a recursive proof.

`integrations/riscv_cpu/recursive_segment_v3_outer_stage.zig` can now prove
and freshly verify the actual 39-component local V2 outer transaction for a
projected V3 leaf, then bind its verifier publication to the host-checked V3
link. The staged manifest has no V3 publication capability: the local proof
still does not constrain global position, so a temporal candidate cannot use
this stage as a verified recursive child.

## Proof path still required

1. Connect the two-pass plan/replay to proof publication. The first pass now
   establishes exact total cycles, completion and per-leaf sizes without
   retaining traces; replay checks ELF/input identity and the leaf sizes.
   Construct one immutable `JobContext` from that total, then bind each replay
   leaf's actual execution and boundary identities to its V3 proof. Do not
   treat the planning receipt as a proof.
2. Complete the recursive leaf wrapper to constrain every V3 metadata word to
   the verified local V2 wire. The Ethereum leaf-link schedule now routes the
   base span, directly equal boundary words, and redundant position/completion
   fields. Separate typed AIR constrains canonical continuation-root limbs,
   completion tags, and 64-bit position arithmetic. These pieces are not yet
   one proof transaction: proof identity, verifier key, ProgramV2/provider
   authority and shared lookup closure still need integration. Make the
   wrapper available to the base RV32 profile as well.
3. Prove global position and length arithmetic with canonical 16-bit limbs:
   `end = start + local_count`, no overflow, exact segment order and bounded
   local count. The transcript must commit the complete V3 statement, local
   proof identity, security configuration and recursive verifier key.
4. Implement a verified temporal parent over two V3 publications. It must
   enforce common job/program/input identity, adjacent global ranges, equal
   CPU and sparse-memory boundary commitments, and exactly one terminal leaf.
   Support odd tails without inventing a dummy proof; mixed leaf/parent inputs
   need explicit family tags and verifier-key admission.
5. Publish a root only after all native leaves, leaf wrappers and temporal
   parents have been freshly verified. Detached loading must bind canonical
   proof bytes to verifier-owned metadata rather than accepting host assertions.
6. Bind public input/output claims to canonical guest I/O bytes through a
   versioned verifier-owned input and AIR relation. Existing SegmentV2 edge
   digests and `MachineState.public_io_state` are copied from the span
   statement, and custody checks only establish first/last placement; they do
   not prove that those digests represent the runner's actual input/output.
   The V3 wrapper must not inherit that unbound claim.

The first normal gate should prove a real two-leaf program, verify both local
proofs, both wrapper proofs and their parent, then reject mutations to global
position, local count, boundary clocks, memory snapshot, completion and child
order. A separate large gate should cross 2^24 total retired instructions with
each leaf below the V3 cap. Until those gates pass, no long-execution root is
claimed.

The public iadd256 experiment in [PR #223](https://github.com/teddyjfpender/stwo-zig/pull/223)
is a useful large-program gate: its
61-repetition first batch retired more than 2^24 instructions across bounded
leaf-local segments, but that capture is execution-only. The same experiment
shows that repeatedly regenerating earlier SHAKE inputs makes late batches
much larger than early ones. A full quantum-circuit proof therefore needs the
sound V3 leaf/parent path here **and** proof-bound SHAKE checkpoints and exact
batch/repetition coverage; merely raising a row cap or adding more leaves is
not sufficient.
