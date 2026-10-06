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

## Proof path still required

1. Build a two-pass real-ELF campaign. The first pass establishes exact total
   cycles, completion and canonical leaf boundaries without retaining traces;
   the second replays the same ELF/input and gives each leaf its immutable
   `JobContext` and global V3 span. Bind the two passes through input, program,
   execution and boundary identities. Do not treat a planning receipt as a
   proof.
2. Complete the recursive leaf wrapper to constrain every V3 metadata word to
   the verified local V2 wire. The existing Ethereum leaf-link schedule now
   routes the base span and 168 directly equal boundary words, but it is not a
   proof transaction. Continuation-root limb conversion, completion tags,
   proof identity and verifier key still need exact AIR joins. Make the
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

The first normal gate should prove a real two-leaf program, verify both local
proofs, both wrapper proofs and their parent, then reject mutations to global
position, local count, boundary clocks, memory snapshot, completion and child
order. A separate large gate should cross 2^24 total retired instructions with
each leaf below the V3 cap. Until those gates pass, no long-execution root is
claimed.
