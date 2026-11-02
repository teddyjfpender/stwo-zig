# RV64 aggregation: leaves, parents, root

Status: implementation proposal for `rv64_aggregate_v1`; no RV64 recursive
leaf/parent/root proof is qualified yet. Reuses the detached
recursion route already qualified for the RV32 typed frontend
(`canonical-typed-recursion.md`: detached leaf producer, detached parent
producer, standalone leaf and parent verifiers) and replaces its statement
contracts with the RV64 batch contract. Depends on fixed batch shapes
(`rv64-word16-cpu-2n.md`) and the manifest (`rv64-global-memory-argument.md`).

## 1. Shape of the problem

One execution produces `S` batch proofs (25 for the round-five reference block), one
INIT/TEARDOWN proof, and a manifest. The current fresh native receiver verifies them in 7.16 s with 6.09 GB peak
RSS in one isolated run. A fixed-key sub-second root verifier is a target,
not a measured property of the existing route.

Three circuits:

| Circuit | Verifies | Public inputs | Rows (projected) |
| --- | --- | --- | --- |
| leaf | one batch proof (or the boundary proof) | execution identity, manifest digest `m`, ordinal, role, boundary state in and out, RAM claim, service call ranges | 2^19 to 2^20 |
| parent | two children (leaf or parent) | the union of the children's publics with adjacency folded | 2^19 |
| root | one parent, plus the manifest and inventory checks | execution identity, block output, total steps | 2^19 |

Arity two keeps every circuit identical in shape; the existing RV32 route uses
the same detached parent model at arities 1/2/4/8.

## 2. Batch proof shape, fixed

A batch proof verifiable by the leaf must have one shape per protocol version:

- PCS: trees fixed, memory, main, interaction, composition; column counts and
  logs fixed by `cpu_word16_v1`; FRI config fixed (70 queries, 26 PoW bits,
  blowup 1, fold 1); all chips at their fixed logs with their full instance
  roster (an absent chip is an all-padding instance, not a missing tree).
- Merkle hash: **Poseidon2 over M31** for the batch PCS, replacing Blake2s.
  Blake2s in-circuit costs roughly 10x more rows per hash; the repository's
  recursion lane already uses the degree-3 Poseidon lane
  (`recursive-poseidon-degree3.md`) and the memory commitment has a qualified
  Poseidon2 AIR (`air/memory_commitment/poseidon2_air.zig`). The batch transcript must use the **same Poseidon2 channel on the native and
  circuit sides** for every mix and draw. Different hash functions cannot
  replay one another's Fiat-Shamir transcript. Canonical root encoding, field
  packing, domain tags, claim mixes and manifest-digest authority need explicit
  versioned schemas and native/circuit known-answer fixtures. This
  is a protocol version change for batch proofs and is scheduled with the
  Word16 switch so there is one re-qualification.
- Statement (public to the leaf): execution identity (ELF, input, policy,
  terminal contract digests), `m`, ordinal, `(pc, registers[32], epoch)` in
  and out, first and count of each service call family, division and
  multiplication request counts, RAM claim (QM31), chip instance counts.

## 3. Leaf circuit

Verifies one batch proof: replays the Poseidon2 channel from the statement,
checks commitment roots against decommitments for the 70 queries, evaluates
the composition at the OODS point from sampled values (the same generic
`emitFor(F)` authority instantiated with the circuit field type, so the leaf
contains the exact constraint set of the batch), folds FRI, checks PoW. The
RV32 lane's `universal_typed_component` already does this for typed programs;
the RV64 CPU and chips expose their constraint programs through the same
`SinkFor(F)` interface, so the leaf is generated, not hand-written.

The leaf additionally proves:

- the batch's `m` equals the leaf's public `m` and the batch's memory root is
  the manifest's root at this ordinal (the manifest is a public input as a
  digest; the ordinal's root is opened through a Merkle path over the manifest
  entries, proven in the leaf);
- the RAM claim exposed publicly is the one bound in the batch transcript;
- the boundary state in and out are the batch statement's.

The boundary (INIT/TEARDOWN) proof uses the same leaf with role = boundary and
exposes the two tables' claims and the terminal output binding.

## 4. Parent circuit

Verifies two children with the leaf/parent verifier (children are fixed
shape, so the parent is also fixed) and folds:

- same execution identity and `m`;
- ordinals contiguous and roles compatible (left.out == right.in for
  `(pc, registers, epoch)`, service ranges adjacent, counts summed);
- RAM claims summed.

Its public output is the folded span. Arity two means S-1 parents for S
batches; the boundary proof joins at the root.

## 5. Root

Verifies the final parent and the boundary leaf and checks: span covers
ordinals 0..S-1 with the expected initial PC/registers and the terminal PC;
`sum RAM claims + claim_INIT + claim_TEARDOWN = 0`; the manifest digest `m`
is the digest of the receiver-derived inventory (the inventory itself is a
public input of the root: shard count, roles, geometries, roots are hashed
inside); output bytes equal the public block output. The root's public
inputs are the execution identity and the output, which is what EthProofs or
an on-chain verifier consumes. A SNARK wrap is out of scope for this version.

## Required authority and cost reconciliation

- A child's verifier key must be independently authorized by the expected
  protocol/role. A key supplied with a valid-looking proof is not authority.
  Explain how leaf and parent identities and any recursive self-reference are
  handled by the qualified detached verifier route.
- A manifest digest is not the full inventory. Root/leaf constraints must
  reconstruct the selected manifest hash or authenticate entries under that
  exact digest and establish complete coverage. Switching child Merkle hashes
  does not silently change the manifest hash.
- Count leaf hashing of every disclosed value, shifted opening masks, FRI
  layers, field/extension arithmetic and all provider components. Counting only
  70 queries times tree depth omits the wide leaves themselves.
- Fixed per-batch full rosters conflict with globally packed chip instances
  whose padding is charged only once per execution. Resolve that statement/key
  boundary with the Word16 ledger and compare complete proof and recursion
  costs before fixing the leaf shape.
- Every chip instance implied by packing needs coverage. An all-padding absent
  chip and multiple fixed-size instances require an explicit bounded statement
  and key contract, not a request-specific verifier key chosen by the prover.

## 6. Unqualified cost hypothesis

Incomplete hypothesis, not a sizing receipt. Leaf: verifying 70 queries over four trees of depth 22 with Poseidon2 costs
about 70 x 4 x 22 x (Poseidon2 permutation rows) plus the composition
evaluation of the batch constraint set at one point and FRI folding. With the
degree-3 Poseidon lane at ~30 rows per permutation that is ~2^18 rows of hash
work; the originally assumed constraint cost has not been established; the leaf was projected near
2^19 rows with Word16 batches. On one 5090 a 2^19-row proof is a fraction of a
second; on the CPU about 3 to 5 s. Parents are the same size. The older 36-batch example has
depth 6, so the critical path after the last batch is one leaf
plus six parents plus the root: 3 to 5 s on GPU, overlapped with batch proving
for all but the last batch.

## 7. Implementation plan

| Step | Files | Gate |
| --- | --- | --- |
| 1. Poseidon2 channel and Merkle for batch proofs | `rv64/air/protocol.zig` (hasher, channel), `prover/vcs_lifted` Poseidon2 hasher, verifier counterpart | fresh receiver on the full block with the new hash; byte parity not expected |
| 2. RV64 batch statement contract for recursion | `recursion/` statement types, `recursive_segment_v2_native_ingress.zig` successor for RV64 | statement substitution attacks |
| 3. Generated leaf verifier from the RV64 constraint programs | `recursion/air/`, `SinkFor(F)` instantiation | leaf verifies a real batch proof; rejects a tampered proof byte, root, claim, `m` |
| 4. Parent and root | detached parent producer with the RV64 fold rules | adjacency attacks (gap, overlap, reorder, duplicated span), claim-sum attacks |
| 5. Pipeline | coordinator schedules leaves as batches finish, parents as pairs complete; standalone root verifier command | full block to a single root, fresh-process root verification, timings |
