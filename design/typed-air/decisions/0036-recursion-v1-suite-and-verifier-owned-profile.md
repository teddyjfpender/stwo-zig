# ADR-0036 — Recursion V1 suite and verifier-owned profile

**Status:** proposed
**Date:** 2026-08-12

**Classification:** recursion protocol; production activation prohibited until
R-008, R-009, and R-012 close

## Context

R-011 must choose the arithmetic field, transcript and Merkle hash, PCS
parameters, public leaf statement, and recursive-verifier control boundary
before a recursive circuit is authored. These choices are protocol, not proof
metadata. Letting proof bytes select a query count, fold width, table roster,
Merkle depth, transcript phase, or public relation would let malformed proofs
shorten the verifier rather than merely fail it.

The source proposal requires more than ordinary two-to-one recursion. Core
execution and hash-precompile work should be independently provable, their
shared relation should close under one session-bound challenge context, and
every recursion-local component must be authored through the same typed AIR
compiler. ADR-0030 defines the cross-proof relation-summary boundary; this ADR
defines the cryptographic suite that must verify it.

The closest reviewed implementation is Stark-V
`origin/chore/scratchpad-cleanups` at
`59172a201bd01f2f4b699bc2f7d4442d8ee81597`. It provides particularly useful
positive and negative evidence:

- its current recursion profile uses M31/QM31, Poseidon2-M31, four commitment
  trees, 16 PCS proof-of-work bits, blowup one, 193 FRI queries, fold step four,
  and a constant last layer;
- its universal AIR has 36 components, all guarded as `define_air!` or
  `define_air_fns!` owners with no handwritten evaluator escape hatch;
- segment, empty, and binary branches produce and verify real recursion
  proofs, including a binary parent over two recursion children;
- its fixed universal proof wire is 3,459,396 bytes; and
- its tree driver and application root API remain unfinished, while its
  hash-precompile proof split is explicitly still pending.

Those facts validate the architecture, not our concrete table counts. Our
RISC-V AIR roster, statement, public I/O capacity, relation registry, and
preprocessed geometry differ. Copying Stark-V's 1,757/2,196-table shapes or
calling its binary test a completed application root would be unsound.

## Decision

### Cryptographic suite

Recursion V1 uses:

- base field M31, modulus `2^31 - 1`;
- secure field QM31 with four canonical M31 coordinates;
- the exact pinned Stark-V Poseidon2-M31 width-16 permutation already used by
  the RISC-V Poseidon and memory-commitment AIR;
- an eight-word rate and eight-word capacity sponge;
- eight canonical M31 words for transcript and lifted-Merkle digests;
- distinct leaf, internal-node, transcript-draw, statement, proof, relation,
  pair, and parameter-identity domains;
- four commitment trees;
- 10 interaction proof-of-work bits;
- 16 PCS proof-of-work bits;
- FRI blowup log one, 193 queries, fold step four, last-layer log-degree zero,
  and no lifting override.

The implementation is
`src/frontends/riscv/recursion/{poseidon2_channel,protocol,engine}.zig`.
`ProverEngineForBackend` couples one Poseidon channel, Merkle channel, and
Merkle hasher so a backend cannot accidentally prove with Poseidon and verify
with Blake2s.

The protocol identity includes every numeric Poseidon round constant and
internal-matrix diagonal through a separately frozen parameter digest. It also
includes the optional-lifting mode, relation schema and arity, maximum leaf
count, secure-field capacity, and security target. Runtime validation compares
the manifest fields with the actual `PcsConfig`; changing code constants while
retaining the checked identity is a test failure.

### Packed FRI leaves

Whenever a layer folds more than one bit and has at least four evaluations,
four adjacent QM31 values form one Merkle leaf. The sixteen M31 inputs are
ordered by evaluation offset, then extension coordinate:

```text
value[0].c0, value[0].c1, value[0].c2, value[0].c3,
value[1].c0, ...,
value[3].c3
```

Commit, lazy commit, and decommit must use the same mapping. Evaluation query
positions are shifted by two and deduplicated only for Merkle traversal; the
original positions and values remain the FRI folding witness. A backend fused
path may run under a multi-fold schedule only after it explicitly implements
this layout. Until then the generic packed path is mandatory.

This is not a cosmetic optimization. A four-fold prover that commits four
ordinary coordinate columns and a verifier that opens packed leaves implement
different protocols. The native Poseidon leaf acceptance test found exactly
that latent mismatch; the corrected ReleaseSafe and ReleaseFast proofs now
verify independently with identical transcripts.

### Security ledger

`PcsConfig.securityBits()` reports 209 configured query-plus-PoW bits. It is a
configuration ledger, not an end-to-end 209-bit claim. QM31 contains about 124
bits and an eight-M31 Poseidon digest has about 124 collision-security bits.
V1 therefore records a 120-bit target, leaving margin below both ceilings. A
soundness review must still account for polynomial degrees, union bounds over
the fixed verifier schedule, LogUp denominator failure, hash assumptions, and
the recursive proof itself. No benchmark or API may advertise 128- or 209-bit
end-to-end security from the configuration sum alone.

### Verifier-owned fixed profile

The recursive verifier consumes a fixed, versioned manifest derived from the
compiled production rosters. The final R-011 profile must bind at least:

- ordered VM and recursion component names and semantic program digests;
- ordered table log sizes and preprocessing identities;
- claimed-sum and sampled-value counts;
- all four tree heights;
- the exact number and width of FRI layers;
- per-query trace and FRI authentication depths;
- public-input, public-output, call, and leaf capacities;
- the complete transcript control plan; and
- the exact fixed proof-wire length.

Proof bytes provide values only. They cannot provide a count that determines
how much of themselves is verified. Dynamic ordinary RISC-V proofs are useful
native inputs, but are not an acceptable recursive wire until checked
adaptation expands them into this fixed shape and zeroes every inactive slot.
The profile must be generated from our own rosters; Stark-V dimensions are
comparison evidence only.

### Leaf and pair statement

One leaf public input binds:

- protocol ID, aggregation session ID, verifier-derived shared-challenge
  context, job ID, and common execution-statement ID;
- exact guest relation domain and ordered public call commitment;
- event count;
- independently reconstructed statement, canonical proof, and terminal
  transcript identities;
- leaf and pair indices, left/right position, and fixed core-request or
  Poseidon-provider role; and
- the proof-bound signed QM31 relation total and its count.

The challenge-context ID is derived from the session ID, protocol ID, and
relation-domain ID. Supplying an arbitrary nonzero context is invalid. The
statement/proof/transcript identity functions consume versioned canonical
words or bytes, never an in-memory struct ABI.

The first parent accepts only adjacent children `2*j` and `2*j+1`, with core
on the left and provider on the right. Context, count, and call commitment must
match; the relation totals must add to zero. Swaps, omissions, duplicates,
cross-session or cross-challenge substitution, noncanonical M31 words, and
unclosed totals reject before the parent statement is published.

A native struct validator is not recursive verification. The in-circuit leaf
branch must reconstruct all three identities from a verified child proof and
bind the relation total to authenticated interaction columns. A detached
summary next to a valid proof has no authority.

### Universal typed recursion AIR

R-012 owns a closed universal roster covering control, transcript replay,
proof-of-work, relation challenges, statement input and semantics, public
claim hashing, composition evaluation, OODS/DEEP checks, query mapping, trace
and FRI Merkle paths, FRI folding and last-layer checks, QM31 arithmetic,
linear operations, Poseidon2, and required range checks.

Every roster owner must be a compiled typed-AIR program. A structural guard
pins component names to source owners and rejects handwritten evaluators,
standalone legacy table declarations, and wrapper macros that hide either.
Generated witness storage is preplanned and row-hot execution performs no
allocation, string lookup, or dynamic semantic dispatch.

### Completion boundary

This ADR selects a V1 development suite; it does not complete recursion.

- R-008 completes only when two independently verified core/provider proofs
  are checked inside a recursive leaf-pair proof.
- R-009 completes only when canonical adjacent parents recursively yield one
  root proof whose verifier needs no descendant proofs.
- R-012 completes only when the entire reachable roster passes the zero-manual
  typed-AIR guard.
- R-010 measures constant size, verifier cost, wall time, total work, memory,
  and crossover across supported leaf counts.

Until those gates pass, production APIs must label these modules protocol
substrate and native reference code.

## Consequences

- Native proving now exercises the same circuit-friendly hash and four-fold
  FRI geometry intended for recursion.
- Poseidon parameter drift and optional PCS-shape drift change or invalidate
  the protocol identity instead of silently changing proof meaning.
- Multi-fold FRI reduces authentication rounds, but each opened leaf is wider;
  the end-to-end proof and verifier measurements decide whether that trade is
  beneficial.
- Fixed proof adaptation adds memory and implementation work, but removes
  proof-selected verifier schedules and makes one universal AIR possible.
- A 120-bit target is lower than the 209-bit configured PCS ledger and is the
  only honest claim before a complete reduction.
- The original single-source requirement applies equally to the inner VM AIR
  and the recursion AIR; recursion cannot fossilize a second handwritten
  component system.

## Rejected alternatives

### Blake2s inside the recursive verifier

Rejected for V1 because the production RISC-V Poseidon AIR already supplies a
reviewed field-native permutation and Blake2s would dominate recursive work.
Blake2s remains useful for cold native artifacts, but those bytes are rehashed
into the versioned Poseidon identity boundary.

### Copy Stark-V's fixed dimensions

Rejected because table counts and public capacities are program-specific.
Only the derivation method and soundness invariants transfer.

### Fold step one

Rejected for the selected profile because it substantially increases FRI
authentication rounds. Fold step four is accepted only with packed-leaf
commit/decommit parity and fixed layer-width tests.

### Dynamic proof vectors in the circuit

Rejected because proof-controlled lengths can shorten verification and create
variable AIR geometry. Native decoders may accept bounded dynamic input only
to adapt it into a verifier-owned fixed wire.

### Treat native pair validation as recursion

Rejected because it does not prove either child-verification computation.

## Activation gates

Move this ADR to accepted only after:

1. the compiled VM and universal rosters generate a fixed manifest and wire;
2. an independent soundness review accepts the 120-bit ledger and all union
   bounds;
3. Poseidon channel/Merkle vectors, parameter identity, packed-FRI layout, and
   native proof verification pass in Debug, ReleaseSafe, and ReleaseFast;
4. the split core/provider leaf protocol exposes proof-bound summaries under
   one non-circular challenge context;
5. every recursion component is typed-AIR-authored and structurally guarded;
6. a binary recursive proof rejects the complete adversarial substitution
   matrix; and
7. the root API verifies one expected statement and one constant-size proof.

## Revisit when

- a reviewed higher-security extension field is required;
- a different Poseidon parameter set or hash gives a better complete recursive
  proof rather than a microbenchmark win;
- post-hoc aggregation requires a relation commitment rather than a
  session-bound challenge; or
- fixed public capacity becomes the dominant proof cost.
