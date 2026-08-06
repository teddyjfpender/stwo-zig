# ADR-0021 — Backend-neutral Poseidon program identity and proof-path co-attestation

**Status:** accepted
**Date:** 2026-08-06

## Context

H-007 proves that authenticated typed Poseidon main columns, interaction
columns, and claims can replace their handwritten counterparts at the live CPU
and Metal proof boundaries. That evidence identifies the generated artifacts
by geometry and behavior, but it does not give both backends one canonical name
for the complete logical, physical, witness-execution, and relation program.

A semantic digest alone is insufficient. Two consumers can agree on authored
AIR while disagreeing about materialization placement, committed-column order,
compiled witness instructions, relation events, batching, or claim slots.
Conversely, backend names, Metal AOT bundle metadata, product-closure hashes,
and telemetry identify an implementation or build, not the backend-neutral
program the proof exercise is intended to compare.

The current proof path does not mix a program-identity digest into the Fiat–
Shamir channel or public statement. Recording an identity beside a successful
proof can therefore establish reproducible cross-backend co-attestation, but
must not be described as a cryptographic transcript binding.

## Decision

Define the canonical Poseidon2-M31 program identity as a self-authenticating
composition of four separately versioned SHA-256 identities:

1. the source-independent typed-AIR semantic digest from ADR-0007;
2. a physical-layout digest covering the authenticated H-004 compatibility
   identity and materializer policy, all 445 ordered main-column roles and
   materialization mappings, all eight H-006 interaction-column roles, and both
   ordered claim slots;
3. the existing H-005 executor digest covering its authenticated envelope,
   complete compiled instruction stream, and input and materialization slot
   maps; and
4. an H-006 relation digest covering every ordered event and batch field and
   binding them to both the semantic and layout identities.

The layout digest uses domain
`stwo-zig/typed-air/poseidon2-layout/v1`. The combined identity uses domain
`stwo-zig/typed-air/poseidon2-program-identity/v1`, format version 1, and
component ID `stwo.riscv.poseidon2-m31`. Its canonical preimage is 182 bytes:
the `STWAIRP\0` magic, format version, length-prefixed component ID, four
explicit child tags with their format versions and 32-byte digests, followed by
the unsigned 16-bit little-endian geometry `445, 8, 2`. The transport receipt
is that preimage followed by the 32-byte combined digest, for 214 bytes total.
No native Zig struct representation is hashed.

The canonical v1 digests are:

| Identity | SHA-256 |
| --- | --- |
| semantic | `9e8c3b5accdc2be31cf8ca128b5b27c87613f691ee8fd25e031f4286ceac81ed` |
| layout | `afbe1dfdf19fff06e2b6954276fd53d9d4bd67eea614acaba84c5678a8b31633` |
| executor | `6fe46c3c4dfc48b9dccc248ae23af8f246a83de3ec03b97274f6b7f90dbb9b88` |
| relation | `e70e62b2ff2815f52011468ad39e29b26c621c3039a9281298215ecaf90988b3` |
| combined | `594c88bfe11d6c8cb65918a7bfcf72257a79b61674997dbed24151ea3fb88a65` |

The SHA-256 of the complete canonical 214-byte transport receipt is
`745d92b8b7b0dc78a12397454d865f3818ce774b8589cc7de12ee357c92bc36c`.
Changing an included child or encoding requires its version or the combined
identity version and golden to change deliberately.

The test-only proof authority constructs this identity from authenticated
H-003/H-004/H-005/H-006 objects before the concrete proof engine observes any
committed column. At receipt creation, after proof construction and typed output
claim installation, it reconstructs the identity from those owned objects and
requires equality with the initial value. Receipt validation checks the
combined seal and requires the exact canonical identity. CPU and Metal product
exercises must return that same combined digest while their proofs verify
through the unchanged production verifier.

Backend name, host and toolchain metadata, source paths and spans, allocator
state, repository revision, product-closure identity, Metal AOT identity, and
telemetry stay outside the program identity. Evidence receipts record those
separately when needed to reproduce or admit a particular backend run.

This is proof-path **co-attestation**, not proof-transcript binding. The program
identity is carried in the local typed proof receipt and compared by product
tests; it is not mixed into the channel, committed as a proof column, included
in the public statement, or checked by the production verifier. This ADR does
not change the proof protocol or activate the typed path as production
authority.

## Consequences

- CPU and Metal can attest equality of the complete typed Poseidon program
  without making backend-specific build data part of logical identity.
- Layout, executor, and relation drift cannot hide behind an unchanged semantic
  digest.
- Construction and end-of-proof recomputation detect identity-affecting drift
  in the owned compatibility binding, executor, or relation plan before a valid
  local receipt is returned.
- Fixed canonical bytes support independent decoding, golden tests, artifact
  transport, and exhaustive one-byte-offset corruption tests.
- A successful V-006 receipt is evidence that two tested backend paths returned
  the same canonical identity alongside verified proofs. It is not evidence
  that an arbitrary proof cryptographically commits to that identity.
- No proving-speed, proof-size, optimized-materialization, production-security,
  or production-activation claim follows from the identity.

## Rejected alternatives

- **Use only the semantic digest:** rejected because physical mapping,
  executable instructions, relation order, and claim layout can drift without
  changing authored semantics.
- **Hash backend, AOT, or product-closure metadata into the combined identity:**
  rejected because it would make correct CPU and Metal executions unequal and
  conflate program identity with build admission.
- **Trust a copied combined constant:** rejected because the authority can
  reconstruct every child from authenticated owned components before and after
  the proof lifecycle.
- **Hash native structs or one monolithic ad hoc serialization:** rejected
  because host layout is not portable and independently versioned children make
  the changed authority reviewable.
- **Claim transcript binding without a protocol change:** rejected because the
  current verifier never receives or authenticates this identity.
- **Mix the identity into the transcript in V-006:** deferred because that is a
  proof-protocol and statement-identity change, not a validation receipt.

## Revisit when

The typed Poseidon path is proposed as production authority, the verifier must
accept more than one program version, program identity becomes a transcript or
public-statement input, a statement-global layout composes multiple components,
or an H-009 materialization proposal is considered for activation.
