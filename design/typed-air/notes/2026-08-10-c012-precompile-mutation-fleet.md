# 2026-08-10 — C-012 precompile mutation fleet

## Question

Does one independently decoded, honest Poseidon2 profile artifact reject every
authority forgery named by C-012, at the strongest boundary available for that
forgery, without concealing ownership bugs behind repeated proof production?

## Method

`guest_precompile_mutation_fleet_test.zig` produces one real CPU proof of the canonical
one-call `CUSTOM-0` fixture, serializes the complete five-section `STWGPF01`
artifact, and verifies a decoded positive control. Every negative arm decodes
that same immutable artifact again and changes exactly one authority. The
verifier consumes the owned proof on success and on failure; the test retains
and releases only decoded metadata afterwards. `std.testing.allocator` makes a
missed or double ownership transition fail the test.

Structural forgeries assert a specific admission error. Mutations which are
deliberately structurally canonical first call profile admission and detailed
claim validation successfully, then must fail inside cryptographic proof
verification. This distinction prevents a future early check from turning a
proof-level soundness regression into a parser-only test while leaving the
test green.

## Mutation matrix

| Authority changed | One-at-a-time mutation | Required rejection boundary |
| --- | --- | --- |
| Public input | Change the authenticated empty input-region base address | Artifact statement digest, before transcript mutation |
| Public output | Change the authenticated empty output-region data address | Artifact statement digest, before transcript mutation |
| Execution mode | Replace the Poseidon2 execution profile with base RV32IM | Extension profile admission |
| Extension identity | Flip one bit of the semantic digest | Artifact semantic identity admission |
| Active count | Increment only `counts.n_guest` | Redundant call-count admission |
| Padding | Increase only the caller descriptor log size | Canonical active-prefix/domain geometry admission |
| Descriptor count | Remove one active core family while retaining total steps | Recomputed extension admission certificate |
| Caller multiplicity | Increment only the detailed caller descriptor row count | Claim/construction descriptor equality |
| Provider multiplicity | Increment only the detailed provider descriptor row count | Claim/construction descriptor equality |
| Detailed claim | Add `delta` to caller batch 0 and `-delta` to batch 1 | Exact `OodsNotMatching` verdict after structural admission |
| Proof opening | Change one canonical Tree 1 OODS field value, re-encode, and decode | Exact `OodsNotMatching` verdict after wire preflight and structural admission |

The compensating detailed-claim mutation preserves its component aggregate and
the global caller/provider cancellation sum. It therefore specifically guards
the version-2 detailed-claim transcript binding, rather than relying on the
older aggregate cancellation check. The proof-opening mutation is reserialized
and decoded before verification, demonstrating that it is canonical wire data
of the expected shape and field range, not merely malformed postcard input.

## Scope limits

- The canonical minimal ELF publishes empty host input/output regions. C-012
  therefore mutates their authenticated addresses, not payload words. Payload
  encoding and count validation remain covered by the artifact codec tests;
  a future public-I/O guest fixture should add non-empty value mutations here.
- This fleet uses functional PCS parameters (`pow_bits = 0`, three queries) to
  keep continuous testing affordable. It tests binding and rejection paths,
  not a security-bit claim; production policy must continue to select the
  independent secure PCS configuration.
- The fleet corrupts one Tree 1 OODS sample. Existing PCS tests cover Merkle
  nodes, the remaining trees, and malformed witness lengths; duplicating those
  cases here would add verifier logging and cost without increasing
  profile-bound coverage.
- Each negative arm performs a fresh decode and verification, but all arms
  share one expensive proof generation. This intentionally optimizes test work,
  not protocol work, and keeps every mutation isolated from the previous arm.

## Acceptance evidence

The isolated C-012 root must pass in Debug, ReleaseSafe, and ReleaseFast. The
repository inventory/build integration is a separate shared-file change; until
that wiring lands, direct isolated execution is the authoritative receipt for
these two new files.
