# Approved RFC: explicit hash-family proof-wire contract

Status: approved in [RFC #325](https://github.com/teddyjfpender/stwo-zig/issues/325).
Owner decision: [approved, recorded by delegate](https://github.com/teddyjfpender/stwo-zig/issues/325#issuecomment-6739260920).
Owner: `proof-wire`. Scope: the existing `stwo_proof_wire` package only.

## Problem and decision requested

The public facade already exports `ForHasher` and `wireToProofFor`, but its
`0.1.0` API ledger does not declare either. The workspace checker correctly
rejects this discrepancy. Existing consumers instantiate `ForHasher` in
`src/integrations/riscv_cpu/poseidon2_outer/proof.zig:20`,
`poseidon2_outer/stark_fixture.zig:20` and
`word16_global_execution/services/poseidon2_native/worker_protocol.zig:34`.
Those call sites establish demand, not qualification of the exported API.

Approve this exact additive contract transaction:

1. Add `ForHasher` and `wireToProofFor` to the sorted `api_surface` ledger.
2. Declare signature and invariant tests for the supported combinations below.
3. Bump `stwo_proof_wire` from `0.1.0` to `0.2.0` and update its owner guide.
4. Keep the dependency on `stwo_core`, the `interchange` layer, existing
   signatures, error tags, protocol discriminants and default bytes unchanged.

No other package ledger, backend, product, source-conformance baseline or
qualification gate is part of this decision. This RFC does not approve the
remaining workspace findings.

## Executable boundary

The existing implementation is in
[family.zig](../../src/waist/proof_wire/family.zig); the facade is
[mod.zig](../../src/waist/proof_wire/mod.zig).

| Operation | Contract to declare |
| --- | --- |
| `ForHasher(comptime Secure: type, comptime HashFamily: type) type` | Select an explicit codec and owned proof type. `Secure` remains restricted to the existing QM31 and OM31 authorities. Qualify the default lifted Blake2s family and the existing Poseidon2 M31 v1/v2 families with provider tests. Do not advertise untested hash families merely because their digest occupies thirty-two bytes. |
| `wireToProofFor(comptime TargetHasher: type, allocator, wire)` | Reconstruct an owned proof using a caller-selected target type whose `Hash` type is exactly the wire representation. This is representation conversion, not authentication of an algorithm choice. The caller must derive the expected family from trusted verifier policy. |

Input wire slices remain borrowed and immutable. A successful decode returns
allocations owned by the caller, released through the proof's existing
`deinit(allocator)`. Failed decoding publishes no result and releases partial
allocations. Allocation failure is retryable with sufficient resources;
malformed or noncanonical data requires corrected input. No new numeric error
code or changed meaning of an existing `CodecError` tag is proposed.

The codec does not prove a statement, choose security parameters, authenticate
a proof producer, or replace application framing, input-size admission and
verification. In particular, matching digest representation does not establish
that two hash algorithms are interchangeable.

## Compatibility and exact framing

| Existing family | QM31 binary header | OM31 binary header |
| --- | --- | --- |
| Default lifted Blake2s | `STWOPRW1` | `STWOPRW8` |
| Poseidon2 M31 v1 | `STP2QW01` | `STP2OW01` |
| Poseidon2 M31 v2 | `STP2QW02` | `STP2OW02` |

The historical default QM31 JSON remains an unenveloped `ProofWire` object.
Existing field/family-specific JSON envelopes and their protocol strings remain
exact. Wrong-family or wrong-field framing, truncated or trailing binary data,
unsupported counts and noncanonical coordinates must retain their existing
rejection behavior. This is an additive declaration of existing implementations;
it introduces no new wire revision or regenerated golden bytes.

## Tests before the ledger transaction

Add provider-owned, backend-free contract tests through the existing package
`test` step and `scripts/dev_test.py`:

- Signature checks instantiate both secure fields with each supported family
  and verify that returned proof types preserve the selected authority.
- Existing default and OM31 JSON/binary golden tests remain unchanged.
- Poseidon2 v1/v2 JSON and binary round trips preserve every digest coordinate,
  every secure-field coordinate and nested empty structures.
- Each version/field rejects the other framing. Noncanonical digest words and
  malformed counts reject before publishing a proof.
- Every decode allocation-failure point balances ownership, and borrowed wire
  inputs remain unchanged on rejection.
- A representation-compatible reconstruction case documents the trusted
  target-family obligation rather than claiming a cryptographic conversion.

Run the package in Debug and ReleaseFast under the shared build lock and local
resource guards. Record actual execution separately from semantic compilation.
These provider tests do not substitute for the planned registered consumer-driven
contract framework or a complete RISC-V product proof.

## Candidate evidence before approval

The existing implementation and the candidate provider tests execute successfully
through `scripts/dev_test.py` in Debug and ReleaseFast. The candidate adds three
named tests in `src/waist/proof_wire/hash_family_test.zig`, reached from the public
module, without changing codec code, bytes, error tags, the API ledger or version.

The six field/family combinations preserve every seeded digest byte, all secure
coordinates and nested empty siblings. Their binary decoders reject each of the
other five headers; Poseidon JSON rejects the other family version. Across four
Poseidon field/version combinations, all nine digest words in all six digest
positions reject a noncanonical word before any allocation, leaving borrowed
input unchanged. JSON/binary decode and re-encode exercise every allocation
failure; caller-selected plain-Blake2s reconstruction also balances every failed
allocation and returns an independently owned target proof.

These are CPU provider-fixture results, not cryptographic proof acceptance or
product qualification. Existing default/OM31 golden and malformed-count tests
remain in the mandatory suite. The candidate code budget is +132/-0/net +132,
including its mandatory import, against the +150 allowance. Flags +0/-0;
scripts +0/-0. Documentation is measured separately.

## Implementation, release and rollback

After the invariant owner records an approved RFC decision, land tests first,
then update the ledger, test references, version and README as one transaction.
The expected code budget is at most +150 test lines, with no production codec
algorithm change, new flags or launchers. Documentation and configuration are
separate. Verify that the workspace discrepancy for this package is removed
without suppressing any other finding.

Before publication the transaction can be reverted as a whole. After releasing
`0.2.0`, removing either declaration needs the normal deprecation and major-version
process. A failing contract test blocks the declaration; it must not be resolved
by weakening a decoder, count bound, input canonicality check or test floor.

## Recorded approval and implementation

The repository owner approved this exact transaction and opening its RFC on
2026-11-09. The signature case precedes the ledger edit; all three candidate
invariant cases are registered. The package/manifest/guide now declare version
0.2.0. The hosted provider lane executes Debug then ReleaseFast, retaining its
original command. Fresh hosted acceptance remains pending; earlier candidate
provider-fixture execution is not full product proof qualification.
