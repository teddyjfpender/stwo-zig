# S31 proof privacy — 2026-10-09

## Problem and scope

`public` and `private` select the public ABI. They do not randomize the witness
trace. The S31 v1 prover currently finalizes and pads a deterministic circuit,
then publishes trace openings, OODS evaluations and LogUp claimed sums. A
private parameter alone is therefore insufficient for confidential payments.
Returning a private value as a public result also discloses it intentionally.

Add an experimental `blinded circuit` declaration, lowered to optional
`proof_mode: "blinded"` in relation v1. An ordinary `circuit`, or JSON without
the field, keeps the existing transparent mode and canonical hash. Unknown
modes fail parsing. The annotation belongs to the circuit, since specialized
pure functions share its proof; input visibility remains an independent choice.

This is a blinding implementation contract, **not a proof of zero knowledge**.
Use the pinned upstream random-row construction without changing the AIR or
PCS. A complete privacy argument must also cover lookup multiplicities,
interaction sums, OODS, FRI openings, hash assumptions and repeated proofs.
Proof non-determinism and successful verification do not establish that claim.

## Invariants and rejected states

- Initially support only `gate`, FRI fold step 1, 70 queries and log blowup 1.
  Reject every chip, sparse, direct and SHA lowering, fold step 4, and all
  recursive/fold commands for a blinded circuit, including direct Zig entry
  points. No implicit fallback is allowed.
- After finalization, before power-of-two padding, append 80 rounds of
  `circuit.common.zk_blinding.addZkBlinding`: 70 query openings plus the pinned
  upstream allowance of 10 non-query M31 openings. All five witness gate kinds
  receive rows, even if absent in the original source.
- Every proof uses a fresh, private 32-byte OS-seeded CSPRNG seed, expanded by the
  existing ChaCha20 implementation. No seed argument, deterministic witness
  derivation, exported seed or zero-seed fallback exists in the prover.
- Topology-only builds use a dummy seed: values cannot affect row counts,
  addresses, source maps, public words, keys or topology. Check value/topology
  equality after blinding and after padding.
- Bind the mode into the canonical IR digest with a versioned domain prefix
  while retaining the old encoding for transparent programs. Use a distinct
  blinded profile/key schema, with the exact blinding policy in the sealed key,
  cost report and manifest. Recompile the blinded topology in key validation.
- A verifier checks the declared topology and budget. It cannot certify that
  an adversarial prover sampled fresh randomness. Privacy requires an honest
  prover, a trusted compiled verifier and a public statement chosen by the
  application. A manifest is an integrity check, not a trust anchor.
- Blinded packages omit recursive keys/capabilities. Unblinded outer circuits
  can expose their child proof, so wrapping is not covered by this first mode.
- The hash-payment example requests blinding and uses the full gate profile.
  Its public receipt, nullifier, notes and context retain their protocol roles.

## Ownership, cost and implementation boundary

The proving call owns the stack seed and the circuit contexts; the contexts
own added gate/value arrays through their existing allocator. Seed bytes are
not serialized or included in diagnostics. Topology builders allocate no
random witness values. The five new raw gate counts are public and constant.
Blinding adds 20 variables and 14 QM31 rows per round, plus one row per round
in each other gate kind. Subsequent padding can cross a power-of-two boundary.
The full profile also commits its existing fixed tables, so payment proof cost
must be measured again; sparse-profile measurements do not apply.

Keep policy/entropy/topology helpers in a small runtime module, and package
policy validation in a small Python module. The existing oversized runtime and
package CLI receive only integration edits; this change does not add a second
proof system or expand their recursive implementations.

## Evidence and release gate

The authoritative construction is `starkware-libs/proving` at
`5a7c5ede4299c91a61df19a07cba4f7502c14230`,
`crates/circuit_common/src/finalize.rs`. The existing R5 fixture authenticates
its random stream, values and gate topology; run `circuit-parity-r5`.
The query budget follows the pinned `NON_QUERY_INFO_LEAK = 10` convention in
the circuit verifier, restricted here to fold step 1.

Test legacy hash stability, mode-sensitive hashing, invalid modes/profiles,
seed-independent topology, distinct values, circuit validity and unchanged
public statements. Native acceptance must prove the same witness twice with
different commitments, reject wrong statements/corrupt proofs, reject a
transparent proof under the blinded key, and reject malformed sealed keys even
when their source digests are retained. Package validation must reject policy
stripping, changes and unsupported recursion metadata.

Keep the PR a research draft until the new package path has complete pinned
Rust proof interoperability evidence and the complete transcript has a reviewed
privacy argument. Do not claim production confidentiality or a security level
from these tests.
