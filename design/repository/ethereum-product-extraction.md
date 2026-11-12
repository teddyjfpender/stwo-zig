# Ethereum product extraction

Owner: `ethereum-statement`, @teddyjfpender. Delivery issue: [#336](https://github.com/teddyjfpender/stwo-zig/issues/336).
The contract and its recorded amendments are [RFC #352](https://github.com/teddyjfpender/stwo-zig/issues/352).
This note records the current extraction boundary; it does not replace that RFC.

## Destination and compatibility

The destination is `src/products/ethereum/statement`, with the six approved
`statement`, `runner`, `prover`, `frontend`, `cpu`, and `cuda` domains. The two
legacy build exports must reuse the actual frontend and CPU component Module
pointers. Neutral packages must never import the product. Existing profile IDs,
protocol bytes, canonical records, rejection ordering, resource ownership and
named test discovery remain acceptance requirements.

The old `backup/c4-product-ownership-partial-20261110` ref is preservation only.
It has no completed package/module DAG and is not an integration candidate.
Use its reviewed path mapping, not its obsolete imports or duplicate metadata.

## Private dependency cuts

The current prerequisite slice separates these existing shared authorities:

- `rv64/services/call_abi.zig` owns the original SecpCall, Sha256Call,
  Arith256ModCall, CurveCall and Event definitions. Their complete bodies are
  unchanged; the existing session exports alias that single definition. Compact
  tape, tape wire, RAM-word capture and boundary capture import these records
  without importing the product executor. The packet modules still require
  their separate ownership cut before strict placement can pass.
- `rv64_proof_artifact_support.zig` owns the original physical-cell accounting,
  exclusive-file write and durable summary replacement. Seventeen consumers use
  this shared owner directly; the Ethereum receipt keeps its existing callable
  aliases and owns its schema, chain checkpoint and proof/receipt transaction.
  Helper bodies and error/cleanup ordering are unchanged.
- The three previously approved RV64 primitive provider names forward to the
  existing Precompiles implementations. No algorithm is copied or moved back
  into the RV64 executor. The additive RV64 package version is `0.2.0`.

The additional `service_calls` and `rv64_proof_artifact_support` public providers
and four checkpoint input-signature changes require the separately requested
RFC amendment before publication. They are not installed by this checkpoint.
Additional contract changes discovered in the remaining closure need an exact
ledger and recorded decision too; the initial fourteen removals are not blanket
permission to remove other neutral APIs.

## Boundary checks and acceptance

The strict product-placement predicate and negative fixtures reject product
paths, including generated paths, and product identifiers on lower public
surfaces. Product-layer dependency validation rejects lower-to-product and
product-to-product edges. These layer rules are active. The placement predicate
is tested but is not yet part of the repository-wide acceptance call: enabling
it belongs to the complete relocation transaction, without an allowlist or
baseline. Its current diagnostic finds 218 placement violations. A clean
existing workspace audit is not strict P3 completion.

Local prerequisite checks execute the real capture/tape and tape-wire cases in
Debug and ReleaseFast, including malformed advice, allocation failure and all
service sidecars. Actual file publication tests cover existing-file refusal,
complete summary replacement and staging cleanup on failed publication.
The RV64 identity case pins the shared records and primitive module aliases;
the original primitive arithmetic/oracle cases remain independent.

These bounded checks do not qualify a complete product build or full proof.
Remaining delivery: complete the private service/packet and request/image cuts,
construct the product package and concrete component DAG, migrate every affected
consumer and discovery root, activate strict P3, and run final frontend/CPU
acceptance with semantic negatives and frozen Native proof identity. No GPU,
performance, release or whole-extraction completion claim follows from this
prerequisite slice.

## Budget

The entire C4 transaction retains RFC #352's maximum +800 net source lines,
including tests/build/compatibility wiring. Moves receive no subtraction credit.
New flags and scripts are zero; documentation and configuration are separate.
The private cuts protect shared ownership and failure semantics; rollback must
restore their original aliases, consumers and tests together.
