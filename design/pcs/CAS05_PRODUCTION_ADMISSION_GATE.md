# CAS05 production admission boundary

The draft CAS05 verifier accepts a separate `S31CAS05` wire with outer version
6. The production PCS still uses `CommitmentSchemeProof(H)` with one legacy
`FriProof(H)`, and `CommitmentSchemeVerifier.verifyValuesImpl` builds quotient
FRI answers for `FriVerifier`. The production prover still builds a lazy
quotient provider and commits with `FriProver`. There is no tagged proof
container or production CAS05 dispatch in those paths.

| Boundary | Current behavior |
| --- | --- |
| Trusted verifier profile | `proof_preflight.Shape`, `Shape5`, and `ShapeFor(N)` carry a `proof_mode`; the default is `legacy_postcard` so existing callers retain their format. The profile must come from the verified statement, never proof bytes. |
| Legacy postcard preflight | Rejects the reserved `S31CAS05` prefix before reading a config or length. Otherwise runs the unchanged allocation-free structural parser. Passing preflight is not proof verification. |
| CAS05-selected profile | Checks the magic, exact outer version 6, reserved field, declared byte count, and maximum length without allocating; then returns `Cas05NotProduction`. A legacy proof, outer version 5, a truncated header, and a wrong declared length all fail separately. |
| Experimental verifier | `paired_sparse_cascade_wire.verifyAgainstStatement` remains separate. Its decoder and statement-bound verifier are not called by production PCS. |

The reserved-prefix check changes no released S31 proof bytes: the current
trusted postcard profiles begin with their configured PoW and FRI varints,
not `S31CAS05`. A future legacy profile whose valid postcard bytes could
begin with that prefix would require a new format decision before admission.

This gate prevents an accidental parser switch. It does **not** make CAS05 a
production PCS. Activation requires a trusted key and proof-container variant,
a prover and verifier dispatch with the full CAS05 transcript and source/line
commitments, an exact statement/claims binding, an end-to-end correspondence
test, and a proved conservative native soundness profile. Until then every
CAS05-selected production preflight fails closed.

Focused checks:

```sh
zig test src/core/pcs_test_root.zig --test-filter 'trusted mode keeps legacy' -O ReleaseSafe
zig test --dep stwo_core -Mroot=src/interop/postcard/proof_preflight.zig -Mstwo_core=src/core/mod.zig -O ReleaseSafe
```
