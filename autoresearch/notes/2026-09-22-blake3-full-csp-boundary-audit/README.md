# Full CSP BLAKE3 publication-boundary audit — 2026-09-22

Current source inspection establishes that the broader runner cannot yet produce
an explicitly selected BLAKE3 software-workload suite. Running it unchanged would
measure the legacy products, not extend the completed BLAKE3 ECDSA qualification.
This changes the next action from launching a benchmark to migrating the regular
product artifact/report/verifier boundary.

Observed boundaries (snapshots retained):

- CPU and Metal product Deps bind their legacy integration engines directly.
- riscv_artifact/schema.zig fixes JSON schema 4 / riscv_proof_json_wire_v4, with
  a documented single BLAKE2s suite; preflight accepts only that version/mode.
- proof_adapter.zig emits that envelope and transcript_state_blake2s fields.
  Its receipt helper is an alias of the legacy receipt digest, so simply changing
  the engine would not give a BLAKE3-labelled, full-counter receipt contract.
- artifact_verifier.zig deserializes with prover.Hasher, independently of the
  supplied Engine, before verifying with Engine.Channel. Engine-generic proving
  alone does not make this artifact decoder suite-generic.
- Software CSP validation explicitly requires schema 4 and the v4 exchange mode.
- ECDSA's separate precompile path already validates BLAKE2s/BLAKE3 suite,
  transcript version, binary artifact version, and hasher id together.
- The full runner has no proof-suite selection flag. Backend selection alone
  does not select BLAKE3.
- The underlying regular RISC-V prover and verifier already have engine-derived
  proof types (ProveOutputForEngine / ProofForEngine); the remaining blockers
  identified here are chiefly the publication/product boundary, not evidence
  that regular RISC-V arithmetic must be duplicated.

Required integration sequence:

1. Add an explicit versioned software artifact suite contract. Preserve v4 bytes
   for existing BLAKE2s artifacts; give BLAKE3 an unambiguous new admission path.
   Reject suite/version/channel mismatches before proof decoding/allocation.
2. Serialize/deserialize via the admitted engine suite. Carry the canonical core
   typed transcript receipt into both benchmark and independent verifier output;
   never relabel the legacy receipt or truncate the BLAKE3 u64 draw counter.
3. Expose explicit suite selection in both product bindings and runner, and
   require every software/precompile/fallback row to match the requested suite.
   Keep authenticated Metal runtime admission attached to the selected engine.
4. Qualify one regular software workload end to end with wrong-suite, wrong
   input and tampered-proof rejection. Then run the full CPU/Metal CSP matrix at
   canonical parameters and record all results with exact product identities.

No full-suite benchmark was launched in this audit: current products would use
legacy suites. No changes to existing schema acceptance/defaults were made.
The original recursion and prover-owned Poseidon migration remain incomplete;
this audit does not narrow those goals or claim any new performance result.
