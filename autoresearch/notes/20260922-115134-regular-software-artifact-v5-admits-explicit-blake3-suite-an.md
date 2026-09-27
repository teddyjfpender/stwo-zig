---
title: Regular software artifact v5 admits explicit BLAKE3 suite and rejects mixed headers
author: Teddy Pender
created_utc: 2026-09-22T11:51:34Z
---

# Versioned software artifact suite boundary — 2026-09-22

The regular JSON artifact now defines an explicit suite/version mapping:
v4 + riscv_proof_json_wire_v4 selects BLAKE2s; v5 +
riscv_proof_json_wire_v5 selects BLAKE3. No field was added to legacy artifacts,
and default producer constants still select v4. Fixed-memory routing and full
structural validation share this mapping and reject mixed version/mode pairs.
requireProofSuite rejects a requested-engine mismatch using only header fields.

The adapter verifier is updated to require an exact Engine Hasher/MerkleChannel/
Channel triple and matching artifact suite before provenance, ELF reconstruction
or proof allocation, then deserialize with Engine.Hasher instead of the legacy
frontend alias. This adapter integration has not yet been instantiated in a
BLAKE3 product proof; its legacy receipt/report path still needs migration.

Validation: `zig test src/interop/riscv_artifact.zig -O ReleaseSafe` passes 20/20.
Coverage includes existing v4/legacy rejection and geometry tests, new v5 full
fixture JSON roundtrip and structural validation, mismatched version/mode, unknown
version, and requested suite mismatch without initialized proof fields. The v5
fixture is structural test data, not a cryptographically verified BLAKE3 proof.
The underlying proof bytes still need verification under the admitted suite;
changing both envelope tags cannot make a legacy proof cryptographically valid.

Remaining next steps: typed software benchmark/verifier transcript receipts,
v5 producer output, explicit product and runner suite selection, then full
regular software proof and canonical CSP CPU/Metal qualification. No product
suite default changed and no full software CSP BLAKE3 result is claimed.
