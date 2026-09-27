---
title: Regular verifier v2 carries typed BLAKE3 receipts and preserves legacy bytes
author: Teddy Pender
created_utc: 2026-09-22T11:54:10Z
---

# Regular independent verifier typed receipts — 2026-09-22

Added riscv_verify_v2 for software artifact v5/BLAKE3. Its transcript_receipt
contains suite blake3, version 2 and a canonical lowercase digest. It does not
publish a misleading transcript_state_blake2s field. The shared encoder accepts
a completed receipt, rejects unknown/mismatched suite/version/envelope tuples
before allocation, and dispatches v4/BLAKE2s through the unchanged v1 serializer.
The legacy encoder now also rejects non-v4 envelopes before allocation.

The independent artifact verifier obtains its receipt with core
transcript_receipt.fromChannel, replacing a fixed legacy digest call. That
canonical helper uses BLAKE3 protocol framing and full u64 draw count for BLAKE3;
legacy receipts remain unchanged. It only runs after proof verification succeeds.
No new hashing algorithm was introduced.

Validation: `zig test src/integrations/riscv_cpu/proof_adapter/verify_receipt.zig -O ReleaseSafe`
passes 2/2 tests. Existing exact JSON bytes remain pinned; a second test compares
legacy dispatch bytes, parses the v2 object and checks suite/version/digest and
absence of the legacy field. A zero-allocation FailingAllocator proves envelope,
receipt-version, unknown-suite and legacy-encoder mismatch rejection precedes
allocation. These encoder tests use synthetic receipt values, not a proof.

The producer still has a fixed serialization hasher and legacy prove/benchmark
report fields. Those must migrate together with v5 output and explicit product
suite selection. The BLAKE3 artifact-verifier instantiation has not yet been
compiled through a complete product proof; these tests qualify encoding and
admission only. Full software CSP BLAKE3 results remain pending.
