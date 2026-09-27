---
title: Real native V2 segment proofs through the BLAKE3 engine
author: Teddy Pender
created_utc: 2026-09-22T01:27:11Z
---

# Real native V2 child proofs using the BLAKE3 suite

Task: qualify the canonical typed RISC-V proving/verification path with BLAKE3
proof commitments and Fiat-Shamir, beyond the standalone recursive AIR fixture.
Existing prover APIs are generic over Engine and already type captures/proofs
through Engine.Hasher. Transfer the existing BLAKE3 suite through that boundary;
do not fork witness generation, AIR construction, statement semantics or verifier.

Reuse the nonfinal/final native V2 segment test as one engine-parameterized helper.
Select a coherent BLAKE3 channel/Merkle hasher pair through recursion.engine and a
verifier-safe protocol module. Make postcard proof serialization use that engine's
Hasher rather than the default alias. Share protocol types with BLAKE3 fixtures.

The V2 program/state/sparse-memory commitments and guest Poseidon semantics remain
as specified by the existing statement. Only proof PCS/Fiat-Shamir is selected here.
This is not removal of all Poseidon or production default/key activation. The test
uses one query and zero PoW solely for qualification, not CSP canonical parameters,
production soundness, throughput or a speed comparison.

Run real execution, nonfinal/final proof generation, postcard roundtrip, independently
verified capture, rejected malformed statement with unchanged capture sentinel,
and final completion verification. Run the original default-suite nonfinal/final
helper as a regression. Keep tests focused and builds serialized. Production child
capture adaptation into the BLAKE3 parent, key/artifact admission, Metal and
parent-of-parent remain after this native boundary is qualified.
