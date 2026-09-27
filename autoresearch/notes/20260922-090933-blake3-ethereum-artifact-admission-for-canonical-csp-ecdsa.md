---
title: BLAKE3 Ethereum artifact admission for canonical CSP ECDSA
author: Teddy Pender
created_utc: 2026-09-22T09:09:33Z
---

# BLAKE3 Ethereum/CSP ECDSA artifact admission

Extend the shared Ethereum leaf codec over canonical core suites: immutable
v2/BLAKE2s and new v6/BLAKE3. Reuse metadata section encoders. Identity framing
must bind the selected artifact version internally as well as in the outer header;
retain v2 bytes and give v6 a distinct metadata hash domain. Select the codec
from the trusted Engine suite in CSP prove/verify, never from untrusted bytes.
Existing Ethereum prover/verifier already carry engine-selected proof types.

Qualify the actual ECDSA precompile guest at canonical 70 queries/26 PoW bits,
including fresh decoding/verification, input/ELF/proof mutation and low-S routing.
Add versioned identity cross-decoder tests. Record raw timings as one sample,
not an A/B speedup or full CSP suite. Production defaults and Metal remain pending.
