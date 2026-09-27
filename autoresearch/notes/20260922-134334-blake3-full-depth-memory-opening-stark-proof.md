---
title: BLAKE3 full-depth memory opening STARK proof
author: Teddy Pender
created_utc: 2026-09-22T13:43:34Z
---

# Full-depth BLAKE3 memory opening STARK proof

Added the dedicated test-riscv-blake3-memory-path gate, explicitly registered in
the product catalog and a dedicated root. It proves the private leaf bridge,
all 30 memory-node hashes, private sibling word rows, byte routing and lookup
tables. The public fixture pins the input byte at an alternating-bit address.
Verifier preprocessing is generated without siblings through path.trusted.

The ReleaseSafe gate passed in 30 seconds build/run (1 GB reported peak RSS).
The shared proof gate commits/proves/verifies under BLAKE3 PCS and transcript,
checks live versus trusted preprocessing, and rejects a changed high-bit root
claim. The fixture uses diagnostic 8-query/0-PoW parameters, not production
security settings. Build/run duration is not a proving benchmark.

This is a real opening proof; it does not prove memory transitions or production
source admission. The byte producer is a public fixture. Remaining work includes
full-width production memory/continuation claims, authenticated snapshot and byte
sources, root transition proofs, artifact/key integration and multi-level CPU/Metal
recursion qualification. Production scalar Poseidon roots remain unchanged.
