---
title: BLAKE3 message-free paired identity preprocessing
author: Teddy Pender
created_utc: 2026-09-22T13:23:39Z
---

# Message-free paired identity preprocessing

Added fixed-row preparation for canonical inputs and trusted constructors for
single and paired parent identities. Verifier-owned plans and public digest
claims determine these rows; statement values are not accepted by the trusted
constructors. Shared encoding fanout is retained for both hashes.

The focused ReleaseSafe gate passed in 17 seconds (1 GB reported peak RSS).
For two distinct statements the new check compares every fixed column across
packing, encoding, routing, BLAKE3 G/XOR and digest/constant boundary rows against
live construction. Trusted constructors report no computed digest. Earlier joined
lookup and adversarial checks remain in the focused gate.

This qualifies metadata generation, not production key admission or a complete
STARK proof. Plans must remain verifier-owned; public digest claims still require
production statement/artifact binding. Production proof assembly, memory and
continuation commitment migration, and multi-level qualification remain pending.
