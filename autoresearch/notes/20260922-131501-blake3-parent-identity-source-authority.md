---
title: BLAKE3 parent identity source authority
author: Teddy Pender
created_utc: 2026-09-22T13:15:01Z
---

# Parent identity source authority

The parent identity builder now validates the sealed BLAKE3 statement semantics
graph and derives every source node from its parent-scope input descriptors.
Parent scope must be active in all proof kinds. The builder replaces the base
row-11 schedule with one preserving graph fanout plus exact packing consumers;
it does not create an additional statement-word consumer. Circuit validation
checks graph structure, descriptor assignments, fanout and the pinned identity.

Focused ReleaseSafe qualification passed in 18 seconds (995 MB peak RSS).
The test verifies all 525 source assignments, preserves every unrelated binding,
checks added multiplicity and changed preprocessing authority, and rejects a
mutated graph node assignment. Earlier input-chain and native identity checks
also remain in the focused gate.

This creates a production-oriented assembly entry point but is not yet connected
to the recursive prover. It currently assembles one identity purpose per graph
instance. Joint job/statement hashes require combined fanout before integration.
Private hash assembly, digest output binding, artifact/key admission and remaining
memory/continuation commitments are still outstanding. No speedup is claimed.
