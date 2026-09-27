---
title: Join full-STARK transcript and arithmetic
author: Teddy Pender
created_utc: 2026-09-21T22:46:38Z
---

# Join full-STARK transcript and arithmetic

Previous turn: progress; native full-STARK composition/DEEP/FRI now share one
arithmetic proof, while transcript is a separate proof. Task: put the complete
transcript and all three arithmetic graphs into the same parent fixture.
Canonical match: heterogeneous typed component composition using the existing
proof-gate roster and transcript witness builder; no new hash or field algorithm.
Extract prefix preparation from its standalone proving wrapper. Merge its rows
with arithmetic rows, using independent fixed reconstruction and disjoint wire
namespaces. Replace the special-cased observer with the composition observer so
there is one recursive fixture assembly owner. Keep the single-graph regression.
Complexity linear in prepared row inventory; no speed prediction. Values remain
public fixture statement inputs from one native capture. Merkle authentication
paths and production profile/key admission remain required for a full verifier.
Validate complete CPU proofs, native transcript counter agreement, substituted
composition-root rejection and independent fixed-key rejection. Use two focused
serialized ReleaseSafe proof gates; do not run broad suites.
