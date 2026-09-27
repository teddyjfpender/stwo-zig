---
title: Private shared parent samples
author: Teddy Pender
created_utc: 2026-09-21T23:08:35Z
---

# One private sample source across DEEP, composition and transcript

Previous turn: progress; claims private and shared, samples routed to transcript
but still publicly anchored in composition and DEEP. Task: remove both sample
anchors while preserving one authenticated value across every consumer.

Canonical match: existing scalar-to-QM31 lookup packing with weighted fanout.
qm31_pack_wire already weights all four scalar consumes and the secure emit by
input 4; there is no boolean constraint. Expose validated positive multiplicity
helpers without changing equations/digest. Emit composition-use-count + encoder
read copies of the packed tuple; each DEEP scalar source supplies its local uses
plus this packing multiplicity. Bind DEEP nodes from sampled_value_word metadata,
not guessed offsets. Reject duplicate/missing coordinates and value mismatches.

No new AIR. Build a linear indexed input-read plan to avoid repeated source scans.
A sample's DEEP scalar sources are private, the secure producer comes exclusively
from packing, and transcript encoding reads it. Other public inputs remain.
Validate weighted tuple signs/counts, malformed multiplicity, actual full parent
proof and shared arithmetic regression with serialized focused builds. Preserve
all path/transcript checks. Reusable keys, query routing/rejection handling,
CPU/Metal and parent-of-parent remain incomplete; no speed claims.
