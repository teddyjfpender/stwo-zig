---
title: Native parent direct-column adoption qualified; preparation memory tradeoff measured
author: Teddy Pender
created_utc: 2026-09-22T08:54:16Z
---

# Native parent emits and adopts final BLAKE3 columns

Normal State.init now allocates combined G/XOR main domains from the validated
layout before emission. Owner initializes padding to zero and lends disjoint
transcript/path ranges; each adapter writes final main coordinates and separate
witness metadata. State.initRowOracle uses the same builder with logical-row
emission solely for differential diagnostics. No production caller selects it.

Final assembly admits owner allocator identity, exact metadata pointers/ranges,
mode flags and domain logs; independently checks generated metadata against fixed
preprocessing. It borrows main descriptors until all fallible assembly succeeds,
then transfers them without projection or copying. Error leaves column ownership
with State; success empties the owner's main descriptors. Metadata is released
when the intermediate State is destroyed. A second finish rejects. Existing
full-row source mode remains an explicit test oracle, never a metadata fallback.

Qualification: ReleaseSafe plan/native gates 8/8 steps, 5/5 tests. Plan 2 tests
8 s /10 MiB reported MaxRSS; native 3 tests 50 s /1 GiB. Owner allocation-failure
fleet checks partial initialization cleanup, zero padding and disjoint offsets.
Native checks mutate generated metadata and reject assembly while retaining the
same main pointer, retry successfully, verify pointer-preserving transfer, reject
a second transfer, destroy State, then compare every final main/fixed column
against the row oracle. Bounded threaded handoff uses the direct-column normal
entry. Both real parent proofs, codec roundtrip and independent verification pass.
No allocator leaks reported. Two compile-time const-view issues in the new owner
were corrected; terminal successful log is authoritative.

Preparation peak increased from 382,427,287 to 449,015,271 bytes (+66,587,984,
17.41%). It still passes the existing 512 MiB cap and 1-byte/64-MiB denials.
Handoff retention remains 130,557,704; worker peak remains 982,008,191. Final
column allocation now occurs earlier, while generated metadata still occupies
full zero-main Row buffers. Fewer materialization passes do not imply a lower
peak or measured latency gain. No end-to-end speedup claim is made.

Key remains 0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46;
artifact remains 116,382 bytes; original input inventory 8,376 is unchanged.
This gate is child q1/PoW0 and parent q8/PoW0, not production security qualification.

Remaining: measure full-profile recursion and its bottlenecks; compact generated
metadata if justified by that profile (do not weaken fixed admission or retry
ownership); core ordinary-RISC-V/CSP suite/artifact/default migration; production
keys, distinct-child and parent-of-parent proofs, Metal and parameter experiments.
