---
title: Native preparation scratch lifetime separation
author: Teddy Pender
created_utc: 2026-09-22T06:00:18Z
---

# Separate native preparation scratch from owned final rows

Task: release temporary graph-lowering and fusion storage at prepare return without
copying final rows again or weakening the owning handoff contract.

Source evidence: blake3_native_parent_rows.prepare currently gives one returned
ArenaAllocator to both Builder and temporary inventory/lowering/fusion work.
Nested arena deinit cannot reliably recover earlier allocations from that outer
arena, so scratch remains charged for the lifetime of the prepared rows.

Selected transfer: separate transient scratch and final-row ownership arenas, both
backed by the supplied budget allocator. Builder writes directly into the returned
arena; inventory, canonical lowering, fusion intermediates and indices use scratch.
Finalize Builder slices with its own allocator, never the transient allocator.
All error paths deinit both arenas; success destroys scratch before returning.
No algorithm, row layout, graph identity or proof parameter changes. Existing row
parity and post-owner-destruction proof checks cover dangling-borrow risk. Measure
retained preparation and peak tracked bytes with the full native gate. This is
lifetime separation, not full elimination of final buffer growth or all staging.
