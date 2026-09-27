# Recursive parent column and scratch changes

Segment proving remains stopped. These changes remove concrete retained storage
and duplicate planning; no whole-proof time or RSS result is claimed.

- Pack cohort11 writes canonical committed columns directly. The input inventory
  borrows those columns and reconstructs a single row at a time, retaining no
  duplicate logical pack roster. Source-fixed admission and row order remain exact.
- Boundary cohort2 releases its initial inventory rows before arithmetic matcher
  scratch is allocated; remaining public terms append directly into its final
  committed columns. Initial source boundary rows still exist until inventory.
- Selector-use accounting reuses one maximum-sized graph counter vector, then
  actually frees it before input inventory. Inventory masks/use counters and
  execution external-input lists use the backing allocator and release before
  arithmetic construction. The earlier arena retained these allocations. External
  input collection now also cleans up after an allocation failure.
- Native PCS query candidates use a sorted sparse index of actual matches rather
  than an optional large candidate payload for every graph node. Query duplicate,
  missing, wrong-value and wrong-multiplicity rejection remain exact. One immutable
  matching plan supplies both counting and direct column emission; graph matching
  no longer runs twice. Only per-pass consumption masks are reset.

Twelve focused nonproving checks pass. They cover canonical column/fixed parity,
borrowed inventory source mutations and every allocation failure, sparse lookup
boundaries/duplicate rejection, a65,536-node authenticated graph with a query
island, all field/source mutations and exhaustive allocation failures through the
matched column lifecycle. The assembled native/execution parent and owned/borrowed
hash-column preparation bodies compile without being called (2-test gate, one
transitive test). Source hashes and logs are retained in
[cpu-performance-gates-v1](cpu-performance-gates-v1/).

Upstream source witnesses and scalar inventory remain materialized; full fresh
recursive proof qualification and end-to-end memory/time measurement remain
outstanding. This preserves the existing AIR schedules and proof encoding.
