# Native interaction prefix group review

Scope: CPU, ROM, LS, BINARY, SHIFT, packed SHIFT table and MUL interaction
scheduling recovered at `8261bc7c0`; relative-block correction `f283477c6`.
Equations, physical column layouts, transcript ordering and claims are unchanged.

The original helper's claimed line-complete grouping was false. For
log12/segment6/group0/row0 the actual circle permutation yields physical indices
`[0,32,16,48,8,40,24,56,4,36,20,52,12,44,28,60]`: four relative64B blocks, not
one. Other groups write those same blocks. This was a performance-model error;
the original segment partition and field-value semantics remain valid.

The correction uses 32 segments per group. The highest four segment bits vary;
the remaining low bits pair `g` with its bit complement. Circle-domain bit
reversal complements the segment bits on odd logical rows. Row offset `r` from
one half and `2^segment_log-1-r` from the other half therefore fill one relative
128-byte block. The group still keeps an independent logical prefix per segment.

This is ownership of **relative128B blocks**, not a hardware-cache-line promise.
Column bases are not guaranteed128B-aligned. The local M5 reports128B cache
lines, but a speedup still requires workload measurement. No locality multiplier
is claimed from the partition theorem alone.

The explicit regression covers118 supported geometries across logs5..23,
workers1/2/3/5/8/16/32, and the CPU/provider chunk policies. It verifies exact
segment partition, complete physical relative blocks and unique group ownership
against the actual core coset/bit-reversal functions. It checks every offset
through log14 and reproducible offsets plus endpoints above that. An independent
Python transcription also checked every row at log12/15/17.

The review found no semantic blocker in these mechanisms:

- Each segment/chunk has a unique writer; every worker owns its inversion scratch.
  Segment sizes remain at least CHUNK/GROUP_ROWS and a multiple of that block.
- Summaries are scanned in logical segment order. Correction uses the inverse
  physical permutation, adds preceding-total minus full-total, and writes
  disjoint physical ranges. Field association changes no value.
- Pool counts are bounded by the validated WorkPool maximum32 and available
  chunks/groups. Structured leases join submitted jobs before error unwind,
  complete both waves, and release reservations.
- Output and dictionaries remain provisional until generation, summary checks
  and correction finish. Metadata is released only after publication, leaving
  poles/allocation/submission failures retryable.
- ROM dictionaries use the same resident-fixed or retired tuple-derived
  denominator authority. The physical dictionary phase joins before the logical
  prefix phase; the CPU consumer validates retired ROM inverses independently.
- MUL keeps its existing schema5 degree3 geometry, function/BYTE interaction
  shapes, padding values and serial reference. No AIR constraint is removed.

Qualification runs are recorded in
`vectors/reports/rv64-word16-execution-20261101/native-prefix-group-layout-v1.json`.
Full proof parity and fresh receiver verification remain the integration gate;
whole-block performance must be measured after that gate passes.
