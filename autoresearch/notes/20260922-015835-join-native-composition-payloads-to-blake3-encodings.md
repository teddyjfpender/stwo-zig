---
title: Join native composition payloads to BLAKE3 encodings
author: Teddy Pender
created_utc: 2026-09-22T01:58:35Z
---

# Native composition payload links

Task: join native VM sampled-value and transcript-aggregate scalar inputs to
canonical BLAKE3 felt payload encodings. Detailed physical claims remain distinct;
the existing VM graph constrains their sums to transcript aggregates.
Canonical problem: exact indexed join of graph bindings and transcript payload
receipts. Reuse the existing scalar producer, QM31 pack and field-byte AIRs;
no new algorithm or cryptography. Sources: native transcript adapter, VM V2
composition recorder, blake3_stark_prefix_fixture, qm31_pack_wire,
blake3_field_bytes and shared arithmetic use counts.
Inputs/model: authenticated composition graph and evaluation, native transcript
plan/operations/receipts. Linear graph scan and direct-index payload mapping;
O(graph nodes + sampled values + 28 aggregates) storage and work, excluding
existing authority validation. Public shape determines all fixed rows.
Constraints: exactly four canonical scalar coordinates per value, complete
nonoverlapping payload inventory, equality with transcript operation values,
matching trusted/live read schedules, exact multiplicities; zero witness cells
in fixed rows. Reject omitted, duplicate, out-of-range or reordered role mappings.
Transfer: graph scalar producers feed arithmetic and pack; pack feeds canonical
field-byte encoding; encoding emits exact transcript word read counts.
Validation: real verified BLAKE3 native capture, every payload coordinate matched,
missing/altered receipt and payload rejected, fixed rows independent of values.
No speedup prediction. Full joined parent/public-boundary/PCS joins remain open.
