---
title: Transcript and full STARK-path main-column adapters qualified
author: Teddy Pender
created_utc: 2026-09-22T08:45:05Z
---

# Direct main columns through transcript and complete STARK paths

Query batches, bounded retry draws and fixed/raw draws now validate complete
caller column geometry and emit through canonical frame/hash sinks into logical
subranges. Public and private state, raw candidate exports, partial query blocks,
retry selection, counters and digest-use metadata retain their existing builders.

Transcript column mode borrows G/XOR metadata as non-resizable list views. All
operation branches forward column offsets; producer indices update metadata.
Its destructor frees only owned rows and receipts. The plan entry validates exact
fixed counts and independently fingerprints emitted metadata/receipts. Native
Planned.emitMainColumns shares final channel checks and transfers planning
ownership only on success. Failed emission preserves its owner.

Complete STARK-path preparation forwards each opening to group column emission.
Fixed rows remain independently owned. Borrowed live metadata is neither resized
nor freed; final used counts must match. Capture/root/leaf/direction validation
and query-read rollback remain in the shared builder. Native parent State still
uses row-mode emission; final allocation/ownership adoption remains outstanding.

Qualification (Zig 0.15.2 ReleaseSafe):
- Draw/query gates: 12/12 steps, 4/4 tests; query 1 s, bounded 2 s, draw 4 s,
  each reported MaxRSS 3 MiB. Differential checks cover output receipts, complete
  reconstructed rows, independent fixed suffixes, offset padding, lifetime and
  malformed shape before writes. Existing row allocation-failure fleets pass.
- Transcript plan: 2/2 tests, 8 s /10 MiB. Rich mixed transcript includes routed
  payload/root, private nonce, partial queries and bounded secure draw. Tests
  include all allocation failures in column emission, successful retry and
  semantic output-role mismatch. Native planning ownership uses column mode.
- Complete transcript sequence: 2/2 tests, 4 s /388 MiB in initial combined run.
- Native segment: 3/3 tests, 48 s /1 GiB, compile 1 min /6 GiB. Actual captured
  paths reconstruct identically after receipt destruction; fixed rows and opening
  sources match, malformed destinations preserve earlier columns, bad roots roll
  back query reads. Both parent proofs, codec, handoff and verification pass.

Two local issues corrected: a test poisoned padding and then expected its old
sentinel after retry (reset test sentinel); a path-local columns name shadowed
new destination argument (renamed query_columns). Initial logs are retained;
terminal successful rechecks are authoritative. No leaks reported.

Current row-mode parent measurement: preparation peak 382,427,287 bytes (+8),
handoff retention 130,557,704, worker peak 982,008,191, preparation cap 512 MiB.
Key remains 0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46;
artifact remains 116,382 bytes. These are diagnostic child q1/PoW0 and parent
q8/PoW0; no production or end-to-end performance claim.

Next: allocate combined parent G/XOR main domains and metadata, lend transcript
and path views, preserve independent fixed comparison and adopt owned columns
into final Prepared. Remove final G/XOR projection, then rerun native ownership,
mutation/proof/codec qualification and measure full-profile recursion. Core/CSP
suite and artifact migration, Metal, production keys and multilevel recursion
remain required; see ../20260922-core-blake3-migration-entrypoints.md.
