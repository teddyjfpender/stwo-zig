---
title: Recursion exact tuple aggregation problem match
author: Teddy Pender
created_utc: 2026-09-21T13:24:20Z
---

# Recursive exact tuple aggregation: injective compact keys

Task: aggregate signed QM31 weights by (domain, arity, ordered QM31 tuple),
retaining exact closure, malformed-range rejection, count and allocation-failure
semantics. Current implementation hashes every non-range tuple with SHA256 before
hash-table aggregation. Fresh stack sampling attributes substantial work to SHA
and hash-map probes; tuple projection is 1.284 s of the retained Metal parent.

Canonical match: exact group-by aggregation over small fixed-width keys in RAM.
This is an exact specialization, not a probabilistic sketch. Encode tuples of at
most seven base-field values into eight u32 words including arity; keep domain
separation in independent maps. A distinct map namespace retains the existing
SHA key for long/extension-field tuples. Encoding is injective; hash-table bucket
collisions still compare the entire key. Empty vs zero-padded tuples remain distinct.

Alternatives: sort-and-reduce adds retained event storage and O(N log N) sorting;
random fingerprints weaken exactness; direct-address tables need bounded circuit
IDs and memory accounting not yet established. Small-key hash grouping retains
expected O(N) aggregation and O(U) storage (N events, U live distinct tuples).
Expected-time caveat: hash-table collision behavior is not worst-case linear.

Transfer: avoid cryptographic digest preprocessing where the complete tuple fits
in the existing 32-byte key size. Reuse Zig std hash maps, no new dependency.
Source: local canonical TupleLedger and compact owner are the semantic oracles;
MonetDB/X100 https://ir.cwi.nl/pub/11098 supplies the broader data-movement/grouped
execution motivation, not a guarantee for this implementation. Complexity and
injectivity claims above are derived from the specified encoding.

Prediction: fewer SHA calls, identical closure reports, lower tuple-projection
phase (target >=25%) with unchanged proof hashes. Falsifier: no total-time gain,
large retained-memory regression, or any mismatch in closure/error behavior.
Test base and extension values, arity 0/7/8, domain separation, cancellation,
non-base weights and allocation failure; differential against canonical ledger.
This is local advisory research, not a judged board submission.
