---
title: BLAKE3 Span identity input routing
author: Teddy Pender
created_utc: 2026-09-22T13:09:33Z
---

# BLAKE3 Span identity input routing

The verifier-owned routing compiler now maps the exact native job and statement
preimages into the existing typed BLAKE3 byte-route AIR. Header words are fixed
constants; payload words consume canonical statement-byte endpoints. Hash graph
fanout weights are retained and each statement source records its required use
count. The compiler takes purpose and circuit coordinates, never statement values
or claimed digests. Aliasing circuits and overflowing source ranges are rejected.

The focused ReleaseSafe statement-codec gate passed (16 seconds, 962 MB peak RSS).
The new test checks every routed output byte against native encoding for both
purposes, all source use counts, destination graph wires and multiplicities, and
invalid caller ranges. Identity tests are also registered in broader recursion
roots. This is routing qualification, not a production recursive proof.

Remaining: connect canonical field-byte producers to authenticated statement
sources, assemble these routes with private hash witness rows, bind digest outputs,
and integrate production key/artifact admission. Memory and continuation
commitments still require migration. Defaults have not changed.
