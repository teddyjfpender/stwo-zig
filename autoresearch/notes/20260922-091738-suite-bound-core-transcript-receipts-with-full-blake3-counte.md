---
title: Suite-bound core transcript receipts with full BLAKE3 counters
author: Teddy Pender
created_utc: 2026-09-22T09:17:38Z
---

# Suite-bound transcript receipts preserve full BLAKE3 counters

Move the immutable BLAKE2s v1 receipt algorithm to core and keep the product
wrapper's old bytes/API. Add a typed receipt (version, suite, digest); BLAKE3 v2
hashes an explicit domain, length-prefixed protocol ID, channel digest and u64
little-endian draw count. Dispatch only canonical channel types. No narrowing
cast from BLAKE3's counter and no legacy JSON field relabeling.

CSP ECDSA now uses caller-owned prove/verify channels, compares full typed receipts
from original proving and independent artifact verification, and returns the
receipt with its result. Preserve the old verification wrapper returning statement
identity. Validate independent Python BLAKE3 vectors including upper counter bits,
legacy vector parity, and canonical full ECDSA proof/verification. Reporting schema
and product default changes remain a coordinated subsequent step.
