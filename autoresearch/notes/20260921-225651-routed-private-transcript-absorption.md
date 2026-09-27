---
title: Routed private transcript absorption
author: Teddy Pender
created_utc: 2026-09-21T22:56:51Z
---

# Remove absorbed witness words from transcript preprocessing

Previous turn: progress; all native verifier checks share a fixture parent.
Audit: public absorption bytes, challenge outputs, rejection-attempt counts,
query outputs, path indices/root anchors and arithmetic inputs still enter
per-proof fixed data. A reusable key is not yet qualified.

Task: extend the transcript compiler with externally routed words/felts. Reuse
frame.preparePayload/trustedPayload and return owned per-operation wire-use
receipts. External field words must come from canonical field-byte AIR producers;
raw words need bounded byte producers. Reject caller namespace overlap before
building. Do not silently privatize public operations or remove their checks.
Canonical match: typed dataflow linking and reference counting, linear in payload
inventory. This is a required building block for private child-proof input
admission, not a claim that all fixed-data dependencies have been removed.
Validate changed payloads retain identical preprocessing, owned receipts survive
builder cleanup, allocation failures, alias rejection, native transcript parity,
and a complete proof with private raw words and canonical field-byte producers.
Keep the existing public transcript regression, using focused serialized gates.
