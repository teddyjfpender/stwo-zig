---
title: Frame routing forwards native main-column hash emission
author: Teddy Pender
created_utc: 2026-09-22T08:24:14Z
---

# Frame adapter forwards native main-column destinations

Extend the existing frame builder with an explicit main-column mode. It borrows
G/XOR metadata ranges and forwards main columns to the canonical hash emitter;
routing, source/payload use receipts and boundary filtering remain shared. Mark
returned G/XOR rows as metadata-only in this mode, avoiding an implicit live-row
contract. Existing row-destination APIs retain their behavior.

Generated metadata is not trusted preprocessing. Fixed frame rows continue to be
constructed independently and compared at admission. Validate every main-column
range/shape before emission through the hash sink; returned frame arena must not
own borrowed metadata or columns. Smaller boundaries/routes remain frame-owned.

Mechanical destination forwarding, no cryptographic or parameter changes. Check
reconstructed rows against ordinary live frames, metadata against independent
fixed frames, routing/digest/use parity, lifetime after frame destruction and
malformed destination before writes. This is frame-level integration; group/draw
and parent orchestration still require forwarding and ownership transfer.
