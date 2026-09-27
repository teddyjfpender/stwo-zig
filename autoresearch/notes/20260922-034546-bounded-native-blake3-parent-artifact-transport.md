---
title: Bounded native BLAKE3 parent artifact transport
author: Teddy Pender
created_utc: 2026-09-22T03:45:46Z
---

# Bounded native BLAKE3 parent artifact codec

Task: transport a native parent artifact without allowing proof bytes to choose
keys, schemas or allocation bounds. Canonical fixed header binds magic/version,
pinned key identity, twenty canonical QM31 claims and exact body length. Retain
the existing postcard proof body and allocation-free preflight parser. Derive
preflight geometry from the same canonical typed verifier components used for
verification, with raw 32-byte BLAKE3 hashes. Refactor component ownership once
rather than duplicate shape formulas. Encoding counts bytes before allocating;
decoding checks header/key/length/claims before proof allocation, preflights all
body lengths, then decodes and validates ownership.

This is bounded canonical serialization with O(wire bytes) scans. Existing
512 MiB proof transport cap applies. Reject truncation, trailing bytes, version,
key, noncanonical claims, config and oversized length prefixes. Roundtrip the
real parent through this codec and independently verify the decoded owner.
Proof serialization never changes Fiat-Shamir parameters or production defaults.
