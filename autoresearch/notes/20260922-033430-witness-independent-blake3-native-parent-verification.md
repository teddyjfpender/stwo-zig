---
title: Witness-independent BLAKE3 native parent verification
author: Teddy Pender
created_utc: 2026-09-22T03:34:30Z
---

# Witness-independent BLAKE3 native parent verification

Task: verify an owned parent proof using only a verifier-pinned key and public
claims; reconstruct all components and column geometry from the canonical typed
roster. Reuse core verification with capture and typed verifier adapters. Extract
the shared roster from test-only naming without changing its implementation.
Ownership transfer is explicit: the input proof is consumed on success and every
error path; successful output owns only a verified capture and public context.

Canonical problem is deterministic protocol replay and resource ownership, not
a new proof algorithm. Verification must not accept witness rows, prover plans,
prepared preprocessing columns, or prover-created component instances. Pin/root,
claim canonicality and exact global cancellation precede core verification. Use
a parent-specific claims domain. Qualify the existing real native parent through
this entrypoint, compare transcript endpoints, and reject mutated public claims,
key identity and roots without losing ownership. Production codec and stronger
security profile remain separate gates; no default migration yet.
