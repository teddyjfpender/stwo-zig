---
title: BLAKE3 committed private hash composition problem match
author: Teddy Pender
created_utc: 2026-09-21T19:40:03Z
---

# Committed private BLAKE3 composition

Extend the existing proof fixture to an append-only four-component test roster:
G, XOR, public boundary, private input bridge, plus the existing two providers.
Reuse all arithmetic, interaction, commitment and verifier code. Generic fixture
assembly replaces manual three-component tuple construction; no production
roster or key changes.

Canonical copy-constraint composition: prove H(H(message)). Remove the first
hash's public digest boundary; its output emissions instead balance the second
hash's caller bridge. The intermediate digest is only witness data, never fixed
columns or verifier input. The first hash's canonical root output IDs are the
caller's eight contiguous word wires. The second graph uses a distinct namespace.
Only original message and final digest form the public statement.

Validation: real BLAKE3 STARK with independent preprocessing reconstruction,
core verifier acceptance and changed-final-digest root rejection. Retain prior
compression/public-message gates through the same generic proof harness. This
qualifies the bridge in composition, not a production child-proof source or
Fiat–Shamir/Merkle framing. Next remains production source/byte framing integration.
