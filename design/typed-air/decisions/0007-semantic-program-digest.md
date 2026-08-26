# ADR-0007 — Domain-separated semantic program digest

**Status:** accepted
**Date:** 2026-08-04

## Context

The canonical logical manifest is a complete reproducibility and interchange
artifact, including source spans. Proof artifacts, backend receipts, caches,
and compatibility comparisons also need a compact program identity. That
identity should change for authored meaning while remaining stable across
allocator addresses, hash-table insertion accidents, and diagnostic-only source
movement.

Hashing Zig memory is not portable. Hashing the full manifest would make source
path or line-number edits look like AIR changes. Reusing a proof-transcript hash
domain would blur two different protocol objects.

## Decision

Define semantic digest format 1 as SHA-256 over the domain
`stwo-zig/typed-air/semantic`, followed by a fixed-width canonical projection of
a validated logical program.

The projection includes:

- record counts and topological value order;
- value types, operation tags, operands, immediates, and semantic input names;
- ordered constraints, their stable names, gates, roots, and categories;
- hint recipe ID/version, algorithm and exceptional policy, activation,
  bindings, and complete value paths;
- ordered effects, liveness, and access ordinals;
- function names, signatures, declaration order, and call records; and
- explicit inline-versus-relation-backed call strategy.

It excludes:

- source paths, positions, and primary-source spans;
- unused interned names or sources;
- hash-table state, pointers, capacities, padding, and allocator behavior; and
- descriptive hint recipe names whose typed ID/version is authoritative.

Counts are unsigned 64-bit little-endian integers. Typed references retain
their canonical unsigned widths. Union and enum tags are explicit switches,
never native memory representations. Validation completes before hashing, and
the digest operation allocates no memory.

Any change to the projection or hash algorithm increments the digest format or
uses a new domain. The empty-program digest is pinned as
`0a8ed93f815b86478c087ca82bdbc63f9fcd6d6d9a170c896ebf610f8c26459f`.

## Consequences

- Equivalent construction under different allocation and interning histories
  produces the same identity.
- Moving source files or lines does not invalidate proof-facing caches.
- Type changes, semantic names, declared effect order, hint binding metadata,
  and call lowering strategy change the identity.
- The manifest remains the richer audit/debug artifact; its bytes and the
  semantic digest intentionally answer different questions.
- Physical layout and protocol identities will be separate digests composed
  with this logical identity, rather than fields added ambiguously here.

## Rejected alternatives

- **Hash the in-memory arena:** rejected because pointers, padding, map state,
  and host representation are not program semantics.
- **Hash the complete logical manifest:** rejected because diagnostic source
  movement should not alter proof-facing program identity.
- **Exclude all names:** rejected because input, constraint, and function names
  are stable semantic interfaces used by authoring and external mappings.
- **Reuse a transcript/Merkle domain:** rejected because cross-domain hash reuse
  makes artifact substitution harder to audit.
- **Allocate a temporary encoding:** rejected because the same explicit stream
  can be hashed directly with a smaller failure surface.

## Revisit when

Typed relation events enter the arena, a physical layout digest is accepted, or
an external consumer requires a language-neutral semantic-encoding
specification with independent test vectors.
