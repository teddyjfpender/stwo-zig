# ADR-0017 — Sectioned `compat-v1` family manifests

**Status:** accepted
**Date:** 2026-08-05

## Context

The logical manifest identifies authored typed semantics, but the production
shadow deliberately retains additional compatibility facts: historical source
node order, erased lookup records, committed column names, interaction
coordinates, runtime program shapes, and selector-specialized AIR IR v2 bytes.
A-011 requires one stable identity for each of the 17 current opcode families
without pretending that those legacy facts are ordinary typed effects.

A digest-only receipt would hide the changed object from review. A single
aggregate file would make one family impossible to inspect or replace in
isolation. Reusing AIR IR JSON would also make a formal wire format carry
runtime layout and degree-policy responsibilities it was not designed to own.

## Decision

Each family emits a canonical `STWAIRC\0` binary artifact at format version 1.
The header fixes the family tag and seven ordered, length-framed sections:

1. identity and authority revisions;
2. preprocessed, main, and interaction layout descriptors;
3. the canonical direct runtime program and named ordered roots;
4. the canonical lookup runtime program, typed event metadata, and batches;
5. complete direct, lookup, interaction, and quotient degree records;
6. ordered hint recipe identities; and
7. AIR IR v2 identities for every manifest opcode in the family.

All integers are fixed-width little-endian values. Strings and sections carry
u32 byte lengths. Stable enum tags are written through explicit switches rather
than in-memory representation. The identity section binds the opcode manifest
schema and Sail/legacy revisions, logical schema and semantic digest versions,
source-schedule digest domain, layout policy, runtime capability versions,
formal schema, global witness-layout digest, and domain-separated hashes of
every payload that has an independent identity.

The direct and lookup sections contain the complete canonical runtime bytes,
not only hashes. Direct roots additionally retain constraint IDs, stable names,
typed roots, raw source roots, and lowered roots. Lookup events retain relation
schema ID/name/version, role, liveness, signed numerator, tuple order, and
access ordinal; batches retain every physical interaction-column reference.
The formal section records opcode ID, mnemonic, byte length, and SHA-256 for
each AIR IR v2 body only after the typed and production emitters compare byte
for byte.

There is one `.stwairc` file per production-family enum value and one readable
TSV index in enum order. The index records whole-manifest and section digests,
geometry, export count, and maximum direct/interaction degree. Package tests
regenerate all artifacts in memory and require exact bytes. The standalone
`typed-air-manifest` build step defaults to fail-closed `check`; `update` is an
explicit option and publishes each replacement atomically.

Receipt encoding accepts separate result and scratch allocators. Normal use
passes one allocator. Allocation-failure tests keep the legacy production
symbolic builder on stable scratch storage—its established contract is
panic-on-OOM—while exhaustively failing every allocation introduced by the new
runtime and manifest encoding boundary.

## Consequences

- All 17 current family identities are separately reviewable and byte-pinned.
- The index makes degree, geometry, and section-level changes visible without
  treating binary dumps as the review interface.
- Runtime and formal identities are bound into the same receipt while retaining
  their distinct selector and wire policies.
- The artifacts describe the isolated compatibility path. They neither switch
  a production consumer nor authorize a protocol revision.
- The allocation-free A-012 parser validates each side independently and names
  the first changed field instead of reporting only a byte offset or digest
  mismatch. Detailed fields precede duplicate envelope digests in review
  order. Check fails closed; explicit update renders the same difference before
  atomic replacement.

## Rejected alternatives

- **Hashes only:** rejected because a reviewer could not inspect ordered roots,
  events, or physical mappings.
- **One aggregate binary:** rejected because unrelated families would share one
  replacement and one coarse failure location.
- **Canonical JSON:** rejected because it requires another escaping/key-order
  authority and makes binary runtime programs needlessly ambiguous.
- **Embed every AIR IR body:** rejected because those bodies already have an
  authoritative artifact workflow; exact comparison plus byte length and digest
  binds them without duplicating the formal corpus.
- **Use raw struct memory:** rejected because padding, enum representation,
  pointers, and host endianness are not protocol identities.

## Revisit when

An optimized layout is proposed, AIR IR v3 replaces the historical source
schedule, hints enter a migrated opcode family, or a production activation
receipt needs statement-global rather than local family coordinates.
