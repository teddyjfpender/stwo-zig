# ADR-0005 — Canonical logical manifest encoding

**Status:** accepted
**Date:** 2026-08-04

## Context

The logical AIR needs a byte identity that is reproducible across allocators,
clean builds, and harmless changes to interning-table insertion order. It must
also preserve order where order carries meaning, especially constraints,
hints, effects, and function declarations. Raw Zig memory and generic JSON do
not provide stable enum tags, integer widths, padding, or field order.

## Decision

Use the versioned `STWAIRL\0` canonical binary encoding for logical manifests.
Version 1 has:

- an eight-byte domain magic, encoding version, and logical-schema version;
- fixed-width little-endian unsigned integers;
- explicit stable tags for every union and enum variant;
- length-prefixed byte strings and reference lists;
- topological node order and declared record order;
- source paths and stable names resolved to their bytes instead of serialized
  arena IDs; and
- structural validation before the first byte is written.

Arena hash tables, capacities, pointers, unused interned IDs, padding bytes,
and iteration order are not serialized. Effects remain in declared order; the
serializer never sorts data whose order is semantic. A breaking change to any
tag or field sequence increments the encoding version.

## Consequences

- Clean constructions have a compact byte-for-byte comparison surface.
- External Haskell, Rust, Lean, and tooling implementations can consume a
  fully specified primitive encoding without matching Zig layout.
- Source/name interning strategies may change without manifest churn.
- Source spans are present for diagnostic reproducibility; the later canonical
  program digest may select a narrower semantic projection.
- Version 1 is write-only until a real external consumer justifies a decoder;
  a decoder must validate rather than reconstruct unchecked arena state.

## Rejected alternatives

- **Raw struct serialization:** rejected because padding, host endianness,
  enum layout, and pointers are not protocol data.
- **Canonical JSON as identity:** rejected because number representation and
  generic object writers add a larger, easier-to-misimplement identity surface.
- **Sorting every record:** rejected because effect and constraint order is
  intentionally observable.
- **Serializing numeric name/source IDs:** rejected because those IDs reflect
  an implementation cache, not logical meaning.

## Revisit when

Revisit the field set when relation schemas, calls, hint bindings, or layout
metadata enter the logical schema. Extend by versioning; never reinterpret a
published version in place.
