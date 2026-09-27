# Typed routing for BLAKE3 memory nodes

Memory node framing now exposes left/right digest roles to the shared BLAKE3
frame router. Native hashing and routing consume the same serialization; generic
digest-only frame witness entry points reuse existing byte-route and full-hash
AIR. Core transcript payload admission stays restricted to its original frame
type. Memory frames also expose exact sizes and serialization for hash preparation.

The focused ReleaseSafe gate passed in 24 seconds (1 GB peak reported RSS).
Memory node checks cover native/witness digest agreement, fixed routing metadata
from placeholder children, full hash-wire closure with explicit child fixtures,
child-byte substitution and missing child role rejection. Existing canonical
transcript-frame and routed-frame allocation tests also pass after the shared
router extension.

This qualifies a memory-node component, not a tree proof or production commitment.
Private leaf-byte routing, path/tree aggregation, full-width public memory roots,
continuation snapshots and artifact/key integration remain outstanding. Guest
Poseidon semantics and existing production scalar roots are unchanged.

Qualification correction: the original focused root omitted the memory test import.
Its earlier green run did not qualify the memory tests. The corrected root now
imports them explicitly; the 2026-09-22 memory-path qualification reran byte-tree,
node, leaf and path checks successfully. See ../2026-09-22-blake3-memory-path/README.md.
