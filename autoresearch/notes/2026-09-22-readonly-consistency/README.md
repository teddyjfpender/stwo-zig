# Sparse read-only consistency for reusable lifted openings

Implemented and qualified two typed AIRs. No existing alias enforcement has been
removed; the complete parent still uses the earlier capture-dependent sharing.

`readonly_consistency` consumes a multiset of (table, index-low16, index-high16,
value, 0, 0) entries in sorted order. A separately authenticated fixed-rank chain
binds each previous index/value to the preceding row. Four byte equations and
three boolean carries enforce nonnegative integer gaps without u32 overflow.
All current/previous/gap bytes use the canonical byte-pair range provider. A
zero test on the gap-byte sum (at most 1020) requires equal values at equal
adjacent indices. Only rank zero is exempt from matching the zero sentinel's
value; its input sentinel is separately anchored. Fixed fields are enable,
first-row flag, table/chain namespaces, rank and next-rank use count.

Shape: 19 main / 6 fixed columns; 10 direct constraints, 9 relation events,
5 interaction batches / 20 columns, maximum degree 3. Identity:
`78428ee7716d1956a5725eb6383fbff7ed833250401a83a48b9c4f66372e4c7f`.

`readonly_input` consumes a bounded four-byte index port and a scalar value port,
then emits the corresponding two-limb table tuple. Its input provider must bind
and bound the bytes. Source ports/table identities are fixed; index and value
are private. Shape: 5 main / 6 fixed columns; no direct constraints, 3 relation
events, 2 interaction batches / 8 columns. Identity:
`79d8d1f12a6892a82e5d7ac54bc0b5ef4f1f32771e0e1b26e27c7866852a797d`.

This is sparse read-only consistency via sorting and multiset equality. It does
not constrain indices to be consecutive. Host sorting costs O(q log q), with
O(q) rows/storage per column. Full u32 indices use two limbs so indices at or
above M31's modulus cannot alias zero. External namespace separation, complete
rank scheduling, input multiset authentication and bounded index producers are
composition requirements, not claims established by a row in isolation.

Validation: serial ReleaseSafe final batch exited zero, 8/8 steps, 3/3 tests.
Two unit tests: 482 ms / 2 MiB (compile 5 s / 643 MiB). Complete CPU proof:
2 s / 346 MiB (compile 20 s / 1 GiB). These are qualification diagnostics, not
speed measurements. Earlier sorted-table-only proof also passed before joining
the input adapter (initial qualification log). Zero-digest bootstrap runs emitted
the semantic identities; these expected mismatches are retained in evidence.
An initial build declaration referenced the framework module before declaration;
it was moved after module creation before AIR qualification.

Tests cover full u32 endpoints, cross-byte carries, equal-index duplicates,
conflicting duplicate values, descending rows, constrained initial sentinel,
zero padding, namespace errors, typed identity/export, source tuple fields,
fixed-row invariance and byte-range aliases. The complete proof consumes six
unsorted input pairs (including duplicates, index 0, 256, 0x7fffffff and
0xffffffff), routes them through the adapter and verifies the sorted table with
independent preprocessing. A changed public input's preprocessing is rejected.
Direct equations alone admit a crafted byte-256 representation; the typed range
lookup excludes it, and the unit test records that distinction explicitly.

Next integration: derive projected index bytes from authenticated DEEP query
bits, preserving native parity projection. DEEP already constrains these bits
boolean in pcs_deep_circuit_build.zig. Reuse existing linear arithmetic and QM31
coordinate packing to assemble bytes; do not reduce a full u32 index into M31.
Share projection work by (query, column log size) where geometry allows. Route
per-opening scalar producers into the adapter, add sorted rows per column with
count-only fixed ranks, and remove host-dedup producer IDs only after the full
parent proof passes. Existing namespace/count/error checks must remain.

Production capacity/key admission, Metal, parent-of-parent and matched end-to-end
performance remain unfinished. This proof is a consistency fragment, not a
reusable production parent key or a Poseidon migration. Formatting and
`git diff --check` passed. All build handles reached terminal exit; no broad
suite was rerun.
