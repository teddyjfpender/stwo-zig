# Recursive upstream claim/challenge/terminal columns, source batch v1

Status on 2026-09-26: root qualified18/18 focused nonproving checks, including all five new upstream behavior/ownership checks, preceding scalar/sample/inventory/matcher regressions and actual native/execution/owned/borrowed parent body generation. Exact log/source evidence is retained in `cpu-performance-gates-v1/direct-recursive-upstream-source-columns-v1.log` and `direct-recursive-upstream-source-columns-qualified-v1.json`. No guest, segment, STARK, device, or benchmark was run. This does not qualify a fresh recursive proof or all of ID14.

Canonical native and execution parent preparation now constructs allocation-owned committed columns directly for claim payloads, shared native samples, PCS challenge routes, public aggregate routes, and terminal coefficients. `blake3_upstream_source_columns_v1.ForSlots` emits one transient logical row into each admitted physical column domain and stores the compact fixed tail once. Indexed emission preserves claim/sample order even when transcript receipts are reversed. Missing/duplicate/late indices reject; construction masks are freed before publication.

The native path calls `prepareColumns` in `blake3_native_parent_preparation.zig`. The execution payload/challenge defaults are direct, and `blake3_execution_parent_preparation.zig` explicitly selects the direct terminal constructor. `blake3_native_parent_rows.appendSources` and `blake3_execution_parent_sources.appendInputs` append borrowed immutable column views in the original cohort order. Nested packed public terms have a separate immutable owner; appending their outputs cannot invalidate the existing sources used by inventory counting or emission.

This changes source storage, not the AIR, scalar/secure bus schedule, public terms, final commitment geometry, key grammar, or verifier authority. The same row constructors and exact fixed-tail checks feed the canonical final parent columns. Legacy row constructors remain parity oracles; they are not selected by these canonical parent preparers. The new source fixtures deliberately construct consistent typed graph/source schedules without claiming fresh child proof authentication.

Temporary claim/sample maps and arithmetic use-count vectors use freeing scratch ownership. Native payload node tuples remain live through sample/public joins, then are released before assembly. Direct owners and legacy arenas have separate error cleanup; fallible subowners are fully constructed before publication. The public-link evaluation also has an error cleanup guard after construction. Borrowed subviews validate physical logs, capacities, and logical spans before counting or emission. The existing execution-parent missing-producer/fail-atomic fixture now mutates the direct owner's compact schedule coordinate, rather than indexing an empty legacy slice.

For N logical rows and P = max(2, nextPowerOfTwo(N)), source main/fixed payload storage is:

| Cohort | Legacy live + dense fixed | Direct physical main + compact fixed |
| --- | ---: | ---: |
| scalar wire (12) | 56N bytes | 4P + 24N bytes |
| QM31 pack (11) | 96N bytes | 16P + 32N bytes |
| field-byte encoding (10) | 264N bytes | 96P + 36N bytes |

These are storage formulas, not measured speedups or total peak-memory guarantees. Construction masks and scratch have temporary cost. Upstream owners overlap the final output columns until the existing release phase. Arithmetic graphs, schedules, and evaluations still exist; their work is unchanged.

Qualification source: `src/frontends/riscv/block_v5_recursive_upstream_columns_test_root.zig`. Filter `upstream direct source columns` selects five new nonproving tests covering native/execution claim/challenge/terminal row and compact-fixed parity, public-source scatter, nested attachment parity, allocation-failure cleanup, duplicate/missing/out-of-range emission, malformed borrowed views, changed claim/sample/export values, changed receipt coordinates, mixed direct/dense storage, and nested source mutation. The root also imports the previously qualified scalar/inventory/matcher tests and the actual native/execution/owned/borrowed parent-body codegen fixture. Parent-body codegen is not a fresh recursive proof.

ID14 remains incomplete. Genuine canonical materializers still include:

- `blake3_native_fri.zig`: terminal answer scalar sources/destinations and dense fixed rows.
- `blake3_native_queries.zig`: query scalar routes and encoded byte rows with dense fixed copies.
- `blake3_native_openings.zig`: authenticated opening scalar routes and fixed rows.
- `blake3_projection_links.zig` and `blake3_stark_paths.zig`: path/query packing, byte encoding, readonly/adapter sources, and their underlying path builders.
- `blake3_native_public_sources.zig`: public boundary coordinate rows and embedded sum rows.
- `blake3_native_root_nonce.zig` and `blake3_execution_roots.zig`: root/nonce word routes.
- Remaining non-hash transcript/path control, routing, and challenge preparers upstream of the common final column assembler. Prior compact hash-column work does not remove these sources.

The next ID14 slice must migrate those actual consumers while preserving their authenticated source inventories and independent typed receive checks. This batch does not redefine ID14 as only claim/challenge/terminal storage.
