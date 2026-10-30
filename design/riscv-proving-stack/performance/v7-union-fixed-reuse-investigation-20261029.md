# Reusing fixed polynomial storage in the complete original STARK

The initial investigation below led to an implemented CPU reuse path. The complete single-window union now leases available original fixed polynomial storage and recomputes only the merged Merkle tree. It falls back explicitly when resident LDEs or coefficients are unavailable. The original five family stages already committed those same columns separately.

Canonical 70-query/26-bit-PoW qualification on the 20,495-cycle guest passed **11 tests**: the required-reuse route and raw-rebuild oracle produced identical 5,841,554-byte STARKs and every physical claim matched. Fresh verification ran after producer destruction. See [qualification receipt](v7-union-fixed-reuse-qualification-20261029.json) and its saved log. The shared-host single pair measured 4.266 versus 4.286 seconds; this does **not** establish a substantive speed improvement. The optimization removes duplicate fixed-polynomial work and storage but does not reduce column count or the original verifier's opening work.

One assumption from the initial investigation was incorrect: the native physical collector explicitly drops coefficients. The first required-reuse gate rejected that state. `commitPhysicalWithFixedRetention` now provides an explicit opt-in for fixed coefficients only; the old collector defaults and main-column retention remain unchanged. The union fixture uses that option. Compact/restored sources still have an explicit fallback.

## Existing storage and safe reuse boundary

`src/prover/pcs/scheme.zig` defaults to retained coefficients and materialized extended columns; `compact_polynomial_storage` defaults to false. Active caller, ordinary ROM, compact lookup and joint-memory first rounds retain coefficients. The native physical collector requires the opt-in above. A restored or future compact stage must be inspected rather than assumed to have those buffers.

`CommitmentTreeProverForBackend` stores `columns`, optional `coefficients`, the Merkle commitment and allocation ownership. Its `share(source_allocator)` and `retainShared()` retain an immutable whole tree. `CircleCoefficients.initBorrowed` creates a non-owning coefficient descriptor. These supply the polynomial representation needed by the merged proof without another interpolation or extension.

The implemented constructor/helper follows this ownership boundary:

1. Admit each original fixed root, source PCS configuration, exact raw/extended column logs and canonical family order. Preserve all original roots in the execution epoch.
2. Acquire one shared-tree lease per original fixed tree and retain its `SharedHostBudget` where applicable. The memory stage's allocator differs from the enclosing union allocator.
3. Allocate only the concatenated column/coefficient descriptors, borrowing existing materialized values in native/caller/ROM/lookup/memory order.
4. Compute a **new** merged Merkle commitment using `Cpu.commitMerkle` / `MerkleProverLifted.commit`. Original Merkle roots cannot simply be combined: the merged leaf layout and lifting differ. Hashing remains necessary.
5. Adopt the new commitment through `initPrecommittedWithTeardown` and `Scheme.appendCommittedTree`. A small explicit lease owner must free new descriptors and Merkle layers, then release source-tree and budget leases. It must not free borrowed field buffers. The current backing/teardown primitives can express this, but the constructor should expose borrowed ownership explicitly rather than relying on an undocumented empty-backing sentinel.
6. Keep independent verifier fixed reconstruction unchanged. Prover-side reuse is not fixed-root verification authority.

Allocation failure must unwind only acquired leases. Regression coverage must compare merged roots and complete proof bytes against the raw route, destroy original stage owners before sampling/proving, test mixed source allocators, and inject failure at every allocation boundary. Wrong root, configuration, column order and log size must reject before adoption.

## Compact and incomplete storage

The current Merkle API consumes materialized column slices. A coefficient-backed column with empty `values` cannot be passed to it as though it were a resident LDE. An initial fast path should require all fixed columns to be materialized with their original coefficient views; otherwise use the unchanged raw route explicitly. A later path can call `extendCoefficientColumnsByGroupForBackend` for only missing LDEs, avoiding interpolation but still charging extension and temporary residency. Streaming Merkle construction could bound that materialization. None of these paths is zero work.

A destination tree has one optional coefficient array for the entire tree. Partial coefficient availability therefore needs explicit fallback or missing-column reconstruction; silently dropping all coefficient views would shift interpolation into later quotient/sampling work.

## Available measurements and limits

The 20-cycle complete-union gate recorded 186.298 ms for **all original setup**, 2.240752 s for union proving and 2.715008 s for the five-proof oracle, with 1.054472 s fresh verification. These are shared-host diagnostic timings. The logs do not isolate the merged fixed commitment, so they do not establish a numerical saving from this proposal. Original setup includes execution, witness preparation and all first commitments; it is not a fixed-FFT measurement.

The original source path is `complete_union_proof.fixed` -> `commitBorrowedStreaming` -> column preparation -> Merkle construction. The new path is `block_v7_union_fixed_reuse_v1.tryAppend` -> borrowed descriptors and retained leases -> merged Merkle construction. New-root hashing remains necessary. Multiwindow adoption and reducing duplicate fixed columns are separate work; this qualified storage change does not establish an order-of-magnitude full-prover gain.
