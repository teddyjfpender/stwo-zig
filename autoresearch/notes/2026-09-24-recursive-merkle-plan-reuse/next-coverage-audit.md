# Next larger recursion investigation: actual native-parent device coverage

Current source distinguishes two catalogs. `recursive_framework_aot_test.zig`
explicitly enumerates `segment_leaf_catalog_v2.LOGICAL_ROWS` and
`detached_parent_catalog_v1.LOGICAL_ROWS`. Its coverage JSON labels its scope
`detached_recursive_leaf_and_parent`. The current native BLAKE3 parent instead
uses the twenty-AIR roster in `blake3_parent_row_storage.zig` through
`blake3_native_parent_producer.zig`. Generated coverage for the former must not
be represented as complete qualification of the latter.

The native producer explicitly calls `framework_parallel_interaction.generate`
for every cohort, regardless of Backend; there is no device interaction dispatch
in that loop. Its current immutable plan owns compact fixed metadata and the
preprocessed commitment. Integrating device interaction requires a correctly
admitted fixed-column view and reusable exported programs, with bounded staging
and failure-safe ownership. The ordinary BLAKE3 owner already has an authenticated
device path and is the implementation reference, not a separate arithmetic author.

The last canonical CPU parent spends roughly twenty seconds in the core proof,
plus interactions and commitments. Before claiming native Metal acceleration,
run this same canonical child/parent fixture with the Metal backend and capture
actual dispatch/fallback coverage by component. Generate/qualify missing kernels
from the native typed roster, and retain CPU/Metal proof-byte parity. The legacy
catalog's coverage flag and core CSP GPU tests alone do not establish this.

This is a source audit and next-action rationale, not a Metal timing result.
The persistent scheduling / PCS-DEEP fusion / final-layout / parameter goals
remain intact; no claim of whole-tree or parent-of-parent completion is made.
