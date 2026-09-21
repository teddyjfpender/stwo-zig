# Leaf typed interaction kernel qualification

The existing typed framework exporter now emits interaction kernels for all 37 leaf components as well as all 29 parent components. Twelve additional kernels are needed after deduplication: the recursive profile grows from 93 to 105 additional exports (271 total with the 166 core exports). Every previous kernel name and declaration digest is unchanged. Source changes were reviewed before the generated shader, inventory, and coverage files were installed.

Admitted-AOT device tests passed 74 leaf cases and 58 parent cases: each component uses both 512 live rows and 509 live rows in a 512-row trace. Complete columns and claims match the CPU framework. Zero-denominator rejection preserves every destination column; successful retries match complete columns and claims again. Per-profile telemetry assertions account for 1,056 successful typed device dispatches. The existing native-table and resident-composition regression tests also pass.

The first test invocation incorrectly included the checksum sidecar's filename in the supplied digest and failed before dispatch. The corrected invocation hashes the manifest JSON directly. The failed invocation log is retained; it was not a kernel failure.

Shared transaction storage now lives in `recursion/transaction_storage_v2.zig`. Its body is identical after the direct manifest import binding, and the existing CPU entry point aliases it. Sixteen focused cohort/storage tests and fourteen ownership checks pass. Complete-proof qualification of this source checkpoint remains pending the leaf integration work.

**Leaf proof dispatch is not yet integrated.** This is component-level qualification, not an end-to-end speedup, complete-proof qualification, or production-security claim. The authenticated zero-column row-10 path should remain a fast path. The explicit generator interface and the remaining owning call sites are recorded in `integration-plan.md`; preserve domain audits, staged publication, and cached receipt validation when connecting the device writer. Do not generate CPU interaction columns merely to replace them with GPU output afterward.

`summary.json` records scope, counts, and AOT pins. `parity.log`, `export-review.json`, the ownership/storage logs, and `storage-transfer.json` retain the checks. `source.patch.gz` and `source-snapshot.json` freeze the code before this report and the later goal-document update. The admitted bundle remains at the local path in the summary.
