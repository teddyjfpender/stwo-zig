//! Actual default collection/replay/promotion bodies retained, never invoked.
const std = @import("std");
const Draft = @import("prover/block_v5_memory_source_fold_draft_pages_v1.zig");
const Collection = @import("prover/block_v5_memory_source_fold_draft_collection_v1.zig").Collection;
test "source fold draft buffer bodies: actual canonical collection current byte hashing cached grammar and rollback" {
    inline for (.{ &Draft.collect, &Draft.Reader.open, &Draft.Reader.next, &Draft.Reader.rewind, &Draft.Reader.deinit, &Draft.Owner.promote, &Draft.Owner.deinit, &Collection.init, &Collection.promote, &Collection.deinit, &@import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).Job.collectWithDrafts }) |body| std.mem.doNotOptimizeAway(body);
}
