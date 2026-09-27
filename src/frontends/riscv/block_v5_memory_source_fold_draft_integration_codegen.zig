//! Actual canonical collection and detached transport bodies retained only.
const std = @import("std");
const Job = @import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).Job;
test "source fold draft integration bodies: actual canonical Controller shared Job collect source seal and detached load" {
    inline for (.{ &@import("prover/block_v5_cpu_source_pages_v1.zig").collect, &Job.collect, &Job.collectWithOperations, &Job.collectWithDrafts, &@import("prover/block_v5_memory_source_fold_premix_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).replay, &@import("prover/block_v5_memory_source_fold_operand_store_v1.zig").load, &@import("prover/block_v5_memory_source_page_durable_loader_v1.zig").Loader.pageLoader }) |body| std.mem.doNotOptimizeAway(body);
}
