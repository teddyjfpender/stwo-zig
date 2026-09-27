//! Actual default leaf/node and explicit cache/stage bodies retained only.
//! Taking addresses performs no commitment, proof, file I/O or capture.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
fn Bodies(comptime kind: @import("prover/block_v5_memory_source_page_semantic_columns_v1.zig").Kind) type {
    @setEvalBranchQuota(500_000);
    const Factory = @import("recursion/block_v5_memory_source_page_recursive_fixed_roster_v1.zig").ForKind(kind).ForBackend(Cpu);
    const Stage = @import("prover/block_v5_memory_source_page_recursive_stage_v1.zig").ForKind(kind).ForBackend(Cpu);
    const Scope = @import("prover/block_v5_memory_source_page_leaf_catalogue_v1.zig").Scope(kind);
    const Capture = @import("prover/block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(kind);
    const Leaf = @import("recursion/block_v5_memory_source_page_forest_leaf_v1.zig").ForKind(kind);
    const Checks = @import("prover/block_v5_page_recursive_expected_setup_v1.zig").ForKind(kind);
    return struct {
        fn keep() void {
            inline for (.{ &Factory.deriveKeyAndScheduleForPolicy, &Factory.deriveKey, &Checks.ForBackend(Cpu).derive, &Checks.requirePrepared, &Stage.publish, &Stage.publishFromVerifiedCapture, &Stage.SetupCache.provePreparedExpectedConsuming, &Stage.SetupCache.provePreparedConsuming, &Scope.expectedClaims, &Scope.decodeOriginal, &Capture.verifyBorrowed, &Leaf.verify }) |body| std.mem.doNotOptimizeAway(body);
        }
    };
}
pub export fn stwo_page_expected_setup_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    Bodies(.raw).keep();
    Bodies(.fold).keep();
    inline for (.{ &@import("prover/block_v5_memory_source_page_forest_policy_owner_v1.zig").ForBackend(Cpu).build, &@import("recursion/block_v5_memory_source_page_forest_fixed_assembly_v1.zig").ForBackend(Cpu).deriveWithCatalogue, &@import("recursion/block_v5_memory_source_page_forest_fixed_assembly_v1.zig").ForBackend(Cpu).materialize, &@import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(Cpu).Job.publishNext, &@import("prover/block_v5_memory_source_page_job_v1.zig").ForBackend(Cpu).Job.publishAll, &@import("prover/block_v5_memory_source_page_policy_export_v1.zig").write, &@import("prover/block_v5_cpu_source_pages_v1.zig").publish, &@import("prover/block_v5_memory_source_page_policy_file_v1.zig").read, &@import("prover/block_v5_memory_source_page_policy_file_v1.zig").write }) |body| std.mem.doNotOptimizeAway(body);
}
