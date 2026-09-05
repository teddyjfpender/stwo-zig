const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const components =
    @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const cohort =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4.zig");
const geometry =
    @import("recursive_common_ethereum_incremental_leaf_transcript_geometry_v4.zig");
const rows =
    @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

test "stage102 role0 transcript cohort tree and tuple APIs instantiate" {
    const Prepared = cohort.PreparedV4(Engine);
    std.testing.refAllDecls(Prepared);
    try std.testing.expect(@hasDecl(Prepared, "fillPreprocessedInto"));
    try std.testing.expect(@hasDecl(Prepared, "fillMainInto"));
    try std.testing.expect(@hasDecl(Prepared, "fillInteractionInto"));
    try std.testing.expect(@hasDecl(Prepared, "appendTupleContributions"));
    try std.testing.expect(cohort.TREE0_AVAILABLE);
    try std.testing.expect(cohort.TREE1_AVAILABLE);
    try std.testing.expect(cohort.TREE2_AVAILABLE);
    try std.testing.expect(cohort.TUPLE_LEDGER_AVAILABLE);
    try std.testing.expect(!cohort.COMPLETE_36_CLAIM_CLOSURE_AVAILABLE);
}

test "stage102 role0 transcript rows retain inactive recursion lanes" {
    std.testing.refAllDecls(rows.OwnerV4(Engine));
    try std.testing.expect(geometry.ROW_MATERIALIZERS_AVAILABLE);
    try std.testing.expect(components.TREE_PUBLICATION_AVAILABLE);
    try std.testing.expect(!components.SEGMENT_V2_NOMINAL_INPUT_ADMITTED);
    try std.testing.expect(!cohort.PRODUCTION_ACTIVATION);
}
