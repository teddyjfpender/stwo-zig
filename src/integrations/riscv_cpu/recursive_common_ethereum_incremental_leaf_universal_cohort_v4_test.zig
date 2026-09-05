const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4.zig");
const complete =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig");
const closure =
    @import("recursive_common_ethereum_incremental_leaf_universal_closure_v4.zig");
const native =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const manifest =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

test "schema3 role0 cohort exposes exact 36-row closure without proof escalation" {
    const Cohort = subject.CompleteCohortV4(Engine);
    std.testing.refAllDecls(Cohort);
    std.testing.refAllDecls(complete.GeneratedV4);
    std.testing.refAllDecls(closure.PublicWireBoundaryV4);
    std.testing.refAllDecls(closure.ReceiptV4);

    try std.testing.expectEqual(@as(usize, 36), subject.COMPONENT_COUNT);
    try std.testing.expect(subject.UNIVERSAL_ROW_MATERIALIZERS_AVAILABLE);
    try std.testing.expect(subject.UNIVERSAL_CLAIM_CLOSURE_AVAILABLE);
    try std.testing.expect(complete.EXACT_TUPLE_CLOSURE_AVAILABLE);
    try std.testing.expect(complete.COMPLETE_36_CLAIM_CLOSURE_AVAILABLE);
    try std.testing.expect(!complete.UNIVERSAL_PROOF_GATE_AVAILABLE);
    try std.testing.expect(!complete.COLD_CAPTURE_AVAILABLE);
    try std.testing.expect(!complete.FOLD_CHILD_AVAILABLE);
    try std.testing.expect(!complete.PRODUCTION_ACTIVATION);
}

test "role0 native core publishes into the nominal universal manifest" {
    const Native = native.OwnerV4(Engine);
    std.testing.refAllDecls(Native);
    if (manifest.Manifest ==
        frontend.recursion.air.segment_outer_adapter_manifest_v2.Manifest)
    {
        @compileError("role0 manifest was nominally relabeled as SegmentV2");
    }
    try std.testing.expectEqual(@as(usize, 18), native.FIRST_ROW);
    try std.testing.expectEqual(@as(usize, 34), native.LAST_ROW);
    try std.testing.expectEqual(@as(usize, 35), complete.COMPONENT_COUNT - 1);
}
