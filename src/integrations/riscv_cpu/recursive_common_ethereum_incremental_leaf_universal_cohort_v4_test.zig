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

test "Ethereum geometry rejects missing source admission before allocating preparation" {
    // Intentionally incomplete ingress: fixed-program admission must reject
    // before any remaining witness is read or a preparation owner is allocated.
    const Materialized = @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig").PreparedOwnedCampaignCaptureV4(Engine);
    var source: Materialized = undefined;
    source.program_admission = null;
    source.initial_input_admission = null;
    source.base.input.fixed_program = null;
    source.base.input.stage101.profile.schema_version = 5;
    var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const Geometry = @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig").OwnerV4(Engine);
    try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, Geometry.init(allocator.allocator(), &source));
    try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, Geometry.initForLogSizes(allocator.allocator(), &source, @splat(4)));
    try std.testing.expectEqual(@as(usize, 0), allocator.allocated_bytes);
}

test "Ethereum native prepared projection owns inputs and moves buffers across every allocation failure" {
    const Core = @import("recursive_fri_outer.zig").NativeSegmentCoreV2;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Core.testing.exerciseProjectionOwnership, .{});
}
