//! Fixed SegmentV2 wire shape selected before inspecting a child proof.
//!
//! The native verifier still authenticates the proof. This constructor
//! separately fixes the recursive verifier's wire geometry from admitted
//! statement/core authorities and a pinned preprocessing root.
const std = @import("std");
const statement_mod = @import("../air/statement.zig");
const transcript_claims = @import("../air/transcript/claims.zig");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const leaf_profile = @import("leaf_profile.zig");
const protocol = @import("protocol.zig");
const core_profile = @import("air/segment_leaf_wrapper_template_v6.zig");
const layout_mod = @import("segment_core_expected_layout_from_statement_v11.zig");
const masks_mod = @import("segment_core_expected_pcs_masks_v12.zig");
const channel = @import("poseidon2_channel.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;

pub fn deriveSegmentV2(
    comptime dimensions: fixed_wire.Dimensions,
    allocator: std.mem.Allocator,
    selected_statement: *const statement_mod.RiscVStatement,
    selected_core: *const core_profile.CoreProfileV6,
    pinned_tree0: channel.Digest,
) !fixed_profile.ProofShapeV1 {
    _ = try selected_core.reference();
    if (!std.meta.eql(selected_core.vm, selected_core.recursion) or
        selected_core.vm.query_count != protocol.FRI_QUERY_COUNT)
        return error.InvalidSelectedWireProfileV12;
    var logs = try layout_mod.OwnedLayout.buildSegmentV2FromCoreProfile(
        allocator,
        selected_statement,
        selected_core,
    );
    defer logs.deinit();
    var masks = try masks_mod.OwnedMasks.build(allocator, selected_statement, selected_core, &logs);
    defer masks.deinit();

    var tree_counts: [fixed_profile.TREE_COUNT]u32 = undefined;
    var table_count: u32 = 0;
    for (logs.views, &tree_counts) |tree, *count| {
        count.* = std.math.cast(u32, tree.len) orelse return error.InvalidSelectedWireProfileV12;
        table_count = try std.math.add(u32, table_count, count.*);
    }
    var sampled_count: u32 = 0;
    for (masks.layouts) |mask|
        sampled_count = try std.math.add(u32, sampled_count, @as(u32, mask.sampleCount()));
    const column_log_degree = std.math.sub(
        u32,
        selected_core.vm.lifting_log_size,
        protocol.FRI_LOG_BLOWUP_FACTOR,
    ) catch return error.InvalidSelectedWireProfileV12;
    const fri = try fixed_profile.FriSchedule.init(column_log_degree, protocol.PCS_CONFIG.fri_config);
    if (selected_core.vm.fri_count != fri.count) return error.InvalidSelectedWireProfileV12;
    for (fri.active(), selected_core.vm.fri_fold_widths[0..selected_core.vm.fri_count]) |round, width|
        if (round.fold_width != width) return error.InvalidSelectedWireProfileV12;
    var tree_heights: [fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, selected_core.vm.tree_heights[0..fixed_profile.TREE_COUNT]);

    const shape = fixed_profile.ProofShapeV1{
        .air_program_id = leaf_profile.airProgramId(),
        .preprocessing_id = pinned_tree0,
        .table_layout_id = leaf_profile.tableLayoutId(selected_statement),
        .table_count = table_count,
        .claimed_sum_count = transcript_claims.COMPONENT_COUNT,
        .sampled_value_count = sampled_count,
        .preprocessed_column_count = tree_counts[0],
        .tree_column_counts = tree_counts,
        .tree_heights = tree_heights,
        .column_log_degree = column_log_degree,
        .proof_wire_bytes = fixed_wire.serializedByteCount(dimensions),
        .fri = fri,
    };
    try shape.validate();
    try fixed_wire.validateDimensionsAgainstShape(dimensions, shape);
    return shape;
}
