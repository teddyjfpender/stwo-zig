//! Verifier-owned committed-column and OODS-mask inventory of S31FCF01.
//! Transport of the five shifted SHA openings is supported; the recursive
//! statement and SHA constraint evaluator are still separate work.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const profile = @import("sha_fused_fold_profile.zig");
const caller = @import("../air/sha_caller_stream_air.zig");
const caller_bus = @import("../air/sha_caller_stream_bus.zig");
const fused = @import("../air/sha_fused_air.zig");
const fused_bus = @import("../air/sha_fused_word_logup.zig");
const feed = @import("../air/sha_feed_direct_air.zig");
const feed_bus = @import("../air/sha_feed_direct_word_logup.zig");

const ComponentShape = core.circuit_proof_shape.ComponentShape;
const circuit_shapes = circuit.statements.circuit_statement.circuit_component_shapes;

/// Verified native proof bytes can be converted into this wire shape. A
/// complete in-circuit joined SHA verifier is not present yet.
pub const supports_recursive_verification = false;

/// The committed interaction tree has no columns for trace-only SHA
/// components. Bus components share their main columns with those trace
/// components and contribute only their own interaction columns.
pub const component_shapes: [profile.component_count]ComponentShape =
    circuit_shapes ++ [_]ComponentShape{
        .{ .trace_columns = caller.main_width, .interaction_columns = 0 },
        .{ .trace_columns = 0, .interaction_columns = caller_bus.interaction_width },
        .{ .trace_columns = fused.main_width, .interaction_columns = 0 },
        .{ .trace_columns = 0, .interaction_columns = fused_bus.interaction_width },
    } ++ ([_]ComponentShape{
        .{ .trace_columns = feed.main_width, .interaction_columns = 0 },
        .{ .trace_columns = 0, .interaction_columns = feed_bus.interaction_width },
    } ** 3);

/// Start of the fused round trace inside the joined main tree.
pub fn fusedMainOffset() usize {
    return profile.main_width + caller.main_width;
}

pub const state_offsets = [_]i8{ -3, -2, -1, 0, 1 };
pub const word_offsets = [_]i8{ -16, -15, -7, -2, 0 };

/// Fused round mask order from `sha_fused_air.Component.maskPoints`:
/// state limbs 0..63, schedule limbs 76..107, then singleton columns.
pub const trace_mask_offsets = blk: {
    var masks: [profile.main_width + caller.main_width + fused.main_width + 3 * feed.main_width][]const i8 = undefined;
    for (&masks) |*entry| entry.* = &.{0};
    const start = fusedMainOffset();
    for (0..64) |i| masks[start + i] = &state_offsets;
    for (0..32) |i| masks[start + 76 + i] = &word_offsets;
    break :blk masks;
};

/// The caller bus carries Gate and word LogUps in separate four-limb
/// cumulative sums. Native sampled-value order is previous, current for
/// both groups; all other components retain their canonical last four.
pub const interaction_mask_offsets = blk: {
    var masks: [profile.interaction_width + caller_bus.interaction_width + fused_bus.interaction_width + 3 * feed_bus.interaction_width][]const i8 = undefined;
    var at: usize = 0;
    for (component_shapes) |component| {
        for (0..component.interaction_columns) |i|
            masks[at + i] = if (i >= component.interaction_columns -| 4) &.{ -1, 0 } else &.{0};
        at += component.interaction_columns;
    }
    std.debug.assert(at == masks.len);
    const caller_bus_start = profile.interaction_width;
    for (4..8) |i| masks[caller_bus_start + i] = &.{ -1, 0 };
    break :blk masks;
};

/// Flattened native claim order: eleven circuit sums, Gate, caller word,
/// fused word, and three feed words. Trace-only AIRs have no claim.
pub const claim_arities = blk: {
    var arities: [profile.component_count]u8 = @splat(0);
    for (0..profile.circuit_components) |i| arities[i] = 1;
    arities[profile.circuit_components + 1] = 2;
    arities[profile.circuit_components + 3] = 1;
    for (.{ 5, 7, 9 }) |offset| arities[profile.circuit_components + offset] = 1;
    break :blk arities;
};

/// The transport shape is derived from an independently admitted joined
/// proof key. Proof bytes cannot choose the column masks or FRI parameters.
pub fn proofShape(key: profile.Key) !core.circuit_proof_shape.ProofShape {
    try key.validate();
    const shape: core.circuit_proof_shape.ProofShape = .{
        .n_preprocessed_columns = profile.debugWidths()[0],
        .component_shapes = &component_shapes,
        .log_trace_size = key.pcs.trace_lifting_log_size - key.pcs.fri_config.log_blowup_factor,
        .fri = key.pcs.fri_config,
        .composition_log_split = 2,
        .trace_mask_offsets = &trace_mask_offsets,
        .interaction_mask_offsets = &interaction_mask_offsets,
        .claim_arities = &claim_arities,
    };
    try shape.validate();
    return shape;
}

test "joined SHA committed-column inventory has 21 components and split-two composition" {
    try std.testing.expect(!supports_recursive_verification);
    const layout = try profile.pp.ColumnLayout.fromComponentSizes(.{
        .eq = 32768,
        .qm31_ops = 2097152,
        .m31_to_u32 = 262144,
        .triple_xor = 131072,
        .blake_g_gate = 2097152,
    });
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    // A transport shape includes all five shifted state/schedule openings.
    const shape: core.circuit_proof_shape.ProofShape = .{
        .n_preprocessed_columns = profile.debugWidths()[0],
        .component_shapes = &component_shapes,
        .log_trace_size = layout.traceLogSize(),
        .fri = fri,
        .composition_log_split = 2,
        .trace_mask_offsets = &trace_mask_offsets,
        .interaction_mask_offsets = &interaction_mask_offsets,
        .claim_arities = &claim_arities,
    };
    try shape.validate();
    try std.testing.expectEqual(@as(usize, 21), shape.nComponents());
    try std.testing.expectEqual(@as(usize, 16), shape.nCompositionColumns());
    try std.testing.expectEqual(@as(usize, 17), shape.nClaimedSums());
    try std.testing.expectEqual(@as(usize, 17 * 4), shape.nCumulativeSumColumns());
    const widths = profile.debugWidths();
    const trees = shape.nColumnsPerTrace();
    try std.testing.expectEqualSlices(usize, &.{ widths[0], widths[1], widths[2], 16 }, &trees);
    try std.testing.expectEqual(profile.main_width + caller.main_width, fusedMainOffset());
    try std.testing.expectEqual(trees[1] + 4 * (64 + 32), shape.nTraceOodsValues());
    try std.testing.expectEqualSlices(i8, &state_offsets, shape.columnMaskOffsets(1, fusedMainOffset()));
    try std.testing.expectEqualSlices(i8, &word_offsets, shape.columnMaskOffsets(1, fusedMainOffset() + 76));
    try std.testing.expectEqualSlices(i8, &.{ -1, 0 }, shape.columnMaskOffsets(2, profile.interaction_width + 4));
    try std.testing.expectEqualSlices(i8, &.{ -1, 0 }, shape.columnMaskOffsets(2, profile.interaction_width + 12));
    try std.testing.expectEqual(@as(usize, 2), shape.claimRange(profile.circuit_components + 1).end - shape.claimRange(profile.circuit_components + 1).start);
}
