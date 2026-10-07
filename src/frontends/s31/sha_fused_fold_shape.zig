//! Committed-column inventory of S31FCF01. It deliberately does not offer a
//! proof transport config: SHA state/schedule columns have five shifted OODS
//! openings, which the current recursion wire format cannot represent.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const profile = @import("sha_fused_fold_profile.zig");
const caller = @import("sha_caller_stream_air.zig");
const caller_bus = @import("sha_caller_stream_bus.zig");
const fused = @import("sha_fused_air.zig");
const fused_bus = @import("sha_fused_word_logup.zig");
const feed = @import("sha_feed_direct_air.zig");
const feed_bus = @import("sha_feed_direct_word_logup.zig");

const ComponentShape = core.circuit_proof_shape.ComponentShape;
const circuit_shapes = circuit.statements.circuit_statement.circuit_component_shapes;

/// The joined native proof has shifted OODS openings that the recursive wire
/// format does not encode. Do not construct a recursion verifier from this
/// committed-column inventory alone.
pub const supports_recursive_proof_transport = false;

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

test "joined SHA committed-column inventory has 21 components and split-two composition" {
    try std.testing.expect(!supports_recursive_proof_transport);
    const layout = try profile.pp.ColumnLayout.fromComponentSizes(.{
        .eq = 32768,
        .qm31_ops = 2097152,
        .m31_to_u32 = 262144,
        .triple_xor = 131072,
        .blake_g_gate = 2097152,
    });
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    // ProofShape models committed widths here only. Its byte count assumes
    // one OODS point per main column and is not the S31FCF01 wire length.
    const shape: core.circuit_proof_shape.ProofShape = .{
        .n_preprocessed_columns = profile.debugWidths()[0],
        .component_shapes = &component_shapes,
        .log_trace_size = layout.traceLogSize(),
        .fri = fri,
        .composition_log_split = 2,
    };
    try shape.validate();
    try std.testing.expectEqual(@as(usize, 21), shape.nComponents());
    try std.testing.expectEqual(@as(usize, 16), shape.nCompositionColumns());
    try std.testing.expectEqual(@as(usize, 16 * 4), shape.nCumulativeSumColumns());
    const widths = profile.debugWidths();
    const trees = shape.nColumnsPerTrace();
    try std.testing.expectEqualSlices(usize, &.{ widths[0], widths[1], widths[2], 16 }, &trees);
    try std.testing.expectEqual(profile.main_width + caller.main_width, fusedMainOffset());
}
