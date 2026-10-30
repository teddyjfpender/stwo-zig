//! Explicit synchronous interaction executor over the original authenticated
//! framework program. Sources and destinations remain caller-owned; every
//! physical claim is returned before the unchanged transcript absorption.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = engine.air.component_prover;
pub const Program = C.OwnedFrameworkPolynomialProgramV1;
pub const Parameters = C.FrameworkPolynomialParametersV1;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Executor = struct {
    context: *anyopaque,
    generate: *const fn (*anyopaque, std.mem.Allocator, *const Program, [3]usize, [2][]const []const M, Parameters, []const []M, []Q) anyerror!void,
};

/// The immutable program and actual column extents are checked independently
/// of device allocation. Future claims are outputs, never input authority.
pub fn validate(program: *const Program, counts: [3]usize, sources: [2][]const []const M, parameters: Parameters, destination: []const []M, claims: []Q) !void {
    try program.validate(&counts);
    if (parameters.trace_log_size == 0 or parameters.trace_log_size > 24) return error.InvalidFrameworkInteractionGeometry;
    const rows = @as(usize, 1) << @intCast(parameters.trace_log_size);
    if (claims.len != (if (program.layout == .same_row_prefix_v1) @as(usize, 1) else program.batches.len) or destination.len != counts[2] or destination.len != program.interaction_columns.len) return error.InvalidFrameworkInteractionGeometry;
    for (sources, counts[0..2]) |columns, count| {
        if (columns.len != count) return error.InvalidFrameworkInteractionGeometry;
        for (columns) |column| if (column.len != rows) return error.InvalidFrameworkInteractionGeometry;
    }
    for (destination) |column| if (column.len != rows) return error.InvalidFrameworkInteractionGeometry;
    for (program.inputs) |input| switch (input) {
        .trace_column => |c| if (c.tree_index > 1) return error.InvalidFrameworkInteractionGeometry,
        .profile_parameter => {},
    };
    for (program.interaction_columns, 0..) |column, i| if (column.tree_index != 2 or column.column_index != i) return error.InvalidFrameworkInteractionGeometry;
    // Supplied parameters do not carry a trusted future claim. Validate the
    // exact runtime challenge/profile geometry using canonical zero outputs.
    if (program.batches.len > 128) return error.InvalidFrameworkInteractionGeometry;
    const zeros = [_]Q{Q.zero()} ** 128;
    var checked = parameters;
    checked.claimed_sum = Q.zero();
    checked.batch_claims = if (program.layout == .independent_prefix_v1) zeros[0..program.batches.len] else &.{};
    try checked.validate(program);
}
