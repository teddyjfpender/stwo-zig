//! Exact typed opening-input inventory and scalar producer multiplicities.
const std = @import("std");
const core = @import("stwo_core");
const deep_mod = @import("blake3_native_deep.zig");
const fri_mod = @import("blake3_native_fri.zig");
const paths_mod = @import("blake3_stark_paths.zig");
const scalar = @import("scalar_wire_source.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Direct = @import("blake3_pcs_source_columns_v1.zig");
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: []scalar.Row,
    fixed: []scalar.Row,
    columns: ?Direct.Openings = null,
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn rowCount(self: *const Prepared) usize {
        return if (self.columns) |*columns| columns.columns.count(12) else self.rows.len;
    }
    pub fn appendInputs(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.rows.len != 0 or self.fixed.len != 0) return error.InvalidNativeOpeningSource;
            try columns.appendInputs(b);
        } else try b.append(12, self.rows, self.fixed);
    }
};
pub fn prepare(a: std.mem.Allocator, paths: *paths_mod.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared) !Prepared {
    const columns = try Direct.Openings.init(a, paths.inputs.sources, deep, fri);
    // No downstream consumer needs the authentic tuple roster after this exact
    // coverage admission. Canonical buffers use backing ownership, not an arena.
    paths.inputs.releaseSources();
    return .{ .arena = std.heap.ArenaAllocator.init(a), .rows = &.{}, .fixed = &.{}, .columns = columns };
}
/// Explicit dense-row parity oracle.
pub fn prepareRows(a: std.mem.Allocator, paths: *const paths_mod.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared) !Prepared {
    try deep.graph.validateEvaluation(&deep.evaluation);
    try fri.evaluation.validateAgainst(&fri.graph);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const expected = [2][]bool{ try temp.alloc(bool, deep.graph.nodes.len), try temp.alloc(bool, fri.graph.nodes.len) };
    for (expected) |mask| @memset(mask, false);
    var count: usize = 0;
    for (deep.graph.bindings) |binding| if (binding.source == .queried_value) {
        expected[0][binding.node_id] = true;
        count += 1;
    };
    for (fri.graph.bindings) |binding| if (binding.source == .authenticated_value_word) {
        expected[1][binding.node_id] = true;
        count += 1;
    };
    if (paths.inputs.sources.len != count) return error.InvalidNativeOpeningSource;
    const uses = [2][]u32{
        try lower.computeUseCountsInto(deep.graph.graph(), try temp.alloc(u32, deep.graph.nodes.len)),
        try lower.computeUseCountsInto(fri.graph.graph(), try temp.alloc(u32, fri.graph.nodes.len)),
    };
    const values = [2][]const Q{ deep.evaluation.values, fri.evaluation.values };
    const rows = try temp.alloc(scalar.Row, count);
    const fixed = try temp.alloc(scalar.Row, count);
    for (paths.inputs.sources, rows, fixed) |source, *row, *fixed_row| {
        if (source.lane != 1 and source.lane != 2) return error.InvalidNativeOpeningSource;
        const lane = source.lane - 1;
        if (source.node >= expected[lane].len or !expected[lane][source.node] or !values[lane][source.node].eql(Q.fromBase(source.value))) return error.InvalidNativeOpeningSource;
        expected[lane][source.node] = false;
        const count_uses = try std.math.add(u32, uses[lane][source.node], if (lane == 0) @as(u32, 2) else 1);
        const circuit: u32 = if (lane == 0) 1502 else 1504;
        row.* = try scalar.logicalRow(circuit, source.node, count_uses, source.value);
        fixed_row.* = try scalar.logicalRow(circuit, source.node, count_uses, M.zero());
    }
    for (expected) |mask| for (mask) |remaining| if (remaining) return error.InvalidNativeOpeningSource;
    return .{ .arena = arena, .rows = rows, .fixed = fixed };
}
