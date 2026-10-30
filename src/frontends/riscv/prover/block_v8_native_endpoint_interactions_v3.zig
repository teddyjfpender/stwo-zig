//! V3 projection and gap-range physical claims, all independently transcript bound.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Layout = @import("block_v8_native_endpoint_layout_v3.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Stage = @import("block_v8_ram_clock_v3_stage.zig");
const Gap = @import("block_v8_ram_clock_v3_component.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Old = @import("block_v8_native_endpoint_components_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Column = engine.pcs.ColumnEvaluation;
pub fn generate(a: std.mem.Allocator, shape: *const Shape, main: []const Column, drawn: *const @import("block_v7_execution_epoch_v1.zig").Drawn) !Old.Interactions {
    var layout = try Layout.init(a, shape, 0);
    defer layout.deinit();
    const logs = try Stage.mainLogs(a, shape);
    defer a.free(logs);
    if (main.len != logs.len) return error.InvalidDirectRamClockColumns;
    for (main, logs) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidDirectRamClockColumns;
    const groups = Halt.count(shape);
    const claims = try a.alloc(Old.Claim, layout.slots.len + groups);
    errdefer a.free(claims);
    const columns = try a.alloc(Column, 4 * claims.len);
    errdefer a.free(columns);
    var ready: usize = 0;
    errdefer for (columns[0..ready]) |column| a.free(column.values);
    // Gap components precede the shared-main projections in the AIR roster.
    var group: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        const aux = logs.len - groups * 3 + group * 3;
        const start = ready;
        for (0..4) |_| {
            columns[ready] = .{ .log_size = desc.log_size, .values = try a.alloc(R.M, @as(usize, 1) << @intCast(desc.log_size)) };
            ready += 1;
        }
        var sums: [1]R.Q = undefined;
        try engine.air.logup_columns.buildIndependentInto(a, desc.log_size, columns[start..ready], &sums, GapRows{
            .aux = main[aux..][0..3],
            .relation = .from(drawn.word.range16),
            .log = desc.log_size,
            .active_rows = desc.n_rows,
        }, GapRows.fill);
        claims[layout.slots.len + group] = .{ .sum = sums[0], .row_count = desc.n_rows };
        group += 1;
    };
    for (layout.slots, 0..) |slot, i| {
        const generated = try Fused.generateProjection(a, main, slot, &drawn.word.universal_prefix);
        claims[i] = .{ .sum = generated.sum, .row_count = slot.n_rows };
        for (generated.columns, columns[ready..][0..4]) |values, *column| column.* = .{ .log_size = slot.log_size, .values = values };
        ready += 4;
    }
    return .{ .a = a, .claims = claims, .columns = columns, .layout_digest = layout.digest };
}
const GapRows = struct {
    aux: []const Column,
    relation: R.Relation(R.Q, 1),
    log: u32,
    active_rows: u32,
    fn fill(self: @This(), physical: usize, fractions: []engine.air.logup_columns.Fraction) !void {
        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.log), self.log);
        var row: [3]R.Q = undefined;
        for (&row, self.aux) |*value, column| value.* = R.Q.fromBase(column.values[physical]);
        const term = Gap.term(R.Q, self.relation, R.Q.fromBase(R.M.fromCanonical(@intFromBool(logical < self.active_rows))), row);
        if (term.left.isZero()) return error.DivisionByZero;
        fractions[0] = .{ .numerator = term.wl, .denominator = term.left };
    }
};
