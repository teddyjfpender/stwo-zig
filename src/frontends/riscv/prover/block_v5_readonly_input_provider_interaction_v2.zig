//! Original shared-epoch group provider fractions and canonical prefix rows.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Air = @import("block_v5_readonly_input_provider_component_v2.zig");
const Protocol = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
pub const Generated = struct {
    a: std.mem.Allocator,
    storage: []M,
    columns: [44]Column,
    claim: Air.Claim,
    pub fn deinit(self: *Generated) void {
        self.a.free(self.storage);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, trace: *const Table.Columns, shared: Protocol.Challenges) !Generated {
    try trace.shape.require();
    const challenges = try Protocol.forGroup(shared, trace.shape.group_id);
    const rows: usize = @as(usize, 1) << @intCast(trace.shape.row_log);
    if (trace.storage.len != rows * 18 or trace.fixed.storage.len != rows * 10) return error.UntrustedReadonlyProviderTrace;
    for (trace.main, 0..) |column, i| if (column.log_size != trace.shape.row_log or column.values.len != rows or column.coefficient_values != null or column.values.ptr != trace.storage[i * rows ..].ptr) return error.UntrustedReadonlyProviderTrace;
    for (trace.fixed.columns, 0..) |column, i| if (column.log_size != trace.shape.row_log or column.values.len != rows or column.coefficient_values != null or column.values.ptr != trace.fixed.storage[i * rows ..].ptr) return error.UntrustedReadonlyProviderTrace;
    const storage = try a.alloc(M, rows * 44);
    errdefer a.free(storage);
    var result = Generated{ .a = a, .storage = storage, .columns = undefined, .claim = undefined };
    for (&result.columns, 0..) |*column, i| column.* = .{ .values = storage[i * rows ..][0..rows], .log_size = trace.shape.row_log };
    var total: [11]Q = @splat(Q.zero());
    for (0..rows) |physical| {
        var fixed: [10]Q = undefined;
        var main: [18]Q = undefined;
        for (&fixed, trace.fixed.columns) |*value, column| value.* = Q.fromBase(column.values[physical]);
        for (&main, trace.main) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const denominator = Air.Algebra(Q).denominators(fixed, main, &challenges);
        const numerator = Air.Algebra(Q).numerators(fixed, main);
        for (0..11) |i| {
            const term = if (numerator[i].isZero()) Q.zero() else try numerator[i].div(denominator[i]);
            total[i] = total[i].add(term);
            for (term.toM31Array(), 0..) |limb, j| storage[(4 * i + j) * rows + physical] = limb;
        }
    }
    result.claim = .{ .classification_sum = total[0], .read_sum = total[1], .range_sums = total[2..11].*, .counts = trace.shape.counts };
    var prefix: [11]Q = @splat(Q.zero());
    var shift: [11]Q = undefined;
    for (total, &shift) |value, *out| out.* = try value.divM31(M.fromCanonical(@intCast(rows)));
    for (0..rows) |logical| {
        const physical = Framework.committedRow(logical, trace.shape.row_log);
        for (0..11) |i| {
            var term: [4]M = undefined;
            for (&term, 0..) |*limb, j| limb.* = storage[(4 * i + j) * rows + physical];
            prefix[i] = prefix[i].add(Q.fromM31Array(term)).sub(shift[i]);
            for (prefix[i].toM31Array(), 0..) |limb, j| storage[(4 * i + j) * rows + physical] = limb;
        }
    }
    for (prefix) |value| if (!value.isZero()) return error.UnclosedReadonlyProviderPrefix;
    return result;
}
