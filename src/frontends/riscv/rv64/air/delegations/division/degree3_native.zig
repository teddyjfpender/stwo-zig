//! Bounded native2n loader. Arithmetic/lookup equations remain in provider.zig.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const D = @import("layout.zig");
const P = @import("provider.zig");
const Base = @import("component.zig").Component;
const Partition = @import("../../full/coset_evaluation.zig").Evaluation;
const cp = engine.air.component_prover;
const Q = E.Q;
const TOTAL = D.FIXED + D.MAIN + D.INTERACTION;

pub const MIN_STACK_BYTES = 256 * 1024;
const F = E.PackedBase;
const PackedRow = struct {
    geometry: [D.FIXED]F,
    main: [D.MAIN]F,
    current: [D.INTERACTION]F,
    previous: [D.INTERACTION]F,
};
pub fn evaluate(self: *const Base, trace: *const cp.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    return evaluateImpl(false, self, trace, accumulator, pool);
}
fn evaluateImpl(comptime scalar_reference: bool, self: *const Base, trace: *const cp.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64DivisionWorkerStack;
    if (self.log_size < 5 or self.log_size > 22 or trace.polys.items.len != 3 or trace.polys.items[0].len < self.fixed_offset + D.FIXED or trace.polys.items[1].len < self.main_offset + D.MAIN or trace.polys.items[2].len < self.interaction_offset + D.INTERACTION) return error.InvalidRv64DivisionShape;
    if (self.count > @as(usize, 1) << @intCast(self.log_size)) return error.InvalidRv64DivisionShape;
    const a = accumulator.allocator;
    var polys: [TOTAL]cp.Poly = undefined;
    @memcpy(polys[0..D.FIXED], trace.polys.items[0][self.fixed_offset..][0..D.FIXED]);
    @memcpy(polys[D.FIXED..][0..D.MAIN], trace.polys.items[1][self.main_offset..][0..D.MAIN]);
    @memcpy(polys[D.FIXED + D.MAIN ..], trace.polys.items[2][self.interaction_offset..][0..D.INTERACTION]);
    var previous_columns: [TOTAL]bool = @splat(false);
    previous_columns[D.FIXED + D.COUNT] = true;
    @memset(previous_columns[D.FIXED + D.MAIN + 4 ..], true);
    var evaluation = try Partition.initDegreeThree(a, &polys, self.log_size, &previous_columns);
    defer evaluation.deinit();
    // Keep the 1135 packed physical coordinates off a bounded worker stack.
    // The arithmetic authority's logical scratch remains on that stack.
    const packed_scratch: ?*PackedRow = if (comptime scalar_reference) null else try a.create(PackedRow);
    defer if (packed_scratch) |value| a.destroy(value);
    const columns = try accumulator.columns(a, &.{.{ .log_size = self.log_size + 1, .n_cols = D.CONSTRAINTS }});
    defer a.free(columns);
    var output = columns[0];
    for (0..2) |part| {
        try evaluation.evaluatePartWithPool(part, pool);
        const inverse = try evaluation.denominatorInverse(part);
        if (comptime scalar_reference) {
            scalarRows(self, &evaluation, part, inverse, &output);
        } else {
            packedRows(self, &evaluation, part, inverse, packed_scratch.?, &output);
        }
    }
}

fn gather(values: []const core.fields.m31.M31, indices: [E.LANES]usize) F {
    var lanes: [E.LANES]core.fields.m31.M31 = undefined;
    for (&lanes, indices) |*v, i| v.* = values[i];
    return F.fromLanes(lanes);
}
fn packedRows(self: *const Base, evaluation: *const Partition, part: usize, inverse: core.fields.m31.M31, scratch: *PackedRow, output: *engine.air.accumulation.ColumnAccumulator) void {
    std.debug.assert(evaluation.size % E.LANES == 0);
    scratch.previous = @splat(F.zero());
    var row: usize = 0;
    while (row < evaluation.size) : (row += E.LANES) {
        var prior: [E.LANES]usize = undefined;
        for (&prior, 0..) |*v, lane| v.* = evaluation.previousRow(part, row + lane);
        for (&scratch.geometry, 0..) |*v, c| v.* = F.load(evaluation.current_values[c].ptr + row);
        for (&scratch.main, 0..) |*v, c| v.* = F.load(evaluation.current_values[D.FIXED + c].ptr + row);
        for (&scratch.current, 0..) |*v, c| {
            v.* = F.load(evaluation.current_values[D.FIXED + D.MAIN + c].ptr + row);
            if (c >= 4) scratch.previous[c] = gather(evaluation.previous_values[D.FIXED + D.MAIN + c], prior);
        }
        const previous_count = gather(evaluation.previous_values[D.FIXED + D.COUNT], prior);
        var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
        var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
        P.evaluateFor(F, scratch.geometry, &scratch.main, &scratch.current, &scratch.previous, previous_count, E.qFor(F, @intCast(self.count)), self.challenges, self.claim, &sink);
        std.debug.assert(sink.count == D.CONSTRAINTS);
        const coordinates = weighted.accumulation.mulBase(F.fromBase(inverse)).coordinates();
        const start = evaluation.globalRow(part, row);
        const fresh = if (output.next_fresh_index) |next| next == start else false;
        output.next_fresh_index = if (fresh) start + E.LANES else null;
        for (output.col.columns, coordinates) |column, coordinate| {
            if (fresh) coordinate.store(column.ptr + start) else F.load(column.ptr + start).add(coordinate).store(column.ptr + start);
        }
    }
}

// The former scalar domain implementation is compiled ONLY by test callers.
// There is no production runtime selector or scalar fallback.
fn scalarRows(self: *const Base, evaluation: *const Partition, part: usize, inverse: core.fields.m31.M31, output: *engine.air.accumulation.ColumnAccumulator) void {
    for (0..evaluation.size) |row| {
        const prior = evaluation.previousRow(part, row);
        var geometry: [D.FIXED]Q = undefined;
        var main: D.Physical = undefined;
        var current: [D.INTERACTION]Q = undefined;
        var previous: [D.INTERACTION]Q = @splat(Q.zero());
        for (&geometry, 0..) |*value, c| value.* = Q.fromBase(evaluation.current_values[c][row]);
        for (&main, 0..) |*value, c| value.* = Q.fromBase(evaluation.current_values[D.FIXED + c][row]);
        for (&current, 0..) |*value, c| {
            value.* = Q.fromBase(evaluation.current_values[D.FIXED + D.MAIN + c][row]);
            if (c >= 4) previous[c] = Q.fromBase(evaluation.previous_values[D.FIXED + D.MAIN + c][prior]);
        }
        const previous_count = Q.fromBase(evaluation.previous_values[D.FIXED + D.COUNT][prior]);
        var weighted = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &weighted };
        P.evaluate(geometry, &main, &current, &previous, previous_count, self.count, self.challenges, self.claim, &sink);
        std.debug.assert(sink.count == D.CONSTRAINTS);
        output.accumulate(evaluation.globalRow(part, row), weighted.accumulation.mulM31(inverse));
    }
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn scalar(self: *const Base, trace: *const cp.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
        return evaluateImpl(true, self, trace, accumulator, null);
    }
} else struct {};
