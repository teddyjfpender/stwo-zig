//! Exact shared-table LogUp quotient over family11 fixed/main roots.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const prover_component = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const logup = @import("../air/logup.zig");
const source = @import("block_v5_precompile_lookup_source_v1.zig");
const Relations = @import("blake3_ethereum_sha_profile.zig").Relations;

pub const Component = struct {
    slot: source.Slot,
    fixed_logs: []const u32,
    main_logs: []const u32,
    root_owner: bool,
    main_open_mask: ?[]const bool = null,
    fixed_open_mask: ?[]const bool = null,
    interaction_offset: usize,
    interaction_logs: []const u32,
    claim: Q,
    relations: *const Relations,
    source_owner: *const source.Owner,
    composition_split: u32,

    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, prover_component.ComponentProver, prover_component.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn init(self: Self) !Self {
        const width = self.slot.width;
        if (self.slot.log_size == 0 or self.slot.log_size > 24 or self.slot.main_offset + width > self.main_logs.len or self.slot.fixed_offset + self.slot.fixed_width > self.fixed_logs.len or
            self.interaction_offset + 4 > self.interaction_logs.len or
            self.composition_split == 0 or self.composition_split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT or
            self.composition_split < std.math.log2_int_ceil(u32, self.slot.degree)) return error.InvalidV5LookupRequestComponent;
        for (self.main_logs[self.slot.main_offset..][0..width]) |log| if (log != self.slot.log_size) return error.InvalidV5LookupRequestComponent;
        for (self.interaction_logs[self.interaction_offset..][0..4]) |log| if (log != self.slot.log_size) return error.InvalidV5LookupRequestComponent;
        for (self.fixed_logs[self.slot.fixed_offset..][0..self.slot.fixed_width]) |log| if (log != self.slot.log_size) return error.InvalidV5LookupRequestComponent;
        return self;
    }
    pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return 1;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.slot.log_size + self.composition_split;
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.composition_split;
    }
    pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
        if (index != 0) return error.InvalidConstraintIndex;
        return self.slot.degree;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, if (self.root_owner) self.fixed_logs else &.{});
        errdefer a.free(fixed);
        const main = try a.dupe(u32, if (self.root_owner) self.main_logs else &.{});
        errdefer a.free(main);
        const interaction = try a.dupe(u32, &([_]u32{self.slot.log_size} ** 4));
        errdefer a.free(interaction);
        return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
        if (max_log < self.slot.log_size) return error.InvalidV5LookupRequestMask;
        const fixed = try pointColumns(a, if (self.root_owner) self.fixed_logs.len else 0, &.{});
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, if (self.root_owner) self.main_logs.len else 0, &.{});
        errdefer freePoints(a, main);
        if (self.root_owner) {
            const fixed_mask = self.fixed_open_mask orelse return error.InvalidV5LookupRequestMask;
            if (fixed_mask.len != fixed.len) return error.InvalidV5LookupRequestMask;
            for (fixed, fixed_mask) |*column, open| if (open) {
                a.free(column.*);
                column.* = try a.dupe(circle.CirclePointQM31, &.{point});
            };
            if (self.main_open_mask) |mask| {
                if (mask.len != main.len) return error.InvalidV5LookupRequestMask;
                for (main, mask) |*column, open| if (open) {
                    a.free(column.*);
                    column.* = try a.dupe(circle.CirclePointQM31, &.{point});
                };
            } else for (main[self.slot.main_offset..][0..self.slot.width]) |*column| {
                a.free(column.*);
                column.* = try a.dupe(circle.CirclePointQM31, &.{point});
            }
        }
        const interaction = try pointColumns(a, 4, &.{ point, logup.prevRowPoint(max_log, point) });
        errdefer freePoints(a, interaction);
        return components.MaskPoints.initOwned(try a.dupe([][]circle.CirclePointQM31, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.slot.fixed_width);
        for (out, 0..) |*index, i| index.* = self.slot.fixed_offset + i;
        return out;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        const width = self.slot.width;
        if (mask.items.len < 3 or mask.items[1].len < self.slot.main_offset + width or mask.items[2].len < self.interaction_offset + 4) return error.InvalidV5LookupRequestMask;
        var main: [source.MAX_MAIN]Q = undefined;
        for (main[0..width], 0..) |*value, i| value.* = try pointAt(mask.items[1][self.slot.main_offset + i], 0);
        var current: [4]Q = undefined;
        var previous: [4]Q = undefined;
        for (&current, &previous, 0..) |*value, *prior, i| {
            value.* = try pointAt(mask.items[2][self.interaction_offset + i], 0);
            prior.* = try pointAt(mask.items[2][self.interaction_offset + i], 1);
        }
        var fixed: [source.MAX_FIXED]Q = undefined;
        for (fixed[0..self.slot.fixed_width], 0..) |*value, i| value.* = try pointAt(mask.items[0][self.slot.fixed_offset + i], 0);
        const equation = try self.residual(fixed[0..self.slot.fixed_width], main[0..width], current, previous);
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.slot.log_size).coset(), point.repeatedDouble(max_log - self.slot.log_size)).inv();
        accumulator.accumulate(equation.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const prover_component.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3) return error.InvalidV5LookupRequestTrees;
        const trees = trace.polys.items;
        const width = self.slot.width;
        if (trees[1].len < self.slot.main_offset + width or trees[2].len < self.interaction_offset + 4) return error.InvalidV5LookupRequestColumns;
        const a = accumulator.allocator;
        const split = self.compositionLogSplit();
        const eval_log = self.slot.log_size + split;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        const fixed_count = self.slot.fixed_width;
        const count = fixed_count + width + 4;
        const polys = try a.alloc(prover_component.Poly, count);
        defer a.free(polys);
        for (0..fixed_count) |i| polys[i] = trees[0][self.slot.fixed_offset + i];
        for (0..width) |i| polys[fixed_count + i] = trees[1][self.slot.main_offset + i];
        for (0..4) |i| polys[fixed_count + width + i] = trees[2][self.interaction_offset + i];
        var owned_count: usize = 0;
        for (polys) |poly| {
            try poly.validate();
            owned_count += @intFromBool(poly.log_size != eval_log);
        }
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const values = try a.alloc([]const M, count);
        defer a.free(values);
        for (polys, values) |poly, *out| out.* = try domainValues(a, poly, self.slot.log_size, eval_log, eval_size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        const inverses = try a.alloc(M, @as(usize, 1) << @intCast(split));
        defer a.free(inverses);
        const trace_coset = canonic.CanonicCoset.new(self.slot.log_size).coset();
        for (inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, split))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = 1 }});
        defer a.free(output);
        var result = output[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.slot.log_size);
        for (0..eval_size) |row| {
            const prev_row = core.utils.previousBitReversedCircleDomainIndex(row, self.slot.log_size, eval_log);
            var main: [source.MAX_MAIN]Q = undefined;
            for (0..width) |i| main[i] = Q.fromBase(values[fixed_count + i][row]);
            var current: [4]Q = undefined;
            var previous: [4]Q = undefined;
            for (0..4) |i| {
                current[i] = Q.fromBase(values[fixed_count + width + i][row]);
                previous[i] = Q.fromBase(values[fixed_count + width + i][prev_row]);
            }
            var fixed: [source.MAX_FIXED]Q = undefined;
            for (0..fixed_count) |i| fixed[i] = Q.fromBase(values[i][row]);
            const equation = try self.residual(fixed[0..fixed_count], main[0..width], current, previous);
            result.accumulate(row, result.random_coeff_powers[result.random_coeff_powers.len - 1].mul(equation).mulM31(inverses[row >> shift]));
        }
    }
    fn residual(self: *const Self, fixed: []const Q, main: []const Q, current: [4]Q, previous: [4]Q) !Q {
        return @import("block_v5_caller_fused_algebra_v1.zig").tableResidual(Q, self.source_owner, self.slot, fixed, main, current, previous, try self.claim.divM31(M.fromCanonical(@as(u32, 1) << @intCast(self.slot.log_size))), self.relations);
    }
};

fn domainValues(a: std.mem.Allocator, poly: prover_component.Poly, trace_log: u32, eval_log: u32, eval_size: usize, owned: [][]M, initialized: *usize) ![]const M {
    return @import("block_v5_program_request_component_v1.zig").domainValues(a, poly, trace_log, eval_log, eval_size, owned, initialized);
}

fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingV5LookupRequestPoint;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, points: []const circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
    const result = try a.alloc([]circle.CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| a.free(column);
        a.free(result);
    }
    for (result) |*column| {
        column.* = try a.dupe(circle.CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}
fn freePoints(a: std.mem.Allocator, columns: [][]circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}
