//! Shared composite AIR for program and typed native partitions.
//! One component per exact request batch; all share the same composition split.
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
const support = @import("../air/memory_commitment/hash_component_prepared_support.zig");
const logup = @import("../air/logup.zig");
const opcode = @import("../runner/trace.zig");
const source = @import("block_v5_native_projection_fused_source_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const quotient_cache = @import("block_v5_quotient_column_cache_v1.zig");

pub const Component = struct {
    quotient_cache: ?*quotient_cache.Cache = null,
    slot: source.Slot,
    fixed_logs: []const u32,
    main_logs: []const u32,
    root_owner: bool,
    main_open_mask: ?[]const bool = null,
    interaction_offset: usize,
    interaction_logs: []const u32,
    claim: Q,
    relations: *const universal.UniversalRelations,
    composition_split: u32,

    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, prover_component.ComponentProver, prover_component.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn init(self: Self) !Self {
        const width = self.slot.width;
        if (self.slot.log_size == 0 or self.slot.log_size > 24 or self.slot.main_offset + width > self.main_logs.len or
            self.interaction_offset + 4 > self.interaction_logs.len or
            self.composition_split == 0 or self.composition_split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT or
            self.composition_split < std.math.log2_int_ceil(u32, self.slot.degree)) return error.InvalidV5FusedProjectionComponent;
        for (self.main_logs[self.slot.main_offset..][0..width]) |log| if (log != self.slot.log_size) return error.InvalidV5FusedProjectionComponent;
        for (self.interaction_logs[self.interaction_offset..][0..4]) |log| if (log != self.slot.log_size) return error.InvalidV5FusedProjectionComponent;
        try self.relations.validate();
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
        if (max_log < self.slot.log_size) return error.InvalidV5FusedProjectionMask;
        const fixed = try pointColumns(a, if (self.root_owner) self.fixed_logs.len else 0, &.{});
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, if (self.root_owner) self.main_logs.len else 0, &.{});
        errdefer freePoints(a, main);
        if (self.root_owner) {
            if (self.main_open_mask) |mask| {
                if (mask.len != main.len) return error.InvalidV5FusedProjectionMask;
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
    pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
        return a.alloc(usize, 0);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        const width = self.slot.width;
        if (mask.items.len < 3 or mask.items[1].len < self.slot.main_offset + width or mask.items[2].len < self.interaction_offset + 4) return error.InvalidV5FusedProjectionMask;
        var main: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        for (main[0..width], 0..) |*value, i| value.* = try pointAt(mask.items[1][self.slot.main_offset + i], 0);
        var current: [4]Q = undefined;
        var previous: [4]Q = undefined;
        for (&current, &previous, 0..) |*value, *prior, i| {
            value.* = try pointAt(mask.items[2][self.interaction_offset + i], 0);
            prior.* = try pointAt(mask.items[2][self.interaction_offset + i], 1);
        }
        const equation = try self.residual(main[0..width], current, previous);
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.slot.log_size).coset(), point.repeatedDouble(max_log - self.slot.log_size)).inv();
        accumulator.accumulate(equation.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const prover_component.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3) return error.InvalidV5FusedProjectionTrees;
        const trees = trace.polys.items;
        const width = self.slot.width;
        if (trees[1].len < self.slot.main_offset + width or trees[2].len < self.interaction_offset + 4) return error.InvalidV5FusedProjectionColumns;
        const a = accumulator.allocator;
        const split = self.compositionLogSplit();
        const eval_log = self.slot.log_size + split;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        const count = width + 4;
        const polys = try a.alloc(prover_component.Poly, count);
        defer a.free(polys);
        for (0..width) |i| polys[i] = trees[1][self.slot.main_offset + i];
        for (0..4) |i| polys[width + i] = trees[2][self.interaction_offset + i];
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
        var twiddles = if (owned.len != 0) try engine.poly.twiddles.precomputeM31(a, domain.half_coset) else null;
        defer if (twiddles) |*tree| engine.poly.twiddles.deinitM31(a, tree);
        const transform: ?engine.poly.twiddles.TwiddleTree([]const M) = if (twiddles) |tree| .init(tree.root_coset, tree.twiddles, tree.itwiddles) else null;
        for (polys, values, 0..) |poly, *out, index| {
            if (index < width) if (self.quotient_cache) |cache| {
                if (try cache.get(.lookup, poly, self.slot.log_size, eval_log, transform)) |shared| {
                    out.* = shared;
                    continue;
                }
            };
            out.* = try domainValues(a, poly, self.slot.log_size, eval_log, eval_size, owned, &initialized);
        }
        if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, transform.?);
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
            var main: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            for (0..width) |i| main[i] = Q.fromBase(values[i][row]);
            var current: [4]Q = undefined;
            var previous: [4]Q = undefined;
            for (0..4) |i| {
                current[i] = Q.fromBase(values[width + i][row]);
                previous[i] = Q.fromBase(values[width + i][prev_row]);
            }
            const equation = try self.residual(main[0..width], current, previous);
            result.accumulate(row, result.random_coeff_powers[result.random_coeff_powers.len - 1].mul(equation).mulM31(inverses[row >> shift]));
        }
    }
    fn residual(self: *const Self, main: []const Q, current: [4]Q, previous: [4]Q) !Q {
        const request = try source.fromCommittedMain(self.slot, main, self.relations);
        const denominator = request.denominator();
        const shift = try self.claim.divM31(M.fromCanonical(@as(u32, 1) << @intCast(self.slot.log_size)));
        return Q.fromPartialEvals(current).sub(Q.fromPartialEvals(previous)).add(shift).mul(denominator).sub(request.numerator());
    }
};

/// Native first-round leases may intentionally retain no coefficient copy.
/// Recover only this component's opened columns; the leased tree stays
/// immutable and no FFT/LDE/Merkle commitment is repeated.
fn domainValues(a: std.mem.Allocator, poly: prover_component.Poly, trace_log: u32, eval_log: u32, eval_size: usize, owned: [][]M, initialized: *usize) ![]const M {
    if (poly.log_size == eval_log or poly.coefficients != null)
        return support.evaluationValues(a, poly, eval_log, eval_size, owned, initialized);
    const domain = canonic.CanonicCoset.new(poly.log_size).circleDomain();
    var coefficients = try engine.poly.circle.poly.interpolateFromEvaluation(a, .{ .domain = domain, .values = poly.values });
    defer coefficients.deinit(a);
    const recovered = coefficients.coefficients();
    const trace_size = @as(usize, 1) << @intCast(trace_log);
    if (recovered.len < trace_size or trace_size > eval_size or initialized.* >= owned.len)
        return error.InvalidV5FusedProjectionSourceDegree;
    for (recovered[trace_size..]) |value| if (!value.isZero())
        return error.InvalidV5FusedProjectionSourceDegree;
    const values = try a.alloc(M, eval_size);
    @memcpy(values[0..trace_size], recovered[0..trace_size]);
    @memset(values[trace_size..], M.zero());
    owned[initialized.*] = values;
    initialized.* += 1;
    return values;
}

fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingV5FusedProjectionPoint;
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
