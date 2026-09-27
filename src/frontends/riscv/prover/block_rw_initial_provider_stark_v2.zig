//! PCS quotient adapter for the block-v2 positive first-touch initial bus.
//! Its fixed address/caller schedule is reconstructed from the sealed public
//! roster. Universal byte-range and recursion-wire effects are proved by the
//! companion typed component in block_rw_initial_provider_v2.zig.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const component_prover = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const support = @import("../air/memory_commitment/hash_component_prepared_support.zig");
const provider = @import("block_rw_initial_provider_v2.zig");
const bus = @import("block_memory_relation_v2.zig");

pub const fixed_count = 10;
pub const main_count = 4;
pub const interaction_count = 8;
const source_count = fixed_count + main_count + interaction_count;
pub const expansion_bits: u32 = 2;
pub const Placement = struct { fixed_offset: usize = 0, main_offset: usize = 0, interaction_offset: usize = 0 };
pub const fixed = struct {
    pub const address = 0;
    pub const circuit = 4;
    pub const wire = 5;
    pub const active = 6;
    pub const initial_emit = 7;
    pub const first = 8;
    pub const domain_last = 9;
};

pub const Component = struct {
    claim: provider.Claim,
    challenges: *const bus.Challenges,
    placement: Placement,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, component_prover.ComponentProver, component_prover.Trace, accumulation.DomainEvaluationAccumulator);

    pub fn init(claim: provider.Claim, challenges: *const bus.Challenges, placement: Placement) !Self {
        if (claim.log_size < 1 or claim.log_size + expansion_bits >= circle.M31_CIRCLE_LOG_ORDER or
            claim.row_count == 0 or claim.row_count > @as(u32, 1) << @intCast(claim.log_size)) return error.InvalidInitialRwClaim;
        return .{ .claim = claim, .challenges = challenges, .placement = placement };
    }
    pub fn asProverComponent(self: *const Self) component_prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return 3;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.claim.log_size + expansion_bits;
    }
    pub fn compositionLogSplit(_: *const Self) u32 {
        return expansion_bits;
    }
    pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
        if (index >= 3) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
        const fixed_logs = try filledLogs(a, fixed_count, self.claim.log_size);
        errdefer a.free(fixed_logs);
        const main_logs = try filledLogs(a, main_count, self.claim.log_size);
        errdefer a.free(main_logs);
        const interaction_logs = try filledLogs(a, interaction_count, self.claim.log_size);
        errdefer a.free(interaction_logs);
        return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed_logs, main_logs, interaction_logs }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
        if (max_log < self.claim.log_size) return error.InvalidInitialRwMaskDegree;
        const shifted = @import("../air/logup.zig").prevRowPoint(max_log, point);
        const fixed_points = try pointColumns(a, fixed_count, &.{point});
        errdefer freePointColumns(a, fixed_points);
        const main_points = try pointColumns(a, main_count, &.{point});
        errdefer freePointColumns(a, main_points);
        const interaction_points = try pointColumns(a, interaction_count, &.{ point, shifted });
        errdefer freePointColumns(a, interaction_points);
        return components.MaskPoints.initOwned(try a.dupe([][]circle.CirclePointQM31, &.{ fixed_points, main_points, interaction_points }));
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        const indices = try a.alloc(usize, fixed_count);
        for (indices, 0..) |*index, i| index.* = self.placement.fixed_offset + i;
        return indices;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3 or max_log < self.claim.log_size or
            mask.items[0].len < self.placement.fixed_offset + fixed_count or
            mask.items[1].len < self.placement.main_offset + main_count or
            mask.items[2].len < self.placement.interaction_offset + interaction_count) return error.InvalidInitialRwPointMask;
        var fixed_values: [fixed_count]Q = undefined;
        var main_values: [main_count]Q = undefined;
        var interaction: [interaction_count]Q = undefined;
        var previous: [interaction_count]Q = undefined;
        for (&fixed_values, 0..) |*value, i| value.* = try pointAt(mask.items[0][self.placement.fixed_offset + i], 0);
        for (&main_values, 0..) |*value, i| value.* = try pointAt(mask.items[1][self.placement.main_offset + i], 0);
        for (&interaction, &previous, 0..) |*value, *before, i| {
            value.* = try pointAt(mask.items[2][self.placement.interaction_offset + i], 0);
            before.* = try pointAt(mask.items[2][self.placement.interaction_offset + i], 1);
        }
        const identities = try provider.interactionConstraints(self.challenges, makePoint(fixed_values, main_values, interaction, previous), self.claim);
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.claim.log_size).coset(), point.repeatedDouble(max_log - self.claim.log_size)).inv();
        for (identities) |identity| accumulator.accumulate(identity.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const component_prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        const a = accumulator.allocator;
        if (source.polys.items.len != 3) return error.InvalidInitialRwTraceTrees;
        const trees = source.polys.items;
        if (trees[0].len < self.placement.fixed_offset + fixed_count or
            trees[1].len < self.placement.main_offset + main_count or
            trees[2].len < self.placement.interaction_offset + interaction_count) return error.InvalidInitialRwTraceColumns;
        const eval_log = self.claim.log_size + expansion_bits;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        var polys: [source_count]component_prover.Poly = undefined;
        for (0..fixed_count) |i| polys[i] = trees[0][self.placement.fixed_offset + i];
        for (0..main_count) |i| polys[fixed_count + i] = trees[1][self.placement.main_offset + i];
        for (0..interaction_count) |i| polys[fixed_count + main_count + i] = trees[2][self.placement.interaction_offset + i];
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.claim.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var evals: [source_count][]const M = undefined;
        for (polys, &evals) |poly, *out| out.* = try support.evaluationValues(a, poly, eval_log, eval_size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        var inverses: [1 << expansion_bits]M = undefined;
        const trace_coset = canonic.CanonicCoset.new(self.claim.log_size).coset();
        for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, expansion_bits))).inv();
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = 3 }});
        defer a.free(columns);
        var result = columns[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.claim.log_size);
        for (0..eval_size) |row| {
            const prev_row = core.utils.previousBitReversedCircleDomainIndex(row, self.claim.log_size, eval_log);
            var fixed_values: [fixed_count]Q = undefined;
            var main_values: [main_count]Q = undefined;
            var interaction: [interaction_count]Q = undefined;
            var previous: [interaction_count]Q = undefined;
            for (&fixed_values, 0..) |*value, i| value.* = Q.fromBase(evals[i][row]);
            for (&main_values, 0..) |*value, i| value.* = Q.fromBase(evals[fixed_count + i][row]);
            for (&interaction, &previous, 0..) |*value, *before, i| {
                value.* = Q.fromBase(evals[fixed_count + main_count + i][row]);
                before.* = Q.fromBase(evals[fixed_count + main_count + i][prev_row]);
            }
            const identities = try provider.interactionConstraints(self.challenges, makePoint(fixed_values, main_values, interaction, previous), self.claim);
            var folded = Q.zero();
            const powers = result.random_coeff_powers;
            for (identities, 0..) |identity, i| folded = folded.add(powers[powers.len - 1 - i].mul(identity));
            result.accumulate(row, folded.mulM31(inverses[row >> shift]));
        }
    }
};

fn makePoint(fixed_values: [fixed_count]Q, main_values: [main_count]Q, interaction: [interaction_count]Q, previous: [interaction_count]Q) provider.Point {
    var tuple: [bus.INITIAL_ARITY]Q = undefined;
    tuple[0] = Q.one();
    @memcpy(tuple[1..5], fixed_values[fixed.address..][0..4]);
    @memcpy(tuple[5..9], &main_values);
    return .{ .active = fixed_values[fixed.active], .initial_emit = fixed_values[fixed.initial_emit], .first = fixed_values[fixed.first], .domain_last = fixed_values[fixed.domain_last], .tuple = tuple, .term = secure(interaction, 0), .prefix = secure(interaction, 4), .previous_prefix = secure(previous, 4) };
}
fn secure(columns: [interaction_count]Q, start: usize) Q {
    return Q.fromPartialEvals(.{ columns[start], columns[start + 1], columns[start + 2], columns[start + 3] });
}
fn filledLogs(a: std.mem.Allocator, count: usize, log_size: u32) ![]u32 {
    const values = try a.alloc(u32, count);
    @memset(values, log_size);
    return values;
}
fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingInitialRwMaskPoint;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, points: []const circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
    const values = try a.alloc([]circle.CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (values[0..initialized]) |column| a.free(column);
        a.free(values);
    }
    for (values) |*column| {
        column.* = try a.dupe(circle.CirclePointQM31, points);
        initialized += 1;
    }
    return values;
}
fn freePointColumns(a: std.mem.Allocator, columns: [][]circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}
