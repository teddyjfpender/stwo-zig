//! One composite handle owns the entire native column inventory. This permits
//! exact absolute-index aliasing without introducing duplicate owned columns
//! in the framework's concatenated component masks. All original equations
//! and shifted interaction masks execute before the four activity equations.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const activity = @import("block_v5_native_capacity_activity_v1.zig");
const native = @import("block_v5_native_components_v3.zig");
const components = core.air.components;
const prover = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
pub const Component = struct {
    inner: *native.Owner,
    plan: protocol.Plan,
    fixed_logs: []const u32,
    main_logs: []const u32,
    interaction_logs: []const u32,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, prover.ComponentProver, prover.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Self) prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) components.Component {
        return Adapter.asVerifierComponent(self);
    }
    fn nativeComponents(self: *const Self) components.Components {
        return .{ .components = self.inner.verifying.components.active(), .n_preprocessed_columns = self.fixed_logs.len };
    }
    pub fn nConstraints(self: *const Self) usize {
        var total: usize = activity.N_CONSTRAINTS * self.plan.len;
        for (self.inner.verifying.components.active()) |item| total += item.nConstraints();
        return total;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        var result = self.nativeComponents().compositionLogDegreeBound();
        for (self.plan.active()) |shard| result = @max(result, shard.log_size + 2);
        return result;
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.nativeComponents().compositionLogSplit() catch unreachable;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, self.fixed_logs);
        errdefer a.free(fixed);
        const main = try a.dupe(u32, self.main_logs);
        errdefer a.free(main);
        const interaction = try a.dupe(u32, self.interaction_logs);
        errdefer a.free(interaction);
        return .initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, self.fixed_logs.len);
        for (result, 0..) |*index, i| index.* = i;
        return result;
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !components.MaskPoints {
        var original = try self.nativeComponents().maskPoints(a, point, max_log, true);
        errdefer original.deinitDeep(a);
        if (original.items.len != 3 or original.items[1].len != self.plan.native_main_count) return error.InvalidNativeCapacityMasks;
        if (self.plan.len == 0) return original;
        const grown = try a.alloc([]Point, self.plan.mainCount());
        var initialized: usize = self.plan.native_main_count;
        errdefer {
            for (grown[self.plan.native_main_count..initialized]) |points| a.free(points);
            a.free(grown);
        }
        @memcpy(grown[0..initialized], original.items[1]);
        for (self.plan.active()) |_| {
            for (0..2) |_| {
                grown[initialized] = try a.dupe(Point, &.{ point, @import("../air/logup.zig").prevRowPoint(max_log, point) });
                initialized += 1;
            }
        }
        a.free(original.items[1]);
        original.items[1] = grown;
        return original;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len != 3 or mask.items[0].len != self.fixed_logs.len or mask.items[1].len != self.main_logs.len) return error.InvalidNativeCapacityMasks;
        // Stack views borrow exactly the authenticated main selector cells.
        // No caller-owned count/selector replaces a PCS opening.
        var fixed: [2 * protocol.MAX_SHARDS][]Q = undefined;
        if (mask.items[0].len > fixed.len) return error.InvalidNativeCapacityMasks;
        @memcpy(fixed[0..mask.items[0].len], mask.items[0]);
        for (self.plan.active()) |shard| {
            if (mask.items[1][shard.main_index].len != 2) return error.InvalidNativeCapacityMasks;
            fixed[shard.active_index] = mask.items[1][shard.main_index][0..1];
        }
        var trees = [_][][]Q{ fixed[0..mask.items[0].len], mask.items[1][0..self.plan.native_main_count], mask.items[2] };
        const view = components.MaskValues{ .items = &trees };
        for (self.inner.verifying.components.active()) |item| try item.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
        for (self.plan.active()) |shard| {
            const active = mask.items[1][shard.main_index];
            const count = mask.items[1][shard.main_index + 1];
            if (active.len != 2 or count.len != 2 or mask.items[0][shard.first_index].len != 1 or max_log < shard.log_size) return error.InvalidNativeCapacityMasks;
            const checks = activity.evaluate(Q, mask.items[0][shard.first_index][0], active[0], active[1], count[0], count[1], Q.fromBase(M.fromCanonical(shard.rows)));
            const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(shard.log_size).coset(), point.repeatedDouble(max_log - shard.log_size)).inv();
            for (checks) |check| accumulator.accumulate(check.mul(inverse));
        }
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3 or trace.polys.items[0].len != self.fixed_logs.len or trace.polys.items[1].len != self.main_logs.len) return error.InvalidNativeCapacityTrees;
        var fixed: [2 * protocol.MAX_SHARDS]prover.Poly = undefined;
        if (trace.polys.items[0].len > fixed.len) return error.InvalidNativeCapacityTrees;
        @memcpy(fixed[0..trace.polys.items[0].len], trace.polys.items[0]);
        for (self.plan.active()) |shard| fixed[shard.active_index] = trace.polys.items[1][shard.main_index];
        var trees = [_][]const prover.Poly{ fixed[0..trace.polys.items[0].len], trace.polys.items[1][0..self.plan.native_main_count], trace.polys.items[2] };
        var view = trace.*;
        view.polys = .{ .items = &trees };
        for (self.inner.proving.components.active()) |item| try item.evaluateConstraintQuotientsOnDomain(&view, accumulator);
        for (self.plan.active()) |shard| try evaluateActivityDomain(shard, trace, accumulator);
    }
};
fn evaluateActivityDomain(shard: protocol.Shard, trace: *const prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
    const a = accumulator.allocator;
    const eval_log = shard.log_size + 2;
    const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
    const polys = [_]prover.Poly{ trace.polys.items[0][shard.first_index], trace.polys.items[1][shard.main_index], trace.polys.items[1][shard.main_index + 1] };
    var owned: [3][]M = undefined;
    var initialized: usize = 0;
    defer for (owned[0..initialized]) |values| a.free(values);
    var values: [3][]const M = undefined;
    for (polys, &values) |poly, *out| out.* = try @import("block_v5_program_request_component_v1.zig").domainValues(a, poly, shard.log_size, eval_log, domain.size(), &owned, &initialized);
    if (initialized != 0) {
        var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &twiddles);
        try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
    }
    var inverses: [4]M = undefined;
    for (&inverses, 0..) |*inverse, i| inverse.* = try core.constraints.cosetVanishing(M, canonic.CanonicCoset.new(shard.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, 2))).inv();
    const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = activity.N_CONSTRAINTS }});
    defer a.free(output);
    var result = output[0];
    for (0..domain.size()) |row| {
        const previous = core.utils.previousBitReversedCircleDomainIndex(row, shard.log_size, eval_log);
        const checks = activity.evaluate(Q, Q.fromBase(values[0][row]), Q.fromBase(values[1][row]), Q.fromBase(values[1][previous]), Q.fromBase(values[2][row]), Q.fromBase(values[2][previous]), Q.fromBase(M.fromCanonical(shard.rows)));
        var folded = Q.zero();
        for (checks, 0..) |check, i| folded = folded.add(result.random_coeff_powers[result.random_coeff_powers.len - 1 - i].mul(check));
        result.accumulate(row, folded.mulM31(inverses[row >> @intCast(shard.log_size)]));
    }
}
