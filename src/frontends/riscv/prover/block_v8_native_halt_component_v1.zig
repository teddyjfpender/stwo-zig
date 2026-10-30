//! Two-column halt guard. Native columns are borrowed at exact current-row openings.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const C = core.air.components;
const P = engine.air.component_prover;
const A = engine.air.accumulation;
const Canonic = core.poly.circle.canonic.CanonicCoset;
const Leased = @import("block_v7_leased_quotient_cache_v1.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
pub const Component = struct {
    log_size: u32,
    active_column: usize,
    main_offset: usize,
    aux_offset: usize,
    policy: Halt.Policy,
    providers: []const C.Component,
    leased_quotient_cache: ?*Leased.Cache = null,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, P.ComponentProver, P.Trace, A.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Self) P.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) C.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return Halt.CONSTRAINT_COUNT;
    }
    pub fn width(_: *const Self) usize {
        return Halt.NativeColumns.width;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return a.dupe(usize, &.{self.active_column});
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, &.{self.log_size});
        errdefer a.free(fixed);
        const main = try a.alloc(u32, 2);
        errdefer a.free(main);
        @memset(main, self.log_size);
        const interaction = try a.alloc(u32, 0);
        errdefer a.free(interaction);
        return .initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
        if (max_log < self.log_size) return error.InvalidNativeHaltMask;
        const fixed = try pointColumns(a, 1, point);
        errdefer freePoints(a, fixed);
        // Require the original providers to supply exactly this current-row mask.
        var offset: usize = 0;
        var covered: usize = 0;
        for (self.providers) |provider| {
            var supplied = try provider.maskPoints(a, point, max_log);
            defer supplied.deinitDeep(a);
            if (supplied.items.len != 3) return error.InvalidNativeHaltMask;
            for (supplied.items[1], 0..) |column, i| {
                if (offset + i >= self.main_offset and offset + i < self.main_offset + Halt.NativeColumns.width) {
                    if (column.len != 1 or !std.meta.eql(column[0], point)) return error.InvalidNativeHaltSharedMask;
                    covered += 1;
                }
            }
            offset += supplied.items[1].len;
        }
        if (covered != Halt.NativeColumns.width) return error.InvalidNativeHaltSharedMask;
        const main = try pointColumns(a, 2, point);
        errdefer freePoints(a, main);
        const interaction = try pointColumns(a, 0, point);
        errdefer freePoints(a, interaction);
        return .initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
    }
    pub fn evaluate(self: *const Self, comptime S: type, main: []const S, active: S, aux: [2]S, out: *[Halt.CONSTRAINT_COUNT]S) ![]const S {
        if (main.len != self.width()) return error.InvalidNativeHaltMask;
        out.* = try Halt.constraintsNative(S, self.policy, active, main, aux);
        return out[0..self.nConstraints()];
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log < self.log_size or mask.items.len < 3 or mask.items[0].len <= self.active_column or mask.items[1].len < self.aux_offset + 2) return error.InvalidNativeHaltMask;
        var row: [Halt.NativeColumns.width]Q = undefined;
        for (row[0..self.width()], mask.items[1][self.main_offset..][0..self.width()]) |*value, column| value.* = try pointAt(column);
        var checks: [Halt.CONSTRAINT_COUNT]Q = undefined;
        const values = try self.evaluate(Q, row[0..self.width()], try pointAt(mask.items[0][self.active_column]), .{ try pointAt(mask.items[1][self.aux_offset]), try pointAt(mask.items[1][self.aux_offset + 1]) }, &checks);
        const inverse = try core.constraints.cosetVanishing(Q, Canonic.new(self.log_size).coset(), point.repeatedDouble(max_log - self.log_size)).inv();
        for (values) |value| accumulator.accumulate(value.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const P.Trace, accumulator: *A.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3 or trace.polys.items[0].len <= self.active_column or trace.polys.items[1].len < self.aux_offset + 2) return error.InvalidNativeHaltMask;
        const a = accumulator.allocator;
        const eval_log = self.log_size + 2;
        const domain = Canonic.new(eval_log).circleDomain();
        // Only thirteen native values are consumed by the exact guard AIR.
        // Fixed active plus two private auxiliaries make sixteen evaluations,
        // instead of recovering the entire fifty-column native row.
        const count = Halt.INPUT_COUNT + 3;
        var polys: [count]P.Poly = undefined;
        polys[0] = trace.polys.items[0][self.active_column];
        for (Halt.NativeColumns.used, 0..) |index, i| polys[1 + i] = trace.polys.items[1][self.main_offset + index];
        @memcpy(polys[1 + Halt.INPUT_COUNT ..][0..2], trace.polys.items[1][self.aux_offset..][0..2]);
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
        var values: [count][]const M = undefined;
        var twiddles = if (owned_count != 0) try engine.poly.twiddles.precomputeM31(a, domain.half_coset) else null;
        defer if (twiddles) |*tree| engine.poly.twiddles.deinitM31(a, tree);
        const transform: ?engine.poly.twiddles.TwiddleTree([]const M) = if (twiddles) |tree| .init(tree.root_coset, tree.twiddles, tree.itwiddles) else null;
        var leases: [Halt.INPUT_COUNT]Leased.Lease = undefined;
        var lease_count: usize = 0;
        defer for (leases[0..lease_count]) |*lease| lease.release();
        for (polys, &values, 0..) |poly, *out, index| {
            if (index >= 1 and index <= Halt.INPUT_COUNT) if (self.leased_quotient_cache) |cache| {
                if (try cache.get(.lookup, poly, self.log_size, eval_log, transform)) |lease| {
                    leases[lease_count] = lease;
                    lease_count += 1;
                    out.* = lease.values;
                    continue;
                }
            };
            out.* = try @import("block_v5_program_request_component_v1.zig").domainValues(a, poly, self.log_size, eval_log, domain.size(), owned, &initialized);
        }
        if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, transform.?);
        var inverses: [4]M = undefined;
        for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, Canonic.new(self.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, 2))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(output);
        var result = output[0];
        const lanes = core.fields.m31.PACK_WIDTH;
        var weights: [Halt.CONSTRAINT_COUNT]Halt.PackedQ = undefined;
        for (&weights, 0..) |*weight, i| weight.* = Halt.PackedQ.splat(result.random_coeff_powers[result.random_coeff_powers.len - 1 - i]);
        var physical: usize = 0;
        while (physical + lanes <= domain.size()) : (physical += lanes) {
            var input: [Halt.INPUT_COUNT]Halt.PackedBase = undefined;
            for (&input, values[1..][0..Halt.INPUT_COUNT]) |*value, column| value.* = .{ .value = core.fields.m31.loadPacked(column.ptr + physical) };
            const active = Halt.PackedBase{ .value = core.fields.m31.loadPacked(values[0].ptr + physical) };
            const aux = [2]Halt.PackedBase{
                .{ .value = core.fields.m31.loadPacked(values[1 + Halt.INPUT_COUNT].ptr + physical) },
                .{ .value = core.fields.m31.loadPacked(values[2 + Halt.INPUT_COUNT].ptr + physical) },
            };
            const checks = Halt.constraintsSparse(Halt.PackedBase, self.policy, active, input, aux);
            const folded = Halt.foldPacked(checks, weights);
            // A packed group may cross a vanishing segment at tiny domains;
            // applying the scalar segment factor per lane handles that too.
            for (0..lanes) |lane| result.accumulate(physical + lane, folded.lane(lane).mulM31(inverses[(physical + lane) >> @intCast(self.log_size)]));
        }
        while (physical < domain.size()) : (physical += 1) {
            var input: [Halt.INPUT_COUNT]M = undefined;
            for (&input, values[1..][0..Halt.INPUT_COUNT]) |*value, column| value.* = column[physical];
            const checks = Halt.constraintsSparse(M, self.policy, values[0][physical], input, .{ values[1 + Halt.INPUT_COUNT][physical], values[2 + Halt.INPUT_COUNT][physical] });
            var folded = Q.zero();
            for (checks, 0..) |check, i| folded = folded.add(result.random_coeff_powers[result.random_coeff_powers.len - 1 - i].mulM31(check));
            result.accumulate(physical, folded.mulM31(inverses[physical >> @intCast(self.log_size)]));
        }
    }
};
fn pointAt(values: []const Q) !Q {
    if (values.len != 1) return error.InvalidNativeHaltOpening;
    return values[0];
}
fn pointColumns(a: std.mem.Allocator, count: usize, point: Point) ![][]Point {
    const columns = try a.alloc([]Point, count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| a.free(column);
        a.free(columns);
    }
    for (columns) |*column| {
        column.* = try a.dupe(Point, &.{point});
        initialized += 1;
    }
    return columns;
}
fn freePoints(a: std.mem.Allocator, columns: [][]Point) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}
