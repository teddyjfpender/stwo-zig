//! R6 native OM31 product plus three paired Var LogUp accumulators.
//! All ports use source FIXED identifiers and complete base-field tuples.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../authority.zig");
const K = @import("authority.zig");
const L = @import("row.zig");
const Row = L;
const W = @import("witness.zig");
const O = A.O;
const M = A.M;
const Point = Core.circle.CirclePoint(O);
const Air = Core.air.components.ForField(O);
const Acc = Core.air.accumulation.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
const Domain = Engine.air.accumulation.ForField(O);
const Canonic = Core.poly.circle.canonic.CanonicCoset;
pub const ROOTS = L.ROOTS;
pub const Component = struct {
    key: *const K.Key,
    elements: W.Elements,
    claim: O,
    pub const Adapter = Core.air.derive.ForField(O).ComponentAdapter(@This(), PC.ComponentProver, PC.Trace, Domain.DomainEvaluationAccumulator);
    pub fn nConstraints(_: *const @This()) usize {
        return ROOTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.key.mul_log + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const trees = try a.alloc([]u32, 3);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |t| a.free(t);
            a.free(trees);
        }
        for (trees, [_]usize{ L.FIXED, L.MAIN, L.INTER }) |*tree, n| {
            tree.* = try a.alloc(u32, n);
            @memset(tree.*, self.key.mul_log);
            made += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, L.FIXED);
        for (out, 0..) |*v, i| v.* = K.FIXED_START + i;
        return out;
    }
    pub fn maskPoints(_: *const @This(), a: std.mem.Allocator, point: Point, max_log: u32) !Air.MaskPoints {
        const raw = Canonic.new(max_log).coset().step;
        const step = Point{ .x = O.fromBase(raw.x), .y = O.fromBase(raw.y) };
        const trees = try a.alloc([][]Point, 3);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |tree| {
                for (tree) |v| a.free(v);
                a.free(tree);
            }
            a.free(trees);
        }
        for (trees, [_]usize{ L.FIXED, L.MAIN, L.INTER }, 0..) |*tree, n, t| {
            tree.* = try a.alloc([]Point, n);
            var inner: usize = 0;
            errdefer {
                for (tree.*[0..inner]) |v| a.free(v);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*v, i| {
                v.* = if (t == 0) try a.alloc(Point, 0) else if (t == 2 and i >= 2 * 8) try a.dupe(Point, &.{ point, point.add(step.mulSigned(-1)) }) else try a.dupe(Point, &.{point});
                inner += 1;
            }
            made += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn roots(self: *const @This(), main: *const [L.MAIN]O, fixed: *const [L.FIXED]O, current: *const [3]O, previous: O) ![ROOTS]O {
        const shift = self.claim.mulM31(try M.fromU64(self.key.mul_rows).inv());
        return Row.rootsFor(O, main, fixed, current, previous, self.elements.z, self.elements.powers, shift);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
        const log = self.key.mul_log;
        if (max_log < log or mask.items.len < 3 or mask.items[0].len < K.FIXED_START + L.FIXED or mask.items[1].len < K.MAIN_START + L.MAIN or mask.items[2].len < K.INTER_START + L.INTER) return error.InvalidNativeOmulMask;
        var fixed: [L.FIXED]O = undefined;
        var main: [L.MAIN]O = undefined;
        var current: [3]O = undefined;
        for (&fixed, mask.items[0][K.FIXED_START..][0..L.FIXED]) |*v, col| {
            if (col.len != 1) return error.InvalidNativeOmulMask;
            v.* = col[0];
        }
        for (&main, mask.items[1][K.MAIN_START..][0..L.MAIN]) |*v, col| {
            if (col.len != 1) return error.InvalidNativeOmulMask;
            v.* = col[0];
        }
        var previous: [8]O = undefined;
        for (&current, 0..) |*value, i| {
            var coords: [8]O = undefined;
            for (&coords, 0..) |*coord, j| {
                const col = mask.items[2][K.INTER_START + 8 * i + j];
                if (col.len != (if (i == 2) @as(usize, 2) else 1)) return error.InvalidNativeOmulMask;
                coord.* = col[0];
                if (i == 2) previous[j] = col[1];
            }
            value.* = O.fromPartialEvals(coords);
        }
        const inv = try Core.constraints.cosetVanishing(O, Canonic.new(log).coset(), point.repeatedDouble(max_log - log)).inv();
        for (try self.roots(&main, &fixed, &current, O.fromPartialEvals(previous))) |root| acc.accumulate(root.mul(inv));
    }
    /// Commitment blowup and quotient degree are independent. Canonical
    /// circle domains at 2n and 4n are disjoint: a larger committed LDE must
    /// be re-evaluated from its authenticated coefficients, never indexed as
    /// if it belonged to the smaller quotient domain.
    const QuotientColumns = struct {
        allocator: std.mem.Allocator,
        columns: []Engine.air.component_trace.Poly,
        owned: []bool,
        fn init(a: std.mem.Allocator, trace: *const PC.Trace, log: u32) !@This() {
            const count = L.FIXED + L.MAIN + L.INTER;
            const columns = try a.alloc(Engine.air.component_trace.Poly, count);
            errdefer a.free(columns);
            const owned = try a.alloc(bool, count);
            errdefer a.free(owned);
            @memset(owned, false);
            var made: usize = 0;
            errdefer for (columns[0..made], owned[0..made]) |column, take| if (take) {
                a.free(@constCast(column.values));
            };
            const domain = Canonic.new(log).circleDomain();
            for ([_]usize{ L.FIXED, L.MAIN, L.INTER }, 0..) |width, tree| {
                const start: usize = switch (tree) {
                    0 => K.FIXED_START,
                    1 => K.MAIN_START,
                    2 => K.INTER_START,
                    else => unreachable,
                };
                if (tree >= trace.polys.items.len or start + width > trace.polys.items[tree].len) return error.InvalidPoseidonTraceShape;
                for (trace.polys.items[tree][start..][0..width]) |source| {
                    try source.validate();
                    if (source.device != null) return error.DeviceColumnRequiresBackend;
                    if (source.log_size == log and source.values.len != 0) {
                        columns[made] = source;
                    } else {
                        const coefficients = source.coefficients orelse return error.PoseidonQuotientRequiresCoefficients;
                        if (coefficients.logSize() > log) return error.InvalidPoseidonQuotientDegree;
                        const evaluation = try coefficients.evaluate(a, domain);
                        columns[made] = .{ .log_size = log, .values = evaluation.values };
                        owned[made] = true;
                    }
                    made += 1;
                }
            }
            return .{ .allocator = a, .columns = columns, .owned = owned };
        }
        fn deinit(self: *@This()) void {
            for (self.columns, self.owned) |column, take| if (take) {
                self.allocator.free(@constCast(column.values));
            };
            self.allocator.free(self.columns);
            self.allocator.free(self.owned);
            self.* = undefined;
        }
    };
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        if (try @import("../op_profile.zig").scalarDomainControl()) return self.evaluateScalarDomain(trace, acc);
        return self.evaluatePackedDomain(trace, acc);
    }
    fn evaluateScalarDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const log = self.key.mul_log;
        const eval_log = log + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = ROOTS }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = try QuotientColumns.init(a, trace, eval_log);
        defer prepared.deinit();
        const fixed_columns = prepared.columns[0..L.FIXED];
        const main_columns = prepared.columns[L.FIXED..][0..L.MAIN];
        const inter_columns = prepared.columns[L.FIXED + L.MAIN ..];
        for (0..domain.size()) |r| {
            var fixed: [L.FIXED]O = undefined;
            var main: [L.MAIN]O = undefined;
            var current: [3]O = undefined;
            var previous: [8]O = undefined;
            for (&fixed, fixed_columns) |*v, poly| v.* = O.fromBase(try poly.valueAtLiftingPosition(eval_log, r));
            for (&main, main_columns) |*v, poly| v.* = O.fromBase(try poly.valueAtLiftingPosition(eval_log, r));
            for (&current, 0..) |*value, i| {
                var coords: [8]M = undefined;
                for (&coords, 0..) |*coord, j| {
                    const poly = inter_columns[8 * i + j];
                    coord.* = try poly.valueAtLiftingPosition(eval_log, r);
                    if (i == 2) previous[j] = O.fromBase(try poly.valueAtLiftingPosition(eval_log, Core.utils.offsetBitReversedCircleDomainIndex(r, log, eval_log, -1)));
                }
                value.* = O.fromM31Array(coords);
            }
            const point = domain.at(Core.utils.bitReverseIndex(r, eval_log));
            const inv = try Core.constraints.cosetVanishing(O, Canonic.new(log).coset(), .{ .x = O.fromBase(point.x), .y = O.fromBase(point.y) }).inv();
            var value = O.zero();
            for (try self.roots(&main, &fixed, &current, O.fromPartialEvals(previous)), 0..) |root, i| value = value.add(root.mul(output.random_coeff_powers[ROOTS - 1 - i]));
            output.accumulate(r, value.mul(inv));
        }
    }
    fn evaluatePackedDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const Lane = @import("domain_lane.zig");
        const MF = Core.fields.m31;
        const Packed = Core.fields.packed_om31;
        const a = acc.allocator;
        const log = self.key.mul_log;
        const eval_log = log + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = ROOTS }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = try QuotientColumns.init(a, trace, eval_log);
        defer prepared.deinit();
        const fixed_columns = prepared.columns[0..L.FIXED];
        const main_columns = prepared.columns[L.FIXED..][0..L.MAIN];
        const inter_columns = prepared.columns[L.FIXED + L.MAIN ..];
        const lane = Lane.Prepared.init(self.elements, self.claim.mulM31(try M.fromU64(self.key.mul_rows).inv()), output.random_coeff_powers);
        // On the canonical 2n quotient domain, the n-coset vanishing value is
        // constant on each contiguous bit-reversed half. Derive both values
        // from the same source polynomial, in M31, once rather than invert an
        // OM31 value on every row. OODS evaluation remains unchanged.
        var inverse: [2]M = undefined;
        for (&inverse, 0..) |*value, half| {
            const row = half * (domain.size() / 2);
            value.* = try Core.constraints.cosetVanishing(M, Canonic.new(log).coset(), domain.at(Core.utils.bitReverseIndex(row, eval_log))).inv();
        }
        var row: usize = 0;
        while (row < domain.size()) : (row += Lane.WIDTH) {
            var fixed: [L.FIXED]Lane.Base = undefined;
            var main: [L.MAIN]Lane.Base = undefined;
            for (&fixed, fixed_columns) |*value, poly| value.* = .{ .v = MF.loadPacked(poly.values[row..].ptr) };
            for (&main, main_columns) |*value, poly| value.* = .{ .v = MF.loadPacked(poly.values[row..].ptr) };
            var current: [3]Lane.Secure = undefined;
            var previous: [8]MF.PackedM31 = undefined;
            for (&current, 0..) |*value, i| {
                var coords: [8]MF.PackedM31 = undefined;
                for (&coords, 0..) |*coordinate, j| {
                    const poly = inter_columns[8 * i + j];
                    coordinate.* = MF.loadPacked(poly.values[row..].ptr);
                    if (i == 2) inline for (0..Lane.WIDTH) |k| {
                        const index = Core.utils.offsetBitReversedCircleDomainIndex(row + k, log, eval_log, -1);
                        previous[j][k] = poly.values[index].v;
                    };
                }
                value.* = Packed.fromCoordinates(coords);
            }
            const sum = (try lane.accumulate(&main, &fixed, &current, Packed.fromCoordinates(previous))).mulBase(@as(MF.PackedM31, @splat(inverse[row / (domain.size() / 2)].v)));
            inline for (0..Lane.WIDTH) |k| output.accumulate(row + k, Packed.lane(sum, k));
        }
    }
};
