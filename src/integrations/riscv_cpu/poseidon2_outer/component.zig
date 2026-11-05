//! Dedicated P2 permutation plus classic horizontal/prefix LogUp constraints.
//! All ports use source FIXED identifiers and complete base-field tuples.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("authority.zig");
const L = @import("layout.zig");
const Row = @import("row.zig");
const W = @import("witness.zig");
const O = A.O;
const M = A.M;
const Point = Core.circle.CirclePoint(O);
const Air = Core.air.components.ForField(O);
const Acc = Core.air.accumulation.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
const Domain = Engine.air.accumulation.ForField(O);
const Canonic = Core.poly.circle.canonic.CanonicCoset;
pub const ROOTS = L.CONSTRAINTS + 24;
pub const Component = struct {
    key: *const A.Authority,
    elements: W.Elements,
    claim: O,
    pub const Adapter = Core.air.derive.ForField(O).ComponentAdapter(@This(), PC.ComponentProver, PC.Trace, Domain.DomainEvaluationAccumulator);
    pub fn nConstraints(_: *const @This()) usize {
        return ROOTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.key.logs[3] + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const trees = try a.alloc([]u32, 3);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |t| a.free(t);
            a.free(trees);
        }
        for (trees, [_]usize{ L.FIXED_COLUMNS, L.MAIN_COLUMNS, L.CLASSIC_INTERACTION_COLUMNS }) |*tree, n| {
            tree.* = try a.alloc(u32, n);
            @memset(tree.*, self.key.logs[3]);
            made += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, L.FIXED_COLUMNS);
        for (out, 0..) |*v, i| v.* = A.FIXED_START[3] + i;
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
        for (trees, [_]usize{ L.FIXED_COLUMNS, L.MAIN_COLUMNS, L.CLASSIC_INTERACTION_COLUMNS }, 0..) |*tree, n, t| {
            tree.* = try a.alloc([]Point, n);
            var inner: usize = 0;
            errdefer {
                for (tree.*[0..inner]) |v| a.free(v);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*v, i| {
                v.* = if (t == 0) try a.alloc(Point, 0) else if (t == 2 and i >= 23 * 8) try a.dupe(Point, &.{ point, point.add(step.mulSigned(-1)) }) else try a.dupe(Point, &.{point});
                inner += 1;
            }
            made += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn roots(self: *const @This(), main: *const [L.MAIN_COLUMNS]O, fixed: *const [L.FIXED_COLUMNS]O, current: *const [24]O, previous: O) ![ROOTS]O {
        var out: [ROOTS]O = undefined;
        out[0..L.CONSTRAINTS].* = try Row.evaluateFor(O, main);
        const ports = Row.portsFor(O, main, fixed);
        var prior = O.zero();
        const shift = self.claim.mulM31(try M.fromU64(self.key.rows[3]).inv());
        for (0..24) |i| {
            var d0 = O.zero();
            var d1 = O.zero();
            for (ports[2 * i].tuple, self.elements.powers) |value, power| d0 = d0.add(value.mul(power));
            for (ports[2 * i + 1].tuple, self.elements.powers) |value, power| d1 = d1.add(value.mul(power));
            d0 = d0.sub(self.elements.z);
            d1 = d1.sub(self.elements.z);
            const numerator = ports[2 * i].numerator.mul(d1).add(ports[2 * i + 1].numerator.mul(d0));
            const delta = if (i == 23) current[i].sub(previous).add(shift).sub(prior) else current[i].sub(prior);
            out[L.CONSTRAINTS + i] = delta.mul(d0.mul(d1)).sub(numerator);
            prior = current[i];
        }
        return out;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
        const log = self.key.logs[3];
        if (max_log < log or mask.items.len < 3 or mask.items[0].len < A.FIXED_START[3] + L.FIXED_COLUMNS or mask.items[1].len < A.MAIN_START[3] + L.MAIN_COLUMNS or mask.items[2].len < A.INTER_START[3] + L.CLASSIC_INTERACTION_COLUMNS) return error.InvalidPoseidonFiveMask;
        var fixed: [L.FIXED_COLUMNS]O = undefined;
        var main: [L.MAIN_COLUMNS]O = undefined;
        var current: [24]O = undefined;
        for (&fixed, mask.items[0][A.FIXED_START[3]..][0..L.FIXED_COLUMNS]) |*v, col| {
            if (col.len != 1) return error.InvalidPoseidonFiveMask;
            v.* = col[0];
        }
        for (&main, mask.items[1][A.MAIN_START[3]..][0..L.MAIN_COLUMNS]) |*v, col| {
            if (col.len != 1) return error.InvalidPoseidonFiveMask;
            v.* = col[0];
        }
        var previous: [8]O = undefined;
        for (&current, 0..) |*value, i| {
            var coords: [8]O = undefined;
            for (&coords, 0..) |*coord, j| {
                const col = mask.items[2][A.INTER_START[3] + 8 * i + j];
                if (col.len != (if (i == 23) @as(usize, 2) else 1)) return error.InvalidPoseidonFiveMask;
                coord.* = col[0];
                if (i == 23) previous[j] = col[1];
            }
            value.* = O.fromPartialEvals(coords);
        }
        const inv = try Core.constraints.cosetVanishing(O, Canonic.new(log).coset(), point.repeatedDouble(max_log - log)).inv();
        for (try self.roots(&main, &fixed, &current, O.fromPartialEvals(previous))) |root| acc.accumulate(root.mul(inv));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const log = self.key.logs[3];
        const eval_log = log + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = ROOTS }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        for (0..domain.size()) |r| {
            var fixed: [L.FIXED_COLUMNS]O = undefined;
            var main: [L.MAIN_COLUMNS]O = undefined;
            var current: [24]O = undefined;
            var previous: [8]O = undefined;
            for (&fixed, trace.polys.items[0][A.FIXED_START[3]..][0..L.FIXED_COLUMNS]) |*v, poly| v.* = O.fromBase(try poly.valueAtLiftingPosition(eval_log, r));
            for (&main, trace.polys.items[1][A.MAIN_START[3]..][0..L.MAIN_COLUMNS]) |*v, poly| v.* = O.fromBase(try poly.valueAtLiftingPosition(eval_log, r));
            for (&current, 0..) |*value, i| {
                var coords: [8]M = undefined;
                for (&coords, 0..) |*coord, j| {
                    const poly = trace.polys.items[2][A.INTER_START[3] + 8 * i + j];
                    coord.* = try poly.valueAtLiftingPosition(eval_log, r);
                    if (i == 23) previous[j] = O.fromBase(try poly.valueAtLiftingPosition(eval_log, Core.utils.offsetBitReversedCircleDomainIndex(r, log, eval_log, -1)));
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
};
