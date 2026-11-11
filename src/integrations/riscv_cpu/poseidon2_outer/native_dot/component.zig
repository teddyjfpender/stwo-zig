//! Scalar reference adapter for the isolated physical gate; no live roster.
//! MAIN accumulator masks and INTER prefix masks use the same native one-row
//! shift, including when the independent auxiliary chip has greater height.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../authority.zig");
const Key = @import("physical_key.zig").Key;
const R = @import("row.zig");
const O = A.O;
const M = A.M;
const Point = Core.circle.CirclePoint(O);
const Air = Core.air.components.ForField(O);
const Acc = Core.air.accumulation.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
const Domain = Engine.air.accumulation.ForField(O);
const Canonic = Core.poly.circle.canonic.CanonicCoset;
pub const Elements = struct {
    z: O,
    powers: [6]O,
    pub fn init(z: O, alpha: O) Elements {
        var powers: [6]O = undefined;
        powers[0] = O.one();
        for (powers[1..], 0..) |*v, i| v.* = powers[i].mul(alpha);
        return .{ .z = z, .powers = powers };
    }
};
pub const Mode = enum { dot, auxiliary };
pub const Component = struct {
    key: *const Key,
    elements: Elements,
    claim: O,
    mode: Mode,
    pub const Adapter = Core.air.derive.ForField(O).ComponentAdapter(@This(), PC.ComponentProver, PC.Trace, Domain.DomainEvaluationAccumulator);
    fn log(self: *const @This()) u32 {
        return if (self.mode == .dot) self.key.dot_log else self.key.auxiliary_log;
    }
    fn widths(self: *const @This()) [3]usize {
        return if (self.mode == .dot) .{ R.FIXED, R.MAIN, R.INTER } else .{ 1, 1, 0 };
    }
    fn offsets(self: *const @This()) [3]usize {
        return if (self.mode == .dot) .{ 0, 0, 0 } else .{ R.FIXED, R.MAIN, R.INTER };
    }
    pub fn nConstraints(self: *const @This()) usize {
        return if (self.mode == .dot) R.ROOTS else 1;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log() + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const trees = try a.alloc([]u32, 3);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |tree| a.free(tree);
            a.free(trees);
        }
        for (trees, self.widths()) |*tree, n| {
            tree.* = try a.alloc(u32, n);
            @memset(tree.*, self.log());
            made += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.widths()[0]);
        for (out, 0..) |*v, i| v.* = self.offsets()[0] + i;
        return out;
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, max_log: u32) !Air.MaskPoints {
        const raw = Canonic.new(max_log).coset().step;
        const step = Point{ .x = O.fromBase(raw.x), .y = O.fromBase(raw.y) };
        const trees = try a.alloc([][]Point, 3);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |tree| {
                for (tree) |p| a.free(p);
                a.free(tree);
            }
            a.free(trees);
        }
        for (trees, self.widths(), 0..) |*tree, width, t| {
            tree.* = try a.alloc([]Point, width);
            var n: usize = 0;
            errdefer {
                for (tree.*[0..n]) |p| a.free(p);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*p, i| {
                const previous = self.mode == .dot and ((t == 1 and i >= R.ACC) or (t == 2 and i >= 16));
                p.* = if (t == 0) try a.alloc(Point, 0) else if (previous) try a.dupe(Point, &.{ point, point.add(step.mulSigned(-1)) }) else try a.dupe(Point, &.{point});
                n += 1;
            }
            made += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
        const off = self.offsets();
        const widths_ = self.widths();
        if (mask.items.len < 3 or max_log < self.log()) return error.NativeDotPhysicalMask;
        for (0..3) |t| if (mask.items[t].len < off[t] + widths_[t]) return error.NativeDotPhysicalMask;
        const inv = try Core.constraints.cosetVanishing(O, Canonic.new(self.log()).coset(), point.repeatedDouble(max_log - self.log())).inv();
        if (self.mode == .auxiliary) {
            if (mask.items[0][off[0]].len != 1 or mask.items[1][off[1]].len != 1) return error.NativeDotPhysicalMask;
            acc.accumulate(mask.items[1][off[1]][0].sub(mask.items[0][off[0]][0]).mul(inv));
            return;
        }
        var fixed: [R.FIXED]O = undefined;
        var main: [R.MAIN]O = undefined;
        var previous_main: [8]O = undefined;
        for (&fixed, mask.items[0][0..R.FIXED]) |*v, col| {
            if (col.len != 1) return error.NativeDotPhysicalMask;
            v.* = col[0];
        }
        for (&main, mask.items[1][0..R.MAIN], 0..) |*v, col, i| {
            if (col.len != (if (i >= R.ACC) @as(usize, 2) else 1)) return error.NativeDotPhysicalMask;
            v.* = col[0];
            if (i >= R.ACC) previous_main[i - R.ACC] = col[1];
        }
        var current: [3]O = undefined;
        var previous: [8]O = undefined;
        for (&current, 0..) |*v, i| {
            var coords: [8]O = undefined;
            for (&coords, 0..) |*c, j| {
                const col = mask.items[2][8 * i + j];
                if (col.len != (if (i == 2) @as(usize, 2) else 1)) return error.NativeDotPhysicalMask;
                c.* = col[0];
                if (i == 2) previous[j] = col[1];
            }
            v.* = O.fromPartialEvals(coords);
        }
        const shift = self.claim.mulM31(try M.fromU64(self.key.dot_rows).inv());
        for (R.rootsFor(O, &main, &previous_main, &fixed, &current, O.fromPartialEvals(previous), self.elements.z, self.elements.powers, shift)) |root| acc.accumulate(root.mul(inv));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const log_ = self.log();
        const eval_log = log_ + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = try Prepared.init(a, trace, eval_log, self.widths(), self.offsets());
        defer prepared.deinit();
        if (self.mode == .auxiliary) {
            for (0..domain.size()) |r| {
                const point = domain.at(Core.utils.bitReverseIndex(r, eval_log));
                const inv = try Core.constraints.cosetVanishing(O, Canonic.new(log_).coset(), .{ .x = O.fromBase(point.x), .y = O.fromBase(point.y) }).inv();
                const root = prepared.polys[1].values[r].sub(prepared.polys[0].values[r]);
                output.accumulate(r, O.fromBase(root).mul(inv).mul(output.random_coeff_powers[0]));
            }
            return;
        }
        const shift = self.claim.mulM31(try M.fromU64(self.key.dot_rows).inv());
        for (0..domain.size()) |r| {
            var fixed: [R.FIXED]O = undefined;
            var main: [R.MAIN]O = undefined;
            var previous_main: [8]O = undefined;
            var current: [3]O = undefined;
            var previous: [8]O = undefined;
            const prior = Core.utils.offsetBitReversedCircleDomainIndex(r, log_, eval_log, -1);
            for (&fixed, prepared.polys[0..R.FIXED]) |*v, poly| v.* = O.fromBase(poly.values[r]);
            for (&main, prepared.polys[R.FIXED..][0..R.MAIN], 0..) |*v, poly, i| {
                v.* = O.fromBase(poly.values[r]);
                if (i >= R.ACC) previous_main[i - R.ACC] = O.fromBase(poly.values[prior]);
            }
            for (&current, 0..) |*v, i| {
                var coords: [8]M = undefined;
                for (&coords, 0..) |*c, j| {
                    const poly = prepared.polys[R.FIXED + R.MAIN + 8 * i + j];
                    c.* = poly.values[r];
                    if (i == 2) previous[j] = O.fromBase(poly.values[prior]);
                }
                v.* = O.fromM31Array(coords);
            }
            const point = domain.at(Core.utils.bitReverseIndex(r, eval_log));
            const inv = try Core.constraints.cosetVanishing(O, Canonic.new(log_).coset(), .{ .x = O.fromBase(point.x), .y = O.fromBase(point.y) }).inv();
            var value = O.zero();
            for (R.rootsFor(O, &main, &previous_main, &fixed, &current, O.fromPartialEvals(previous), self.elements.z, self.elements.powers, shift), 0..) |root, i| value = value.add(root.mul(output.random_coeff_powers[R.ROOTS - 1 - i]));
            output.accumulate(r, value.mul(inv));
        }
    }
};
const Prepared = struct {
    allocator: std.mem.Allocator,
    polys: []Engine.air.component_trace.Poly,
    owned: []bool,
    fn init(a: std.mem.Allocator, trace: *const PC.Trace, log_: u32, widths: [3]usize, offsets: [3]usize) !Prepared {
        const count = widths[0] + widths[1] + widths[2];
        const polys = try a.alloc(Engine.air.component_trace.Poly, count);
        errdefer a.free(polys);
        const owned = try a.alloc(bool, count);
        errdefer a.free(owned);
        @memset(owned, false);
        var made: usize = 0;
        errdefer for (polys[0..made], owned[0..made]) |poly, take| if (take) a.free(@constCast(poly.values));
        const domain = Canonic.new(log_).circleDomain();
        for (widths, offsets, 0..) |width, start, tree| {
            if (tree >= trace.polys.items.len or start + width > trace.polys.items[tree].len) return error.NativeDotPhysicalTrace;
            for (trace.polys.items[tree][start..][0..width]) |poly| {
                try poly.validate();
                if (poly.device != null) return error.DeviceColumnRequiresBackend;
                if (poly.log_size == log_ and poly.values.len != 0) {
                    polys[made] = poly;
                } else {
                    const coefficients = poly.coefficients orelse return error.NativeDotCoefficientsRequired;
                    if (coefficients.logSize() > log_) return error.NativeDotPhysicalDegree;
                    const evaluation = try coefficients.evaluate(a, domain);
                    polys[made] = .{ .log_size = log_, .values = evaluation.values };
                    owned[made] = true;
                }
                made += 1;
            }
        }
        return .{ .allocator = a, .polys = polys, .owned = owned };
    }
    fn deinit(self: *Prepared) void {
        for (self.polys, self.owned) |poly, take| if (take) self.allocator.free(@constCast(poly.values));
        self.allocator.free(self.owned);
        self.allocator.free(self.polys);
        self.* = undefined;
    }
};
