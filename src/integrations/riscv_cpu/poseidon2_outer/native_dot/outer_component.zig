//! R7 seventh component. The same dot row authority closes on the shared Var bus.
//! MAIN accumulator masks and INTER prefix masks use the same native one-row
//! shift, including when another roster role has greater height.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../authority.zig");
const K = @import("outer_authority.zig");
const Key = K.Key;
const R = @import("row.zig");
const O = A.O;
const M = A.M;
const Point = Core.circle.CirclePoint(O);
const Air = Core.air.components.ForField(O);
const Acc = Core.air.accumulation.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
const Domain = Engine.air.accumulation.ForField(O);
const Canonic = Core.poly.circle.canonic.CanonicCoset;
pub const Elements = @import("outer_witness.zig").Elements;
pub const Component = struct {
    key: *const Key,
    elements: Elements,
    claim: O,
    pub const Adapter = Core.air.derive.ForField(O).ComponentAdapter(@This(), PC.ComponentProver, PC.Trace, Domain.DomainEvaluationAccumulator);
    fn log(self: *const @This()) u32 {
        return self.key.dot_log;
    }
    fn widths(_: *const @This()) [3]usize {
        return .{ R.FIXED, R.MAIN, R.INTER };
    }
    fn offsets(_: *const @This()) [3]usize {
        return .{ K.FIXED_START, K.MAIN_START, K.INTER_START };
    }
    pub fn nConstraints(_: *const @This()) usize {
        return R.ROOTS;
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
                const previous = ((t == 1 and i >= R.ACC) or (t == 2 and i >= 16));
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
        var fixed: [R.FIXED]O = undefined;
        var main: [R.MAIN]O = undefined;
        var previous_main: [8]O = undefined;
        for (&fixed, mask.items[0][K.FIXED_START..][0..R.FIXED]) |*v, col| {
            if (col.len != 1) return error.NativeDotPhysicalMask;
            v.* = col[0];
        }
        for (&main, mask.items[1][K.MAIN_START..][0..R.MAIN], 0..) |*v, col, i| {
            if (col.len != (if (i >= R.ACC) @as(usize, 2) else 1)) return error.NativeDotPhysicalMask;
            v.* = col[0];
            if (i >= R.ACC) previous_main[i - R.ACC] = col[1];
        }
        var current: [3]O = undefined;
        var previous: [8]O = undefined;
        for (&current, 0..) |*v, i| {
            var coords: [8]O = undefined;
            for (&coords, 0..) |*c, j| {
                const col = mask.items[2][K.INTER_START + 8 * i + j];
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
        if (try @import("../op_profile.zig").scalarDomainControl()) return self.evaluateScalarDomain(trace, acc);
        return self.evaluatePackedDomain(trace, acc);
    }
    fn evaluateScalarDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const log_ = self.log();
        const eval_log = log_ + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = try Prepared.init(a, trace, eval_log, self.widths(), self.offsets());
        defer prepared.deinit();
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
    fn evaluatePackedDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const Lane = @import("outer_domain_lane.zig");
        const a = acc.allocator;
        const log_ = self.log();
        const eval_log = log_ + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = R.ROOTS }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = blk: {
            var scope = try @import("domain_profile.zig").begin("op_r7.dot_prepare", "R7 dot column preparation");
            defer scope.end();
            break :blk try Prepared.init(a, trace, eval_log, self.widths(), self.offsets());
        };
        defer prepared.deinit();
        const lane = Lane.Prepared.init(self.elements, self.claim.mulM31(try M.fromU64(self.key.dot_rows).inv()), output.random_coeff_powers);
        var inverse: [2]M = undefined;
        for (&inverse, 0..) |*value, half| {
            const r = half * (domain.size() / 2);
            value.* = try Core.constraints.cosetVanishing(M, Canonic.new(log_).coset(), domain.at(Core.utils.bitReverseIndex(r, eval_log))).inv();
        }
        const rows = PackedRows{ .polys = prepared.polys, .lane = &lane, .output = output.*, .inverse = inverse, .log = log_, .count = domain.size() };
        var row_scope = try @import("domain_profile.zig").begin("op_r7.dot_rows", "R7 dot packed rows");
        defer row_scope.end();
        try @import("domain_tiles.zig").run(PackedRows, &rows, domain.size(), Lane.WIDTH);
    }
    const PackedRows = struct {
        polys: []const Engine.air.component_trace.Poly,
        lane: *const @import("outer_domain_lane.zig").Prepared,
        output: Domain.ColumnAccumulator,
        inverse: [2]M,
        log: u32,
        count: usize,
        pub fn runRange(self: *const @This(), first: usize, end: usize) !void {
            const Lane = @import("outer_domain_lane.zig");
            const MF = Core.fields.m31;
            const Packed = Core.fields.packed_om31;
            const log_ = self.log;
            const eval_log = log_ + 1;
            const fixed_columns = self.polys[0..R.FIXED];
            const main_columns = self.polys[R.FIXED..][0..R.MAIN];
            const inter_columns = self.polys[R.FIXED + R.MAIN ..];
            const lane = self.lane;
            const inverse = self.inverse;
            // One copy per range, writing disjoint indices into the zeroed or
            // previously accumulated bucket; no shared fresh-index mutation.
            var output = self.output;
            output.next_fresh_index = null;
            var r = first;
            while (r < end) : (r += Lane.WIDTH) {
                var fixed: [R.FIXED]Lane.Base = undefined;
                var main: [R.MAIN]Lane.Base = undefined;
                var previous_main: [8]Lane.Base = undefined;
                for (&fixed, fixed_columns) |*v, poly| v.* = .{ .v = MF.loadPacked(poly.values[r..].ptr) };
                for (&main, main_columns) |*v, poly| v.* = .{ .v = MF.loadPacked(poly.values[r..].ptr) };
                for (&previous_main, 0..) |*v, j| inline for (0..Lane.WIDTH) |k| {
                    const prior = Core.utils.offsetBitReversedCircleDomainIndex(r + k, log_, eval_log, -1);
                    v.v[k] = main_columns[R.ACC + j].values[prior].v;
                };
                var current: [3]Lane.Secure = undefined;
                var previous: [8]MF.PackedM31 = undefined;
                for (&current, 0..) |*v, i| {
                    var coordinates: [8]MF.PackedM31 = undefined;
                    for (&coordinates, 0..) |*coordinate, j| {
                        const poly = inter_columns[8 * i + j];
                        coordinate.* = MF.loadPacked(poly.values[r..].ptr);
                        if (i == 2) inline for (0..Lane.WIDTH) |k| {
                            const prior = Core.utils.offsetBitReversedCircleDomainIndex(r + k, log_, eval_log, -1);
                            previous[j][k] = poly.values[prior].v;
                        };
                    }
                    v.* = Packed.fromCoordinates(coordinates);
                }
                const sum = (try lane.accumulate(&main, &previous_main, &fixed, &current, Packed.fromCoordinates(previous))).mulBase(@as(MF.PackedM31, @splat(inverse[r / (self.count / 2)].v)));
                inline for (0..Lane.WIDTH) |k| output.accumulate(r + k, Packed.lane(sum, k));
            }
        }
    };
};
const Prepared = @import("polynomials.zig").Prepared;
