//! Eighth R7-v2 role: complete Var producers for source-registered QM31 guesses.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const K = @import("outer_authority.zig");
const R = @import("input_row.zig");
const W = @import("outer_witness.zig");
const Prepared = @import("polynomials.zig").Prepared;
const O = Core.fields.om31.OM31;
const M = Core.fields.m31.M31;
const Air = Core.air.components.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
const Acc = Core.air.accumulation.ForField(O);
const Domain = Engine.air.accumulation.ForField(O);
const Point = Core.circle.CirclePoint(O);
const Canonic = Core.poly.circle.canonic.CanonicCoset;
pub const Component = struct {
    key: *const K.Key,
    elements: W.Elements,
    claim: O,
    pub const Adapter = Core.air.derive.ForField(O).ComponentAdapter(@This(), PC.ComponentProver, PC.Trace, Domain.DomainEvaluationAccumulator);
    pub fn nConstraints(_: *const @This()) usize {
        return 1;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.key.input_log + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const trees = try a.alloc([]u32, 3);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |t| a.free(t);
            a.free(trees);
        }
        for (trees, [_]usize{ R.FIXED, R.MAIN, R.INTER }) |*tree, width| {
            tree.* = try a.alloc(u32, width);
            @memset(tree.*, self.key.input_log);
            made += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, R.FIXED);
        for (out, 0..) |*v, i| v.* = K.INPUT_FIXED_START + i;
        return out;
    }
    pub fn maskPoints(_: *const @This(), a: std.mem.Allocator, point: Point, max_log: u32) !Air.MaskPoints {
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
        for (trees, [_]usize{ R.FIXED, R.MAIN, R.INTER }, 0..) |*tree, width, t| {
            tree.* = try a.alloc([]Point, width);
            var inner: usize = 0;
            errdefer {
                for (tree.*[0..inner]) |p| a.free(p);
                a.free(tree.*);
            }
            for (tree.*) |*p| {
                p.* = if (t == 0) try a.alloc(Point, 0) else if (t == 1) try a.dupe(Point, &.{point}) else try a.dupe(Point, &.{ point, point.add(step.mulSigned(-1)) });
                inner += 1;
            }
            made += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3 or max_log < self.key.input_log or mask.items[0].len < K.INPUT_FIXED_START + R.FIXED or mask.items[1].len < K.INPUT_MAIN_START + R.MAIN or mask.items[2].len < K.INPUT_INTER_START + R.INTER) return error.InvalidNativeInputMask;
        var fixed: [R.FIXED]O = undefined;
        var main: [R.MAIN]O = undefined;
        var current: [8]O = undefined;
        var previous: [8]O = undefined;
        for (&fixed, mask.items[0][K.INPUT_FIXED_START..][0..R.FIXED]) |*v, col| {
            if (col.len != 1) return error.InvalidNativeInputMask;
            v.* = col[0];
        }
        for (&main, mask.items[1][K.INPUT_MAIN_START..][0..R.MAIN]) |*v, col| {
            if (col.len != 1) return error.InvalidNativeInputMask;
            v.* = col[0];
        }
        for (&current, &previous, mask.items[2][K.INPUT_INTER_START..][0..8]) |*v, *p, col| {
            if (col.len != 2) return error.InvalidNativeInputMask;
            v.* = col[0];
            p.* = col[1];
        }
        const inverse = try Core.constraints.cosetVanishing(O, Canonic.new(self.key.input_log).coset(), point.repeatedDouble(max_log - self.key.input_log)).inv();
        const shift = self.claim.mulM31(try M.fromU64(self.key.input_rows).inv());
        acc.accumulate(R.rootFor(O, &main, &fixed, O.fromPartialEvals(current), O.fromPartialEvals(previous), self.elements.z, self.elements.powers, shift).mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        if (try @import("../op_profile.zig").scalarDomainControl()) return self.scalarDomain(trace, acc);
        return self.packedDomain(trace, acc);
    }
    fn scalarDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const log = self.key.input_log;
        const eval_log = log + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = 1 }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = try Prepared.init(a, trace, eval_log, .{ R.FIXED, R.MAIN, R.INTER }, .{ K.INPUT_FIXED_START, K.INPUT_MAIN_START, K.INPUT_INTER_START });
        defer prepared.deinit();
        const shift = self.claim.mulM31(try M.fromU64(self.key.input_rows).inv());
        for (0..domain.size()) |row| {
            var fixed: [R.FIXED]O = undefined;
            var main: [R.MAIN]O = undefined;
            var current: [8]M = undefined;
            var previous: [8]M = undefined;
            for (&fixed, prepared.polys[0..R.FIXED]) |*v, col| v.* = O.fromBase(col.values[row]);
            for (&main, prepared.polys[R.FIXED..][0..R.MAIN]) |*v, col| v.* = O.fromBase(col.values[row]);
            const prior = Core.utils.offsetBitReversedCircleDomainIndex(row, log, eval_log, -1);
            for (&current, &previous, prepared.polys[R.FIXED + R.MAIN ..]) |*v, *p, col| {
                v.* = col.values[row];
                p.* = col.values[prior];
            }
            const point = domain.at(Core.utils.bitReverseIndex(row, eval_log));
            const inverse = try Core.constraints.cosetVanishing(O, Canonic.new(log).coset(), .{ .x = O.fromBase(point.x), .y = O.fromBase(point.y) }).inv();
            const root = R.rootFor(O, &main, &fixed, O.fromM31Array(current), O.fromM31Array(previous), self.elements.z, self.elements.powers, shift);
            output.accumulate(row, root.mul(inverse).mul(output.random_coeff_powers[0]));
        }
    }
    fn packedDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const MF = Core.fields.m31;
        const Packed = Core.fields.packed_om31;
        const a = acc.allocator;
        const log = self.key.input_log;
        const eval_log = log + 1;
        const slots = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = 1 }});
        defer a.free(slots);
        const output = &slots[0];
        const domain = Canonic.new(eval_log).circleDomain();
        var prepared = blk: {
            var scope = try @import("domain_profile.zig").begin("op_r7.input_prepare", "R7 input column preparation");
            defer scope.end();
            break :blk try Prepared.init(a, trace, eval_log, .{ R.FIXED, R.MAIN, R.INTER }, .{ K.INPUT_FIXED_START, K.INPUT_MAIN_START, K.INPUT_INTER_START });
        };
        defer prepared.deinit();
        var inverse: [2]M = undefined;
        for (&inverse, 0..) |*v, half| v.* = try Core.constraints.cosetVanishing(M, Canonic.new(log).coset(), domain.at(Core.utils.bitReverseIndex(half * (domain.size() / 2), eval_log))).inv();
        const shift = Packed.splat(self.claim.mulM31(try M.fromU64(self.key.input_rows).inv()));
        const coefficient = Packed.splat(output.random_coeff_powers[0]);
        const rows = PackedRows{ .polys = prepared.polys, .elements = self.elements, .output = output.*, .inverse = inverse, .shift = shift, .coefficient = coefficient, .log = log, .count = domain.size() };
        var row_scope = try @import("domain_profile.zig").begin("op_r7.input_rows", "R7 input packed rows");
        defer row_scope.end();
        try @import("domain_tiles.zig").run(PackedRows, &rows, domain.size(), MF.PACK_WIDTH);
    }
    const PackedRows = struct {
        polys: []const Engine.air.component_trace.Poly,
        elements: W.Elements,
        output: Domain.ColumnAccumulator,
        inverse: [2]M,
        shift: Core.fields.packed_om31.PackedOM31,
        coefficient: Core.fields.packed_om31.PackedOM31,
        log: u32,
        count: usize,
        pub fn runRange(self: *const @This(), first: usize, end: usize) !void {
            const MF = Core.fields.m31;
            const Packed = Core.fields.packed_om31;
            const Base = @import("../domain_lane.zig").Base;
            const log = self.log;
            const eval_log = log + 1;
            const inverse = self.inverse;
            const shift = self.shift;
            const coefficient = self.coefficient;
            var output = self.output;
            output.next_fresh_index = null;
            var row = first;
            while (row < end) : (row += MF.PACK_WIDTH) {
                var fixed: [R.FIXED]Base = undefined;
                var main: [R.MAIN]Base = undefined;
                for (&fixed, self.polys[0..R.FIXED]) |*v, poly| v.* = .{ .v = MF.loadPacked(poly.values[row..].ptr) };
                for (&main, self.polys[R.FIXED..][0..R.MAIN]) |*v, poly| v.* = .{ .v = MF.loadPacked(poly.values[row..].ptr) };
                const port = R.portFor(Base, &main, &fixed);
                var denominator = Packed.splat(self.elements.z.neg());
                for (port.tuple, self.elements.powers) |v, power| denominator = denominator.add(Packed.splat(power).mulBase(v.v));
                var current: [8]MF.PackedM31 = undefined;
                var previous: [8]MF.PackedM31 = undefined;
                for (&current, &previous, self.polys[R.FIXED + R.MAIN ..]) |*v, *p, poly| {
                    v.* = MF.loadPacked(poly.values[row..].ptr);
                    inline for (0..MF.PACK_WIDTH) |k| p[k] = poly.values[Core.utils.offsetBitReversedCircleDomainIndex(row + k, log, eval_log, -1)].v;
                }
                const delta = Packed.fromCoordinates(current).sub(Packed.fromCoordinates(previous)).add(shift);
                const root = Packed.mul(denominator, delta).add(Packed.splat(O.one()).mulBase(fixed[1].v));
                const sum = Packed.mul(root, coefficient).mulBase(@as(MF.PackedM31, @splat(inverse[row / (self.count / 2)].v)));
                inline for (0..MF.PACK_WIDTH) |k| output.accumulate(row + k, Packed.lane(sum, k));
            }
        }
    };
};
