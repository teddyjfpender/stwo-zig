//! One authenticated BYTE projection plus unchanged public output-Wire debt.
//! Packed execution reuses the common qualified truth-role domain kernel.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const D = A.crypto.bn254_dense;
const N = @import("native.zig");
const P = @import("projection.zig");
const B = @import("../../../word16_global_execution/services/gkr_local/binding.zig");
const O = N.Q;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const CP = engine.air.component_prover.ForField(O);
const Acc = engine.air.accumulation.ForField(O);
pub const INTER = 24;
fn secure(comptime F: type, v: anytype, start: usize, comptime shift: i32) E.SecureFor(F) {
    var c: [8]F = undefined;
    for (&c, 0..) |*x, i| x.* = v.interactionAt(start + i, shift);
    return E.secureFromCoordinatesForField(O, F, c);
}
pub fn Component(comptime operation: D.spec.Kind) type {
    return struct {
        const Self = @This();
        const R = D.row.Layout(operation);
        pub const DOMAIN_BINDINGS = 1;
        input: *const [D.spec.inputs(operation)]u256,
        data: *const P.Data,
        wire: A.crypto.curves.equations.WireFor(O),
        claim: O,
        log_size: u32 = 8,
        offsets: [3]usize = .{ 0, 0, 0 },
        kind: enum { dense } = .dense,
        pub fn validate(self: *const Self) !void {
            if (self.log_size != 8 or self.data.weights.len != 512 or self.data.point.n != 8) return error.DenseProjectionShape;
        }
        pub fn widths(_: *const Self) [3]usize {
            return .{ D.air.FIXED, R.MAIN, INTER };
        }
        pub fn nConstraints(_: *const Self) usize {
            return D.air.constraints(operation) + B.CONSTRAINTS + 1;
        }
        pub fn maxConstraintLogDegreeBound(_: *const Self) u32 {
            return 9;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn domainBindingPoint(self: *const Self, index: usize) *const P.MP.MleEvalPointFor(O) {
            std.debug.assert(index == 0);
            return &self.data.point;
        }
        pub fn shifts(_: *const Self, tree: usize, column: usize) []const i32 {
            if (tree != 2) return &.{0};
            return if (column < 8) &.{ 0, 2 } else &.{ 0, -1 };
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
            try self.validate();
            const trees = try a.alloc([]u32, 3);
            errdefer a.free(trees);
            var n: usize = 0;
            errdefer for (trees[0..n]) |v| a.free(v);
            for (trees, self.widths()) |*v, width| {
                v.* = try a.alloc(u32, width);
                @memset(v.*, 8);
                n += 1;
            }
            return Air.TraceLogDegreeBounds.initOwned(trees);
        }
        pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
            const v = try a.alloc(usize, D.air.FIXED);
            for (v, 0..) |*x, i| x.* = i;
            return v;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
            try self.validate();
            _ = try A.geometry.localPointFor(O, point, global_log, 8);
            const trees = try a.alloc([][]Point, 3);
            errdefer a.free(trees);
            var done: usize = 0;
            errdefer for (trees[0..done]) |tree| {
                for (tree) |col| a.free(col);
                a.free(tree);
            };
            const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
            const lift = Point{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) };
            for (trees, self.widths(), 0..) |*tree, width, t| {
                tree.* = try a.alloc([]Point, width);
                var n: usize = 0;
                errdefer {
                    for (tree.*[0..n]) |col| a.free(col);
                    a.free(tree.*);
                }
                for (tree.*, 0..) |*col, c| {
                    const shifts_ = self.shifts(t, c);
                    col.* = try a.alloc(Point, shifts_.len);
                    for (col.*, shifts_) |*v, shift| v.* = point.add(lift.mulSigned(shift));
                    n += 1;
                }
                done += 1;
            }
            return Air.MaskPoints.initOwned(trees);
        }
        pub fn Workspace(comptime F: type) type {
            return @import("../../../word16_global_execution/services/gkr_local/truth_role.zig").Component.Workspace(F);
        }
        pub fn emitForWithWorkspace(self: *const Self, comptime F: type, samples: anytype, sink: *E.SinkFor(F), _: *Workspace(F)) !void {
            const View = struct {
                fixed_values: [D.air.FIXED]F,
                main_values: [R.MAIN]F,
                current: [INTER]F,
                shifted: [INTER]F,
                pub fn fixed(v: *const @This(), c: usize) F {
                    return v.fixed_values[c];
                }
                pub fn main(v: *const @This(), c: usize) F {
                    return v.main_values[c];
                }
                pub fn interactionAt(v: *const @This(), c: usize, comptime shift: i32) F {
                    return if (shift == 0) v.current[c] else v.shifted[c];
                }
            };
            var v: View = undefined;
            for (&v.fixed_values, 0..) |*x, c| x.* = try samples.get(0, c, 0);
            for (&v.main_values, 0..) |*x, c| x.* = try samples.get(1, c, 0);
            for (&v.current, &v.shifted, 0..) |*now, *shifted, c| {
                now.* = try samples.get(2, c, 0);
                shifted.* = try samples.get(2, c, if (c < 8) 2 else -1);
            }
            D.air.emit(operation, F, &v, self.input, sink);
            const projected = try P.evaluate(operation, F, &v, self.data.beta, self.data.weights);
            const combined = projected[0].add(E.splatFor(F, self.data.eta).mul(projected[1]));
            B.emitFor(F, .{ .eq = secure(F, &v, 0, 0), .eq_next2 = secure(F, &v, 0, 2), .prefix = secure(F, &v, 8, 0), .prefix_previous = secure(F, &v, 8, -1) }, try samples.auxAt(0), combined, E.splatFor(F, self.data.target), sink);
            const delta = secure(F, &v, 16, 0).sub(secure(F, &v, 16, -1)).add(E.splatFor(F, self.claim.mulM31(try N.M.fromCanonical(256).inv())));
            const ch = D.fixture_component.Challenges{ .byte = self.data.beta, .wire = self.wire };
            sink.emit(delta.mul(D.fixture_component.outputDenominator(operation, F, &v, ch)).sub(E.liftFor(F, v.main(0))));
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, acc: *Acc.DomainEvaluationAccumulator) !void {
            return @import("../../../word16_global_execution/services/gkr_local/truth_role_domain.zig").evaluate(self, trace, acc);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, masks: *const Air.MaskValues, acc: *core.air.accumulation.ForField(O).PointEvaluationAccumulator, global_log: u32) !void {
            try self.validate();
            const local = try A.geometry.localPointFor(O, point, global_log, 8);
            const Samples = struct {
                owner: *const Self,
                masks: *const Air.MaskValues,
                point: Point,
                pub fn get(s: @This(), tree: usize, c: usize, shift: i32) !O {
                    if (tree >= s.masks.items.len or c >= s.masks.items[tree].len) return error.DenseProjectionMask;
                    const values = s.masks.items[tree][c];
                    const shifts_ = s.owner.shifts(tree, c);
                    if (values.len != shifts_.len) return error.DenseProjectionMask;
                    for (values, shifts_) |v, w| if (shift == w) return v;
                    return error.DenseProjectionMask;
                }
                pub fn auxAt(s: @This(), index: usize) !B.AuxFor(O) {
                    if (index != 0) return error.DenseProjectionShape;
                    const p = &s.owner.data.point;
                    const anchors = try P.MP.evalAnchorsFor(O, 8, s.point);
                    return .{ .first = anchors[0], .second = anchors[1], .carry = try P.MP.evalCarryQuotientFor(O, p, s.point), .eq0 = p.eq0, .eq1 = p.eq1 };
                }
            };
            var workspace: Workspace(O) = undefined;
            var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, 8) };
            try self.emitForWithWorkspace(O, Samples{ .owner = self, .masks = masks, .point = local }, &sink, &workspace);
            std.debug.assert(sink.count == self.nConstraints());
        }
        const Adapter = core.air.derive.ForField(O).ComponentAdapter(Self, CP.ComponentProver, CP.Trace, Acc.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) CP.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.pool_exclusive_domain = true;
            result.cooperative_domain = true;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) Air.Component {
            return Adapter.asVerifierComponent(self);
        }
    };
}
