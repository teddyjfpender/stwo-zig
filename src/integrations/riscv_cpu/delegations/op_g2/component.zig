//! Canonical G2 arithmetic, source frontier and local BYTE/SSA bindings.
//! Packed execution reuses the common qualified truth-role domain kernel.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_g2;
const S = G.spec;
const N = @import("native.zig");
const P = @import("projection.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const O = N.Q;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const CP = engine.air.component_prover.ForField(O);
const Acc = engine.air.accumulation.ForField(O);
pub fn interactionWidth(comptime role: N.Role) usize {
    return if (role == .arithmetic) 32 else 16;
}
pub fn fixedWidth(comptime kind: S.Kind, comptime role: N.Role) usize {
    return G.fixture.fixedWidth(kind, role);
}
pub fn mainWidth(comptime kind: S.Kind, comptime role: N.Role) usize {
    return G.fixture.mainWidth(kind, role);
}
pub fn logSize(comptime role: N.Role) u32 {
    return G.fixture.rowLog(role);
}
pub fn bindingCount(comptime role: N.Role) usize {
    return if (role == .arithmetic) 2 else 1;
}
pub fn bindingCountForRuntime(role: N.Role) usize {
    return if (role == .arithmetic) 2 else 1;
}
fn secure(comptime F: type, v: anytype, start: usize, comptime shift: i32) E.SecureFor(F) {
    var c: [8]F = undefined;
    for (&c, 0..) |*x, i| x.* = v.interactionAt(start + i, shift);
    return E.secureFromCoordinatesForField(O, F, c);
}
pub fn Component(comptime operation: S.Kind, comptime role: N.Role) type {
    return struct {
        const Self = @This();
        const R = G.witness.Layout(operation);
        const FIXED = fixedWidth(operation, role);
        const MAIN = mainWidth(operation, role);
        const INTER = interactionWidth(role);
        pub const DOMAIN_BINDINGS = bindingCount(role);
        data: [DOMAIN_BINDINGS]*const P.Data,
        log_size: u32 = logSize(role),
        offsets: [3]usize = .{ 0, 0, 0 },
        kind: enum { dense } = .dense,
        pub fn validate(self: *const Self) !void {
            if (self.log_size != logSize(role)) return error.DenseSsaShape;
            for (self.data, 0..) |d, index| {
                if (d.instance.role != role or d.instance.row_log != self.log_size or d.weights.len != d.instance.lanes() or d.point.n != self.log_size) return error.DenseSsaShape;
                const expected: N.Family = if (role == .frontier or index == 1) .ssa else .bytes;
                if (d.instance.family != expected) return error.DenseSsaShape;
            }
        }
        pub fn widths(_: *const Self) [3]usize {
            return .{ FIXED, MAIN, INTER };
        }
        pub fn nConstraints(_: *const Self) usize {
            return G.fixture.constraints(operation, role) + B.CONSTRAINTS * DOMAIN_BINDINGS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn domainBindingPoint(self: *const Self, index: usize) *const P.MP.MleEvalPointFor(O) {
            std.debug.assert(index < DOMAIN_BINDINGS);
            return &self.data[index].point;
        }
        pub fn shifts(_: *const Self, tree: usize, column: usize) []const i32 {
            if (tree != 2) return &.{0};
            return if (column < 16 * DOMAIN_BINDINGS and column % 16 < 8) &.{ 0, 2 } else &.{ 0, -1 };
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
            try self.validate();
            const trees = try a.alloc([]u32, 3);
            errdefer a.free(trees);
            var n: usize = 0;
            errdefer for (trees[0..n]) |v| a.free(v);
            for (trees, self.widths()) |*v, width| {
                v.* = try a.alloc(u32, width);
                @memset(v.*, self.log_size);
                n += 1;
            }
            return Air.TraceLogDegreeBounds.initOwned(trees);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const v = try a.alloc(usize, FIXED);
            for (v, 0..) |*x, i| x.* = self.offsets[0] + i;
            return v;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
            try self.validate();
            _ = try A.geometry.localPointFor(O, point, global_log, self.log_size);
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
            return @import("../../word16_global_execution/services/gkr_local/truth_role.zig").Component.Workspace(F);
        }
        pub fn emitForWithWorkspace(self: *const Self, comptime F: type, samples: anytype, sink: *E.SinkFor(F), _: *Workspace(F)) !void {
            const View = struct {
                fixed_values: [FIXED]F,
                main_values: [MAIN]F,
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
                shifted.* = try samples.get(2, c, if (c < 16 * DOMAIN_BINDINGS and c % 16 < 8) 2 else -1);
            }
            G.fixture.emit(operation, role, F, &v, sink);
            inline for (0..DOMAIN_BINDINGS) |index| {
                const data = self.data[index];
                const projected = try P.evaluate(operation, F, &v, data);
                const combined = projected[0].add(E.splatFor(F, data.eta).mul(projected[1]));
                B.emitFor(F, .{ .eq = secure(F, &v, 16 * index, 0), .eq_next2 = secure(F, &v, 16 * index, 2), .prefix = secure(F, &v, 16 * index + 8, 0), .prefix_previous = secure(F, &v, 16 * index + 8, -1) }, try samples.auxAt(index), combined, E.splatFor(F, data.target), sink);
            }
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, acc: *Acc.DomainEvaluationAccumulator) !void {
            return @import("../../word16_global_execution/services/gkr_local/truth_role_domain.zig").evaluate(self, trace, acc);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, masks: *const Air.MaskValues, acc: *core.air.accumulation.ForField(O).PointEvaluationAccumulator, global_log: u32) !void {
            try self.validate();
            const local = try A.geometry.localPointFor(O, point, global_log, self.log_size);
            const Samples = struct {
                owner: *const Self,
                masks: *const Air.MaskValues,
                point: Point,
                pub fn get(s: @This(), tree: usize, c: usize, shift: i32) !O {
                    if (tree >= s.masks.items.len or s.owner.offsets[tree] + c >= s.masks.items[tree].len) return error.DenseProjectionMask;
                    const values = s.masks.items[tree][s.owner.offsets[tree] + c];
                    const shifts_ = s.owner.shifts(tree, c);
                    if (values.len != shifts_.len) return error.DenseProjectionMask;
                    for (values, shifts_) |v, w| if (shift == w) return v;
                    return error.DenseProjectionMask;
                }
                pub fn auxAt(s: @This(), index: usize) !B.AuxFor(O) {
                    if (index >= DOMAIN_BINDINGS) return error.DenseProjectionShape;
                    const p = &s.owner.data[index].point;
                    const anchors = try P.MP.evalAnchorsFor(O, s.owner.log_size, s.point);
                    return .{ .first = anchors[0], .second = anchors[1], .carry = try P.MP.evalCarryQuotientFor(O, p, s.point), .eq0 = p.eq0, .eq1 = p.eq1 };
                }
            };
            var workspace: Workspace(O) = undefined;
            var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.log_size) };
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
