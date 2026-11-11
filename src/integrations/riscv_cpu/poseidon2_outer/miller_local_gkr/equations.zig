//! New opt-in physical row authority: original MAIN, per-instance authenticated
//! terminal bindings and unchanged global Wire35 fractions. No schema2 entry.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const N = A.crypto.bn254_tower.narrow;
const S = N.source;
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const P = @import("projection.zig");
const Frame = @import("authority.zig");
pub fn Layout(comptime role: S.Role) type {
    return struct {
        pub const LOCAL_INSTANCES = if (role == .arithmetic) 3 else 1;
        pub const WIRE_FIRST = LOCAL_INSTANCES * B.INTERACTION_COLUMNS;
        pub const INTERACTION = Frame.interactionWidth(role);
        comptime {
            if (INTERACTION != WIRE_FIRST + 8) @compileError("Miller binding width mismatch");
        }
        pub const MAIN = S.mainWidth(role);
        pub const FIXED = S.FIXED;
        pub const CONSTRAINTS = N.equations.LayoutForField(role, @import("stwo_core").fields.om31.OM31).MAIN_CONSTRAINTS + LOCAL_INSTANCES * B.CONSTRAINTS + 1;
        pub const LOG_EXTENSION = 1;
        pub const DEGREE = 3;
        pub fn widths() [3]usize {
            return .{ FIXED, MAIN, INTERACTION };
        }
        pub fn shifts(tree: usize, column: usize) []const i32 {
            if (tree == 1 and column == 0) return &.{ 0, -1 };
            if (tree != 2) return &.{0};
            if (column >= WIRE_FIRST or column % 16 >= 8) return &.{ 0, -1 };
            return &.{ 0, 2 };
        }
    };
}
pub fn BindingFor(comptime C: type) type {
    return struct { instance: Frame.Instance, weights: []const C, eta: C, target: C };
}
pub fn secure(comptime F: type, view: anytype, start: usize, comptime shift: i32) E.SecureFor(F) {
    var values: [8]F = undefined;
    for (&values, 0..) |*value, index| value.* = view.interactionAt(start + index, shift);
    return E.secureFromCoordinatesForField(E.ConstFor(F), F, values);
}
pub fn emit(comptime role: S.Role, comptime F: type, view: anytype, public: E.CallSpanFor(E.ConstFor(F)), challenges: N.equations.ChallengesFor(E.ConstFor(F)), bindings: []const BindingFor(E.ConstFor(F)), aux: []const B.AuxFor(E.SecureFor(F)), global_claim: E.ConstFor(F), sink: *E.SinkFor(F)) !void {
    const L = Layout(role);
    if (bindings.len != L.LOCAL_INSTANCES or aux.len != L.LOCAL_INSTANCES) return error.MillerLocalProjectionShape;
    N.equations.EquationsForField(role, E.ConstFor(F)).emitMain(F, view, public, sink);
    for (bindings, aux, 0..) |binding, helper, index| {
        if (binding.instance.sourceRole() != role) return error.MillerLocalProjectionShape;
        // The immutable role roster, not incoming producer labels, fixes order.
        const expected: Frame.Role = if (role == .frontier) .frontier_ssa else switch (index) {
            0 => .bytes,
            1 => .carries,
            2 => .arithmetic_ssa,
            else => unreachable,
        };
        if (binding.instance.role != expected) return error.MillerLocalProjectionShape;
        const projected = try P.evaluate(F, binding.instance, view, public, challenges, binding.weights);
        const combined = projected[0].add(E.splatFor(F, binding.eta).mul(projected[1]));
        const first = 16 * index;
        B.emitFor(F, .{ .eq = secure(F, view, first, 0), .eq_next2 = secure(F, view, first, 2), .prefix = secure(F, view, first + 8, 0), .prefix_previous = secure(F, view, first + 8, -1) }, helper, combined, E.splatFor(F, binding.target), sink);
    }
    const Eq = N.equations.EquationsForField(role, E.ConstFor(F));
    const fraction = Eq.fraction(F, view, public, challenges, .wire, 0);
    const delta = secure(F, view, L.WIRE_FIRST, 0).sub(secure(F, view, L.WIRE_FIRST, -1)).add(E.mulBaseFor(F, E.splatFor(F, global_claim), view.fixed(S.FIRST)));
    sink.emit(delta.mul(fraction[1]).sub(E.liftFor(F, fraction[0])));
}
test "Miller local GKR physical row geometry preserves independent 2n shapes" {
    try std.testing.expectEqual(@as(usize, 24), Layout(.frontier).INTERACTION);
    try std.testing.expectEqual(@as(usize, 56), Layout(.arithmetic).INTERACTION);
    try std.testing.expectEqual(@as(u32, 1), @as(u32, Layout(.arithmetic).LOG_EXTENSION));
    try std.testing.expectEqualSlices(i32, &.{ 0, 2 }, Layout(.arithmetic).shifts(2, 32));
    try std.testing.expectEqualSlices(i32, &.{ 0, -1 }, Layout(.arithmetic).shifts(2, 48));
}

test "Miller local GKR physical row authority rejects forged prefix and global Wire cells" {
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    const View = struct {
        interaction_values: [56]O = @splat(O.zero()),
        pub fn fixed(_: *const @This(), column: usize) O {
            return O.fromBase(core.fields.m31.M31.fromCanonical(S.fixedRow(.arithmetic, 100, 15)[column]));
        }
        pub fn main(_: *const @This(), _: usize) O {
            return O.zero();
        }
        pub fn previousActive(_: *const @This()) O {
            return O.zero();
        }
        pub fn interactionAt(self: *const @This(), column: usize, comptime shift: i32) O {
            return if (shift == 0) self.interaction_values[column] else O.zero();
        }
    };
    var channel = @import("native.zig").Channel.init();
    var ch = @import("native.zig").draw(&channel);
    ch.wire = A.crypto.curves.equations.WireFor(O).draw(&channel);
    const instances = try (Frame.Geometry{ .calls = 1, .first_id = 1, .frontier_log = 8, .arithmetic_log = 15 }).instances();
    var weights: [3][]O = undefined;
    var allocated: usize = 0;
    defer for (weights[0..allocated]) |data| std.testing.allocator.free(data);
    var bindings: [3]BindingFor(O) = undefined;
    for (instances[0..3], &weights, &bindings) |instance, *ww, *binding| {
        ww.* = try std.testing.allocator.alloc(O, @as(usize, 1) << @intCast(instance.laneLog()));
        allocated += 1;
        @memset(ww.*, O.zero());
        ww.*[0] = O.one();
        binding.* = .{ .instance = instance, .weights = ww.*, .eta = O.zero(), .target = O.zero() };
    }
    const aux = [_]B.AuxFor(O){.{ .first = O.zero(), .second = O.zero(), .carry = O.zero(), .eq0 = O.zero(), .eq1 = O.zero() }} ** 3;
    var values: [Layout(.arithmetic).CONSTRAINTS]O = undefined;
    var view = View{};
    var sink = E.SinkFor(O){ .values = &values };
    try emit(.arithmetic, O, &view, .{ .calls = 1, .first_id = 1 }, ch, &bindings, &aux, O.zero(), &sink);
    try std.testing.expectEqual(values.len, sink.count);
    for (values) |value| try std.testing.expect(value.isZero());
    view.interaction_values[8] = O.one();
    sink = .{ .values = &values };
    try emit(.arithmetic, O, &view, .{ .calls = 1, .first_id = 1 }, ch, &bindings, &aux, O.zero(), &sink);
    var nonzero: usize = 0;
    for (values) |value| nonzero += @intFromBool(!value.isZero());
    try std.testing.expectEqual(@as(usize, 1), nonzero);
    view.interaction_values[8] = O.zero();
    view.interaction_values[48] = O.one();
    sink = .{ .values = &values };
    try emit(.arithmetic, O, &view, .{ .calls = 1, .first_id = 1 }, ch, &bindings, &aux, O.zero(), &sink);
    try std.testing.expect(!values[values.len - 1].isZero());
}
