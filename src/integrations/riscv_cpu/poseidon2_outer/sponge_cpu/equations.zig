//! The complete tiny frontier authority: exact call prefix, local source MLE,
//! and one unit-weight shared Wire accumulator. No global RAM/KIO rows here.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const Ftr = A.crypto.keccak_sponge.serialized.frontier;
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const O = core.fields.om31.OM31;
pub const Layout = struct {
    pub const FIXED = Ftr.FIXED;
    pub const MAIN = Ftr.MAIN;
    pub const INTERACTION = Ftr.OM31_INTER;
    pub const LOCAL_INSTANCES = 1;
    pub const CONSTRAINTS = Ftr.MAIN_CONSTRAINTS + B.CONSTRAINTS + 1;
    pub fn widths() [3]usize {
        return .{ FIXED, MAIN, INTERACTION };
    }
    pub fn shifts(tree: usize, c: usize) []const i32 {
        if (tree == 1 and c == Ftr.c.active) return &.{ 0, -1 };
        if (tree != 2) return &.{0};
        if (c < 8) return &.{ 0, 2 };
        return &.{ 0, -1 };
    }
};
pub fn PublicFor(comptime C: type) type {
    return struct { calls: E.CountFor(C), epoch: E.CountFor(C), ordinal: E.CountFor(C), nonempty: E.FlagFor(C) = E.flagDefault(C) };
}
pub const Public = PublicFor(O);
pub fn BindingFor(comptime C: type) type {
    return struct { weights: [4]C, eta: C, target: C };
}
pub const Binding = BindingFor(O);
// Preserve the original native/symbolic expression order and IR identity.
// External verifier lanes use the caller's authenticated public wires.
inline fn countFor(comptime F: type, value: E.CountFor(E.ConstFor(F))) F {
    if (comptime E.isExternalLane(F)) return value;
    return E.qFor(F, value);
}
inline fn nonemptyFor(comptime F: type, public: PublicFor(E.ConstFor(F))) !F {
    if (comptime E.isExternalLane(F)) return public.nonempty orelse error.MissingRv64LaneFlag;
    return E.qFor(F, @intFromBool(public.calls != 0));
}
pub fn secure(comptime F: type, view: anytype, start: usize, comptime shift: i32) E.SecureFor(F) {
    var values: [8]F = undefined;
    for (&values, 0..) |*v, c| v.* = view.interactionAt(start + c, shift);
    return E.secureFromCoordinatesForField(E.ConstFor(F), F, values);
}
pub fn emitLocal(comptime F: type, main: *const [Ftr.MAIN]F, ordinal: F, sink: anytype) void {
    const Adapter = struct {
        target: @TypeOf(sink),
        pub fn emit(self: *@This(), comptime relation: usize, tuple: anytype, weight: F) void {
            switch (relation) {
                A.crypto.keccak_sponge.equations.OWNER => {
                    if (tuple.len != 19) @compileError("frontier OWNER arity");
                    self.target.emit(.owner, tuple, weight);
                },
                A.crypto.keccak_sponge.equations.RANGE16 => {
                    if (tuple.len != 1) @compileError("frontier U16 arity");
                    self.target.emit(.range16, tuple, weight);
                },
                A.crypto.keccak_sponge.equations.RANGE8 => {
                    if (tuple.len != 1) @compileError("frontier U8 arity");
                    self.target.emit(.range8, tuple, weight);
                },
                Ftr.WIRE => {
                    if (tuple.len != 35) @compileError("frontier Wire arity");
                },
                else => @compileError("unaccounted frontier relation"),
            }
        }
    };
    var adapter = Adapter{ .target = sink };
    Ftr.emitRaw(F, main, ordinal, &adapter);
}
pub fn emit(comptime F: type, view: anytype, public: PublicFor(E.ConstFor(F)), local: @import("../../word16_global_execution/services/gkr_local/challenges.zig").For(E.ConstFor(F)), wire: A.crypto.secp256k1.equations.WireFor(E.ConstFor(F)), binding: BindingFor(E.ConstFor(F)), aux: B.AuxFor(E.SecureFor(F)), claim: E.ConstFor(F), sink: *E.SinkFor(F)) !void {
    var fixed: [Ftr.FIXED]F = undefined;
    var main: [Ftr.MAIN]F = undefined;
    for (&fixed, 0..) |*v, c| v.* = view.fixed(c);
    for (&main, 0..) |*v, c| v.* = view.main(c);
    const MainSink = struct {
        target: *E.SinkFor(F),
        pub fn emit(self: *@This(), v: F) void {
            self.target.emit(E.liftFor(F, v));
        }
    };
    var main_sink = MainSink{ .target = sink };
    Ftr.emitMain(F, &fixed, &main, view.previousMain(Ftr.c.active), countFor(F, public.calls), try nonemptyFor(F, public), countFor(F, public.epoch), countFor(F, public.ordinal), &main_sink);
    var weights: [4]E.SecureFor(F) = undefined;
    for (binding.weights, &weights) |v, *out| out.* = E.splatFor(F, v);
    var projection = B.ProjectionFor(F){ .challenges = &local, .lane_weights = &weights, .terms = Ftr.LOCAL_QUERIES };
    emitLocal(F, &main, countFor(F, public.ordinal), &projection);
    try projection.finish();
    B.emitFor(F, .{ .eq = secure(F, view, 0, 0), .eq_next2 = secure(F, view, 0, 2), .prefix = secure(F, view, 8, 0), .prefix_previous = secure(F, view, 8, -1) }, aux, projection.combine(E.splatFor(F, binding.eta)), E.splatFor(F, binding.target), sink);
    Ftr.emitWireFor(false, F, &main, countFor(F, public.ordinal), fixed[1], secure(F, view, 16, 0), secure(F, view, 16, -1), claim, wire, sink);
}
comptime {
    std.debug.assert(Layout.INTERACTION == 24);
}
