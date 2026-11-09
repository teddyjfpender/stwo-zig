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
pub const Public = struct { calls: u32, epoch: u16, ordinal: u32 };
pub const Binding = struct { weights: [4]O, eta: O, target: O };
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
pub fn emit(comptime F: type, view: anytype, public: Public, local: @import("provider.zig").Challenges, wire: A.crypto.secp256k1.equations.WireFor(O), binding: Binding, aux: B.AuxFor(E.SecureFor(F)), claim: O, sink: *E.SinkFor(F)) !void {
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
    Ftr.emitMain(F, &fixed, &main, view.previousMain(Ftr.c.active), E.qFor(F, public.calls), E.qFor(F, @intFromBool(public.calls != 0)), E.qFor(F, public.epoch), E.qFor(F, public.ordinal), &main_sink);
    var weights: [4]E.SecureFor(F) = undefined;
    for (binding.weights, &weights) |v, *out| out.* = E.splatFor(F, v);
    var projection = B.ProjectionFor(F){ .challenges = &local, .lane_weights = &weights, .terms = Ftr.LOCAL_QUERIES };
    emitLocal(F, &main, E.qFor(F, public.ordinal), &projection);
    try projection.finish();
    B.emitFor(F, .{ .eq = secure(F, view, 0, 0), .eq_next2 = secure(F, view, 0, 2), .prefix = secure(F, view, 8, 0), .prefix_previous = secure(F, view, 8, -1) }, aux, projection.combine(E.splatFor(F, binding.eta)), E.splatFor(F, binding.target), sink);
    Ftr.emitWireFor(false, F, &main, E.qFor(F, public.ordinal), fixed[1], secure(F, view, 16, 0), secure(F, view, 16, -1), claim, wire, sink);
}
comptime {
    std.debug.assert(Layout.INTERACTION == 24);
}
