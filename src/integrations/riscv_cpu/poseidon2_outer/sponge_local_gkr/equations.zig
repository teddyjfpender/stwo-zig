//! Original full-tuple source equations plus independent local MLE binding and
//! classic paired global RAM/KIO prefixes. Degree≤3,2n for every component.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak_sponge;
const S = K.serialized;
const R = @import("authority.zig");
const Fr = @import("fractions.zig");
const Source = @import("source.zig");
const P = @import("projection.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
pub const PublicFor = P.PublicFor;
pub fn GlobalFor(comptime C: type) type {
    return struct { ram: Fr.TupleFor(C, 14), io: Fr.TupleFor(C, 11) };
}
pub fn globalCount(comptime role: R.Role, comptime io: bool) usize {
    return if (io) (if (role == .state or role == .lane) 2 else 0) else switch (role) {
        .descriptor => 8,
        .state, .word => 2,
        else => 0,
    };
}
pub fn Layout(comptime role: R.Role) type {
    return struct {
        pub const LOCAL_INSTANCES = 1;
        pub const MAIN = R.mainWidth(role);
        pub const FIXED = R.fixedWidth(role);
        pub const INTERACTION = R.interactionWidth(role);
        pub const MAIN_CONSTRAINTS = switch (role) {
            .descriptor => 54,
            .state => 20,
            .header => 87,
            .word => 22,
            .lane => 79,
            else => 0,
        };
        pub const CONSTRAINTS = MAIN_CONSTRAINTS + B.CONSTRAINTS + (globalCount(role, false) / 2 + @intFromBool(globalCount(role, false) != 0)) + (globalCount(role, true) / 2 + @intFromBool(globalCount(role, true) != 0));
        pub fn widths() [3]usize {
            return .{ FIXED, MAIN, INTERACTION };
        }
        pub fn shifts(tree: usize, c: usize) []const i32 {
            if (tree == 1 and ((role == .descriptor or role == .state) and c == 0 or role == .header)) return &.{ 0, -1 };
            if (tree != 2) return &.{0};
            if (c < 8) return &.{ 0, 2 };
            if (c < 16) return &.{ 0, -1 };
            const ram = globalCount(role, false);
            const rp = 16 + 8 * (ram / 2);
            if (ram != 0 and c >= rp and c < rp + 8) return &.{ 0, -1 };
            if (globalCount(role, true) != 0 and c >= INTERACTION - 8) return &.{ 0, -1 };
            return &.{0};
        }
    };
}
pub fn BindingFor(comptime C: type) type {
    return struct { instance: R.Instance, weights: []const C, eta: C, target: C };
}
pub fn secure(comptime F: type, view: anytype, start: usize, comptime shift: i32) E.SecureFor(F) {
    var v: [8]F = undefined;
    for (&v, 0..) |*x, i| x.* = view.interactionAt(start + i, shift);
    return E.secureFromCoordinatesForField(E.ConstFor(F), F, v);
}
pub fn GlobalList(comptime F: type, comptime role: R.Role, comptime io: bool) type {
    return struct {
        n: [globalCount(role, io)]F = undefined,
        d: [globalCount(role, io)]E.SecureFor(F) = undefined,
        count: usize = 0,
        ch: GlobalFor(E.ConstFor(F)),
        pub fn emit(self: *@This(), relation: usize, tuple: anytype, weight: F) void {
            if (comptime (io and tuple.len != 11) or (!io and tuple.len != 14)) return;
            if (relation != (if (io) K.equations.IO else K.equations.RAM)) return;
            const params = if (comptime io) self.ch.io else self.ch.ram;
            self.n[self.count] = weight;
            self.d[self.count] = E.denominatorFor(F, params.offset, &params.coefficients, &tuple, true);
            self.count += 1;
        }
    };
}
pub fn globalFractions(comptime role: R.Role, comptime F: type, comptime io: bool, view: anytype, public: PublicFor(E.ConstFor(F)), ch: GlobalFor(E.ConstFor(F))) GlobalList(F, role, io) {
    var list = GlobalList(F, role, io){ .ch = ch };
    var f: [R.fixedWidth(role)]F = undefined;
    var m: [R.mainWidth(role)]F = undefined;
    for (&f, 0..) |*v, c| v.* = view.fixed(c);
    for (&m, 0..) |*v, c| v.* = view.main(c);
    Source.emitRaw(role, F, &f, &m, public.first_id, &list);
    return list;
}
pub fn emitSourceMain(comptime role: R.Role, comptime F: type, view: anytype, public: PublicFor(E.ConstFor(F)), sink: anytype) void {
    var f: [R.fixedWidth(role)]F = undefined;
    var m: [R.mainWidth(role)]F = undefined;
    var pm: [R.mainWidth(role)]F = undefined;
    for (&f, 0..) |*v, c| v.* = view.fixed(c);
    for (&m, &pm, 0..) |*v, *p, c| {
        v.* = view.main(c);
        p.* = view.previousMain(c);
    }
    switch (role) {
        .descriptor => S.descriptor.emitMain(F, &f, &m, pm[0], E.scalarFor(F, public.calls), F.one(), sink),
        .state => S.state.emitMain(F, &f, &m, pm[0], E.scalarFor(F, public.calls).mul(E.qFor(F, 25)), F.one(), sink),
        .header => S.header.emitMain(F, &f, &m, &pm, E.scalarFor(F, public.permutations), F.one(), sink),
        .word => S.word.emitMain(F, f[0..3], &m, sink),
        .lane => S.lane.emitMain(F, f[0..3], &m, sink),
        else => {},
    }
}
pub fn emit(comptime role: R.Role, comptime F: type, view: anytype, public: PublicFor(E.ConstFor(F)), local: Fr.ChallengesFor(E.ConstFor(F)), global: GlobalFor(E.ConstFor(F)), binding: BindingFor(E.ConstFor(F)), aux: B.AuxFor(E.SecureFor(F)), claims: [2]E.ConstFor(F), sink: *E.SinkFor(F)) !void {
    if (binding.instance.role != role) return error.SpongeLocalProjectionShape;
    emitSourceMain(role, F, view, public, sink);
    const projection = try P.evaluate(role, F, view, public, local, binding.weights);
    const combined = projection[0].add(E.splatFor(F, binding.eta).mul(projection[1]));
    B.emitFor(F, .{ .eq = secure(F, view, 0, 0), .eq_next2 = secure(F, view, 0, 2), .prefix = secure(F, view, 8, 0), .prefix_previous = secure(F, view, 8, -1) }, aux, combined, E.splatFor(F, binding.target), sink);
    var start: usize = 16;
    inline for (.{ false, true }, 0..) |io, claim_index| {
        const count = comptime globalCount(role, io);
        if (count != 0) {
            const fractions = globalFractions(role, F, io, view, public, global);
            if (fractions.count != count) return error.SpongeGlobalFractionShape;
            var sum = E.SecureFor(F).zero();
            inline for (0..count / 2) |pair| {
                const inv = secure(F, view, start + 8 * pair, 0);
                const i = 2 * pair;
                const d0 = fractions.d[i];
                const d1 = fractions.d[i + 1];
                sink.emit(inv.mul(d0).mul(d1).sub(E.SecureFor(F).one()));
                sum = sum.add(E.mulBaseFor(F, inv.mul(d1), fractions.n[i])).add(E.mulBaseFor(F, inv.mul(d0), fractions.n[i + 1]));
            }
            const at = start + 8 * (count / 2);
            const delta = secure(F, view, at, 0).sub(secure(F, view, at, -1)).add(E.mulBaseFor(F, E.splatFor(F, claims[claim_index]), if (role == .word or role == .lane) view.fixed(3) else view.fixed(1)));
            sink.emit(delta.sub(sum));
            start = at + 8;
        }
    }
    if (start != Layout(role).INTERACTION) return error.SpongeGlobalFractionShape;
}
