//! Original truth MAIN arithmetic and every original fraction, with one late
//! native-GKR binding pair per physical component. Shared by native point
//! verification, symbolic CUDA lowering and recursive circuit evaluation.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak;
const T = @import("../types.zig");
const Wire = @import("../wire.zig");
const Catalog = @import("../gkr_local/truth_v3_catalog.zig");
const TF = @import("../gkr_local/truth_fractions.zig");
const CPU = @import("cpu_component.zig");
const Raw = @import("projection.zig");
const V2 = @import("v2.zig");
const B = CPU.Authority.Binding;
pub const Descriptor = struct { declaration: Wire.TruthDeclaration, part: u2 = 0 };
pub fn terms(d: Descriptor) ![4]u32 {
    if (d.declaration.family == .keccak) {
        const policy = try @import("../gkr_local/truth_profile.zig").fromDeclaration(d.declaration);
        if (policy != .throughput_r27_v1 and policy != .triple_v2) return error.NativeGkrTruthPolicy;
        return switch (d.part) {
            0 => .{ @intCast(policy.lookups()), 0, @intCast(policy.ioLookups()), 0 },
            1, 2 => .{ 1, 0, 0, 0 },
            else => error.NativeGkrTruthComponent,
        };
    }
    if (d.part != 0 or d.declaration.logs[1] != 0) return error.NativeGkrLegacyTruthUnsupported;
    const q = try Catalog.lookupCountsForDeclaration(d.declaration);
    return .{ @intCast(if (q.byte_queries_per_row == 0) 0 else q.byte_queries_per_row + 1), 0, 0, @intCast(q.wire_fractions_per_row) };
}
pub fn ParametersFor(comptime C: type) type {
    return struct {
        span: E.CallSpanFor(C),
        local: Raw.LocalFor(C),
        shared: CPU.Authority.SharedFor(C),
        weights: [4][]const C,
        gamma: C,
        target_per_row: C,
    };
}
/// Runtime dispatch is topology only. Every request scalar is an explicit
/// parameter or authenticated sample; no request count is specialized here.
pub fn visitType(family: T.Family, ctx: anytype) !void {
    switch (family) {
        .sha256 => try ctx.call(Catalog.Sha()),
        .arith256_mod => try ctx.call(Catalog.Arith()),
        .add => try ctx.call(Catalog.Curve(A.crypto.curves.spec.SecpKind.add)),
        .double => try ctx.call(Catalog.Curve(A.crypto.curves.spec.SecpKind.double)),
        .bn254_g1_add => try ctx.call(Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_add)),
        .bn254_g1_double => try ctx.call(Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_double)),
        .bn254_fp2_mul => try ctx.call(Catalog.Curve(A.crypto.curves.spec.Op.bn254_fp2_mul)),
        .bls12_381_fp2_mul => try ctx.call(Catalog.Curve(A.crypto.curves.spec.Op.bls12_381_fp2_mul)),
        .arith384_mont => try ctx.call(Catalog.Curve(A.crypto.curves.spec.Op.arith384_mont)),
        else => return error.NativeGkrTruthPolicy,
    }
}
/// `samples.get(tree,column,signed_offset)` is the same input authority used by
/// the old truth AIR. Terminal auxiliaries are derived at the PCS OODS point.
pub fn emitFor(comptime F: type, d: Descriptor, params: ParametersFor(E.ConstFor(F)), samples: anytype, masks: B.MaskFor(E.SecureFor(F)), aux: B.AuxFor(E.SecureFor(F)), sink: *E.SinkFor(F)) !void {
    var projection = Raw.ProjectionFor(F){ .local = &params.local, .shared = &params.shared, .terms = try terms(d), .weights = params.weights };
    var ls = projection.truthSink();
    var gs = projection.globalSink();
    if (d.declaration.family == .keccak) {
        const policy = try @import("../gkr_local/truth_profile.zig").fromDeclaration(d.declaration);
        if (d.part == 0) {
            var fixed: [K.layout.FIXED]F = undefined;
            var main: [K.layout.MAIN]F = undefined;
            var shifted: [4][K.layout.STATE]F = undefined;
            var header: [3]F = undefined;
            for (&fixed, 0..) |*v, c| v.* = try samples.get(0, c, 0);
            for (&main, 0..) |*v, c| v.* = try samples.get(1, c, 0);
            for (&shifted, [_]i32{ -2, -1, 1, 2 }) |*state, offset| for (state, 0..) |*v, c| {
                v.* = try samples.get(1, c, offset);
            };
            for (&header, 0..) |*v, c| v.* = try samples.get(1, K.layout.ACTIVE_A + c, -1);
            const row = K.equations.RowFor(F){ .fixed = &fixed, .main = &main, .previous_header = &header, .state_minus_two = &shifted[0], .state_minus_one = &shifted[1], .state_plus_one = &shifted[2], .state_plus_two = &shifted[3] };
            if (policy == .throughput_r27_v1) K.equations.emitDirectR27For(F, row, params.span, sink) else K.equations.emitDirectFor(F, row, params.span, sink, true);
            TF.keccakForPolicy(F, policy, row, &ls);
            for (0..policy.ioLookups()) |entry| {
                const tuple = if (policy == .throughput_r27_v1) K.equations.ioTupleR27For(F, row, entry) else K.equations.ioTupleFor(F, row, entry);
                const weight = if (policy == .throughput_r27_v1) K.equations.ioActiveR27For(F, row, entry) else K.equations.ioActiveFor(F, row);
                gs.emit(.kio, tuple, weight);
            }
        } else {
            var tuple: [6]F = undefined;
            for (&tuple, 0..) |*v, c| v.* = try samples.get(0, c, 0);
            TF.keccakTableFor(F, if (d.part == 1) .chi else .xor5, tuple, try samples.get(1, 0, 0), &ls);
        }
    } else {
        var context = struct {
            params: *const ParametersFor(E.ConstFor(F)),
            samples: @TypeOf(samples),
            ls: *@TypeOf(ls),
            gs: *@TypeOf(gs),
            sink: *E.SinkFor(F),
            pub fn call(c: *@This(), comptime Type: type) !void {
                var fixed_values: [Type.fixed]F = undefined;
                var main_values: [Type.L.MAIN]F = undefined;
                for (&fixed_values, 0..) |*v, i| v.* = try c.samples.get(0, i, 0);
                for (&main_values, 0..) |*v, i| v.* = try c.samples.get(1, i, 0);
                const View = struct {
                    f: *const [Type.fixed]F,
                    m: *const [Type.L.MAIN]F,
                    previous: F,
                    pub fn fixed(v: *const @This(), i: usize) F {
                        return v.f[i];
                    }
                    pub fn main(v: *const @This(), i: usize) F {
                        return v.m[i];
                    }
                    pub fn previousActive(v: *const @This()) F {
                        return v.previous;
                    }
                };
                const view = View{ .f = &fixed_values, .m = &main_values, .previous = try c.samples.get(1, 0, -1) };
                Type.Eq.emitMain(F, &view, c.params.span, c.sink);
                if (comptime Type.bytes != 0) {
                    for (0..Type.bytes) |i| c.ls.emit(.byte, [_]F{Type.Eq.byteQuery(F, &view, i)}, F.one());
                    c.ls.emit(.byte, [_]F{view.fixed(A.crypto.curves.layout.BYTE)}, view.main(Type.L.MULT).neg());
                }
                for (0..Type.wires) |i| {
                    const tuple = if (comptime Type == Catalog.Sha() or Type == Catalog.Arith()) Type.Eq.tuple(F, &view, c.params.span, @intCast(i)) else Type.Eq.tuple(F, &view, c.params.span, i);
                    const positive = if (comptime Type == Catalog.Sha() or Type == Catalog.Arith()) i == Type.L.OUTPUT_WIRE else i >= Type.L.COORDS;
                    const active = view.main(Type.L.ACTIVE);
                    c.gs.emit(.wire, tuple, if (positive) active else active.neg());
                }
            }
        }{ .params = &params, .samples = samples, .ls = &ls, .gs = &gs, .sink = sink };
        try visitType(d.declaration.family, &context);
    }
    try projection.finish();
    B.emitFor(F, masks, aux, projection.combine(params.gamma), params.target_per_row, sink);
}
