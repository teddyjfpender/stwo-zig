//! V3 classic OM31 truth. BYTE is proof-local; only Wire35 escapes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = @import("../roster.zig");
const C = @import("truth_v3_catalog.zig");
const Geo = @import("role_geometry.zig");
const O = core.fields.om31.OM31;
const Air = core.air.components.ForField(O);
const Point = core.circle.CirclePoint(O);
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
pub const Component = struct {
    pub const LOCAL_GKR = false;
    pub const MAX_FIXED = 4;
    pub const MAX_MAIN = blk: {
        var n: usize = A.crypto.sha256.layout.MAIN;
        n = @max(n, A.crypto.arith256.layout.MAIN);
        for (std.enums.values(A.crypto.curves.Op)) |op| n = @max(n, A.crypto.curves.Layout(op).MAIN);
        for (std.enums.values(A.crypto.curves.spec.SecpKind)) |op| n = @max(n, A.crypto.curves.Layout(op).MAIN);
        break :blk n;
    };
    pub const MAX_INTER = blk: {
        var n: usize = A.crypto.arith256.layout.BATCHES * 8;
        for (std.enums.values(A.crypto.curves.Op)) |op| n = @max(n, A.crypto.curves.Layout(op).BATCHES * 8);
        for (std.enums.values(A.crypto.curves.spec.SecpKind)) |op| n = @max(n, A.crypto.curves.Layout(op).BATCHES * 8);
        break :blk n;
    };
    truth: R.Truth,
    offsets: [2]usize = .{ 0, 0 },
    inter_offset: usize = 0,
    wire: A.crypto.sha256.equations.WireFor(O),
    bytes: O = O.zero(),
    claim: O = O.zero(),
    pub fn mainShape(s: *const @This()) A.main_only.authority.Shape {
        const d = C.shape(s.truth) catch unreachable;
        return .{ .fixed = d.fixed, .main = d.main, .constraints = d.constraints };
    }
    pub fn columnOffsets(s: *const @This()) [2]usize {
        return s.offsets;
    }
    pub fn logSize(s: *const @This()) u32 {
        return C.logSize(s.truth) catch unreachable;
    }
    pub fn interWidth(s: *const @This()) usize {
        return (C.shape(s.truth) catch unreachable).inter;
    }
    pub fn previousMain(_: *const @This(), c: usize) bool {
        return c == 0;
    }
    pub fn previousInter(s: *const @This(), c: usize) bool {
        const d = C.shape(s.truth) catch unreachable;
        const b = c / 8;
        return (d.byte_batches > 0 and b == d.byte_batches - 1) or b == d.byte_batches + d.wire_batches - 1;
    }
    pub fn nConstraints(s: *const @This()) usize {
        return (C.shape(s.truth) catch unreachable).constraints;
    }
    pub fn compositionLogSplit(s: *const @This()) u32 {
        return if ((C.shape(s.truth) catch unreachable).degree > 3) 2 else 1;
    }
    pub fn maxConstraintLogDegreeBound(s: *const @This()) u32 {
        return s.logSize() + s.compositionLogSplit();
    }
    pub fn constraintDegreeBound(s: *const @This(), i: usize) !u8 {
        if (i >= s.nConstraints()) return error.InvalidConstraintIndex;
        return @intCast((try C.shape(s.truth)).degree);
    }
    pub fn validate(s: *const @This()) !void {
        try C.validate(s.truth);
        const d = try C.shape(s.truth);
        if (d.main > MAX_MAIN or d.inter > MAX_INTER) return error.V3TruthShapeExceeded;
    }
    pub fn emitMainFor(s: *const @This(), comptime F: type, fixed_values: []const F, main_values: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        const View = struct {
            f: []const F,
            m: []const F,
            p: []const F,
            pub fn fixed(v: *const @This(), c: usize) F {
                return v.f[c];
            }
            pub fn main(v: *const @This(), c: usize) F {
                return v.m[c];
            }
            pub fn previousActive(v: *const @This()) F {
                return v.p[0];
            }
        };
        var ctx = struct {
            owner: *const Component,
            v: View,
            sink: *E.SinkFor(F),
            pub fn call(c: *@This(), comptime T: type) !void {
                T.Eq.emitMain(F, &c.v, .{ .calls = c.owner.truth.count(), .first_id = c.owner.truth.first() }, c.sink);
            }
        }{ .owner = s, .v = .{ .f = fixed_values, .m = main_values, .p = previous }, .sink = sink };
        try C.visit(s.truth, &ctx);
    }
    pub fn emitGlobalFor(s: *const @This(), comptime F: type, fixed_values: []const F, main_values: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        const View = struct {
            f: []const F,
            m: []const F,
            i: []const F,
            p: []const F,
            pa: F,
            pub fn fixed(v: *const @This(), c: usize) F {
                return v.f[c];
            }
            pub fn main(v: *const @This(), c: usize) F {
                return v.m[c];
            }
            pub fn interaction(v: *const @This(), c: usize) F {
                return v.i[c];
            }
            pub fn previousInteraction(v: *const @This(), c: usize) F {
                return v.p[c];
            }
            pub fn previousActive(v: *const @This()) F {
                return v.pa;
            }
        };
        var ctx = struct {
            owner: *const Component,
            v: View,
            sink: *E.SinkFor(F),
            pub fn call(c: *@This(), comptime T: type) !void {
                const span = E.CallSpanFor(O){ .calls = c.owner.truth.count(), .first_id = c.owner.truth.first() };
                if (T.bytes == 0) T.Eq.emitInteraction(F, &c.v, span, c.owner.claim, c.owner.wire, c.sink) else T.Eq.emitInteraction(F, &c.v, span, c.owner.claim, .{ .bytes = c.owner.bytes, .wire = c.owner.wire }, c.sink);
            }
        }{ .owner = s, .v = .{ .f = fixed_values, .m = main_values, .i = current, .p = previous, .pa = F.zero() }, .sink = sink };
        // Original activity uses previous MAIN; domain passes it through emitMainFor below.
        ctx.v.pa = if (main_values.len > 0) main_values[0] else F.zero();
        try C.visit(s.truth, &ctx);
    }
    pub fn traceLogDegreeBounds(s: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        return Geo.bounds(s, a);
    }
    pub fn preprocessedColumnIndices(s: *const @This(), a: std.mem.Allocator) ![]usize {
        return Geo.indices(s, a);
    }
    pub fn maskPoints(s: *const @This(), a: std.mem.Allocator, p: Point, g: u32) !Air.MaskPoints {
        return Geo.masks(s, a, p, g);
    }
    pub fn evaluateConstraintQuotientsAtPoint(s: *const @This(), p: Point, m: *const Air.MaskValues, a: *Acc, g: u32) !void {
        return @import("role_oods.zig").evaluate(s, p, m, a, g);
    }
    pub fn evaluateConstraintQuotientsOnDomain(s: *const @This(), t: *const P.Trace, a: *D.DomainEvaluationAccumulator) !void {
        return @import("role_domain.zig").evaluate(s, t, a, null);
    }
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(s: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(s);
    }
    pub fn asProverComponent(s: *const @This()) P.ComponentProver {
        return Adapter.asProverComponent(s);
    }
};
