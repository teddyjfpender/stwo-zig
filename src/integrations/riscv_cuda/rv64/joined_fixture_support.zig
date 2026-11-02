//! Cold native oracle for joined-kernel qualification. No runtime prover or
//! accepted proof can consume these synthetic rows or synthetic field draws.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const G = @import("joined_codegen.zig");
const P = G.Parameters;
const B = G.Authority.Binding;
pub const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const Catalog = @import("projection_fixture_support.zig");
pub const count = Catalog.count + 2;
pub fn descriptors() [count]G.Source.Descriptor {
    var out: [count]G.Source.Descriptor = undefined;
    @memcpy(out[0..Catalog.count], &Catalog.descriptors());
    out[Catalog.count] = .{ .origin = .{ .core = .initial } };
    out[Catalog.count + 1] = .{ .origin = .{ .core = .terminal } };
    return out;
}
pub fn random(rng: std.Random) O {
    return Catalog.random(rng);
}
fn base(v: u32) O {
    return O.fromBase(M.fromCanonical(v));
}
fn integer(v: O) !u32 {
    const c = v.toM31Array();
    for (c[1..]) |x| if (!x.isZero()) return error.NonBaseJoinedPublic;
    if (c[0].v >= core.fields.m31.Modulus) return error.NonCanonicalJoinedPublic;
    return c[0].v;
}
pub fn metadata(rng: std.Random, mode: u32) [P.count]O {
    var out: [P.count]O = undefined;
    for (&out) |*v| v.* = if (mode == 0) random(rng) else if (mode == 1) O.one() else O.zero();
    for (out[0..P.local]) |*v| v.* = base(rng.uintLessThan(u32, 65536));
    out[P.cpu_steps] = base(if (mode == 2) 0 else 3);
    for (out[P.initial_pc..][0..4], 0..) |*v, i| v.* = base(if (i == 0) 4096 else 0);
    for (out[P.final_pc..][0..4], 0..) |*v, i| v.* = base(if (i == 0) 4108 else 0);
    out[P.epoch] = O.one();
    out[P.rows] = base(if (mode == 2) 0 else 3);
    out[P.nonempty] = base(@intFromBool(mode != 2));
    out[P.calls] = base(if (mode == 2) 0 else 3);
    out[P.first_id] = O.one();
    out[P.calls_nonempty] = base(@intFromBool(mode != 2));
    out[P.source_public + G.Source.Public.sponge_first_id] = O.one();
    return out;
}
pub fn nativeResiduals(a: std.mem.Allocator, descriptor: G.Source.Descriptor, params: *const [P.count]O, fixed: []const O, main: []const O, previous_main: []const O, current: []const O, shifted: []const O, aux: []const O) ![]O {
    const shape = try G.Authority.shape(descriptor);
    const local = G.Authority.hasLocal(descriptor);
    const local_width: usize = if (local) 16 else 0;
    const global = G.Authority.Global.layout(descriptor.origin);
    const width = local_width + global.width();
    if (current.len != width or shifted.len != width or aux.len != (if (local) @as(usize, 10) else 0)) return error.InvalidJoinedFixtureShape;
    var public: G.Authority.PublicFor(O) = .{
        .cpu = .{ .steps = try integer(params[P.cpu_steps]), .initial_pc = undefined, .final_pc = undefined, .epoch = try integer(params[P.epoch]) },
        .rows = try integer(params[P.rows]),
        .nonempty = {},
        .span = .{ .calls = try integer(params[P.calls]), .first_id = try integer(params[P.first_id]) },
    };
    for (&public.cpu.initial_pc, &public.cpu.final_pc, 0..) |*initial, *final, i| {
        initial.* = try integer(params[P.initial_pc + i]);
        final.* = try integer(params[P.final_pc + i]);
    }
    if (try integer(params[P.nonempty]) != @intFromBool(public.rows != 0) or try integer(params[P.calls_nonempty]) != @intFromBool(public.span.calls != 0)) return error.InvalidJoinedFixtureFlag;
    var source_public = params[P.source_public..][0..G.Source.Public.count].*;
    source_public[G.Source.Public.epoch] = params[P.epoch];
    source_public[G.Source.Public.initial_pc] = params[P.initial_pc].add(params[P.initial_pc + 1].mul(base(65536)));
    const expected_count = shape.constraints + (if (local) @as(usize, B.CONSTRAINTS) else 0) + global.constraints();
    const values = try a.alloc(O, expected_count);
    errdefer a.free(values);
    var sink = E.SinkFor(O){ .values = values };
    try G.Authority.emitMain(descriptor, O, public, fixed, main, previous_main, &sink);
    if (local) {
        var ch: G.Source.Challenges.For(O) = .{ .offsets = @splat(O.zero()), .coefficients = @splat(@splat(O.zero())) };
        for (std.enums.values(G.Source.Fractions.Relation)) |relation| {
            const r = @intFromEnum(relation);
            const slot = P.local + r * P.local_stride;
            ch.offsets[r] = params[slot];
            for (0..relation.arity()) |i| ch.coefficients[r][i] = if (relation == .range8) O.one() else params[slot + 1 + i];
        }
        const terms = try descriptor.terms();
        const lanes = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms));
        var projection = B.ProjectionFor(O){ .challenges = &ch, .lane_weights = params[P.weights..][0..lanes], .terms = terms };
        try descriptor.emit(O, fixed, main, previous_main, &source_public, &projection);
        try projection.finish();
        B.emitFor(O, .{ .eq = O.fromPartialEvals(current[0..8].*), .eq_next2 = O.fromPartialEvals(shifted[0..8].*), .prefix = O.fromPartialEvals(current[8..16].*), .prefix_previous = O.fromPartialEvals(shifted[8..16].*) }, .{ .eq0 = params[P.eq0], .eq1 = params[P.eq1], .first = aux[0], .second = aux[1], .carry = O.fromPartialEvals(aux[2..10].*) }, projection.combine(params[P.eta]), params[P.target], &sink);
    }
    var shared: G.Authority.SharedFor(O) = undefined;
    inline for (.{ "ram", "kio", "wire" }) |name| {
        const slot = @field(P, name);
        @field(shared, name).offset = params[slot];
        for (&@field(shared, name).coefficients, 0..) |*v, i| v.* = params[slot + 1 + i];
    }
    try G.Authority.emitGlobal(descriptor, O, fixed, main, &source_public, shared, .{ .ram = params[P.claims], .kio = params[P.claims + 1], .wire = params[P.claims + 2] }, current[local_width..], shifted[local_width..], &sink);
    if (sink.count != expected_count) return error.WrongNativeJoinedConstraintCount;
    return values;
}
pub const Row = struct {
    a: std.mem.Allocator,
    fixed: []O,
    main: []O,
    previous: []O,
    inter: []O,
    shifted: []O,
    aux: []O,
    pub fn init(a: std.mem.Allocator, descriptor: G.Source.Descriptor, rng: std.Random, secure: bool) !Row {
        const s = try G.Authority.shape(descriptor);
        const local = G.Authority.hasLocal(descriptor);
        const width = (if (local) @as(usize, 16) else 0) + G.Authority.Global.layout(descriptor.origin).width();
        const fixed = try a.alloc(O, s.fixed);
        errdefer a.free(fixed);
        const main = try a.alloc(O, s.main);
        errdefer a.free(main);
        const previous = try a.alloc(O, s.main);
        errdefer a.free(previous);
        const inter = try a.alloc(O, width);
        errdefer a.free(inter);
        const shifted = try a.alloc(O, width);
        errdefer a.free(shifted);
        const aux = try a.alloc(O, if (local) 10 else 0);
        errdefer a.free(aux);
        const out = Row{ .a = a, .fixed = fixed, .main = main, .previous = previous, .inter = inter, .shifted = shifted, .aux = aux };
        for ([_][]O{ fixed, main, previous, inter, shifted, aux }) |slice| {
            for (slice) |*v| v.* = if (secure) random(rng) else base(rng.uintLessThan(u32, core.fields.m31.Modulus));
        }
        return out;
    }
    pub fn deinit(self: *Row) void {
        for ([_][]O{ self.fixed, self.main, self.previous, self.inter, self.shifted, self.aux }) |slice| self.a.free(slice);
        self.* = undefined;
    }
    pub fn inputs(self: Row, program: *const @import("composition_codegen.zig").Program) ![]O {
        const values = try self.a.alloc(O, program.inputs.len);
        errdefer self.a.free(values);
        for (values, program.inputs) |*v, mask| v.* = switch (mask.tree) {
            0 => self.fixed[mask.column],
            1 => if (mask.offset == 0) self.main[mask.column] else self.previous[mask.column],
            2 => if (mask.column >= self.inter.len) self.aux[mask.column - self.inter.len] else if (mask.offset == 0) self.inter[mask.column] else self.shifted[mask.column],
            else => return error.InvalidJoinedFixtureTree,
        };
        return values;
    }
};
