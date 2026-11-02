//! Arithmetic-wire qualification only, not an accepting recursive statement.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const E = rv.evaluation;
const LS = rv.memory.load_store_v2;
const L = LS.layout;
const T = LS.types;
const C = LS.component;
const Lane = @import("../rv64_recursion/circuit_lane.zig");
const F = Lane.Lane;
const Q = E.Q;
const a = std.testing.allocator;
const kinds = [_]L.Kind{ .ls, .initial, .terminal, .selection, .range16, .range8 };
const offsets = [3]usize{ 2, 3, 5 };
fn wire(ctx: *Lane.Context, q: Q) !F {
    return F.wire(try ctx.guess(q));
}
const Case = struct {
    component: C.Component,
    data: [5][L.MAIN]Q,
    fn init(ch: *core.channel.blake2s.Blake2sChannel, kind: L.Kind, rows: u32) Case {
        var result: Case = undefined;
        result.component = .{ .kind = kind, .log_size = if (kind == .selection or kind == .range16) 16 else if (kind == .range8) 8 else 6, .rows = rows, .offsets = offsets, .claims = undefined, .challenges = undefined };
        inline for (.{ "ram", "owner", "selection" }) |name| {
            @field(result.component.challenges, name).offset = ch.drawSecureFelt();
            for (&@field(result.component.challenges, name).coefficients) |*x| x.* = ch.drawSecureFelt();
        }
        inline for (.{ "range16", "range8" }) |name| @field(result.component.challenges, name) = .{ .offset = ch.drawSecureFelt(), .coefficient = ch.drawSecureFelt() };
        inline for (.{ "ram", "owner", "range16", "range8", "selection" }) |name| @field(result.component.claims, name) = ch.drawSecureFelt();
        for (&result.data) |*row| for (row) |*v| {
            v.* = ch.drawSecureFelt();
        };
        return result;
    }
};
fn lifted(ctx: *Lane.Context, c: C.Component) !C.ComponentFor(F) {
    var out: C.ComponentFor(F) = .{ .kind = c.kind, .log_size = c.log_size, .rows = try wire(ctx, E.q(c.rows)), .rows_nonzero = try wire(ctx, E.q(@intFromBool(c.rows != 0))), .offsets = c.offsets, .claims = undefined, .challenges = undefined };
    inline for (.{ "ram", "owner", "selection" }) |name| {
        @field(out.challenges, name).offset = try wire(ctx, @field(c.challenges, name).offset);
        for (&@field(out.challenges, name).coefficients, @field(c.challenges, name).coefficients) |*x, q| x.* = try wire(ctx, q);
    }
    inline for (.{ "range16", "range8" }) |name| @field(out.challenges, name) = .{ .offset = try wire(ctx, @field(c.challenges, name).offset), .coefficient = try wire(ctx, @field(c.challenges, name).coefficient) };
    inline for (.{ "ram", "owner", "range16", "range8", "selection" }) |name| @field(out.claims, name) = try wire(ctx, @field(c.claims, name));
    return out;
}
fn emit(c: anytype, comptime V: type, data: *const [5][L.MAIN]V, sink: *E.SinkFor(V)) void {
    const widths = c.widths();
    c.emitFor(V, data[0][0..widths[0]], data[1][0..widths[1]], data[2][0..widths[1]], data[3][0..widths[2]], data[4][0..widths[2]], sink);
}
fn mutated(c: *C.Component, mutation: u8) void {
    switch (mutation) {
        1 => switch (c.kind) {
            .ls, .initial, .terminal => c.challenges.ram.offset = c.challenges.ram.offset.add(Q.one()),
            .selection => c.challenges.selection.offset = c.challenges.selection.offset.add(Q.one()),
            .range16 => c.challenges.range16.offset = c.challenges.range16.offset.add(Q.one()),
            .range8 => c.challenges.range8.offset = c.challenges.range8.offset.add(Q.one()),
        },
        2 => switch (c.kind) {
            .ls, .initial, .terminal => c.claims.ram = c.claims.ram.add(Q.one()),
            .selection => c.claims.selection = c.claims.selection.add(Q.one()),
            .range16 => c.claims.range16 = c.claims.range16.add(Q.one()),
            .range8 => c.claims.range8 = c.claims.range8.add(Q.one()),
        },
        3 => c.rows += 1,
        else => {},
    }
}
test "LS lane all6 kinds preserve complete arbitrary-Q residuals with dynamic counts and public wires" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| for ([_]u32{ 0, 7 }) |rows| {
        const native = Case.init(&ch, kind, rows);
        var expected: [L.constraints(.ls)]Q = undefined;
        var ns = E.Sink{ .values = &expected };
        emit(&native.component, Q, &native.data, &ns);
        var ctx = try Lane.Context.init(a, 0);
        defer ctx.deinit();
        const component = try lifted(&ctx, native.component);
        var data: [5][L.MAIN]F = undefined;
        for (&data, native.data) |*out, in| for (out, in) |*v, q| {
            v.* = try wire(&ctx, q);
        };
        var actual: [L.constraints(.ls)]F = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        Lane.begin(&ctx);
        emit(&component, F, &data, &sink);
        try Lane.finish();
        try std.testing.expectEqual(L.constraints(kind), sink.count);
        try std.testing.expectEqual(ns.count, sink.count);
        for (actual[0..sink.count], expected[0..ns.count]) |v, q| try ctx.eq(v.v, try ctx.constant(q));
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    };
}
test "LS lane changed count nonempty challenge and claim wires cannot hide behind native constants" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| {
        const native = Case.init(&ch, kind, 7);
        var expected: [L.constraints(.ls)]Q = undefined;
        var ns = E.Sink{ .values = &expected };
        emit(&native.component, Q, &native.data, &ns);
        const count_matters = kind == .ls or kind == .initial or kind == .terminal;
        for (1..if (count_matters) @as(usize, 5) else 3) |mutation| {
            var ctx = try Lane.Context.init(a, 0);
            defer ctx.deinit();
            var changed = native.component;
            mutated(&changed, @intCast(mutation));
            var component = try lifted(&ctx, changed);
            if (mutation == 4) component.rows_nonzero = try wire(&ctx, Q.zero());
            var data: [5][L.MAIN]F = undefined;
            for (&data, native.data) |*out, in| for (out, in) |*v, q| {
                v.* = try wire(&ctx, q);
            };
            var actual: [L.constraints(.ls)]F = undefined;
            var sink = E.SinkFor(F){ .values = &actual };
            Lane.begin(&ctx);
            emit(&component, F, &data, &sink);
            try Lane.finish();
            for (actual[0..sink.count], expected[0..ns.count]) |v, q| try ctx.eq(v.v, try ctx.constant(q));
            try ctx.finalize(false);
            try std.testing.expect(!try ctx.isCircuitValid());
        }
    }
}
const Masks = struct {
    c: *const Case,
    broken: bool = false,
    pub fn count(self: @This(), tree: usize, column: usize) !usize {
        if (tree >= 3 or column < offsets[tree]) return error.InvalidRv64MaskShape;
        const local = column - offsets[tree];
        if (local >= L.widths(self.c.component.kind)[tree]) return error.InvalidRv64MaskShape;
        if (self.broken and tree == 0 and local == 0) return 0;
        const prior = if (tree == 1) L.previousMainFor(self.c.component.kind, local) else tree == 2 and L.previousInterFor(self.c.component.kind, local);
        return if (prior) 2 else 1;
    }
    pub fn at(self: @This(), tree: usize, column: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, column)) return error.InvalidRv64MaskShape;
        return self.c.data[if (tree == 0) 0 else if (tree == 1) (if (sample == 0) @as(usize, 1) else 2) else (if (sample == 0) @as(usize, 3) else 4)][column - offsets[tree]];
    }
};
const CircuitMasks = struct {
    native: Masks,
    ctx: *Lane.Context,
    pub fn count(self: @This(), tree: usize, c: usize) !usize {
        return self.native.count(tree, c);
    }
    pub fn at(self: @This(), tree: usize, c: usize, sample: usize) !F {
        return wire(self.ctx, try self.native.at(tree, c, sample));
    }
};
test "LS lane all6 point adapters bind nonzero offsets previous masks and quotient scaling" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| {
        const native = Case.init(&ch, kind, 7);
        const point = core.circle.secureFieldPointFromRandomSeed(ch.drawSecureFelt());
        const alpha = ch.drawSecureFelt();
        var acc = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
        var ns = E.Sink{ .values = null, .accumulator = &acc };
        try native.component.evaluateQuotientsAtPointFor(Q, point, 19, Masks{ .c = &native }, &ns);
        for (0..2) |mutation| {
            var ctx = try Lane.Context.init(a, 0);
            defer ctx.deinit();
            const component = try lifted(&ctx, native.component);
            const p = rv.geometry.PointFor(F){ .x = try wire(&ctx, point.x.add(if (mutation == 1) Q.one() else Q.zero())), .y = try wire(&ctx, point.y) };
            var result = E.lane.PointAccumulator(F).init(try wire(&ctx, alpha));
            var sink = E.SinkFor(F){ .accumulator = &result };
            Lane.begin(&ctx);
            try component.evaluateQuotientsAtPointFor(F, p, 19, CircuitMasks{ .native = .{ .c = &native }, .ctx = &ctx }, &sink);
            try Lane.finish();
            try std.testing.expectEqual(ns.count, sink.count);
            try ctx.eq(result.finalize().v, try ctx.constant(acc.finalize()));
            try ctx.finalize(false);
            try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
        }
    }
}
test "LS lane point adapter rejects missing nonempty flag and malformed mask before acceptance" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    const native = Case.init(&ch, .ls, 7);
    const point = core.circle.secureFieldPointFromRandomSeed(ch.drawSecureFelt());
    var ctx = try Lane.Context.init(a, 0);
    defer ctx.deinit();
    var component = try lifted(&ctx, native.component);
    const p = rv.geometry.PointFor(F){ .x = try wire(&ctx, point.x), .y = try wire(&ctx, point.y) };
    var sink = E.SinkFor(F){};
    component.rows_nonzero = null;
    try std.testing.expectError(error.MissingRv64LaneFlag, component.evaluateQuotientsAtPointFor(F, p, 19, CircuitMasks{ .native = .{ .c = &native }, .ctx = &ctx }, &sink));
    var ns = E.Sink{ .values = null };
    try std.testing.expectError(error.InvalidRv64MaskShape, native.component.evaluateQuotientsAtPointFor(Q, point, 19, Masks{ .c = &native, .broken = true }, &ns));
}
test "LS lane authenticates separate RAM debt and only the sum of local ledger shares" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    const native = Case.init(&ch, .ls, 7);
    var expected: [L.constraints(.ls)]Q = undefined;
    var ns = E.Sink{ .values = &expected };
    emit(&native.component, Q, &native.data, &ns);
    var changed = native.component;
    changed.claims.owner = changed.claims.owner.add(Q.one());
    changed.claims.range16 = changed.claims.range16.sub(Q.one());
    var ctx = try Lane.Context.init(a, 0);
    defer ctx.deinit();
    const component = try lifted(&ctx, changed);
    var data: [5][L.MAIN]F = undefined;
    for (&data, native.data) |*out, in| for (out, in) |*v, q| {
        v.* = try wire(&ctx, q);
    };
    var actual: [L.constraints(.ls)]F = undefined;
    var sink = E.SinkFor(F){ .values = &actual };
    Lane.begin(&ctx);
    emit(&component, F, &data, &sink);
    try Lane.finish();
    for (actual[0..sink.count], expected[0..ns.count]) |v, q| try ctx.eq(v.v, try ctx.constant(q));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
