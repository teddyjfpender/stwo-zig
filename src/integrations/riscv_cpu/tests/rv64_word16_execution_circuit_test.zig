//! Actual builder wires, not a numeric wrapper pretending to be a circuit.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const E = front.rv64_air.evaluation;
const LaneModule = @import("../rv64_recursion/circuit_lane.zig");
const F = LaneModule.Lane;
const Context = LaneModule.Context;
const Q = E.Q;
fn wire(ctx: *Context, q: Q) !F {
    return F.wire(try ctx.guess(q));
}
fn lift(ctx: *Context, ch: X.types.Challenges) !X.types.ChallengesFor(F) {
    var out: X.types.ChallengesFor(F) = undefined;
    inline for (.{ "register", "function", "rom", "owner" }) |field| {
        @field(out, field).offset = try wire(ctx, @field(ch, field).offset);
        for (&@field(out, field).coefficients, @field(ch, field).coefficients) |*v, q| v.* = try wire(ctx, q);
    }
    inline for (.{ "range16", "range8" }) |field| @field(out, field) = .{ .offset = try wire(ctx, @field(ch, field).offset), .coefficient = try wire(ctx, @field(ch, field).coefficient) };
    return out;
}
const Mode = enum { cpu, rom, jalr };
const Masks = struct {
    mode: Mode = .cpu,
    data: [5][53]Q,
    pub fn count(self: Masks, tree: usize, c: usize) !usize {
        const widths: [3]usize = switch (self.mode) {
            .cpu => .{ 3, 53, 40 },
            .rom => .{ 32, 1, 8 },
            .jalr => .{ 2, 18, 12 },
        };
        if (tree > 2 or c >= widths[tree]) return error.InvalidMask;
        const previous = switch (self.mode) {
            .cpu => (tree == 1 and X.layout.previousMain(c)) or (tree == 2 and X.layout.previousInter(c)),
            .rom => tree == 2 and c >= 4,
            .jalr => tree == 2 and c >= 8,
        };
        return if (previous) 2 else 1;
    }
    pub fn at(self: Masks, tree: usize, c: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, c)) return error.InvalidMask;
        return self.data[if (tree == 0) 0 else if (tree == 1) (if (sample == 0) @as(usize, 1) else 2) else (if (sample == 0) @as(usize, 3) else 4)][c];
    }
};
const CircuitMasks = struct {
    ctx: *Context,
    native: Masks,
    pub fn count(self: @This(), tree: usize, c: usize) !usize {
        return self.native.count(tree, c);
    }
    pub fn at(self: @This(), tree: usize, c: usize, sample: usize) !F {
        return wire(self.ctx, try self.native.at(tree, c, sample));
    }
};
test "full CPU circuit point evaluator binds every challenge claim public count and mask exactly like QM31" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: X.types.Challenges = undefined;
    inline for (.{ "register", "function", "rom", "owner" }) |field| {
        @field(ch, field).offset = channel.drawSecureFelt();
        for (&@field(ch, field).coefficients) |*v| v.* = channel.drawSecureFelt();
    }
    inline for (.{ "range16", "range8" }) |field| @field(ch, field) = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    const claim = channel.drawSecureFelt();
    var masks = Masks{ .data = undefined };
    for (&masks.data) |*row| for (row) |*v| {
        v.* = channel.drawSecureFelt();
    };
    const public = X.types.Inputs{ .steps = 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 }, .epoch = 3 };
    const native = X.component.Component{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .public = public, .claim = claim, .challenges = ch };
    const point = core.circle.secureFieldPointFromRandomSeed(channel.drawSecureFelt());
    var expected: [55]Q = undefined;
    var native_sink = E.Sink{ .values = &expected };
    try native.evaluateQuotientsAtPointFor(Q, point, 7, masks, &native_sink);
    for (0..2) |mutation| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var pubw: X.types.InputsFor(F) = undefined;
        pubw.steps = try wire(&ctx, E.q(public.steps + @as(u32, @intCast(mutation))));
        pubw.epoch = try wire(&ctx, E.q(public.epoch));
        for (&pubw.initial_pc, public.initial_pc) |*v, q| v.* = try wire(&ctx, E.q(q));
        for (&pubw.final_pc, public.final_pc) |*v, q| v.* = try wire(&ctx, E.q(q));
        const component = X.component.ComponentFor(F){ .log_size = 6, .offsets = .{ 0, 0, 0 }, .public = pubw, .claim = try wire(&ctx, claim), .challenges = try lift(&ctx, ch) };
        const p = front.rv64_air.geometry.PointFor(F){ .x = try wire(&ctx, point.x), .y = try wire(&ctx, point.y) };
        var result: [55]F = undefined;
        var sink = E.SinkFor(F){ .values = &result };
        LaneModule.begin(&ctx);
        var active = true;
        defer if (active) {
            LaneModule.finish() catch {};
        };
        try component.evaluateQuotientsAtPointFor(F, p, 7, CircuitMasks{ .ctx = &ctx, .native = masks }, &sink);
        try LaneModule.finish();
        active = false;
        try std.testing.expectEqual(@as(usize, 55), sink.count);
        if (mutation == 0) try std.testing.expect(ctx.get(sink.scale.?.v).eql(native_sink.scale.?));
        for (result, expected) |value, wanted| try ctx.eq(value.v, try ctx.constant(wanted));
        try ctx.finalize(false);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
    _ = circuit.builder;
}

test "ROM and unit JALR circuit point adapters bind physical claims without native challenge capture" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    inline for (.{ true, false }) |is_rom| {
        const Native = if (is_rom) X.rom_component.Component else X.jalr_component.Component;
        const External = if (is_rom) X.rom_component.ComponentFor(F) else X.jalr_component.ComponentFor(F);
        const Challenge = if (is_rom) X.types.RomChallenges else X.types.FunctionChallenges;
        var ch: Challenge = undefined;
        ch.offset = channel.drawSecureFelt();
        for (&ch.coefficients) |*v| v.* = channel.drawSecureFelt();
        const claim = channel.drawSecureFelt();
        const native = Native{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .claim = claim, .challenges = ch };
        var masks = Masks{ .mode = if (is_rom) .rom else .jalr, .data = undefined };
        for (&masks.data) |*row| for (row) |*v| {
            v.* = channel.drawSecureFelt();
        };
        const point = core.circle.secureFieldPointFromRandomSeed(channel.drawSecureFelt());
        var expected: [6]Q = undefined;
        var ns = E.Sink{ .values = &expected };
        try native.evaluateQuotientsAtPointFor(Q, point, 7, masks, &ns);
        for (0..2) |mutation| {
            var ctx = try Context.init(std.testing.allocator, 0);
            defer ctx.deinit();
            var external = External{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .claim = try wire(&ctx, claim.add(E.q(@intCast(mutation)))), .challenges = undefined };
            external.challenges.offset = try wire(&ctx, ch.offset);
            for (&external.challenges.coefficients, ch.coefficients) |*v, q| v.* = try wire(&ctx, q);
            const p = front.rv64_air.geometry.PointFor(F){ .x = try wire(&ctx, point.x), .y = try wire(&ctx, point.y) };
            var result: [6]F = undefined;
            var sink = E.SinkFor(F){ .values = &result };
            LaneModule.begin(&ctx);
            var active = true;
            defer if (active) {
                LaneModule.finish() catch {};
            };
            try external.evaluateQuotientsAtPointFor(F, p, 7, CircuitMasks{ .ctx = &ctx, .native = masks }, &sink);
            try LaneModule.finish();
            active = false;
            try std.testing.expectEqual(ns.count, sink.count);
            if (mutation == 0) try std.testing.expect(ctx.get(sink.scale.?.v).eql(ns.scale.?));
            for (result[0..sink.count], expected[0..ns.count]) |value, wanted| try ctx.eq(value.v, try ctx.constant(wanted));
            try ctx.finalize(false);
            try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
        }
    }
}

test "merged BINARY circuit authority binds secure challenges claims and inverse witnesses" {
    const B = front.rv64_air.word16_v1.binary_lookup;
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: B.Challenges = undefined;
    inline for (.{ "and_", "function" }) |field| {
        @field(ch, field).offset = channel.drawSecureFelt();
        for (&@field(ch, field).coefficients) |*v| v.* = channel.drawSecureFelt();
    }
    const claims = B.Claims{ .and_ = channel.drawSecureFelt(), .function = channel.drawSecureFelt() };
    var main: [B.MAIN]Q = undefined;
    var current: [B.INTERACTION]Q = undefined;
    var previous: [B.INTERACTION]Q = undefined;
    for (&main) |*v| v.* = channel.drawSecureFelt();
    for (&current, &previous) |*v, *p| {
        v.* = channel.drawSecureFelt();
        p.* = channel.drawSecureFelt();
    }
    const first = channel.drawSecureFelt();
    const last = channel.drawSecureFelt();
    var reference: [B.CONSTRAINTS]Q = undefined;
    var ns = E.Sink{ .values = &reference };
    B.emitFor(Q, &main, &current, &previous, first, last, claims, ch, &ns);
    for (0..4) |mutation| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var cw: B.ChallengesFor(F) = undefined;
        inline for (.{ "and_", "function" }) |field| {
            @field(cw, field).offset = try wire(&ctx, @field(ch, field).offset.add(if (mutation == 1 and std.mem.eql(u8, field, "function")) Q.one() else Q.zero()));
            for (&@field(cw, field).coefficients, @field(ch, field).coefficients) |*v, q| v.* = try wire(&ctx, q);
        }
        const claims_w = B.ClaimsFor(F){ .and_ = try wire(&ctx, claims.and_), .function = try wire(&ctx, claims.function.add(if (mutation == 2) Q.one() else Q.zero())) };
        var mw: [B.MAIN]F = undefined;
        var iw: [B.INTERACTION]F = undefined;
        var pw: [B.INTERACTION]F = undefined;
        for (&mw, main) |*v, q| v.* = try wire(&ctx, q);
        for (&iw, &pw, current, previous, 0..) |*v, *p, q, prior, c| {
            v.* = try wire(&ctx, q.add(if (mutation == 3 and c == 16) Q.one() else Q.zero()));
            p.* = try wire(&ctx, prior);
        }
        const fw = try wire(&ctx, first);
        const lw = try wire(&ctx, last);
        var actual: [B.CONSTRAINTS]F = undefined;
        var sink = E.SinkFor(F){ .values = &actual };
        LaneModule.begin(&ctx);
        B.emitFor(F, &mw, &iw, &pw, fw, lw, claims_w, cw, &sink);
        try LaneModule.finish();
        try std.testing.expectEqual(B.CONSTRAINTS, sink.count);
        for (actual, reference) |v, q| try ctx.eq(v.v, try ctx.constant(q));
        try ctx.finalize(false);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
