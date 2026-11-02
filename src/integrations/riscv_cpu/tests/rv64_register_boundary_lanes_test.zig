//! Endpoint/provider arithmetic only. No accepting recursive receiver.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const W = rv.word16_cpu;
const B = W.boundary;
const C = W.boundary_component;
const E = rv.evaluation;
const Q = E.Q;
const Lane = @import("../rv64_recursion/circuit_lane.zig");
const F = Lane.Lane;
const a = std.testing.allocator;
const kinds = [_]C.Kind{ .boundary, .range16, .range8 };
fn public() W.public.Public {
    var result = W.public.Public{ .steps = 4194303, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = undefined, .final_registers = undefined, .register_clocks = undefined };
    for (0..32) |r| {
        result.initial_registers[r] = 0x8000800080008000 ^ (@as(u64, r) * 0x1000100010001);
        result.final_registers[r] = ~result.initial_registers[r];
        result.register_clocks[r] = @intCast(4 * r + 3);
    }
    result.initial_registers[0] = 0;
    result.final_registers[0] = 0;
    result.register_clocks[0] = 0;
    result.initial_registers[31] = std.math.maxInt(u64);
    result.final_registers[31] = 0x80000000ffffffff;
    result.register_clocks[31] = 4 * result.steps - 1;
    return result;
}
fn wire(ctx: *Lane.Context, value: Q) !F {
    return F.wire(try ctx.guess(value));
}
fn liftedPublic(ctx: *Lane.Context, p: W.public.Public) !B.PublicFor(F) {
    var result: B.PublicFor(F) = undefined;
    for (0..32) |r| {
        for (0..4) |limb| {
            const shift: u6 = @intCast(16 * limb);
            result.initial_registers[r][limb] = try wire(ctx, E.q(@as(u16, @truncate(p.initial_registers[r] >> shift))));
            result.final_registers[r][limb] = try wire(ctx, E.q(@as(u16, @truncate(p.final_registers[r] >> shift))));
        }
        result.register_clocks[r] = try wire(ctx, E.q(p.register_clocks[r]));
    }
    return result;
}
fn challenges(ch: *core.channel.blake2s.Blake2sChannel) C.ChallengesFor(Q) {
    var result: C.ChallengesFor(Q) = undefined;
    result.register.offset = ch.drawSecureFelt();
    for (&result.register.coefficients) |*v| v.* = ch.drawSecureFelt();
    inline for (.{ "range16", "range8" }) |name| @field(result, name) = .{ .offset = ch.drawSecureFelt(), .coefficient = ch.drawSecureFelt() };
    return result;
}
fn lifted(ctx: *Lane.Context, component: C.Component) !C.ComponentFor(F) {
    var result = C.ComponentFor(F){ .kind = component.kind, .log_size = component.log_size, .offsets = component.offsets, .public = null, .claim = try wire(ctx, component.claim), .challenges = undefined };
    if (component.public) |p| result.public = try liftedPublic(ctx, p);
    result.challenges.register.offset = try wire(ctx, component.challenges.register.offset);
    for (&result.challenges.register.coefficients, component.challenges.register.coefficients) |*v, q| v.* = try wire(ctx, q);
    inline for (.{ "range16", "range8" }) |name| @field(result.challenges, name) = .{ .offset = try wire(ctx, @field(component.challenges, name).offset), .coefficient = try wire(ctx, @field(component.challenges, name).coefficient) };
    return result;
}
fn makeComponent(ch: *core.channel.blake2s.Blake2sChannel, kind: C.Kind) C.Component {
    return .{ .kind = kind, .log_size = switch (kind) {
        .boundary => 5,
        .range16 => 16,
        .range8 => 8,
    }, .offsets = .{ 2, 4, 6 }, .public = if (kind == .boundary) public() else null, .claim = ch.drawSecureFelt(), .challenges = challenges(ch) };
}
fn nativeReference(c: C.Component) W.component.Component {
    return .{
        .kind = switch (c.kind) {
            .boundary => .boundary,
            .range16 => .range16,
            .range8 => .range8,
        },
        .log_size = c.log_size,
        .offsets = c.offsets,
        .public = c.public orelse public(),
        .cpu_claims = undefined,
        .claim = c.claim,
        .challenges = .{ .register = c.challenges.register, .range16 = c.challenges.range16, .range8 = c.challenges.range8, .function = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .rom = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) } },
    };
}
fn emitNativeReference(c: C.Component, data: *const [4][34]Q, sink: *E.Sink) void {
    const original = nativeReference(c);
    const w = c.widths();
    original.emitFor(Q, data[0][0..w[0]], data[1][0..w[1]], data[2][0..8], &.{}, data[3][0..8], sink);
}
test "Register endpoint tuple matches every independently split full64 value and hard zero initial clocks" {
    const p = public();
    try p.validate(22);
    for (0..32) |r| for ([_]bool{ false, true }) |after| {
        var fixed: [34]Q = @splat(Q.zero());
        fixed[r] = Q.one();
        const actual = B.tupleFor(Q, &fixed, p, after);
        try std.testing.expect(actual[0].eql(E.q(@intCast(r))));
        const value = if (after) p.final_registers[r] else p.initial_registers[r];
        for (0..4) |limb| try std.testing.expect(actual[1 + limb].eql(E.q(@as(u16, @truncate(value >> @as(u6, @intCast(16 * limb)))))));
        try std.testing.expect(actual[5].eql(E.q(if (after) p.register_clocks[r] else 0)));
    };
}
fn packedParity(comptime V: type) !void {
    const base = V == E.PackedBase;
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| {
        const c = makeComponent(&ch, kind);
        const w = c.widths();
        var data: [E.LANES][4][34]Q = undefined;
        for (&data) |*lane| for (lane) |*row| for (row) |*v| {
            const value = ch.drawSecureFelt();
            v.* = if (base) Q.fromBase(value.toM31Array()[0]) else value;
        };
        var simd: [4][34]V = undefined;
        for (&simd, 0..) |*row, t| for (row, 0..) |*v, column| {
            var values: [E.LANES]if (base) core.fields.m31.M31 else Q = undefined;
            for (&values, 0..) |*x, lane| x.* = if (base) data[lane][t][column].toM31Array()[0] else data[lane][t][column];
            v.* = V.fromLanes(values);
        };
        var output: [3]E.PackedSecure = undefined;
        var sink = E.PackedSink{ .values = &output };
        c.emitFor(V, simd[0][0..w[0]], simd[1][0..w[1]], simd[2][0..8], simd[3][0..8], &sink);
        try std.testing.expectEqual(@as(usize, 3), sink.count);
        for (data, 0..) |row, lane| {
            var expected: [3]Q = undefined;
            var ns = E.Sink{ .values = &expected };
            emitNativeReference(c, &row, &ns);
            for (output, expected) |actual, q| try std.testing.expect(actual.lane(lane).eql(q));
        }
    }
}
test "Register boundary and both scalar providers agree in scalar PackedM31 and PackedQM31 lanes" {
    try packedParity(E.PackedBase);
    try packedParity(E.PackedSecure);
}
const Masks = struct {
    kind: C.Kind,
    data: [4][34]Q,
    broken: bool = false,
    pub fn count(self: @This(), tree: usize, absolute: usize) !usize {
        const offsets = [3]usize{ 2, 4, 6 };
        const widths: [3]usize = if (self.kind == .boundary) .{ 34, 0, 8 } else .{ 3, 1, 8 };
        if (tree >= 3 or absolute < offsets[tree] or absolute - offsets[tree] >= widths[tree]) return error.InvalidRv64MaskShape;
        if (self.broken and tree == 2 and absolute == 10) return 1;
        return if (tree == 2 and absolute - offsets[tree] >= 4) 2 else 1;
    }
    pub fn at(self: @This(), tree: usize, absolute: usize, sample: usize) !Q {
        if (sample >= try self.count(tree, absolute)) return error.InvalidRv64MaskShape;
        const offsets = [3]usize{ 2, 4, 6 };
        return self.data[if (tree < 2) tree else if (sample == 0) @as(usize, 2) else 3][absolute - offsets[tree]];
    }
};
const CircuitMasks = struct {
    native: Masks,
    ctx: *Lane.Context,
    pub fn count(self: @This(), t: usize, c: usize) !usize {
        return self.native.count(t, c);
    }
    pub fn at(self: @This(), t: usize, c: usize, s: usize) !F {
        return wire(self.ctx, try self.native.at(t, c, s));
    }
};
test "Register endpoint scalar point adapters bind all endpoint clock challenge claim and OODS wires" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| {
        const c = makeComponent(&ch, kind);
        var masks = Masks{ .kind = kind, .data = undefined };
        for (&masks.data) |*row| for (row) |*v| {
            v.* = ch.drawSecureFelt();
        };
        const point = core.circle.secureFieldPointFromRandomSeed(ch.drawSecureFelt());
        const alpha = ch.drawSecureFelt();
        var acc = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
        var ns = E.Sink{ .values = null, .accumulator = &acc, .scale = try rv.geometry.denominatorInverse(point, 20, c.log_size) };
        // Independent point gathering: the original native emit entrypoint,
        // complete values and known quotient inverse, not the new point adapter.
        emitNativeReference(c, &masks.data, &ns);
        for (0..if (kind == .boundary) @as(usize, 8) else 5) |mutation| {
            var ctx = try Lane.Context.init(a, 0);
            defer ctx.deinit();
            var cw = try lifted(&ctx, c);
            const change = Q.fromU32Unchecked(0, 1, 0, 0);
            if (mutation == 1) cw.claim = try wire(&ctx, c.claim.add(change));
            if (mutation == 2) switch (kind) {
                .boundary => cw.challenges.register.offset = try wire(&ctx, c.challenges.register.offset.add(change)),
                .range16 => cw.challenges.range16.offset = try wire(&ctx, c.challenges.range16.offset.add(change)),
                .range8 => cw.challenges.range8.offset = try wire(&ctx, c.challenges.range8.offset.add(change)),
            };
            if (mutation == 3) switch (kind) {
                .boundary => cw.challenges.register.coefficients[5] = try wire(&ctx, c.challenges.register.coefficients[5].add(change)),
                .range16 => cw.challenges.range16.coefficient = try wire(&ctx, c.challenges.range16.coefficient.add(change)),
                .range8 => cw.challenges.range8.coefficient = try wire(&ctx, c.challenges.range8.coefficient.add(change)),
            };
            if (mutation == 5) cw.public.?.initial_registers[31][3] = try wire(&ctx, E.q(65535).add(change));
            if (mutation == 6) cw.public.?.final_registers[0][0] = try wire(&ctx, change);
            if (mutation == 7) cw.public.?.register_clocks[31] = try wire(&ctx, E.q(c.public.?.register_clocks[31]).add(change));
            const p = rv.geometry.PointFor(F){ .x = try wire(&ctx, point.x.add(if (mutation == 4) change else Q.zero())), .y = try wire(&ctx, point.y) };
            var result = E.lane.PointAccumulator(F).init(try wire(&ctx, alpha));
            var sink = E.SinkFor(F){ .accumulator = &result };
            Lane.begin(&ctx);
            try cw.evaluateQuotientsAtPointFor(F, p, 20, CircuitMasks{ .native = masks, .ctx = &ctx }, &sink);
            try Lane.finish();
            try std.testing.expectEqual(@as(usize, 3), sink.count);
            try ctx.eq(result.finalize().v, try ctx.constant(acc.finalize()));
            try ctx.finalize(false);
            try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
        }
    }
}
test "Register endpoint adapters reject missing public geometry and previous masks" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    var c = makeComponent(&ch, .boundary);
    const point = core.circle.secureFieldPointFromRandomSeed(ch.drawSecureFelt());
    var masks = Masks{ .kind = .boundary, .data = undefined };
    for (&masks.data) |*row| for (row) |*v| {
        v.* = ch.drawSecureFelt();
    };
    var sink = E.Sink{ .values = null };
    c.public = null;
    try std.testing.expectError(error.MissingRegisterBoundaryPublic, c.evaluateQuotientsAtPointFor(Q, point, 20, masks, &sink));
    c.public = public();
    c.log_size = 6;
    try std.testing.expectError(error.InvalidWord16BoundaryGeometry, c.evaluateQuotientsAtPointFor(Q, point, 20, masks, &sink));
    c.log_size = 5;
    masks.broken = true;
    try std.testing.expectError(error.InvalidRv64MaskShape, c.evaluateQuotientsAtPointFor(Q, point, 20, masks, &sink));
}
test "Register boundary scalar residuals are at most cubic and boundary reaches cubic" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| {
        const c = makeComponent(&ch, kind);
        const w = c.widths();
        var affine: [2][4][34]Q = undefined;
        for (&affine) |*matrix| for (matrix) |*row| for (row) |*v| {
            v.* = ch.drawSecureFelt();
        };
        var differences: [5][3]Q = undefined;
        for (0..5) |t| {
            var data: [4][34]Q = undefined;
            for (&data, 0..) |*row, group| for (row, 0..) |*v, col| {
                v.* = affine[0][group][col].add(affine[1][group][col].mul(E.q(@intCast(t))));
            };
            var sink = E.Sink{ .values = &differences[t] };
            c.emitFor(Q, data[0][0..w[0]], data[1][0..w[1]], data[2][0..8], data[3][0..8], &sink);
            try std.testing.expectEqual(@as(usize, 3), sink.count);
        }
        for (0..3) |order| for (0..4 - order) |t| for (0..3) |i| {
            differences[t][i] = differences[t + 1][i].sub(differences[t][i]);
        };
        if (kind == .boundary) try std.testing.expect(!differences[0][0].eql(Q.zero()));
        for (0..3) |i| try std.testing.expect(differences[1][i].sub(differences[0][i]).eql(Q.zero()));
    }
}
fn allocateMetadata(allocator: std.mem.Allocator, c: C.Component) !void {
    const handle = c.asVerifierComponent();
    var logs = try handle.traceLogDegreeBounds(allocator);
    defer logs.deinitDeep(allocator);
    const indices = try handle.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    var masks = try handle.maskPoints(allocator, core.circle.secureFieldPointFromRandomSeed(E.q(17)), 20);
    defer masks.deinitDeep(allocator);
}
test "Register point metadata preserves native roster and all allocation failures clean up" {
    var ch = core.channel.blake2s.Blake2sChannel{};
    for (kinds) |kind| {
        const c = makeComponent(&ch, kind);
        const original = nativeReference(c);
        const h = c.asVerifierComponent();
        const old = original.asVerifierComponent();
        try std.testing.expectEqual(old.nConstraints(), h.nConstraints());
        try std.testing.expectEqual(old.maxConstraintLogDegreeBound(), h.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(old.compositionLogSplit(), h.compositionLogSplit());
        var logs = try h.traceLogDegreeBounds(a);
        defer logs.deinitDeep(a);
        var expected = try old.traceLogDegreeBounds(a);
        defer expected.deinitDeep(a);
        for (logs.items, expected.items) |x, y| try std.testing.expectEqualSlices(u32, x, y);
        const point = core.circle.secureFieldPointFromRandomSeed(ch.drawSecureFelt());
        var masks = try h.maskPoints(a, point, 20);
        defer masks.deinitDeep(a);
        var before = try old.maskPoints(a, point, 20);
        defer before.deinitDeep(a);
        for (masks.items, before.items) |x, y| for (x, y) |column, oldcolumn| {
            try std.testing.expectEqual(column.len, oldcolumn.len);
            for (column, oldcolumn) |p, q| try std.testing.expect(p.eql(q));
        };
        try std.testing.checkAllAllocationFailures(a, allocateMetadata, .{c});
    }
}
