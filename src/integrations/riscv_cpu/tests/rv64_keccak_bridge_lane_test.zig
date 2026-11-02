const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const V = rv.evaluation;
const K = rv.crypto.keccak;
const B = K.bridge;
const C = B.component;
const E = B.equations;
const L = B.layout;
const P = C.testing.parallel;
const Q = V.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn fill(comptime F: type, rng: std.Random, destination: []F, scalar: []C.Scratch, comptime field: []const u8) void {
    for (destination, 0..) |*value, column| {
        var secure: [V.LANES]Q = undefined;
        var base: [V.LANES]M = undefined;
        for (0..V.LANES) |lane| {
            secure[lane] = if (F == V.PackedBase) Q.fromBase(M.fromU64(rng.int(u32))) else randomQ(rng);
            base[lane] = secure[lane].c0.a;
            @field(scalar[lane], field)[column] = secure[lane];
        }
        value.* = if (F == V.PackedBase) V.PackedBase.fromLanes(base) else V.PackedSecure.fromLanes(secure);
    }
}
fn challenges(channel: *core.channel.blake2s.Blake2sChannel) E.Challenges {
    const k = K.equations.Challenges.draw(channel);
    return .{ .io = k.io, .call = E.CallChallenges.draw(channel), .ram = rv.relations.Challenges.draw(channel), .bytes = channel.drawSecureFelt() };
}
fn compare(comptime F: type) !void {
    var prng = std.Random.DefaultPrng.init(0x4b42524944474516);
    const rng = prng.random();
    const scalar = try a.alloc(C.Scratch, V.LANES);
    defer a.free(scalar);
    const packet = try a.create(C.ScratchFor(F));
    defer a.destroy(packet);
    fill(F, rng, &packet.fixed, scalar, "fixed");
    fill(F, rng, &packet.main, scalar, "main");
    fill(F, rng, &packet.previous, scalar, "previous");
    fill(F, rng, &packet.previous_header, scalar, "previous_header");
    for (&packet.interaction, 0..) |*value, column| {
        var secure: [V.LANES]Q = undefined;
        for (0..V.LANES) |lane| {
            secure[lane] = randomQ(rng);
            scalar[lane].interaction[column] = secure[lane];
        }
        value.* = V.PackedSecure.fromLanes(secure);
    }
    var prior: [V.LANES]Q = undefined;
    for (&prior) |*value| value.* = randomQ(rng);
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b425249, 16 });
    const ch = challenges(&channel);
    const claim = randomQ(rng);
    const public = E.Public{ .calls = 3, .first_id = core.fields.m31.Modulus - 3 };
    const output = try a.alloc(V.PackedSecure, L.CONSTRAINTS);
    defer a.free(output);
    var packed_sink = V.PackedSink{ .values = output };
    E.emitFor(F, packet.row(), &packet.interaction, V.PackedSecure.fromLanes(prior), claim, ch, public, &packed_sink);
    try std.testing.expectEqual(L.CONSTRAINTS, packed_sink.count);
    const expected = try a.alloc(Q, L.CONSTRAINTS);
    defer a.free(expected);
    for (scalar, 0..) |*row, lane| {
        var sink = V.Sink{ .values = expected };
        E.emit(row.row(), &row.interaction, prior[lane], claim, ch, public, &sink);
        try std.testing.expectEqual(sink.count, packed_sink.count);
        for (expected, output) |value, actual| try std.testing.expect(value.eql(actual.lane(lane)));
        for (0..L.EVENTS) |index| {
            const event = E.event(row.row(), ch, index);
            const actual = E.eventFor(F, packet.row(), ch, index);
            try std.testing.expect(event.denominator.eql(actual.denominator.lane(lane)));
            const coefficient = V.liftFor(F, actual.coefficient);
            try std.testing.expect(event.coefficient.eql(coefficient.lane(lane)));
        }
    }
}
test "Keccak bridge SIMD shares strict clock RAM call and byte equations for arbitrary base rows" {
    try compare(V.PackedBase);
}
test "Keccak bridge SIMD keeps arbitrary extension OODS polynomial residuals" {
    try compare(V.PackedSecure);
}
test "Keccak bridge SIMD quotient exactly matches scalar additive masks and tails at1/3/8/16workers" {
    const log = 10;
    const n = 1 << log;
    const total = L.FIXED + L.MAIN + L.INTERACTION;
    const coefficients = try a.alloc([8]M, total);
    defer a.free(coefficients);
    const polys = try a.alloc(engine.air.component_prover.Poly, total);
    defer a.free(polys);
    const previous = try a.alloc(bool, total);
    defer a.free(previous);
    for (polys, coefficients, previous, 0..) |*poly, *c, *masked, i| {
        for (c, 0..) |*v, j| v.* = M.fromU64(37 + i * 113 + j * 29 + i * j);
        poly.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(c) };
        masked.* = (i >= L.FIXED and i < L.FIXED + L.PREVIOUS_MAIN) or (i >= L.FIXED + L.ACTIVE and i < L.FIXED + L.MAIN) or i >= total - 4;
    }
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b42524f, 16 });
    const component = C.Component{ .log_size = log, .calls = 21, .first_call_id = core.fields.m31.Modulus - 21, .challenges = challenges(&channel), .claim = channel.drawSecureFelt() };
    var evaluation = try C.testing.Evaluation.init(a, polys, log, previous);
    defer evaluation.deinit();
    const alpha = channel.drawSecureFelt();
    var oracle = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, L.CONSTRAINTS);
    defer oracle.deinit();
    var candidate = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, L.CONSTRAINTS);
    defer candidate.deinit();
    const old = try oracle.columns(a, &.{.{ .log_size = log + 2, .n_cols = L.CONSTRAINTS }});
    defer a.free(old);
    const actual = try candidate.columns(a, &.{.{ .log_size = log + 2, .n_cols = L.CONSTRAINTS }});
    defer a.free(actual);
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
        defer pool.deinit();
        for (0..4) |part| {
            try evaluation.evaluatePart(part);
            const inverse = try evaluation.denominatorInverse(part);
            try P.testing.evaluateScalar(&component, &evaluation, part, &old[0], inverse, null);
            try P.evaluatePart(&component, &evaluation, part, &actual[0], inverse, &pool);
            for (0..4 * n) |row| try std.testing.expect(old[0].col.at(row).eql(actual[0].col.at(row)));
        }
        const before = actual[0].col.at(0);
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        evaluation.allocator = failing.allocator();
        const allocation_result = P.evaluatePart(&component, &evaluation, 0, &actual[0], M.one(), &pool);
        evaluation.allocator = a;
        try std.testing.expectError(error.OutOfMemory, allocation_result);
        try std.testing.expect(before.eql(actual[0].col.at(0)));
        if (workers > 1) {
            var reservation = try pool.acquire(try engine.work_pool.WorkerBudget.init(workers));
            const reserved_result = P.evaluatePart(&component, &evaluation, 0, &actual[0], M.one(), &pool);
            reservation.deinit();
            try std.testing.expectError(error.WorkerBudgetUnavailable, reserved_result);
            try std.testing.expect(before.eql(actual[0].col.at(0)));
        }
    }
    const saved = evaluation.previous_values[L.FIXED];
    evaluation.previous_values[L.FIXED] = &.{};
    const malformed = P.evaluatePart(&component, &evaluation, 0, &actual[0], M.one(), null);
    evaluation.previous_values[L.FIXED] = saved;
    try std.testing.expectError(error.InvalidKeccakBridgeCosetShape, malformed);
}
test "Keccak bridge SIMD preserves serialized proof and independent scalar point verification at1/3/8/16workers" {
    const fixture = @import("rv64_keccak_bridge_proof_test.zig");
    var reference: ?[32]u8 = null;
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        if (reference == null) {
            var scalar = P.testing.Binding.init(false);
            defer scalar.deinit();
            reference = try fixture.lane_testing.digest(a, 21);
        }
        var simd = P.testing.Binding.init(true);
        defer simd.deinit();
        const digest = try fixture.lane_testing.digest(a, 21);
        try std.testing.expectEqualSlices(u8, &reference.?, &digest);
    }
}
