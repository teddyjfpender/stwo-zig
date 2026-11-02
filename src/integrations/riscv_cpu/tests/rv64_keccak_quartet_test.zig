//! Experimental quartet policy only; not admitted by the production CPU coordinator.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const E = K.equations;
const L = K.layout;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn literal(d: [4]Q, c: [4]Q, delta: Q) Q {
    var product = Q.one();
    for (d) |value| product = product.mul(value);
    var numerator = Q.zero();
    for (c, 0..) |coefficient, i| {
        var term = coefficient;
        for (d, 0..) |value, j| if (i != j) {
            term = term.mul(value);
        };
        numerator = numerator.add(term);
    }
    return delta.mul(product).sub(numerator);
}
test "quartet clearing is one exact arbitrary secure polynomial with weighted and dummy entries" {
    var prng = std.Random.DefaultPrng.init(0x4b51554152544554);
    const rng = prng.random();
    for (0..64) |iteration| {
        var d: [4]Q = undefined;
        var c: [4]Q = undefined;
        for (&d, &c) |*denominator, *coefficient| {
            denominator.* = randomQ(rng);
            coefficient.* = randomQ(rng);
        }
        if (iteration % 4 != 0) for (iteration % 4..4) |i| {
            d[i] = Q.one();
            c[i] = Q.zero();
        };
        const delta = randomQ(rng);
        try std.testing.expect(literal(d, c, delta).eql(E.clearQuartetFor(Q, false, d, c, delta)));
        c = @splat(randomQ(rng));
        try std.testing.expect(literal(d, c, delta).eql(E.clearQuartetFor(Q, true, d, c, delta)));
    }
    const policy = E.BatchPolicy.quartet_v3;
    try std.testing.expectEqual(@as(usize, 487), policy.batches());
    try std.testing.expectEqual(@as(usize, 1948), policy.interactionCount());
    try std.testing.expectEqual(@as(usize, 3903), L.FIXED + L.MAIN + policy.interactionCount());
}
fn affine(values: []Q, rng: std.Random, x: Q) void {
    for (values) |*value| value.* = randomQ(rng).add(randomQ(rng).mul(x));
}
test "quartet raw rows have degree at most five and genuinely require the fifth degree" {
    const policy = E.BatchPolicy.quartet_v3;
    const count = policy.constraints();
    const output = try a.alloc(Q, 7 * count);
    defer a.free(output);
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    var channel = core.channel.blake2s.Blake2sChannel{};
    policy.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    for (0..7) |t| {
        var prng = std.Random.DefaultPrng.init(0x4b44454752454535);
        const rng = prng.random();
        const x = Q.fromBase(M.fromCanonical(@intCast(t)));
        affine(&scratch.fixed, rng, x);
        affine(&scratch.main, rng, x);
        for (&scratch.shifted) |*state| affine(state, rng, x);
        affine(&scratch.previous_header, rng, x);
        affine(scratch.interaction[0..policy.batches()], rng, x);
        const prior = randomQ(rng).add(randomQ(rng).mul(x));
        var sink = rv.evaluation.Sink{ .values = output[t * count ..][0..count] };
        E.emitForPolicy(Q, policy, scratch.row(), scratch.interaction[0..policy.batches()], prior, claim, ch, .{ .calls = 3, .first_id = core.fields.m31.Modulus - 3 }, &sink);
        try std.testing.expectEqual(count, sink.count);
    }
    var fifth_nonzero = false;
    for (0..count) |constraint| {
        var differences: [7]Q = undefined;
        for (&differences, 0..) |*value, i| value.* = output[i * count + constraint];
        for (0..6) |order| {
            for (0..6 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            if (order == 4 and constraint >= L.DIRECT) fifth_nonzero = fifth_nonzero or !differences[0].isZero();
        }
        try std.testing.expect(differences[0].isZero());
    }
    try std.testing.expect(fifth_nonzero);
}
test "quartet Base and full extension SIMD lanes retain every scalar residual" {
    const oracle = @import("rv64_keccak_lane_test.zig");
    try oracle.compareWithPolicy(rv.evaluation.PackedBase, .quartet_v3);
    try oracle.compareWithPolicy(rv.evaluation.PackedSecure, .quartet_v3);
}
test "quartet actual4n quotient and independent OODS receiver pass with policy binding at1/3/8/16workers" {
    const fixture = @import("rv64_keccak_proof_test.zig");
    var reference: ?[32]u8 = null;
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        const digest = try fixture.quartet_testing.digest(a, 3, core.fields.m31.Modulus - 3, 10);
        if (reference) |expected| try std.testing.expectEqualSlices(u8, &expected, &digest) else reference = digest;
    }
    _ = try fixture.quartet_testing.prove(a, 0, 1, 5, false);
    _ = try fixture.quartet_testing.prove(a, 1, 1, 6, true);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const component = K.quartet_component.Component{ .base = .{ .kind = .permutation, .log_size = 10, .calls = 3, .challenges = E.Challenges.draw(&channel), .claim = Q.zero() } };
    try std.testing.expectEqual(@as(u8, 5), try component.constraintDegreeBound(L.DIRECT));
    try std.testing.expectEqual(@as(u32, 12), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 2), component.compositionLogSplit());
}
test "quartet narrow metadata witness preserves transactional poles and allocation failure ownership" {
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const fixture = @import("rv64_keccak_proof_test.zig");
            const input = [_]K.trace.State{fixture.inputState(41)};
            var trace = try K.trace.Trace.init(allocator, &input, 1);
            defer trace.deinit();
            try trace.releaseMain();
            var channel = core.channel.blake2s.Blake2sChannel{};
            E.BatchPolicy.quartet_v3.mix(&channel);
            const ch = E.Challenges.draw(&channel);
            const claim = try K.interaction.generateForPolicy(&trace, ch, .quartet_v3, .{});
            _ = claim;
            try std.testing.expectEqual(E.BatchPolicy.quartet_v3.interactionCount() * trace.size(), trace.interaction.len);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{});
    const fixture = @import("rv64_keccak_proof_test.zig");
    const input = [_]K.trace.State{fixture.inputState(41)};
    var trace = try K.trace.Trace.init(a, &input, 1);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    var bad = E.Challenges.draw(&channel);
    bad.chi = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    try std.testing.expectError(error.DivisionByZero, K.interaction.generateForPolicy(&trace, bad, .quartet_v3, .{}));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    _ = try K.interaction.generateForPolicy(&trace, E.Challenges.draw(&channel), .quartet_v3, .{});
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
    defer pool.deinit();
    const ch = E.Challenges.draw(&channel);
    var control = try K.trace.Trace.initWithLog(a, &input, 1, 8);
    defer control.deinit();
    const expected = try K.interaction.generateForPolicy(&control, ch, .quartet_v3, .{});
    inline for (.{
        .{ K.interaction.testing.Faults{ .prefix_spawn_after = 1 }, error.InjectedKeccakPrefixSubmissionFailure },
        .{ K.interaction.testing.Faults{ .correction_spawn_after = 1 }, error.InjectedKeccakCorrectionSubmissionFailure },
        .{ K.interaction.testing.Faults{ .correction_fail_job = 1 }, error.InjectedKeccakCorrectionFailure },
    }) |case| {
        var attempt = try K.trace.Trace.initWithLog(a, &input, 1, 8);
        defer attempt.deinit();
        try attempt.releaseMain();
        try std.testing.expectError(case[1], K.interaction.testing.generatePolicyWithFaults(&attempt, ch, .quartet_v3, .{ .pool = &pool }, case[0]));
        try std.testing.expectEqual(@as(usize, 0), attempt.interaction.len);
        const actual = try K.interaction.generateForPolicy(&attempt, ch, .quartet_v3, .{ .pool = &pool });
        try std.testing.expect(expected.eql(actual));
        try std.testing.expectEqualSlices(M, control.interaction, attempt.interaction);
    }
}
