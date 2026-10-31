//! Experimental native2n route; the legacy4n receiver remains unchanged.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const E = rv.evaluation;
const Q = E.Q;

test "every DIV provider residual is cubic at arbitrary full extension coordinates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = D.provider.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    const N = D.layout.FIXED + D.layout.MAIN + 2 * D.layout.INTERACTION + 1;
    var origin: [N]Q = undefined;
    var slope: [N]Q = undefined;
    for (&origin, &slope) |*o, *s| {
        o.* = channel.drawSecureFelt();
        s.* = channel.drawSecureFelt();
    }
    var evaluations: [5][D.layout.CONSTRAINTS]Q = undefined;
    for (&evaluations, 0..) |*result, i| {
        var v: [N]Q = undefined;
        for (&v, origin, slope) |*out, o, s| out.* = o.add(s.mul(E.q(@intCast(i))));
        var sink = E.Sink{ .values = result };
        D.provider.evaluate(v[0..3].*, v[3..][0..D.layout.MAIN], v[3 + D.layout.MAIN ..][0..D.layout.INTERACTION], v[3 + D.layout.MAIN + D.layout.INTERACTION ..][0..D.layout.INTERACTION], v[N - 1], 64, ch, claim, &sink);
        try std.testing.expectEqual(D.layout.CONSTRAINTS, sink.count);
    }
    var cubic = false;
    for (0..D.layout.CONSTRAINTS) |c| {
        var differences: [5]Q = undefined;
        for (&differences, evaluations) |*v, row| v.* = row[c];
        for (0..4) |order| {
            for (0..4 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            if (order == 2) cubic = cubic or !differences[0].isZero();
        }
        if (!differences[0].isZero()) {
            std.debug.print("DIV quartic residual {d}\n", .{c});
            return error.UnexpectedDivisionDegree;
        }
    }
    try std.testing.expect(cubic);
}

const Fixture = @import("../delegations/division/degree3_fixture.zig");
test "actual q70 degree3 DIV2n proof independently verifies and rejects changed requests claims and roots" {
    const a = std.testing.allocator;
    var proof = try Fixture.produce(a, &Fixture.REQUESTS);
    defer proof.deinit(a);
    try Fixture.verify(a, &Fixture.REQUESTS, proof);
    var changed = Fixture.REQUESTS;
    changed[0].result ^= 1;
    if (Fixture.verify(a, &changed, proof)) |_| return error.ExpectedDivisionRequestRejection else |_| {}
    var bad_claim = proof;
    bad_claim.claim[0] = (bad_claim.claim[0] + 1) % core.fields.m31.Modulus;
    if (Fixture.verify(a, &Fixture.REQUESTS, bad_claim)) |_| return error.ExpectedDivisionClaimRejection else |_| {}
    const wire = @import("stwo_proof_wire");
    for (0..3) |mutation| {
        var decoded = try wire.decodeProofBytesBinary(a, proof.bytes);
        defer decoded.deinit(a);
        if (mutation == 0) decoded.commitment_scheme_proof.commitments.items[0][0] ^= 1;
        if (mutation == 1) decoded.commitment_scheme_proof.sampled_values.items[2][4][1] = decoded.commitment_scheme_proof.sampled_values.items[2][4][1].add(Q.one());
        if (mutation == 2) decoded.commitment_scheme_proof.sampled_values.items[1][D.layout.COUNT][1] = decoded.commitment_scheme_proof.sampled_values.items[1][D.layout.COUNT][1].add(Q.one());
        const bad_bytes = try wire.encodeProofBytesBinary(a, decoded);
        defer a.free(bad_bytes);
        if (Fixture.verify(a, &Fixture.REQUESTS, .{ .bytes = bad_bytes, .claim = proof.claim })) |_| return error.ExpectedDivisionPhysicalMutationRejection else |_| {}
    }
    try std.testing.expectError(error.ConstraintsNotSatisfied, Fixture.produce(a, &changed));
    var empty = try Fixture.produce(a, &.{});
    defer empty.deinit(a);
    try Fixture.verify(a, &.{}, empty);
}

fn laneValue(comptime F: type, column: usize, lane: usize) Q {
    const value: u32 = @intCast(1 + 64 * column + 4 * lane);
    return if (F == E.PackedBase) E.q(value) else Q.fromU32Unchecked(value, value + 1, value + 2, value + 3);
}
fn packedValues(comptime F: type, comptime n: usize, start: usize) [n]F {
    var result: [n]F = undefined;
    for (&result, 0..) |*v, c| {
        if (F == E.PackedBase) {
            var values: [16]core.fields.m31.M31 = undefined;
            for (&values, 0..) |*x, lane| x.* = laneValue(F, start + c, lane).toM31Array()[0];
            v.* = F.fromLanes(values);
        } else {
            var values: [16]Q = undefined;
            for (&values, 0..) |*x, lane| x.* = laneValue(F, start + c, lane);
            v.* = F.fromLanes(values);
        }
    }
    return result;
}
test "DIV degree3 authority preserves every scalar residual in native and secure SIMD lanes" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = D.provider.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        const geometry = packedValues(F, 3, 0);
        const main = packedValues(F, D.layout.MAIN, 3);
        const current = packedValues(F, D.layout.INTERACTION, 3 + D.layout.MAIN);
        const previous = packedValues(F, D.layout.INTERACTION, 3 + D.layout.MAIN + D.layout.INTERACTION);
        const prior_count = packedValues(F, 1, 3 + D.layout.MAIN + 2 * D.layout.INTERACTION);
        var values: [D.layout.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &values };
        D.provider.evaluateFor(F, geometry, &main, &current, &previous, prior_count[0], E.qFor(F, 64), ch, claim, &sink);
        try std.testing.expectEqual(D.layout.CONSTRAINTS, sink.count);
        for (0..16) |lane| {
            var g: [3]Q = undefined;
            var m: D.layout.Physical = undefined;
            var i: [D.layout.INTERACTION]Q = undefined;
            var p: [D.layout.INTERACTION]Q = undefined;
            for (&g, 0..) |*v, c| v.* = laneValue(F, c, lane);
            for (&m, 0..) |*v, c| v.* = laneValue(F, 3 + c, lane);
            for (&i, &p, 0..) |*v, *prior, c| {
                v.* = laneValue(F, 3 + D.layout.MAIN + c, lane);
                prior.* = laneValue(F, 3 + D.layout.MAIN + D.layout.INTERACTION + c, lane);
            }
            var expected: [D.layout.CONSTRAINTS]Q = undefined;
            var scalar = E.Sink{ .values = &expected };
            D.provider.evaluate(g, &m, &i, &p, laneValue(F, 3 + D.layout.MAIN + 2 * D.layout.INTERACTION, lane), 64, ch, claim, &scalar);
            for (values, expected) |actual, wanted| try std.testing.expect(actual.lane(lane).eql(wanted));
        }
    }
}

test "DIV2n native pole failure keeps committed metadata available for retry" {
    var trace = try D.trace.Trace.init(std.testing.allocator, Fixture.REQUESTS[0..1]);
    defer trace.deinit();
    try trace.releaseMain();
    const zero = D.provider.Challenges{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    try std.testing.expectError(error.DivisionByZero, trace.generateInteraction(zero));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    try std.testing.expectEqual(@as(usize, 1), trace.request_metadata.len);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = D.provider.Challenges.draw(&channel);
    const claim = try trace.generateInteraction(ch);
    const expected = (try ch.denominator(&try D.trace.requestTuple(Fixture.REQUESTS[0])).inv()).neg();
    try std.testing.expect(claim.eql(expected));
}

test "packed DIV2n full proof equals scalar reference at1 3 and16 bounded-stack workers" {
    const engine = @import("stwo_prover_engine");
    const a = std.testing.allocator;
    var reference = try Fixture.testing.produceScalarReference(a, &Fixture.REQUESTS);
    defer reference.deinit(a);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(reference.bytes, &digest, .{});
    var expected_bytes: [32]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_bytes, "58433b44252ece53d80b47031ab40e70981355ada623796b57b3aba6f29f0c96");
    try std.testing.expectEqualSlices(u8, expected, &digest);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 256 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try Fixture.produce(a, &Fixture.REQUESTS);
        defer actual.deinit(a);
        try std.testing.expectEqualSlices(u8, reference.bytes, actual.bytes);
        try std.testing.expectEqual(reference.claim, actual.claim);
        try Fixture.verify(a, &Fixture.REQUESTS, actual);
    }
}

fn packedAllocationCase(allocator: std.mem.Allocator) !void {
    const engine = @import("stwo_prover_engine");
    const M = core.fields.m31.M31;
    const coefficient = [_]M{M.one()};
    const source = engine.air.component_prover.Poly{ .log_size = 6, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficient) };
    const polys: [D.layout.FIXED + D.layout.MAIN + D.layout.INTERACTION]engine.air.component_prover.Poly = @splat(source);
    var headers = [_][]const engine.air.component_prover.Poly{ polys[0..D.layout.FIXED], polys[D.layout.FIXED..][0..D.layout.MAIN], polys[D.layout.FIXED + D.layout.MAIN ..] };
    // Trace and coefficient headers are borrowed stack values, never deinitialized.
    const trace = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&headers) };
    var accumulator = try engine.air.accumulation.DomainEvaluationAccumulator.init(allocator, E.q(3), 6, D.layout.CONSTRAINTS);
    defer accumulator.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const component = D.degree3_component.Component{ .base = .{ .log_size = 5, .count = 0, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = D.provider.Challenges.draw(&channel), .claim = Q.zero() } };
    try component.evaluateConstraintQuotientsOnDomain(&trace, &accumulator);
}
test "packed DIV2n heap scratch and output allocation failures release every owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, packedAllocationCase, .{});
}

test "actual packed DIV domain authority runs on256KiB worker and equals caller evaluation" {
    const engine = @import("stwo_prover_engine");
    const cp = engine.air.component_prover;
    const Acc = engine.air.accumulation.DomainEvaluationAccumulator;
    const Component = D.degree3_component.Component;
    const M = core.fields.m31.M31;
    const a = std.testing.allocator;
    var coefficients: [32]M = undefined;
    for (&coefficients, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 19 + 1));
    const source = cp.Poly{ .log_size = 6, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficients) };
    const polys: [D.layout.FIXED + D.layout.MAIN + D.layout.INTERACTION]cp.Poly = @splat(source);
    var headers = [_][]const cp.Poly{ polys[0..D.layout.FIXED], polys[D.layout.FIXED..][0..D.layout.MAIN], polys[D.layout.FIXED + D.layout.MAIN ..] };
    const trace = cp.Trace{ .polys = core.pcs.TreeVec([]const cp.Poly).initOwned(&headers) };
    var caller = try Acc.init(a, E.q(7), 6, D.layout.CONSTRAINTS);
    defer caller.deinit();
    var worker = try Acc.init(a, E.q(7), 6, D.layout.CONSTRAINTS);
    defer worker.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const component = Component{ .base = .{ .log_size = 5, .count = 17, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = D.provider.Challenges.draw(&channel), .claim = channel.drawSecureFelt() } };
    try component.evaluateConstraintQuotientsOnDomain(&trace, &caller);
    const Job = struct {
        component: *const Component,
        trace: *const cp.Trace,
        accumulator: *Acc,
        caller_thread: std.Thread.Id,
        worker_thread: ?std.Thread.Id = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.worker_thread = std.Thread.getCurrentId();
            // This directly executes the domain/row authority on the helper.
            // Its pool argument is null, so no nested lease or FFT job hides
            // row evaluation back on the caller's larger stack.
            self.component.evaluateConstraintQuotientsOnDomain(self.trace, self.accumulator) catch |err| {
                self.failure = err;
            };
        }
    };
    var job = Job{ .component = &component, .trace = &trace, .accumulator = &worker, .caller_thread = std.Thread.getCurrentId() };
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 2, .stack_size = 256 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(2));
    defer lease.deinit();
    var wait_group: std.Thread.WaitGroup = .{};
    try lease.spawnWg(&wait_group, Job.run, .{&job});
    wait_group.wait();
    lease.completeWave();
    if (job.failure) |err| return err;
    try std.testing.expect(job.worker_thread != null and job.worker_thread.? != job.caller_thread);
    var expected = try caller.finalize();
    defer expected.deinit(a);
    var actual = try worker.finalize();
    defer actual.deinit(a);
    for (expected.columns, actual.columns) |want, got| try std.testing.expectEqualSlices(M, want, got);
}
