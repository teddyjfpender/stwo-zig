const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const M = rv.arithmetic.multiplication;
const L = M.degree3_layout;
const P = M.degree3_provider;
const E = rv.evaluation;
const Q = E.Q;

test "MUL strict-pair authority is genuinely cubic for every arbitrary extension residual" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = M.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    const claim = channel.drawSecureFelt();
    const N = L.FIXED + L.MAIN + L.INTERACTION + 4 + 1;
    var origin: [N]Q = undefined;
    var slope: [N]Q = undefined;
    for (&origin, &slope) |*o, *s| {
        o.* = channel.drawSecureFelt();
        s.* = channel.drawSecureFelt();
    }
    var evaluated: [5][L.CONSTRAINTS]Q = undefined;
    for (&evaluated, 0..) |*values, i| {
        var input: [N]Q = undefined;
        for (&input, origin, slope) |*v, o, s| v.* = o.add(s.mul(E.q(@intCast(i))));
        var sink = E.Sink{ .values = values };
        P.evaluateFor(Q, input[0..3].*, input[3..][0..L.MAIN], input[3 + L.MAIN ..][0..L.INTERACTION], E.secureFor(Q, &input, 3 + L.MAIN + L.INTERACTION), input[N - 1], E.q(17), ch, alpha, claim, &sink);
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
        var reference: [L.ARITHMETIC_CONSTRAINTS]Q = undefined;
        var oracle = E.Sink{ .values = &reference };
        M.provider.arithmeticFor(Q, input[0..3].*, input[3..][0..L.MAIN], input[N - 1], E.q(17), &oracle);
        try std.testing.expectEqualSlices(Q, &reference, values[0..L.ARITHMETIC_CONSTRAINTS]);
    }
    var cubic = false;
    for (0..L.CONSTRAINTS) |c| {
        var differences: [5]Q = undefined;
        for (&differences, evaluated) |*v, row| v.* = row[c];
        for (0..4) |order| {
            for (0..4 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            if (order == 2) cubic = cubic or !differences[0].isZero();
        }
        if (!differences[0].isZero()) {
            std.debug.print("MUL D4 at{d}\n", .{c});
            return error.UnexpectedMultiplicationDegree;
        }
    }
    try std.testing.expect(cubic);
}

const Fixture = @import("../delegations/multiplication/degree3_fixture.zig");
test "actual MUL2n BYTE2n q70 closed proof verifies and forged signed-high result fails" {
    const a = std.testing.allocator;
    const wire = @import("stwo_proof_wire");
    const public = Fixture.Public{ .requests = &Fixture.REQUESTS, .log_size = 5 };
    var bundle = try Fixture.prove(a, public);
    defer bundle.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try Fixture.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var balanced = bundle.claims;
    balanced.multiplication = balanced.multiplication.add(Q.one());
    balanced.bytes = balanced.bytes.sub(Q.one());
    if (Fixture.verifyOwned(a, public, balanced, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.ExpectedBalancedClaimRejection else |_| {}
    const forged = [_]M.trace.Request{.{ .opcode = .MULH, .a = 0xffffffffffffffff, .b = 0xffffffffffffffff, .result = 1 }};
    try std.testing.expectError(error.ConstraintsNotSatisfied, Fixture.prove(a, .{ .requests = &forged, .log_size = 5 }));
}

fn fieldValue(comptime F: type, c: usize, lane: usize) Q {
    const x: u32 = @intCast(1 + 64 * c + 4 * lane);
    return if (F == E.PackedBase) E.q(x) else Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn pack(comptime F: type, comptime n: usize, start: usize) [n]F {
    var values: [n]F = undefined;
    for (&values, 0..) |*v, c| {
        if (F == E.PackedBase) {
            var lanes: [16]core.fields.m31.M31 = undefined;
            for (&lanes, 0..) |*x, lane| x.* = fieldValue(F, start + c, lane).toM31Array()[0];
            v.* = F.fromLanes(lanes);
        } else {
            var lanes: [16]Q = undefined;
            for (&lanes, 0..) |*x, lane| x.* = fieldValue(F, start + c, lane);
            v.* = F.fromLanes(lanes);
        }
    }
    return values;
}
test "every MUL2n residual matches scalar in PackedM31 and full secure lanes" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = M.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    const claim = channel.drawSecureFelt();
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        const fixed = pack(F, 3, 0);
        const main = pack(F, L.MAIN, 3);
        const inter = pack(F, L.INTERACTION, 3 + L.MAIN);
        const previous = pack(F, 4, 3 + L.MAIN + L.INTERACTION);
        const count = pack(F, 1, 7 + L.MAIN + L.INTERACTION);
        var results: [L.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &results };
        P.evaluateFor(F, fixed, &main, &inter, E.secureFromCoordinatesFor(F, previous), count[0], E.qFor(F, 15), ch, alpha, claim, &sink);
        for (0..16) |lane| {
            var f: [3]Q = undefined;
            var m: [L.MAIN]Q = undefined;
            var i: [L.INTERACTION]Q = undefined;
            var prior: [4]Q = undefined;
            for (&f, 0..) |*v, c| v.* = fieldValue(F, c, lane);
            for (&m, 0..) |*v, c| v.* = fieldValue(F, 3 + c, lane);
            for (&i, 0..) |*v, c| v.* = fieldValue(F, 3 + L.MAIN + c, lane);
            for (&prior, 0..) |*v, c| v.* = fieldValue(F, 3 + L.MAIN + L.INTERACTION + c, lane);
            var expected: [L.CONSTRAINTS]Q = undefined;
            var scalar = E.Sink{ .values = &expected };
            P.evaluateFor(Q, f, &m, &i, Q.fromPartialEvals(prior), fieldValue(F, 7 + L.MAIN + L.INTERACTION, lane), E.q(15), ch, alpha, claim, &scalar);
            for (results, expected) |actual, want| try std.testing.expect(actual.lane(lane).eql(want));
        }
    }
}
test "MUL2n source retains exact legacy main counts and rational debt after main release" {
    const a = std.testing.allocator;
    const native = core.fields.m31.M31;
    var old = try M.trace.Trace.init(a, &Fixture.REQUESTS);
    defer old.deinit();
    var source = try M.degree3_source.Source.init(a, &Fixture.REQUESTS);
    defer source.deinit();
    try std.testing.expectEqualSlices(native, old.main, source.base.main);
    try std.testing.expectEqual(old.byte_counts, source.base.byte_counts);
    const saved = try a.dupe(native, source.base.main);
    defer a.free(saved);
    try source.releaseMain();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = M.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    const expected = try old.generateInteraction(ch, alpha);
    const claim = try source.generate(ch, alpha);
    try std.testing.expect(claim.eql(expected));
    const n = source.base.domainSize();
    for (0..n) |logical| {
        const row = rv.program.provider.physical(logical, source.base.log_size);
        const prev = rv.program.provider.physical((logical + n - 1) % n, source.base.log_size);
        var f: [3]Q = undefined;
        var m: [L.MAIN]Q = undefined;
        var i: [L.INTERACTION]Q = undefined;
        var prior: [4]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(source.base.fixed[c * n + row]);
        for (&m, 0..) |*v, c| v.* = Q.fromBase(saved[c * n + row]);
        for (&i, 0..) |*v, c| v.* = Q.fromBase(source.base.interaction[c * n + row]);
        for (&prior, 0..) |*v, c| v.* = Q.fromBase(source.base.interaction[(L.PREFIX + c) * n + prev]);
        var residuals: [L.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        P.evaluateFor(Q, f, &m, &i, Q.fromPartialEvals(prior), Q.fromBase(saved[L.COUNT * n + prev]), E.q(source.base.count), ch, alpha, claim, &sink);
        for (residuals) |v| try std.testing.expect(v.isZero());
    }
}
test "MUL2n strict padding poles and allocation failures preserve ownership and retry" {
    const a = std.testing.allocator;
    var source = try M.degree3_source.Source.init(a, &Fixture.REQUESTS);
    defer source.deinit();
    try source.releaseMain();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = M.provider.Challenges.draw(&channel);
    const alpha = channel.drawSecureFelt();
    try std.testing.expectError(error.DivisionByZero, source.generate(ch, Q.zero()));
    var bad = ch;
    bad.offset = Q.zero();
    try std.testing.expectError(error.DivisionByZero, source.generate(bad, alpha));
    try std.testing.expectEqual(@as(usize, 0), source.base.interaction.len);
    try std.testing.expectEqual(@as(usize, Fixture.REQUESTS.len), source.base.request_metadata.len);
    _ = try source.generate(ch, alpha);
    try std.testing.expectError(error.InvalidRv64MultiplicationPhase, source.generate(ch, alpha));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var source = try M.degree3_source.Source.init(a, &Fixture.REQUESTS);
    defer source.deinit();
    try source.releaseMain();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = M.provider.Challenges.draw(&channel);
    _ = try source.generate(ch, channel.drawSecureFelt());
}
test "actual packed MUL domain authority runs on256KiB worker and equals caller evaluation" {
    const engine = @import("stwo_prover_engine");
    const cp = engine.air.component_prover;
    const Acc = engine.air.accumulation.DomainEvaluationAccumulator;
    const Component = M.degree3_component.Component;
    const Base = core.fields.m31.M31;
    const a = std.testing.allocator;
    var coefficients: [32]Base = undefined;
    for (&coefficients, 0..) |*v, i| v.* = Base.fromCanonical(@intCast(i * 19 + 1));
    const source = cp.Poly{ .log_size = 6, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficients) };
    const polys: [L.FIXED + L.MAIN + L.INTERACTION]cp.Poly = @splat(source);
    var headers = [_][]const cp.Poly{ polys[0..L.FIXED], polys[L.FIXED..][0..L.MAIN], polys[L.FIXED + L.MAIN ..] };
    const trace = cp.Trace{ .polys = core.pcs.TreeVec([]const cp.Poly).initOwned(&headers) };
    var caller = try Acc.init(a, E.q(7), 6, L.CONSTRAINTS);
    defer caller.deinit();
    var worker = try Acc.init(a, E.q(7), 6, L.CONSTRAINTS);
    defer worker.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const component = Component{ .log_size = 5, .count = 17, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = M.provider.Challenges.draw(&channel), .byte_alpha = channel.drawSecureFelt(), .claim = channel.drawSecureFelt() };
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
    for (expected.columns, actual.columns) |want, got| try std.testing.expectEqualSlices(Base, want, got);
}

test "MUL2n full proof scalar reference equals packed at1 3 and16 workers" {
    const engine = @import("stwo_prover_engine");
    const wire = @import("stwo_proof_wire");
    const a = std.testing.allocator;
    const public = Fixture.Public{ .requests = &Fixture.REQUESTS, .log_size = 5 };
    var reference = try Fixture.testing.proveScalarReference(a, public);
    defer reference.deinit(a);
    const bytes = try wire.encodeProofBytesBinary(a, reference.proof);
    defer a.free(bytes);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 256 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try Fixture.prove(a, public);
        defer actual.deinit(a);
        const encoded = try wire.encodeProofBytesBinary(a, actual.proof);
        defer a.free(encoded);
        try std.testing.expectEqualSlices(u8, bytes, encoded);
        try std.testing.expectEqual(reference.claims, actual.claims);
        try Fixture.verifyOwned(a, public, actual.claims, try wire.decodeProofBytesBinary(a, encoded));
    }
}
fn packedAllocationCase(allocator: std.mem.Allocator) !void {
    const engine = @import("stwo_prover_engine");
    const Base = core.fields.m31.M31;
    const coefficient = [_]Base{Base.one()};
    const source = engine.air.component_prover.Poly{ .log_size = 6, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficient) };
    const polys: [L.FIXED + L.MAIN + L.INTERACTION]engine.air.component_prover.Poly = @splat(source);
    var headers = [_][]const engine.air.component_prover.Poly{ polys[0..L.FIXED], polys[L.FIXED..][0..L.MAIN], polys[L.FIXED + L.MAIN ..] };
    // Trace and coefficient headers are borrowed stack values, never deinitialized.
    const trace = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&headers) };
    var accumulator = try engine.air.accumulation.DomainEvaluationAccumulator.init(allocator, E.q(3), 6, L.CONSTRAINTS);
    defer accumulator.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const component = M.degree3_component.Component{ .log_size = 5, .count = 0, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = M.provider.Challenges.draw(&channel), .byte_alpha = channel.drawSecureFelt(), .claim = Q.zero() };
    try component.evaluateConstraintQuotientsOnDomain(&trace, &accumulator);
}
test "packed MUL2n heap scratch and output allocation failures release every owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, packedAllocationCase, .{});
}
