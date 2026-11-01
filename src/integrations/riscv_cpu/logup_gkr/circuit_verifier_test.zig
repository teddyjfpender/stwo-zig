const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const lane = @import("../rv64_recursion/circuit_lane.zig");
const C = @import("circuit_verifier.zig");
const Q = C.Q;
const F = C.F;
const L = engine.lookups;
const a = std.testing.allocator;
const NativeChannel = core.channel.blake2s.Blake2sChannel;
const gates = [_]L.gkr_verifier.Gate{ .LogUp, .LogUp };
const Fixture = struct {
    layers: [2]L.gkr_prover.Layer,
    result: L.gkr_prover.ProveBatchResult,
    channel: NativeChannel,
    fn init() !Fixture {
        var draw = NativeChannel{};
        draw.mixU32s(&.{0x47524343});
        var layers: [2]L.gkr_prover.Layer = undefined;
        var initialized: usize = 0;
        errdefer for (layers[0..initialized]) |*l| l.deinit(a);
        for ([_]usize{ 32, 8 }, 0..) |n, i| {
            layers[i] = .{ .LogUpSingles = .{ .denominators = try L.mle.Mle(Q).initOwned(try draw.drawSecureFelts(a, n)) } };
            initialized += 1;
        }
        var channel = NativeChannel{};
        return .{ .layers = layers, .result = try L.gkr_prover.proveBatch(a, &channel, &layers), .channel = channel };
    }
    fn deinit(self: *Fixture) void {
        self.result.deinit(a);
        for (&self.layers) |*l| l.deinit(a);
    }
};
const Mutation = enum { none, coefficient, mask, terminal, input };
pub const Metrics = struct {
    gates: circuit.builder.context.GateCounts,
    operations: circuit.builder.context.Stats,
    variables: u32,
};

fn circuitMle(context: *C.Context, values: []const Q, point: []const F) !F {
    const scratch = context.scratch();
    const buffer = try scratch.alloc(F, values.len);
    for (buffer, values) |*wire, value| wire.* = F.wire(try context.guess(value));
    var n = buffer.len;
    for (point) |x| {
        for (0..n / 2) |i| buffer[i] = x.mul(buffer[i + n / 2].sub(buffer[i])).add(buffer[i]);
        n /= 2;
    }
    try std.testing.expectEqual(@as(usize, 1), n);
    return buffer[0];
}

fn runCircuit(fixture: *const Fixture, mutation: Mutation, metrics: ?*Metrics) !bool {
    var context = try C.Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var proof = try C.wireProof(&context, &fixture.result.proof);
    switch (mutation) {
        .coefficient => {
            const wire = proof.sumcheck_proofs[2].round_polys[0].coefficients[0];
            context.value_table.items[wire.v.idx] = context.get(wire.v).add(Q.one());
        },
        .mask => {
            const wire = proof.layer_masks_by_instance[0][2].columns[1][0];
            context.value_table.items[wire.v.idx] = context.get(wire.v).add(Q.one());
        },
        else => {},
    }
    var channel = try C.Channel.init(&context);
    var artifact = try C.verify(&context, &gates, &proof, &channel);
    defer artifact.deinit(a);
    if (mutation == .none) {
        for (artifact.ood_point, fixture.result.artifact.ood_point) |wire, value|
            try std.testing.expect(context.get(wire.v).eql(value));
        for (channel.inner.digest.words, 0..) |word, i|
            try std.testing.expectEqual(std.mem.readInt(u32, fixture.channel.digestBytes()[4 * i ..][0..4], .little), circuit.builder.ivalue.unpackU32(Q, context.get(word.get())));
    }
    var inputs: [2][2]F = undefined;
    var expected: [2][]const F = undefined;
    for (&inputs, fixture.layers, 0..) |*values, layer, i| {
        const n = artifact.n_variables_by_instance[i];
        const point = artifact.ood_point[artifact.ood_point.len - n ..];
        values.* = .{ F.one(), try circuitMle(&context, layer.LogUpSingles.denominators.evalsSlice(), point) };
        if (mutation == .input and i == 0) values[1] = values[1].add(F.one());
        expected[i] = values;
    }
    if (mutation == .terminal) {
        const old = artifact.claims_to_verify_by_instance[0][1];
        artifact.claims_to_verify_by_instance[0][1] = old.add(F.one());
    }
    try C.kernel.verifyTerminalInputs(F, &artifact, &expected, C.Checks{ .context = &context });
    try channel.finish();
    bound = false;
    try lane.finish();
    try context.finalize(false);
    if (metrics) |out| out.* = .{ .gates = context.gate_counts, .operations = context.stats, .variables = context.circuit.n_vars };
    return context.isCircuitValid();
}

test "GKR shared authority native replay preserves prover terminal claims and transcript" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var channel = NativeChannel{};
    var artifact = try L.gkr_verifier.partiallyVerifyBatch(a, &gates, &fixture.result.proof, &channel);
    defer artifact.deinit(a);
    try std.testing.expectEqualDeep(fixture.result.artifact, artifact);
    try std.testing.expectEqualDeep(fixture.channel, channel);
    var expected_values: [2][2]Q = undefined;
    var expected: [2][]const Q = undefined;
    for (&expected_values, fixture.layers, 0..) |*values, layer, i| {
        const n = artifact.n_variables_by_instance[i];
        values.* = .{ Q.one(), try layer.LogUpSingles.denominators.evalAtPoint(a, artifact.ood_point[artifact.ood_point.len - n ..]) };
        expected[i] = values;
    }
    try C.kernel.verifyTerminalInputs(Q, &artifact, &expected, L.gkr_verifier.NativeChecks{});
}

test "GKR circuit real proof replay has nonconstant Blake and field gates and valid terminal binding" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var metrics: Metrics = undefined;
    try std.testing.expect(try runCircuit(&fixture, .none, &metrics));
    try std.testing.expect(metrics.gates.blake_g_gate > 1000);
    try std.testing.expect(metrics.gates.qm31_ops > 1000);
    try std.testing.expect(metrics.operations.guess > 100);
    std.debug.print("\nGKR_CIRCUIT_COST {f}\n", .{std.json.fmt(metrics, .{})});
}

test "GKR circuit altered sumcheck coefficient yields unsatisfied graph and native rejects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .coefficient, null));
    const poly = &fixture.result.proof.sumcheck_proofs[2].round_polys[0];
    poly.coeffs[0] = poly.coeffs[0].add(Q.one());
    var channel = NativeChannel{};
    try std.testing.expectError(error.InvalidSumcheck, L.gkr_verifier.partiallyVerifyBatch(a, &gates, &fixture.result.proof, &channel));
}

test "GKR circuit altered layer mask yields unsatisfied graph and native rejects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .mask, null));
    const mask = &fixture.result.proof.layer_masks_by_instance[0][2];
    mask.columns[1][0] = mask.columns[1][0].add(Q.one());
    var channel = NativeChannel{};
    try std.testing.expectError(error.CircuitCheckFailure, L.gkr_verifier.partiallyVerifyBatch(a, &gates, &fixture.result.proof, &channel));
}

test "GKR circuit altered terminal claim cannot bypass final input equality" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .terminal, null));
}

test "GKR circuit final claims must equal independently evaluated input expressions" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .input, null));
}

fn replayAllocationFailure(allocator: std.mem.Allocator, fixture: *const Fixture) !void {
    var channel = NativeChannel{};
    var artifact = L.gkr_verifier.partiallyVerifyBatch(allocator, &gates, &fixture.result.proof, &channel) catch |err| switch (err) {
        // The historical Gate.eval API maps its allocator failure to this
        // error. For this valid fixed fixture, it can only be injected OOM.
        error.ShapeMismatch => return error.OutOfMemory,
        else => |other| return other,
    };
    defer artifact.deinit(allocator);
}
test "GKR numerical authority failure cleanup is atomic at every native allocation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(a, replayAllocationFailure, .{&fixture});
}

test "GKR carry and anchor circuit authority matches native at local and lifted points" {
    const MP = @import("mle_point.zig");
    var random = NativeChannel{};
    random.mixU32s(&.{0x42494e44});
    for ([_]u32{ 3, 5, 10, 22 }) |log| {
        var native_r: [MP.MAX_VARIABLES]Q = undefined;
        for (native_r[0..log]) |*v| v.* = random.drawSecureFelt();
        const native_point = try MP.MleEvalPoint.init(native_r[0..log]);
        const global_point = core.circle.secureFieldPointFromRandomSeed(random.drawSecureFelt());
        for ([_]u32{ log, log + 3 }) |global_log| {
            const local_point = global_point.repeatedDouble(global_log - log);
            const native_carry = try MP.evalCarryQuotient(&native_point, local_point);
            const native_anchors = try MP.evalAnchors(log, local_point);
            var context = try C.Context.init(a, 0);
            defer context.deinit();
            lane.begin(&context);
            var bound = true;
            defer if (bound) lane.finish() catch {};
            var r: [MP.MAX_VARIABLES]F = undefined;
            for (r[0..log], native_r[0..log]) |*wire, value| wire.* = F.wire(try context.guess(value));
            const point = try MP.MleEvalPointFor(F).init(r[0..log]);
            const global: core.circle.CirclePoint(F) = .{ .x = F.wire(try context.guess(global_point.x)), .y = F.wire(try context.guess(global_point.y)) };
            const folded = global.repeatedDouble(global_log - log);
            const carry = try MP.evalCarryQuotientFor(F, &point, folded);
            const anchors = try MP.evalAnchorsFor(F, log, folded);
            try context.eq(carry.v, try context.constant(native_carry));
            for (anchors, native_anchors) |value, expected| try context.eq(value.v, try context.constant(expected));
            bound = false;
            try lane.finish();
            try context.finalize(false);
            try std.testing.expect(try context.isCircuitValid());
            if (log == 22) std.debug.print("\nGKR_BINDING_COST row_log={d} global_log={d} {f}\n", .{ log, global_log, std.json.fmt(Metrics{ .gates = context.gate_counts, .operations = context.stats, .variables = context.circuit.n_vars }, .{}) });
        }
    }
}

test "GKR circuit degenerate binding point is unsatisfied rather than value-mode panic" {
    const MP = @import("mle_point.zig");
    try std.testing.expectError(error.DegenerateEvalPoint, MP.MleEvalPoint.init(&.{ Q.zero(), Q.one() }));
    var context = try C.Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const values = [_]F{ F.wire(try context.guess(Q.zero())), F.wire(try context.guess(Q.one())) };
    _ = try MP.MleEvalPointFor(F).init(&values);
    bound = false;
    try lane.finish();
    try context.finalize(false);
    try std.testing.expect(!try context.isCircuitValid());
}
