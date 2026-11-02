const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const lane = @import("../rv64_recursion/om31_circuit_lane.zig");
const C = @import("om31_circuit_verifier.zig");
const Q = C.Q;
const O = C.O;
const P = L.gkr_prover.ForField(O);
const V = L.gkr_verifier.ForField(O);
const F = C.F;
const L = engine.lookups;
const a = std.testing.allocator;
const NativeChannel = core.channel.raw_mod_m31.Om31Channel;
const gates = [_]V.Gate{ .LogUp, .LogUp };
const Fixture = struct {
    layers: [2]P.Layer,
    result: P.ProveBatchResult,
    channel: NativeChannel,
    fn init() !Fixture {
        var draw = NativeChannel.init();
        draw.mixU32s(&.{0x47524343});
        var layers: [2]P.Layer = undefined;
        var initialized: usize = 0;
        errdefer for (layers[0..initialized]) |*l| l.deinit(a);
        for ([_]usize{ 8, 4 }, 0..) |n, i| {
            layers[i] = .{ .LogUpSingles = .{ .denominators = try L.mle.MleFor(O, O).initOwned(try draw.drawSecureFelts(a, n)) } };
            initialized += 1;
        }
        var channel = NativeChannel.init();
        return .{ .layers = layers, .result = try P.proveBatch(a, &channel, &layers), .channel = channel };
    }
    fn deinit(self: *Fixture) void {
        self.result.deinit(a);
        for (&self.layers) |*l| l.deinit(a);
    }
};
const Mutation = enum { none, coefficient, mask, terminal, input, pole };
pub const Metrics = struct {
    gates: circuit.builder.context.GateCounts,
    operations: circuit.builder.context.Stats,
    variables: u32,
};

fn circuitMle(context: *C.Context, values: []const O, point: []const F) !F {
    const scratch = context.scratch();
    const buffer = try scratch.alloc(F, values.len);
    for (buffer, values) |*wire, value| wire.* = try F.guess(context, value);
    var n = buffer.len;
    for (point) |x| {
        for (0..n / 2) |i| buffer[i] = x.mul(buffer[i + n / 2].sub(buffer[i])).add(buffer[i]);
        n /= 2;
    }
    try std.testing.expectEqual(@as(usize, 1), n);
    return buffer[0];
}

fn runCircuit(fixture: *const Fixture, mutation: Mutation, metrics: ?*Metrics) !bool {
    return runCircuitAt(fixture, mutation, 0, metrics);
}
fn perturb(context: *C.Context, wire: F, coordinate: usize) void {
    const half = if (coordinate < 4) wire.c0.v else wire.c1.v;
    var delta = [_]core.fields.m31.M31{core.fields.m31.M31.zero()} ** 4;
    delta[coordinate % 4] = core.fields.m31.M31.one();
    context.value_table.items[half.idx] = context.get(half).add(Q.fromM31Array(delta));
}
fn unit(coordinate: usize) O {
    var delta = [_]core.fields.m31.M31{core.fields.m31.M31.zero()} ** 8;
    delta[coordinate] = core.fields.m31.M31.one();
    return O.fromM31Array(delta);
}
fn runCircuitAt(fixture: *const Fixture, mutation: Mutation, coordinate: usize, metrics: ?*Metrics) !bool {
    var context = try C.Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var proof = try C.wireProof(&context, &fixture.result.proof);
    switch (mutation) {
        .coefficient => {
            const wire = proof.sumcheck_proofs[2].round_polys[0].coefficients[0];
            perturb(&context, wire, coordinate);
        },
        .mask => {
            const wire = proof.layer_masks_by_instance[0][2].columns[1][0];
            perturb(&context, wire, coordinate);
        },
        .pole => {
            const wire = proof.output_claims_by_instance[0][1];
            context.value_table.items[wire.c0.v.idx] = Q.zero();
            context.value_table.items[wire.c1.v.idx] = Q.zero();
        },
        else => {},
    }
    var channel = try C.Channel.init(&context);
    var artifact = try C.verify(&context, &gates, &proof, &channel);
    defer artifact.deinit(a);
    if (mutation == .none) {
        for (artifact.ood_point, fixture.result.artifact.ood_point) |wire, value|
            try std.testing.expect(wire.value().eql(value));
        try std.testing.expectEqual(fixture.channel.inner.n_draws, channel.inner.inner.n_draws);
        for (channel.inner.inner.digest.words, 0..) |word, i|
            try std.testing.expectEqual(std.mem.readInt(u32, fixture.channel.inner.digestBytes()[4 * i ..][0..4], .little), circuit.builder.ivalue.unpackU32(Q, context.get(word.get())));
    }
    // Projective GKR alone admits poles. Require every root denominator
    // nonzero and bind its rational value to the independently computed public
    // statement, rather than trusting proof-declared output claims.
    for (proof.output_claims_by_instance, fixture.layers) |root, source| {
        var expected_sum = O.zero();
        for (source.LogUpSingles.denominators.evalsSlice()) |d| expected_sum = expected_sum.add(try O.one().div(d));
        const ratio = root[0].mul(root[1].inv());
        try (C.Checks{ .context = &context }).requireEq(ratio, F.fromOm31(expected_sum), .terminal);
    }
    var inputs: [2][2]F = undefined;
    var expected: [2][]const F = undefined;
    for (&inputs, fixture.layers, 0..) |*values, layer, i| {
        const n = artifact.n_variables_by_instance[i];
        const point = artifact.ood_point[artifact.ood_point.len - n ..];
        values.* = .{ F.one(), try circuitMle(&context, layer.LogUpSingles.denominators.evalsSlice(), point) };
        if (mutation == .input and i == 0) values[1] = values[1].add(F.fromOm31(unit(coordinate)));
        expected[i] = values;
    }
    if (mutation == .terminal) {
        const old = artifact.claims_to_verify_by_instance[0][1];
        artifact.claims_to_verify_by_instance[0][1] = old.add(F.fromOm31(unit(coordinate)));
    }
    try C.kernel.verifyTerminalInputs(F, &artifact, &expected, C.Checks{ .context = &context });
    try channel.finish();
    bound = false;
    try lane.finish();
    try context.finalize(false);
    if (metrics) |out| out.* = .{ .gates = context.gate_counts, .operations = context.stats, .variables = context.circuit.n_vars };
    return context.isCircuitValid();
}

test "OM31 GKR shared authority native replay preserves prover terminal claims and transcript" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var channel = NativeChannel.init();
    var artifact = try V.partiallyVerifyBatch(a, &gates, &fixture.result.proof, &channel);
    defer artifact.deinit(a);
    try std.testing.expectEqualDeep(fixture.result.artifact, artifact);
    try std.testing.expectEqualDeep(fixture.channel, channel);
    var expected_values: [2][2]O = undefined;
    var expected: [2][]const O = undefined;
    for (&expected_values, fixture.layers, 0..) |*values, layer, i| {
        const n = artifact.n_variables_by_instance[i];
        values.* = .{ O.one(), try layer.LogUpSingles.denominators.evalAtPoint(a, artifact.ood_point[artifact.ood_point.len - n ..]) };
        expected[i] = values;
    }
    try C.kernel.verifyTerminalInputs(O, &artifact, &expected, V.NativeChecks{});
}

test "OM31 GKR circuit real proof replay has nonconstant Blake and field gates and valid terminal binding" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var metrics: Metrics = undefined;
    const valid = try runCircuit(&fixture, .none, &metrics);
    std.debug.print("\nOM31_GKR_CIRCUIT_COST valid={} {f}\n", .{ valid, std.json.fmt(metrics, .{}) });
    try std.testing.expect(valid);
    try std.testing.expect(metrics.gates.blake_g_gate > 1000);
    try std.testing.expect(metrics.gates.qm31_ops > 1000);
    try std.testing.expect(metrics.operations.guess >= 80);
}

test "OM31 GKR circuit altered sumcheck coefficient yields unsatisfied graph and native rejects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .coefficient, null));
    const poly = &fixture.result.proof.sumcheck_proofs[2].round_polys[0];
    poly.coeffs[0] = poly.coeffs[0].add(O.one());
    var channel = NativeChannel.init();
    try std.testing.expectError(error.InvalidSumcheck, V.partiallyVerifyBatch(a, &gates, &fixture.result.proof, &channel));
}

test "OM31 GKR circuit altered layer mask yields unsatisfied graph and native rejects" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .mask, null));
    const mask = &fixture.result.proof.layer_masks_by_instance[0][2];
    mask.columns[1][0] = mask.columns[1][0].add(O.one());
    var channel = NativeChannel.init();
    try std.testing.expectError(error.CircuitCheckFailure, V.partiallyVerifyBatch(a, &gates, &fixture.result.proof, &channel));
}

test "OM31 GKR circuit altered terminal claim cannot bypass final input equality" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .terminal, null));
}

test "OM31 GKR circuit final claims must equal independently evaluated input expressions" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .input, null));
}

test "OM31 GKR every base coordinate of proof and independent terminal input is constrained" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for (0..8) |coordinate| {
        try std.testing.expect(!try runCircuitAt(&fixture, .coefficient, coordinate, null));
        try std.testing.expect(!try runCircuitAt(&fixture, .input, coordinate, null));
        try std.testing.expect(!try runCircuitAt(&fixture, .terminal, coordinate, null));
    }
}
test "OM31 GKR projective root poles are rejected by actual inverse constraints" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expect(!try runCircuit(&fixture, .pole, null));
}

test "OM31 circuit accepts all four actual GKR layer kinds and independently closes roots" {
    const M31 = core.fields.m31.M31;
    const M = L.mle;
    var random = NativeChannel.init();
    var denominators: [8]O = undefined;
    var numerators: [8]O = undefined;
    for (&denominators, &numerators) |*d, *n| {
        d.* = random.drawSecureFelt();
        n.* = random.drawSecureFelt();
    }
    var weights = [_]M31{ M31.one(), M31.zero(), M31.fromCanonical(2), M31.fromCanonical(core.fields.m31.Modulus - 1) };
    var wide_weights: [4]O = undefined;
    for (&wide_weights, weights) |*w, n| w.* = O.fromBase(n);
    const layers = [_]P.Layer{
        .{ .GrandProduct = try M.MleFor(O, O).initBorrowed(&denominators) },
        .{ .LogUpGeneric = .{ .numerators = try M.MleFor(O, O).initBorrowed(&numerators), .denominators = try M.MleFor(O, O).initBorrowed(&denominators) } },
        .{ .LogUpMultiplicities = .{ .numerators = try M.MleFor(O, M31).initBorrowed(&weights), .denominators = try M.MleFor(O, O).initBorrowed(denominators[0..4]) } },
        .{ .LogUpSingles = .{ .denominators = try M.MleFor(O, O).initBorrowed(denominators[0..4]) } },
    };
    const all_gates = [_]V.Gate{ .GrandProduct, .LogUp, .LogUp, .LogUp };
    var native = NativeChannel.init();
    var result = try P.proveBatch(a, &native, &layers);
    defer result.deinit(a);
    var context = try C.Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const proof = try C.wireProof(&context, &result.proof);
    var channel = try C.Channel.init(&context);
    var artifact = try C.verify(&context, &all_gates, &proof, &channel);
    defer artifact.deinit(a);
    var terminal: [4][2]F = undefined;
    var expected: [4][]const F = undefined;
    const checks = C.Checks{ .context = &context };
    for (layers, 0..) |source, i| {
        const n = artifact.n_variables_by_instance[i];
        const point = artifact.ood_point[artifact.ood_point.len - n ..];
        const root = proof.output_claims_by_instance[i];
        var trusted = if (i == 0) O.one() else O.zero();
        switch (source) {
            .GrandProduct => |mle| {
                terminal[i][0] = try circuitMle(&context, mle.evalsSlice(), point);
                expected[i] = terminal[i][0..1];
                for (mle.evalsSlice()) |v| trusted = trusted.mul(v);
                try checks.requireEq(root[0], F.fromOm31(trusted), .terminal);
            },
            .LogUpGeneric => |mle| {
                terminal[i] = .{ try circuitMle(&context, mle.numerators.evalsSlice(), point), try circuitMle(&context, mle.denominators.evalsSlice(), point) };
                expected[i] = &terminal[i];
                for (mle.numerators.evalsSlice(), mle.denominators.evalsSlice()) |num, den| trusted = trusted.add(try num.div(den));
            },
            .LogUpMultiplicities => |mle| {
                terminal[i] = .{ try circuitMle(&context, &wide_weights, point), try circuitMle(&context, mle.denominators.evalsSlice(), point) };
                expected[i] = &terminal[i];
                for (wide_weights, mle.denominators.evalsSlice()) |num, den| trusted = trusted.add(try num.div(den));
            },
            .LogUpSingles => |mle| {
                terminal[i] = .{ F.one(), try circuitMle(&context, mle.denominators.evalsSlice(), point) };
                expected[i] = &terminal[i];
                for (mle.denominators.evalsSlice()) |den| trusted = trusted.add(try O.one().div(den));
            },
        }
        if (i != 0) try checks.requireEq(root[0].mul(root[1].inv()), F.fromOm31(trusted), .terminal);
    }
    try C.kernel.verifyTerminalInputs(F, &artifact, &expected, checks);
    for (artifact.ood_point, result.artifact.ood_point) |wire, value| try std.testing.expect(wire.value().eql(value));
    try std.testing.expectEqual(native.inner.n_draws, channel.inner.inner.n_draws);
    for (channel.inner.inner.digest.words, 0..) |word, i| try std.testing.expectEqual(std.mem.readInt(u32, native.inner.digestBytes()[4 * i ..][0..4], .little), circuit.builder.ivalue.unpackU32(Q, context.get(word.get())));
    try channel.finish();
    bound = false;
    try lane.finish();
    try context.finalize(false);
    try std.testing.expect(try context.isCircuitValid());
}
