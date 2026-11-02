//! Native-fresh-verified real-bundle numerical circuit cost oracle. This is
//! not a recursive leaf proof: it evaluates shared GKR/terminal-binding
//! arithmetic with real witness wires, while PCS authentication remains native.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_proof_wire");
const C = @import("circuit_verifier.zig");
const Lane = @import("../rv64_recursion/circuit_lane.zig");
const P = @import("protocol.zig");
const W = @import("witness.zig");
const Air = @import("air.zig");
const MP = @import("mle_point.zig");
const Codec = @import("wire.zig");
const Q = C.Q;
const F = C.F;
const L = engine.lookups;
const Wrappers = circuit.builder.wrappers;
const Metrics = struct {
    gates: circuit.builder.context.GateCounts,
    operations: circuit.builder.context.Stats,
    variables: u32,
    fn read(ctx: *const C.Context) Metrics {
        return .{ .gates = ctx.gate_counts, .operations = ctx.stats, .variables = ctx.circuit.n_vars };
    }
};
const Challenges = struct {
    values: [4]F,
    pub fn offset(self: Challenges, j: usize) F {
        return self.values[if (j < W.HI_LANES) 0 else 2];
    }
    pub fn coefficient(self: Challenges, j: usize) F {
        return self.values[if (j < W.HI_LANES) 1 else 3];
    }
};
fn guess(ctx: *C.Context, value: Q) !F {
    return F.wire(try ctx.guess(value));
}
fn assertValue(ctx: *C.Context, value: F, expected: Q) !void {
    // Test oracle equality only. The computation producing `value` consumes
    // guessed input wires; this constant does not fold its arithmetic away.
    try ctx.eq(value.v, try ctx.constant(expected));
}
fn commitRoot(ctx: *C.Context, channel: *C.Channel, root: [32]u8) !void {
    var hash: circuit.builder.blake.HashValue(circuit.builder.Var) = undefined;
    for (&hash.words, 0..) |*word, i| word.* = try Wrappers.guessU32(Q, ctx, Wrappers.u32Value(Q, std.mem.readInt(u32, root[4 * i ..][0..4], .little)));
    try channel.inner.mixRoot(Q, ctx, hash);
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 6) return error.ExpectedProofLsTailHiLoLogs;
    const statement: W.Statement = .{
        .ls_log = try std.fmt.parseUnsigned(u32, args[2], 10),
        .tail_log = try std.fmt.parseUnsigned(u32, args[3], 10),
        .hi_log = try std.fmt.parseUnsigned(u32, args[4], 10),
        .lo_log = try std.fmt.parseUnsigned(u32, args[5], 10),
    };
    try statement.validate();
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 16 << 20);
    defer a.free(bytes);
    // Receiver-owned geometry and q70/P26 suite, then independent full native
    // acceptance before running this diagnostic graph fragment.
    _ = try P.verify(a, P.productionConfig(), statement, .gkr, bytes);
    var timer = try std.time.Timer.start();
    var reader: Codec.Reader = .{ .bytes = bytes };
    _ = try reader.take(8 + 4 + 16);
    const nclaims = try reader.bounded(4);
    var public_claims: [4]Q = undefined;
    for (public_claims[0..nclaims]) |*value| value.* = try reader.q();
    var proof = try P.decodeGkr(a, try reader.take(try reader.u32_()));
    defer proof.deinit(a);
    var stark = try wire.decodeProofBytesBinary(a, try reader.take(try reader.u32_()));
    defer stark.deinit(a);
    const roots = stark.commitment_scheme_proof.commitments.items;
    var native = P.Channel{};
    P.productionConfig().mixInto(&native);
    P.MerkleChannel.mixRoot(&native, roots[0]);
    P.mixStatement(&native, statement, .gkr);
    P.MerkleChannel.mixRoot(&native, roots[1]);
    const ch = Air.Challenges.draw(&native);
    const before_gkr = native;
    const native_outcome = try P.verifyGkr(a, statement, ch, &proof, &native);
    const after_native_gkr = native;
    native.mixFelts(public_claims[0..nclaims]);
    P.MerkleChannel.mixRoot(&native, roots[2]);
    _ = native.drawSecureFelt();
    P.MerkleChannel.mixRoot(&native, roots[3]);
    const native_seed = native.drawSecureFelt();
    const native_oods = core.circle.secureFieldPointFromRandomSeed(native_seed);
    const global_log = @max(@max(statement.ls_log, statement.tail_log), @max(statement.hi_log, statement.lo_log));

    var context = try C.Context.init(a, 0);
    defer context.deinit();
    Lane.begin(&context);
    var bound = true;
    defer if (bound) Lane.finish() catch {};
    var channel = try C.Channel.init(&context);
    for (&channel.inner.digest.words, 0..) |*word, i| word.* = try Wrappers.guessU32(Q, &context, Wrappers.u32Value(Q, std.mem.readInt(u32, before_gkr.digestBytes()[4 * i ..][0..4], .little)));
    channel.inner.n_draws = before_gkr.n_draws;
    var wired = try C.wireProof(&context, &proof);
    var gates: [2]L.gkr_verifier.Gate = .{ .LogUp, .LogUp };
    var artifact = try C.verify(&context, gates[0..statement.instanceCount()], &wired, &channel);
    defer artifact.deinit(a);
    const after_gkr = Metrics.read(&context);
    const gkr_ns = timer.read();
    for (channel.inner.digest.words, 0..) |word, i| {
        const got = circuit.builder.ivalue.unpackU32(Q, context.get(word.get()));
        if (got != std.mem.readInt(u32, after_native_gkr.digestBytes()[4 * i ..][0..4], .little)) return error.CircuitTranscriptMismatch;
    }
    var claims: [4]F = undefined;
    for (claims[0..nclaims], public_claims[0..nclaims]) |*out, value| out.* = try guess(&context, value);
    channel.mixFelts(claims[0..nclaims]);
    try commitRoot(&context, &channel, roots[2]);
    const composition = channel.drawSecureFelt();
    try context.markAsMaybeUnused(composition.v);
    try commitRoot(&context, &channel, roots[3]);
    const seed = channel.drawSecureFelt();
    try assertValue(&context, seed, native_seed);
    const cp = try circuit.native_verifier.verify.pointFromSeed(Q, &context, seed.v);
    const oods: core.circle.CirclePoint(F) = .{ .x = F.wire(cp.x), .y = F.wire(cp.y) };
    const cch: Challenges = .{ .values = .{ try guess(&context, ch.z_hi), try guess(&context, ch.c_hi), try guess(&context, ch.z_lo), try guess(&context, ch.c_lo) } };
    var fraction_sum = F.zero();
    for (0..statement.instanceCount()) |i| {
        const inputs = artifact.claims_to_verify_by_instance[i];
        try context.eq(inputs[0].v, F.one().v);
        const root_claims = wired.output_claims_by_instance[i];
        fraction_sum = fraction_sum.add(root_claims[0].div(root_claims[1]));
        const nv = artifact.n_variables_by_instance[i];
        const log = statement.instanceLog(i);
        const binding = try P.BindingFor(F).init(artifact.ood_point[artifact.ood_point.len - nv ..], log, cch, inputs[1]);
        const local = oods.repeatedDouble(global_log - log);
        const carry = try MP.evalCarryQuotientFor(F, &binding.point, local);
        const anchors = try MP.evalAnchorsFor(F, log, local);
        const native_binding = native_outcome.bindings[i];
        const native_local = native_oods.repeatedDouble(global_log - log);
        try assertValue(&context, carry, try MP.evalCarryQuotient(&native_binding.point, native_local));
        const expected_anchors = try MP.evalAnchors(log, native_local);
        for (anchors, expected_anchors) |value, expected| try assertValue(&context, value, expected);
        var main_values: [W.LANES]F = undefined;
        var native_main: [W.LANES]Q = undefined;
        const pcs = stark.commitment_scheme_proof.sampled_values.items;
        for (&main_values, &native_main, 0..) |*value, *native_value, j| {
            native_value.* = pcs[1][i * W.LANES + j][0];
            value.* = try guess(&context, native_value.*);
        }
        var samples: [4]Q = undefined;
        for (&samples, 0..) |*value, k| {
            const base = i * Air.GKR_INTER + (if (k < 2) @as(usize, 0) else 4);
            var coords: [4]Q = undefined;
            for (&coords, 0..) |*coord, j| coord.* = pcs[2][base + j][k % 2];
            value.* = Q.fromPartialEvals(coords);
        }
        const values = try Air.gkrConsumerResidualsFor(F, binding, log, main_values, try guess(&context, samples[0]), try guess(&context, samples[1]), try guess(&context, samples[2]), try guess(&context, samples[3]), carry, anchors[0], anchors[1]);
        const expected = try Air.gkrConsumerResidualsFor(Q, native_binding, log, native_main, samples[0], samples[1], samples[2], samples[3], try MP.evalCarryQuotient(&native_binding.point, native_local), expected_anchors[0], expected_anchors[1]);
        for (values, expected) |value, native_value| try assertValue(&context, value, native_value);
    }
    for (claims[0..nclaims]) |claim| fraction_sum = fraction_sum.add(claim);
    try context.eq(fraction_sum.v, F.zero().v);
    try channel.finish();
    bound = false;
    try Lane.finish();
    try context.finalize(false);
    if (!try context.isCircuitValid()) return error.UnsatisfiedGkrFragment;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    const report = .{ .schema = "rv64-gkr-actual-circuit-cost-v1", .scope = "native-fresh-accepted-mini-AIR; circuit GKR+terminal-binding fragment only, PCS authentication remains native", .whole_recursive_proof = false, .whole_protocol_128 = false, .statement = statement, .proof_sha256 = std.fmt.bytesToHex(hash, .lower), .gkr_fragment_ns = gkr_ns, .total_fragment_ns = timer.read(), .after_gkr = after_gkr, .after_finalization = Metrics.read(&context), .valid = true };
    const json = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(json);
    var stdout = std.fs.File.stdout();
    try stdout.writeAll(json);
    try stdout.writeAll("\n");
}
