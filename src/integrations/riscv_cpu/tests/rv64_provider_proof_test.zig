const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const byte = rv.providers.byte;
test {
    _ = rv.range.provider;
    const component = byte.Component{ .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .alpha = core.fields.qm31.QM31.one(), .claim = core.fields.qm31.QM31.zero() };
    const prover = component.asProverComponent();
    _ = prover;
    const verifier = component.asVerifierComponent();
    var logs = try verifier.traceLogDegreeBounds(std.testing.allocator);
    defer logs.deinitDeep(std.testing.allocator);
    const p = core.poly.circle.canonic.CanonicCoset.new(14).circleDomain().at(0);
    var mask = try verifier.maskPoints(std.testing.allocator, .{ .x = core.fields.qm31.QM31.fromBase(p.x), .y = core.fields.qm31.QM31.fromBase(p.y) }, 12);
    defer mask.deinitDeep(std.testing.allocator);
}

const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const B = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const provider = rv.range.provider;
const physical = rv.witness.physical;

// Synthetic execution consumer: 1024 accesses with every byte occurring four
// times. Its larger domain and previous-row prefix use the same rational AIR.
fn consumerFixed(a: std.mem.Allocator) ![]M {
    const fixed = try a.alloc(M, 3 * 1024);
    @memset(fixed, M.zero());
    for (0..1024) |i| {
        const row = physical(i, 10);
        fixed[row] = M.fromCanonical(@intCast((i * 17 + 31) % 256));
        fixed[1024 + row] = M.fromCanonical(@intFromBool(i == 0));
        fixed[2048 + row] = M.fromCanonical(@intFromBool(i == 1023));
    }
    return fixed;
}
fn appendColumns(output: []engine.pcs.ColumnEvaluation, storage: []const M, log: u32) void {
    const size = @as(usize, 1) << @intCast(log);
    for (output, 0..) |*column, i| column.* = .{ .log_size = log, .values = storage[i * size ..][0..size] };
}
fn consumerInteraction(a: std.mem.Allocator, fixed: []const M, alpha: Q) !struct { data: []M, claim: Q } {
    const data = try a.alloc(M, 8 * 1024);
    errdefer a.free(data);
    var sum = Q.zero();
    for (0..1024) |i| {
        const row = physical(i, 10);
        const inverse = try alpha.sub(Q.fromBase(fixed[row])).inv();
        sum = sum.add(inverse);
        for (inverse.toM31Array(), 0..) |coordinate, c| data[c * 1024 + row] = coordinate;
        for (sum.toM31Array(), 0..) |coordinate, c| data[(4 + c) * 1024 + row] = coordinate;
    }
    return .{ .data = data, .claim = sum };
}

fn mixedProof(tamper: enum { none, previous_sample, terminal_claim }) !void {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 12) };
    const consumer_fixed = try consumerFixed(a);
    defer a.free(consumer_fixed);
    const consumer_main = try a.alloc(M, 1024);
    defer a.free(consumer_main);
    @memset(consumer_main, M.one().neg());
    const counts: [256]u64 = @splat(4);
    var table = try provider.Trace.init(a, &counts);
    defer table.deinit();
    var fixed: [6]engine.pcs.ColumnEvaluation = undefined;
    appendColumns(fixed[0..3], consumer_fixed, 10);
    appendColumns(fixed[3..6], table.fixed, 8);
    var main: [2]engine.pcs.ColumnEvaluation = undefined;
    appendColumns(main[0..1], consumer_main, 10);
    appendColumns(main[1..2], table.main, 8);
    var channel = Channel{};
    config.mixInto(&channel);
    channel.mixU32s(&.{ 0x48544552, 10, 8 });
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    try scheme.commit(a, &fixed, &channel);
    try scheme.commit(a, &main, &channel);
    const alpha = channel.drawSecureFelt();
    const consumer = try consumerInteraction(a, consumer_fixed, alpha);
    defer a.free(consumer.data);
    const table_claim = try table.generateInteraction(alpha);
    try std.testing.expect(consumer.claim.add(table_claim).isZero());
    channel.mixFelts(&.{ consumer.claim, table_claim });
    var interaction: [16]engine.pcs.ColumnEvaluation = undefined;
    appendColumns(interaction[0..8], consumer.data, 10);
    appendColumns(interaction[8..16], table.interaction, 8);
    try scheme.commit(a, &interaction, &channel);
    const cpu = byte.Component{ .log_size = 10, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .alpha = alpha, .claim = consumer.claim };
    const rom = byte.Component{ .fixed_offset = 3, .main_offset = 1, .interaction_offset = 8, .alpha = alpha, .claim = table_claim };
    const components = [_]engine.air.component_prover.ComponentProver{ cpu.asProverComponent(), rom.asProverComponent() };
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &components, &channel, scheme);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    try std.testing.expectEqual(@as(usize, 4), proof.commitment_scheme_proof.commitments.items.len);

    // A fresh receiver derives its fixed columns rather than accepting a root.
    const expected_fixed = try consumerFixed(a);
    defer a.free(expected_fixed);
    const empty_counts: [256]u64 = @splat(0);
    var expected_table = try provider.Trace.init(a, &empty_counts);
    defer expected_table.deinit();
    var receiver_fixed: [6]engine.pcs.ColumnEvaluation = undefined;
    appendColumns(receiver_fixed[0..3], expected_fixed, 10);
    appendColumns(receiver_fixed[3..6], expected_table.fixed, 8);
    var fixed_scheme = try Scheme.init(a, config);
    defer fixed_scheme.deinit(a);
    var scratch_channel = Channel{};
    try fixed_scheme.commit(a, &receiver_fixed, &scratch_channel);
    var roots = try fixed_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var replay = Channel{};
    config.mixInto(&replay);
    replay.mixU32s(&.{ 0x48544552, 10, 8 });
    const commitments = proof.commitment_scheme_proof.commitments.items;
    try verifier.commit(a, commitments[0], &.{ 10, 10, 10, 8, 8, 8 }, &replay);
    try verifier.commit(a, commitments[1], &.{ 10, 8 }, &replay);
    const receiver_alpha = replay.drawSecureFelt();
    try std.testing.expect(receiver_alpha.eql(alpha));
    try std.testing.expect(consumer.claim.add(table_claim).isZero());
    replay.mixFelts(&.{ consumer.claim, table_claim });
    try verifier.commit(a, commitments[2], &.{ 10, 10, 10, 10, 10, 10, 10, 10, 8, 8, 8, 8, 8, 8, 8, 8 }, &replay);
    var receiver_rom = rom;
    if (tamper == .terminal_claim) receiver_rom.claim = receiver_rom.claim.add(Q.one());
    if (tamper == .previous_sample) {
        const sample = &proof.commitment_scheme_proof.sampled_values.items[2][12][1];
        sample.* = sample.add(Q.one());
    }
    const receiver_components = [_]core.air.components.Component{ cpu.asVerifierComponent(), receiver_rom.asVerifierComponent() };
    owns_proof = false;
    if (tamper == .none) {
        try core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, proof);
    } else {
        try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, proof));
    }
}

test "one PCS FRI transaction closes log10 consumer against log8 byte provider" {
    try mixedProof(.none);
}
test "heterogeneous proof rejects previous-prefix sample corruption" {
    try mixedProof(.previous_sample);
}
test "heterogeneous proof rejects substituted terminal claim" {
    try mixedProof(.terminal_claim);
}

const tables = rv.providers.tables;
const table_component = rv.providers.table_component;
fn typedProviderProof(kind: tables.Kind, tamper: bool) !void {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 12) };
    var setup = try tables.Setup.init(a, kind);
    defer setup.deinit();
    const counts = try a.alloc(u64, kind.size());
    defer a.free(counts);
    @memset(counts, 0);
    // Expected receiver reads are public and derive the target rational sum.
    const read_rows = [_]usize{ 0, 17, 17, kind.size() - 1 };
    for (read_rows) |row| counts[row] += 1;
    var request = try tables.Request.init(a, &setup, counts);
    defer request.deinit();
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    var channel = Channel{};
    config.mixInto(&channel);
    channel.mixU32s(&.{ 0x54595045, @intFromEnum(kind) });
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    const main = try request.mainColumns(a);
    defer a.free(main);
    try scheme.commit(a, fixed, &channel);
    try scheme.commit(a, main, &channel);
    const challenges = tables.Challenges.draw(&channel);
    const claim = try request.generateInteraction(challenges);
    var expected_claim = Q.zero();
    for (read_rows) |row| {
        const tuple = kind.tupleAt(row);
        var secure_tuple: [tables.MAX_ARITY]Q = undefined;
        for (&secure_tuple, tuple) |*value, input| value.* = Q.fromBase(M.fromCanonical(input));
        expected_claim = expected_claim.sub(try challenges.denominator(secure_tuple[0..kind.arity()]).inv());
    }
    try std.testing.expect(expected_claim.eql(claim));
    channel.mixFelts(&.{claim});
    const interaction = try request.interactionColumns(a);
    defer a.free(interaction);
    try scheme.commit(a, interaction, &channel);
    const component = table_component.Component{ .kind = kind, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .claim = expected_claim };
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &components, &channel, scheme);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    // Fresh receiver preprocessing comes only from the table identity.
    var receiver_setup = try tables.Setup.init(a, kind);
    defer receiver_setup.deinit();
    const receiver_fixed = try receiver_setup.fixedColumns(a);
    defer a.free(receiver_fixed);
    var fixed_scheme = try Scheme.init(a, config);
    defer fixed_scheme.deinit(a);
    var root_channel = Channel{};
    try fixed_scheme.commit(a, receiver_fixed, &root_channel);
    var roots = try fixed_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var replay = Channel{};
    config.mixInto(&replay);
    replay.mixU32s(&.{ 0x54595045, @intFromEnum(kind) });
    const fixed_logs = try a.alloc(u32, kind.arity() + 2);
    defer a.free(fixed_logs);
    @memset(fixed_logs, kind.logSize());
    const commitments = proof.commitment_scheme_proof.commitments.items;
    try verifier.commit(a, commitments[0], fixed_logs, &replay);
    try verifier.commit(a, commitments[1], &.{kind.logSize()}, &replay);
    const receiver_challenges = tables.Challenges.draw(&replay);
    try std.testing.expect(std.meta.eql(challenges, receiver_challenges));
    replay.mixFelts(&.{expected_claim});
    const interaction_logs: [8]u32 = @splat(kind.logSize());
    try verifier.commit(a, commitments[2], &interaction_logs, &replay);
    if (tamper) {
        const sample = &proof.commitment_scheme_proof.sampled_values.items[0][2][0];
        sample.* = sample.add(Q.one());
    }
    const receiver_components = [_]core.air.components.Component{component.asVerifierComponent()};
    owns_proof = false;
    if (tamper) {
        try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, proof));
    } else {
        try core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, proof);
    }
}
test "AND65536 provider proves membership with independently derived preprocessing" {
    try typedProviderProof(.byte_and, false);
}
test "shift2048 provider proves membership with independently derived preprocessing" {
    try typedProviderProof(.byte_shift, false);
}
test "typed provider proof rejects substituted lookup tuple sample" {
    try typedProviderProof(.byte_shift, true);
}
