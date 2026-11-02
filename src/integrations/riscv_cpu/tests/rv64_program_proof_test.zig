//! Small native provider proof exercises the real composition/OODS/PCS path.
//! Reduced PoW/query settings are test-only, not a production proof profile.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("stwo_cpu_backend").CpuBackend;
const program_air = @import("stwo_riscv_frontend").rv64_air.program;
const rom = program_air.setup;
const provider = program_air.provider;
const compact = program_air.compact;
const C = program_air.component.Component;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const a = std.testing.allocator;
const program = rom.Program{ .base = 0x8765432100001000, .words = &.{ 0x00108093, 0x001080b3, 0xffffffff } };
const reads = [_]u64{ 0x8765432100001000, 0x8765432100001004, 0x8765432100001004 };

fn columns(storage: []const M, log: u32, output: []engine.pcs.ColumnEvaluation) void {
    const n = @as(usize, 1) << @intCast(log);
    for (output, 0..) |*column, i| column.* = .{ .log_size = log, .values = storage[i * n ..][0..n] };
}
fn proveProvider(tamper: bool) !void {
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 12) };
    var setup = try rom.Setup.init(a, program);
    defer setup.deinit();
    var request = try provider.Request.init(a, &setup, &reads);
    defer request.deinit();
    const storage = try setup.compactFixedColumns(a);
    defer a.free(storage);
    var fixed: [compact.COUNT + 2]engine.pcs.ColumnEvaluation = undefined;
    columns(storage, setup.log_size, &fixed);
    var main: [1]engine.pcs.ColumnEvaluation = undefined;
    columns(request.multiplicities, setup.log_size, &main);
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    var channel = Channel{};
    config.mixInto(&channel);
    channel.mixU32s(&.{0x524f4d43});
    try scheme.commit(a, &fixed, &channel);
    try scheme.commit(a, &main, &channel);
    const challenges = compact.draw(&channel);
    const claim = try request.generateInteraction(&setup, challenges);
    channel.mixFelts(&.{claim});
    var interaction: [provider.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    columns(request.interaction, setup.log_size, &interaction);
    try scheme.commit(a, &interaction, &channel);
    const component = C{ .log_size = setup.log_size, .encoding = .compact41, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .claim = claim };
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &components, &channel, scheme);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);

    // Receiver reconstructs program-only preprocessing from expected bytes.
    var receiver = try rom.Setup.init(a, program);
    defer receiver.deinit();
    const receiver_storage = try receiver.compactFixedColumns(a);
    defer a.free(receiver_storage);
    var receiver_columns: [compact.COUNT + 2]engine.pcs.ColumnEvaluation = undefined;
    columns(receiver_storage, receiver.log_size, &receiver_columns);
    var root_scheme = try Scheme.init(a, config);
    defer root_scheme.deinit(a);
    var root_channel = Channel{};
    try root_scheme.commit(a, &receiver_columns, &root_channel);
    var roots = try root_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var replay = Channel{};
    config.mixInto(&replay);
    replay.mixU32s(&.{0x524f4d43});
    const commitments = proof.commitment_scheme_proof.commitments.items;
    const fixed_logs: [compact.COUNT + 2]u32 = @splat(receiver.log_size);
    try verifier.commit(a, commitments[0], &fixed_logs, &replay);
    try verifier.commit(a, commitments[1], &.{receiver.log_size}, &replay);
    const receiver_challenges = compact.draw(&replay);
    var expected_claim = Q.zero();
    for (reads) |pc| {
        const entry = compact.fromRow(&receiver.rows[try receiver.lookup(pc)]);
        const expanded = compact.expand(&entry);
        expected_claim = expected_claim.sub(try receiver_challenges.denominator(&expanded).inv());
    }
    try std.testing.expect(expected_claim.eql(claim));
    replay.mixFelts(&.{expected_claim});
    const interaction_logs: [provider.INTERACTION]u32 = @splat(receiver.log_size);
    try verifier.commit(a, commitments[2], &interaction_logs, &replay);
    if (tamper) {
        const sample = &proof.commitment_scheme_proof.sampled_values.items[0][5][0];
        sample.* = sample.add(Q.one());
    }
    const receiver_component = C{ .log_size = receiver.log_size, .encoding = .compact41, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = receiver_challenges, .claim = expected_claim };
    const receiver_components = [_]core.air.components.Component{receiver_component.asVerifierComponent()};
    owns_proof = false;
    if (tamper) {
        try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, proof));
    } else {
        try core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, proof);
    }
}
test "rv64 compact41 native provider proves against independently derived program preprocessing" {
    try proveProvider(false);
}
test "rv64 compact41 native provider rejects substituted high PC sample" {
    try proveProvider(true);
}
