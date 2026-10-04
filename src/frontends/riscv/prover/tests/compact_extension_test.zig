const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../../runner/mod.zig");
test "compact range provider Ethereum and guest Poseidon witness admission" {
    try run(false, false);
}
test "compact range provider extension STARKs independently verify" {
    run(true, false) catch |err| {
        std.debug.print("COMPACT_EXTENSION_ERROR {s}\n", .{@errorName(err)});
        return err;
    };
}
test "compact range provider extension canonical recursive parents verify" {
    run(true, true) catch |err| {
        std.debug.print("COMPACT_EXTENSION_PARENT_ERROR {s}\n", .{@errorName(err)});
        return err;
    };
}
fn run(comptime prove: bool, comptime recurse: bool) !void {
    const a = std.testing.allocator;
    const fixture = @import("../../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumWithCompletion(.self_loop);
    const ethereum_elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var ethereum = try runner.runEthereumExtensionWithInput(a, &ethereum_elf, &.{}, 100);
    defer ethereum.deinit();
    var ethereum_witness = try @import("../blake3_ethereum_witness.zig").Owner.initCompactRun(a, &ethereum);
    defer ethereum_witness.deinit();
    try std.testing.expectEqual(@as(usize, 1), ethereum.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 1), ethereum.keccakf_calls.len());
    try check(@import("../blake3_ethereum_profile.zig"), &ethereum_witness);
    if (prove) try checkProof(@import("../blake3_ethereum_profile.zig"), .rv32im_zkvm_ethereum_v1, &ethereum_witness, &ethereum_elf, recurse);
    const instructions = [_]u32{ 0x0010_02b7, 0x1002_8293, @import("../../isa/custom0.zig").encodePoseidon2(5), 0x0010_0537, 0x0005_2223, 0x0000_006f };
    const poseidon_elf = fixture.buildReleaseProgram(instructions.len, &instructions, 64, .rv32im_zkvm_poseidon2_v1);
    var poseidon = try runner.runPoseidon2ExtensionWithInput(a, &poseidon_elf, &.{}, 100);
    defer poseidon.deinit();
    var poseidon_witness = try @import("../blake3_poseidon_witness.zig").Owner.initCompactRun(a, &poseidon);
    defer poseidon_witness.deinit();
    try std.testing.expectEqual(@as(u32, 1), poseidon_witness.statement.counts.n_guest);
    try check(@import("../blake3_poseidon_profile.zig"), &poseidon_witness);
    if (prove) try checkProof(@import("../blake3_poseidon_profile.zig"), .rv32im_zkvm_poseidon2_v1, &poseidon_witness, &poseidon_elf, recurse);
}
fn check(comptime Profile: type, owner: *Profile.Witness) !void {
    const ranges = owner.native.compact_ranges orelse return error.MissingCompactProviders;
    const Contract = @import("../compact_extension_contract.zig").ForProfile(Profile);
    const contract = Contract{ .native = &owner.native.statement, .extension = &owner.statement, .ranges = ranges.plan };
    const pin = try owner.admission();
    const bound = try contract.validate(pin, owner.hashes.logs);
    const index = @intFromEnum(@import("../../air/lookups/tables/schema.zig").Kind.range_check_8_8);
    try std.testing.expectEqual(owner.statement.admission.extended_fixed_table_bounds[index] + try ranges.plan.additionalByteTerms(), bound);
    const config: core.pcs.PcsConfig = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
    var compact = core.channel.blake3.Channel{};
    var original = core.channel.blake3.Channel{};
    try contract.mix(&compact, config, pin, owner.hashes.logs);
    try Profile.protocol.mix(&original, config, &owner.native.statement, &owner.statement, pin, owner.hashes.logs);
    try std.testing.expect(!std.mem.eql(u8, &compact.digestBytes(), &original.digestBytes()));
    const key = try contract.identity(config, pin, owner.hashes.logs, @splat(0));
    const old_key = try Profile.protocol.identity(config, &owner.native.statement, &owner.statement, pin, owner.hashes.logs, @splat(0));
    try std.testing.expect(!std.mem.eql(u8, &key, &old_key));
    var invalid = owner.statement;
    invalid.admission.extended_fixed_table_bounds[index] += 1;
    const bad = Contract{ .native = &owner.native.statement, .extension = &invalid, .ranges = ranges.plan };
    const saved = compact.digestBytes();
    try std.testing.expectError(error.AdmissionCertificateMismatch, bad.mix(&compact, config, pin, owner.hashes.logs));
    try std.testing.expectEqual(saved, compact.digestBytes());
}

fn checkProof(comptime Profile: type, comptime profile: @import("../../isa/execution_profile.zig").ExecutionProfile, owner: *Profile.Witness, elf: []const u8, comptime recurse: bool) !void {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = @import("../blake3_extension_proof.zig").ForProfile(Profile);
    const backend = api.ForBackend(Cpu);
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    const config: core.pcs.PcsConfig = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
    const prepared = try backend.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();
    var proved = try backend.prove(a, owner, prepared, prepared.id, &pool);
    defer proved.proof.deinit(a);
    const encoded = try api.codec.encode(a, &proved.proof, prepared, prepared.id);
    defer a.free(encoded);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[8..12], .little));
    const digest = try backend.verifyOwned(a, try api.codec.decode(a, encoded, prepared, prepared.id), prepared, prepared.id);
    try std.testing.expectEqual(proved.transcript_digest, digest);
    var bad = try api.codec.decode(a, encoded, prepared, prepared.id);
    bad.compact_claims[0] = bad.compact_claims[0].add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.UnclosedExecutionRelations, backend.verifyOwned(a, bad, prepared, prepared.id));
    var captured = try backend.verifyCaptureOwned(a, try api.codec.decode(a, encoded, prepared, prepared.id), prepared, prepared.id);
    defer captured.deinit();
    try @import("../blake3_extension_replay_test_support.zig").check(a, prepared, &captured, prepared.id);
    captured.compact_claims[0] = captured.compact_claims[0].add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.InvalidExecutionCapture, captured.validate(prepared, prepared.id));
    captured.compact_claims[0] = captured.compact_claims[0].sub(core.fields.qm31.QM31.one());
    if (recurse) {
        binding.deinit();
        binding_alive = false;
        try @import("../blake3_extension_parent_test_support.zig").check(true, a, prepared, &captured, prepared.id, &pool);
        std.debug.print("COMPACT_EXTENSION_PARENT profile={s} child_queries=70 child_pow_bits=26 parent_queries=70 parent_pow_bits=26 independently_verified=true\n", .{@tagName(profile)});
    }
    const artifact = @import("../blake3_profile_artifact.zig").ForExecutionProfile(profile);
    const published = try artifact.encode(a, &proved.proof, prepared, elf, &.{}, .{});
    defer a.free(published.bytes);
    try std.testing.expectEqual(proved.transcript_digest, try artifact.ForBackend(Cpu).verify(a, published.bytes, published.statement_id, config, elf, &.{}, .{}));
    var wrong_id = published.statement_id;
    wrong_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionManifest, artifact.ForBackend(Cpu).verify(a, published.bytes, wrong_id, config, elf, &.{}, .{}));
    std.debug.print("COMPACT_EXTENSION_PROOF profile={s} queries={d} pow_bits={d} bytes={d} independently_verified=true\n", .{ @tagName(profile), config.fri_config.n_queries, config.pow_bits, encoded.len });
}
