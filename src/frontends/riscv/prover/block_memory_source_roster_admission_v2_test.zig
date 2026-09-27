const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const sha = @import("blake3_ethereum_sha_proof.zig");
const admission = @import("block_memory_source_roster_admission_v2.zig");
const roster = @import("block_memory_source_roster_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");

test "Ethereum SHA prepared keys independently pin program and hash source descriptors" {
    const a = std.testing.allocator;
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    var owner = try profile.Witness.initRun(a, &run);
    defer owner.deinit();
    const Api = sha.ForBackend(Cpu);
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const prepared = try Api.PreparedVerifier.init(a, &owner.native.statement, owner.statement, try owner.admission(), config);
    defer prepared.deinit();
    const program_root = owner.native.statement.public_data.program_root.?.bytes;
    const pin = admission.EthereumShaPin(Cpu){ .prepared = prepared, .expected_key_id = prepared.id };
    const pins = [_]admission.EthereumShaPin(Cpu){pin};
    const rw_digest: [32]u8 = @splat(90);
    var entries = [_]roster.Entry{
        .{ .family = .public_rw_fallback, .index = 0, .digest = rw_digest },
        .{ .family = .program, .index = 0, .digest = roster.programDescriptor(program_root) },
        .{ .family = .hash, .index = 0, .digest = roster.hashDescriptor(0, prepared.plan_id, prepared.id) },
    };
    const aggregate = try roster.digest(&entries);
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(91), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, aggregate, 1, 1, @splat(92), @splat(93));
    try admission.admitEthereumSha(Cpu, a, seal, &entries, rw_digest, program_root, &pins, config);
    var bad_root = program_root;
    bad_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedPreparedProgramRoot, admission.admitEthereumSha(Cpu, a, seal, &entries, rw_digest, bad_root, &pins, config));
    entries[2].digest[0] ^= 1;
    try std.testing.expectError(error.InvalidPinnedSourceDescriptors, admission.admitEthereumSha(Cpu, a, seal, &entries, rw_digest, program_root, &pins, config));
    entries[2].digest[0] ^= 1;
    var bad_pin = pins;
    bad_pin[0].expected_key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, admission.admitEthereumSha(Cpu, a, seal, &entries, rw_digest, program_root, &bad_pin, config));
}
