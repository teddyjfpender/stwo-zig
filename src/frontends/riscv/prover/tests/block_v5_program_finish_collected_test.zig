const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const programs = @import("../block_v5_program_first_round_v1.zig");
const tables = @import("../block_v5_program_table_proof_v1.zig");
const execution = @import("../block_v5_cpu_execution_source_v1.zig");
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

test "block-v5 program census reuses collected ROM roots without another commitment" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, profile);
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    var segment_owned = true;
    defer if (segment_owned) segment.deinit();
    var rom = try @import("../../air/program/blake3_commitment.zig").buildDeclared(a, @as(@import("../../air/program/commitment.zig").DeclaredDecodeAuthority, .{ .profile = profile }), .{}, segment.base.rw_memory.program_words, null);
    defer rom.deinit();
    segment_owned = false; // Current.init consumes it on success and error.
    const current = try execution.Current.init(a, segment, rom.root);
    defer current.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var native = try @import("../block_v5_cpu_native_root_proposal_v1.zig").ForBackend(Cpu).collect(a, current.owner, config, profile, 0, 1, .{ .max_public_words = 1024, .max_metadata_bytes = 1024 * 1024 });
    defer native.deinit();
    const fetches = try execution.fetches(a, current, false);
    defer a.free(fetches);
    var reused = try programs.ForBackend(Cpu).init(a, rom.root, rom.leaves, 1);
    defer reused.deinit();
    var default = try programs.ForBackend(Cpu).init(a, rom.root, rom.leaves, 1);
    defer default.deinit();
    const instance: [32]u8 = @splat(91); // Proposal binding only; no receipt.
    for ([_]*programs.ForBackend(Cpu){ &reused, &default }) |collector| {
        try collector.addLightweight(fetches, &native.shape, native.template_id, instance, native.roots, native.roots);
        try collector.addLightweightExtension(0, fetches, &.{}, 0, null);
    }
    const expected_fetches = reused.census.total_fetches;
    const plan = try reused.census.smallestTablePlan(1, expected_fetches);
    var physical = try tables.ForBackend(Cpu).commitFirstRound(a, plan, config);
    defer physical.deinit(a);
    const entry = @import("../block_v5_source_seal_v1.zig").Entry{ .family = .program, .index = 0, .instance_id = try tables.instanceId(plan), .roots = physical.roots };
    var changed = entry;
    changed.family = .memory;
    try std.testing.expectError(error.UntrustedV5CollectedProgramPlan, reused.finishCollected(expected_fetches, config, changed));
    changed = entry;
    changed.index = 1;
    try std.testing.expectError(error.UntrustedV5CollectedProgramPlan, reused.finishCollected(expected_fetches, config, changed));
    changed = entry;
    changed.instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CollectedProgramPlan, reused.finishCollected(expected_fetches, config, changed));
    changed = entry;
    changed.roots[1] = @splat(0);
    try std.testing.expectError(error.UntrustedV5CollectedProgramRoots, reused.finishCollected(expected_fetches, config, changed));
    try std.testing.expect(reused.table_roots == null and reused.config == null and reused.expected_fetches == null);
    reused.extension_recorded[0] = false;
    try std.testing.expectError(error.IncompleteV5ProgramExtensionCensus, reused.finishCollected(expected_fetches, config, entry));
    reused.extension_recorded[0] = true;
    reused.extension_next = 1;
    try std.testing.expectError(error.IncompleteV5ProgramExtensionCensus, reused.finishCollected(expected_fetches, config, entry));
    reused.extension_next = 0;
    try std.testing.expectError(error.IncompleteV5ProgramCensus, reused.finishCollected(expected_fetches + 1, config, entry));
    const accepted = try reused.finishCollected(expected_fetches, config, entry);
    const original = try default.finish(expected_fetches, config);
    try std.testing.expectEqualDeep(original, accepted);
    try std.testing.expectEqualDeep(default.table_roots, reused.table_roots);
    try std.testing.expectEqualDeep(default.config, reused.config);
    try std.testing.expectEqual(default.expected_fetches, reused.expected_fetches);
    try std.testing.expectEqualDeep(default.executionEntries(), reused.executionEntries());
    try std.testing.expectEqualDeep(default.requestEntries(), reused.requestEntries());
    try std.testing.expectError(error.IncompleteV5ProgramFirstRound, reused.finishCollected(expected_fetches, config, entry));
}
