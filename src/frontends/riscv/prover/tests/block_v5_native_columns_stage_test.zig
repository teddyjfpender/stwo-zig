//! Real runner -> stored native cells -> independently pinned physical roots.
//! This test commits witnesses; it neither proves segments nor benchmarks.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../../runner/mod.zig");
const fixture = @import("../../runner/guest_precompile/test_elf.zig");
const Public = @import("../blake3_segment_public.zig");
const Native = @import("../blake3_execution_trace.zig");
const Root = @import("../block_v5_cpu_native_root_proposal_v1.zig");
const Stage = @import("../block_v5_native_columns_stage_v1.zig");
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
const limits = Stage.Limits{ .columns = .{ .max_columns = 1024, .max_log_size = 22, .max_file_bytes = 64 << 20, .max_loaded_bytes = 64 << 20 }, .max_public_words = 1024, .max_public_bytes = 64 << 10 };

test "native staged columns reconstruct real opcode aliases counters and original roots" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00700293, 0x00328313, 0x005302b3, 0x0000006f };
    const elf = fixture.buildReleaseProgram(instructions.len, &instructions, 64, profile);
    var session = try Runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segment = try session.startSegment(3);
    defer segment.deinit();
    var io = try Public.Owned.init(a, &segment.base);
    defer io.deinit();
    // Explicit independent public pin for this physical-only native gate; ROM
    // authority is deliberately outside its scope and is not claimed here.
    io.data.program_root = .{ .bytes = @splat(7) };
    const owner = try Native.Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, 0);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var proposal = try Root.ForBackend(Cpu).collect(a, owner, config, profile, 0, segment.base.global_first_cycle, .{ .max_public_words = 1024, .max_metadata_bytes = 1 << 20 });
    defer proposal.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const pin = try Stage.write(a, temporary.dir, "native.columns", owner, &proposal, limits);
    var loaded = try Stage.ForBackend(Cpu).load(a, temporary.dir, "native.columns", &proposal, pin, limits, profile);
    defer loaded.deinit(a);
    try std.testing.expectEqualDeep(proposal.roots, loaded.first.roots);
    try std.testing.expect(loaded.owner.native_only_v5 and !loaded.owner.interaction_ready);
    var at: usize = 0;
    for (loaded.owner.statement.component_descs[0..loaded.owner.statement.n_components], 0..) |desc, index| {
        const component = &loaded.owner.opcode_columns.components[index];
        for (component.columns[0..desc.n_columns], loaded.owner.main.items[at..][0..desc.n_columns]) |values, column|
            try std.testing.expect(values.ptr == column.values.ptr);
        at += desc.n_columns;
    }
    const expected = &owner.opcode_columns.lookup_counters.?;
    const actual = &loaded.owner.opcode_columns.lookup_counters.?;
    for (expected.counters, actual.counters) |left, right| {
        try std.testing.expectEqual(left.values.len, right.values.len);
        for (left.values, right.values) |x, y| try std.testing.expectEqual(x.toU32(), y.toU32());
    }
    // A file's own root field cannot substitute for an independent expected
    // physical root: even a fully rehashed file fails the fresh recommit gate.
    var wrong = proposal;
    wrong.roots[1][0] ^= 1;
    const wrong_pin = try Stage.write(a, temporary.dir, "wrong.columns", owner, &wrong, limits);
    try std.testing.expectError(error.V5StagedNativeRootMismatch, Stage.ForBackend(Cpu).load(a, temporary.dir, "wrong.columns", &wrong, wrong_pin, limits, profile));
}
