const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Segment = @import("block_execution_sha_external_artifact_v2.zig");
const Receiver = @import("block_execution_external_receiver_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");

test "block-v4 external SHA Keccak sidecar freshly proves 103 native-root accesses" {
    try checkExternalFixture(false);
}

test "block-v4 external signer Keccak sidecar freshly proves native-root accesses" {
    try checkExternalFixture(true);
}

fn checkExternalFixture(comptime with_signer: bool) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = if (with_signer)
        fixture.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1)
    else
        fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(if (with_signer) 100 else 16);
    defer run.deinit();
    var owner = try Profile.Witness.initCompactRun(a, &run);
    defer owner.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const NativeApi = Native.ForBackend(Cpu);
    const prepared = try NativeApi.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement,
        try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();
    const data = &owner.native.statement.public_data;
    const frame = @import("../air/block/memory_event.zig").Frame{
        .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = data.clock };
    var first = try Segment.ForBackend(Cpu).init(a, &owner, prepared, frame, 0, config);
    defer first.deinit();
    const expected: u64 = if (with_signer) 94 else 103;
    try std.testing.expectEqual(expected, try first.externalEventCount());
    try std.testing.expectEqual(@as(u32, @intCast(expected * 14)), first.externalCounter().signedTotal().toU32());
    if (with_signer) {
        try std.testing.expectEqual(@as(usize, 1), run.extension.signer_recovery_calls.len());
        const pair_source = @import("block_execution_access_bridge_v2.zig");
        const Key = struct { space: u1, address: u32, clock: u32, after: u32 };
        var recorded = std.AutoHashMap(Key, u32).init(a);
        defer recorded.deinit();
        for (run.base.state_chain_tracker.accesses.items) |access| {
            const entry = try recorded.getOrPut(.{ .space = access.addr_space, .address = access.addr, .clock = access.clk, .after = access.value });
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
        for (first.traces) |*trace| {
            for (0..trace.domainSize()) |logical| {
                const pair = try pair_source.decodePair(try trace.pairAt(logical));
                if (!pair.active) continue;
                const address = if (pair.space == 0) pair.source_address else try std.math.mul(u32, pair.source_address, 4);
                const key = Key{ .space = pair.space, .address = address, .clock = pair.local_clock, .after = pair.after };
                const count = recorded.getPtr(key) orelse return error.ExternalAccessMissingFromRunner;
                if (count.* == 0) return error.ExternalAccessDuplicatedAgainstRunner;
                count.* -= 1;
            }
        }
        var remaining: u64 = 0;
        var values = recorded.valueIterator();
        while (values.next()) |count| remaining += count.*;
        try std.testing.expectEqual(first.opcodeEventCount(), remaining);
    }
    const entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .execution, .index = 0, .roots = first.nativeRoots() },
        .{ .family = .execution_sidecar_witness, .index = 0, .roots = .{ first.opcodeWitnessRoot(), @splat(0) } },
        .{ .family = .execution_extension_witness, .index = 0, .roots = .{ first.externalWitnessRoot(), @splat(0) } },
    };
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(44), .instance_count = 1 };
    const sealed = try seal_mod.SourceSeal.initBoundWithExtension(base, 0, @splat(45), 1, 1,
        @splat(46), seal_mod.digestFirstRoundRoster(&entries), @splat(47));
    var serialized = try first.proveAndSerialize(&owner, prepared, sealed, &pool);
    defer serialized.deinit(a);
    const span = @import("../recursion/span_statement_blake3.zig");
    const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
    const io = @import("../recursion/blake3_public_io.zig");
    const anchor = data.initial_rw_root.?;
    const entry = try span.MachineState.init(data.initial_pc, data.initial_regs, anchor, .{ .bytes = @splat(0) });
    const exit_state = try span.MachineState.init(data.final_pc, data.final_regs, anchor, .{ .bytes = @splat(0) });
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), data.program_root.?, entry,
        exit_state, try io.input(data), try io.output(data), data.clock);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, data.clock, entry, exit_state,
        .{ .digest = try io.input(data) }, .{ .digest = try io.output(data) });
    const statement = try span.SpanStatement.segmentLeaf(job, 0, executed);
    var receipt = try Receiver.ForEthereumShaBackend(Cpu).verify(a,
        serialized.externalWire(), prepared, prepared.id, statement, sealed, 0, first.externalWitnessRoot(), config);
    defer receipt.deinit(a);
    try std.testing.expectEqual(expected, receipt.event_count);
    try std.testing.expect(!receipt.transition_sum.isZero());
    try std.testing.expectError(error.UntrustedExternalFirstRound,
        Receiver.ForEthereumShaBackend(Cpu).verify(a, serialized.externalWire(),
            prepared, prepared.id, statement, sealed, 0, @splat(99), config));
}
