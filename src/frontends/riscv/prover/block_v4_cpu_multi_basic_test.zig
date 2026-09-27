const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const Replay = @import("block_memory_replay.zig").Replay;
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const io = @import("../recursion/blake3_public_io.zig");
const assembly = @import("block_v4_cpu_multi_segment_assembly.zig");

test "block-v4 CPU multi assembler stages and fresh verifies two real precompile leaves" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pin_tmp = std.testing.tmpDir(.{});
    defer pin_tmp.cleanup();
    const guest = @import("../runner/guest_precompile/test_elf.zig");
    const program = guest.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = guest.withReleaseAbi(program.len, &program);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var segments: [2]runner.EthereumShaSegmentResult = undefined;
    segments[0] = try session.startSegment(4);
    defer segments[0].deinit();
    segments[1] = try session.resumeSegment(segments[0].base.continuation.?, 3);
    defer segments[1].deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var owners: [2]Profile.Witness = undefined;
    var owner_count: usize = 0;
    defer for (owners[0..owner_count]) |*owner| owner.deinit();
    var keys: [2][32]u8 = undefined;
    for (&owners, &segments, &keys) |*owner, *segment, *key| {
        owner.* = try Profile.Witness.initCompactSegment(a, segment);
        owner_count += 1;
        const prepared = try Native.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
        key.* = prepared.id;
        prepared.deinit();
    }
    var pin_replay = try Replay.initFromSnapshot(a, pin_tmp.dir, segments[0].base.entry_cpu.regs, &segments[0].base.rw_memory, 256);
    defer pin_replay.deinit();
    const anchor = try pin_replay.initialRwRoot();
    const first = &owners[0].native.statement.public_data;
    const last = &owners[1].native.statement.public_data;
    const entry = try span.MachineState.init(first.initial_pc, first.initial_regs, anchor, .{ .bytes = @splat(0) });
    const exit = try span.MachineState.init(last.final_pc, last.final_regs, anchor, .{ .bytes = @splat(0) });
    const cycles = segments[1].base.global_first_cycle - 1 + segments[1].base.cycle_count;
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), first.program_root.?, entry, exit, try io.input(first), try io.output(last), cycles);
    const job = try span.JobContext.init(complete, 2);
    const trusted = assembly.Trusted{ .job = job, .base_seal = .{ .digest = @splat(41), .instance_count = 2 }, .native_key_ids = &keys, .outer_key_id = @splat(1), .forest_roster_digest = @splat(2) };
    const callback = struct {
        fn verify(view: assembly.View) !void {
            try std.testing.expectEqual(@as(usize, 2), view.metrics.segments);
            try std.testing.expectEqual(@as(u64, 0), view.statement.execution_active_counts[1]);
            try std.testing.expectEqual(@as(usize, 2), view.receipts.len);
            try std.testing.expect(view.metrics.stark_payload_bytes > 0);
            std.debug.print("BLOCK_V4_MULTI_ASSEMBLY verified=true segments={d} events={d} external={d} memory_instances={d} staged_payload_bytes={d} elapsed_ns={d}\n", .{ view.metrics.segments, view.metrics.execution_events, view.metrics.external_events, view.metrics.memory_instances, view.metrics.stark_payload_bytes, view.metrics.elapsed_ns });
        }
    };
    try assembly.withAssembledSegments(a, tmp.dir, &pool, &segments, trusted, config, .{ .memory_instance_capacity = 1 << 12, .spool_chunk_events = 256 }, null, callback.verify);
}
