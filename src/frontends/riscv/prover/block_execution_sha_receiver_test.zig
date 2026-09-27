const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Segment = @import("block_execution_sha_artifact_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");

fn qualifyShaProgramSchedule(sparse_program: bool) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    var owner = if (sparse_program)
        try Profile.Witness.initCompactRunSparseProgram(a, &run)
    else try Profile.Witness.initCompactRun(a, &run);
    defer owner.deinit();
    if (sparse_program) {
        try std.testing.expectEqual(@import("blake3_commitment_plan.zig").ProgramSchedule.sparse_active, owner.plan.program_schedule);
        try std.testing.expect(owner.memory.programs.len <= owner.memory.program.rows.len);
    }
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Api = Native.ForBackend(Cpu);
    const prepared = try Api.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();

    const data = &owner.native.statement.public_data;
    const frame = @import("../air/block/memory_event.zig").Frame{
        .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = data.clock,
    };
    var first = try Segment.ForBackend(Cpu).init(a, &owner, prepared, frame, 0, config);
    defer first.deinit();

    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(33), .instance_count = 1 };
    const entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .execution, .index = 0, .roots = first.native_roots },
        .{ .family = .execution_sidecar_witness, .index = 0, .roots = .{ first.witnessRoot(), @splat(0) } },
    };
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(34), 1, 1, @splat(35), seal_mod.digestFirstRoundRoster(&entries));
    var serialized = try first.proveAndSerialize(&owner, prepared, sealed, &pool);
    defer serialized.deinit(a);
    const span = @import("../recursion/span_statement_blake3.zig");
    const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
    const io = @import("../recursion/blake3_public_io.zig");
    const anchor = data.initial_rw_root.?;
    const entry = try span.MachineState.init(data.initial_pc, data.initial_regs, anchor, .{ .bytes = @splat(0) });
    const exit_state = try span.MachineState.init(data.final_pc, data.final_regs, anchor, .{ .bytes = @splat(0) });
    const input_digest = try io.input(data);
    const output_digest = try io.output(data);
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), data.program_root.?, entry, exit_state, input_digest, output_digest, data.clock);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, data.clock, entry, exit_state, .{ .digest = input_digest }, .{ .digest = output_digest });
    const statement = try span.SpanStatement.segmentLeaf(job, 0, executed);
    const Receiver = @import("block_execution_batch_receiver_v2.zig").ForEthereumShaBackend(Cpu);
    var receipt = try Receiver.verify(a, serialized.wire(), prepared, prepared.id, statement, sealed, 0, first.witnessRoot(), config);
    defer receipt.deinit(a);
    try std.testing.expectEqualDeep(first.native_roots, receipt.native_roots);
    try std.testing.expectEqual(first.event_count, receipt.event_count);
    try std.testing.expect(receipt.event_count > 0);
}

test "block-v2 native-root execution sidecar SHA extension fresh receiver" {
    try qualifyShaProgramSchedule(false);
}

test "block-v3 sparse active-program-row SHA extension fresh receiver" {
    try qualifyShaProgramSchedule(true);
}
