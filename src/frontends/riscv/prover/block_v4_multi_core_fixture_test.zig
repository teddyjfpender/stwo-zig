//! Two continuous SHA-profile leaves, one memory bus, and a fresh v4 core.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Segment = runner.EthereumShaSegmentResult;
const execution_mod = @import("block_v4_cpu_multi_execution_assembly.zig");
const source_mod = @import("block_v4_multi_core_source_test.zig");
const producer = @import("block_memory_batch_produce_v2.zig");
const capture_mod = @import("block_memory_core_capture_test.zig");
const batch = @import("block_memory_batch_verify_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const shard = @import("block_execution_range_shard_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const roster = @import("block_memory_source_roster_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const manifest = @import("block_commitment_manifest.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const io = @import("../recursion/blake3_public_io.zig");
const Artifact = @import("block_execution_sha_external_artifact_v2.zig");

pub const View = struct {
    config: core.pcs.PcsConfig,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    execution_pins: *const [2]batch.EthereumShaExecutionPin(Cpu),
    public_initial: batch.PublicInitialSource,
    receipts: []const @import("block_execution_sidecar_batch_v2.zig").VerifiedExecutionReceipt,
    segments: *[2]Segment,
    executions: *[2]execution_mod.Execution,
    verified: batch.VerifiedBlockCore,
    core_elapsed_ns: u64,
};

pub fn withFixture(config: core.pcs.PcsConfig, comptime callback: anytype) !void {
    return withVariant(config, true, callback);
}

pub fn withUnpaddedFixture(config: core.pcs.PcsConfig, comptime callback: anytype) !void {
    return withVariant(config, false, callback);
}

fn withVariant(config: core.pcs.PcsConfig, comptime padded: bool, comptime callback: anytype) !void {
    const a = std.testing.allocator;
    var timer = try std.time.Timer.start();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const guest = @import("../runner/guest_precompile/test_elf.zig");
    // Both leaves contain a real opcode-access row as well as precompile
    // callers. A precompile-only leaf remains a separate sidecar coverage gap.
    const instructions = [_]u32{
        0x0010_02b7, // LUI x5, 0x100.
        0x1002_8293, // ADDI x5, x5, 0x100.
        0x0802_8313, // ADDI x6, x5, 128.
        @import("../isa/sha256_compression_v1.zig").encode(5, 6),
        0x0002_8393, // ADDI x7, x5, 0: second leaf opcode access.
        @import("../isa/custom0.zig").encodeKeccakf(5),
        0x0002_8413, // ADDI x8, x5, 0.
        @import("../isa/sha256_compression_v1.zig").encode(5, 6),
        0x0000_006f, // Unretired terminal self-loop.
    };
    const program = if (padded)
        guest.buildProgram(instructions.len, &instructions, 256, .rv32im_zkvm_ethereum_sha_v1)
    else
        guest.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = guest.withReleaseAbi(program.len, &program);
    var session = try runner.EthereumShaExecutionSession.init(
        a,
        &elf,
        .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned },
    );
    defer session.deinit();
    var segments: [2]Segment = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    segments[0] = try session.startSegment(4);
    segment_count += 1;
    if (segments[0].base.isComplete()) return error.ExpectedContinuationAfterFirstSha;
    segments[1] = try session.resumeSegment(segments[0].base.continuation.?, if (padded) 5 else 3);
    segment_count += 1;
    if (!segments[1].base.isComplete()) return error.ExpectedTerminalSecondSegment;

    var executions: [2]execution_mod.Execution = undefined;
    var execution_count: usize = 0;
    defer for (executions[0..execution_count]) |*item| item.deinit();
    for (&executions, &segments, 0..) |*item, *segment, i| {
        item.* = try execution_mod.Execution.initForFixture(a, segment, @intCast(i), config);
        execution_count += 1;
    }
    var source = try source_mod.Source.init(a, tmp.dir, &segments);
    defer source.deinit();
    const event_count = source.replay.spooler.event_count;
    var opcode_counts: [2]u64 = undefined;
    var external_counts: [2]u64 = undefined;
    var seen: u64 = 0;
    for (&executions, 0..) |*item, i| {
        opcode_counts[i] = item.opcodeCount();
        external_counts[i] = try item.externalCount();
        seen = try std.math.add(u64, seen, opcode_counts[i] + external_counts[i]);
    }
    try std.testing.expectEqual(event_count, seen);

    var replay_source = capture_mod.Source{ .replay = &source.replay };
    var memory_first = try producer.collectFirstPass(Cpu, a, replay_source.asSource(), event_count, 1 << 12, 8, config);
    defer memory_first.deinit();
    const data_first = &executions[0].owner.native.statement.public_data;
    const data_last = &executions[1].owner.native.statement.public_data;
    const source_files = source.files();
    const rw_digest = try fallback.digestRoster(source.pin, source_files);
    const source_entries = [_]roster.Entry{
        .{ .family = .public_rw_fallback, .index = 0, .digest = rw_digest },
        .{ .family = .program, .index = 0, .digest = roster.programDescriptor(data_first.program_root.?.bytes) },
        .{ .family = .hash, .index = 0, .digest = roster.hashDescriptor(0, executions[0].prepared.plan_id, executions[0].prepared.id) },
        .{ .family = .hash, .index = 1, .digest = roster.hashDescriptor(1, executions[1].prepared.plan_id, executions[1].prepared.id) },
    };
    const source_digest = try roster.digest(&source_entries);
    var opcode_plan = try shard.plan(a, &opcode_counts);
    defer opcode_plan.deinit(a);
    var external_plan = try shard.plan(a, &external_counts);
    defer external_plan.deinit(a);
    var opcode_counter = try mergeCounters(a, &executions, false);
    defer opcode_counter.deinit(a);
    var external_counter = try mergeCounters(a, &executions, true);
    defer external_counter.deinit(a);
    const table_api = table.ForBackend(Cpu);
    var opcode_table_first = try table_api.commitFirstRound(a, &opcode_counter, opcode_plan.shards[0], config);
    defer opcode_table_first.deinit(a);
    var external_table_first = try table_api.commitFirstRound(a, &external_counter, external_plan.shards[0], config);
    defer external_table_first.deinit(a);

    const memory_pins = try a.alloc(batch.MemoryPin, memory_first.claims.len);
    defer a.free(memory_pins);
    for (memory_pins, memory_first.claims, memory_first.memory_roots) |*pin, claim, roots| pin.* = .{ .claim = claim, .roots = roots };
    var native_roots: [2]batch.Roots = undefined;
    var opcode_witness_roots: [2]batch.Roots = undefined;
    var external_roots: [2]seal_mod.FirstRoundEntry = undefined;
    for (&executions, 0..) |*item, i| {
        native_roots[i] = item.nativeRoots();
        opcode_witness_roots[i] = .{ item.opcodeWitnessRoot(), @splat(0) };
        external_roots[i] = .{ .family = .execution_extension_witness, .index = @intCast(i), .roots = .{ item.externalWitnessRoot().?, @splat(0) } };
    }
    const opcode_table_roots = [_]batch.Roots{opcode_table_first.roots};
    const external_table_roots = [_]batch.Roots{external_table_first.roots};
    const anchor = source.pin.initial_rw_root;
    const entry = try span.MachineState.init(data_first.initial_pc, data_first.initial_regs, anchor, .{ .bytes = @splat(0) });
    const exit_state = try span.MachineState.init(data_last.final_pc, data_last.final_regs, anchor, .{ .bytes = @splat(0) });
    const total_cycles = segments[1].base.global_first_cycle - 1 + segments[1].base.cycle_count;
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), data_first.program_root.?, entry, exit_state, try io.input(data_first), try io.output(data_last), total_cycles);
    const job = try span.JobContext.init(complete, 2);
    const leaf_statements = [_]span.SpanStatement{
        try v3.leaf(job, &segments[0].base),
        try v3.leaf(job, &segments[1].base),
    };
    const base = manifest.Sealed{ .digest = @splat(41), .instance_count = 2 };
    var statement = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, source.register_mask, source_digest),
        .expected_events = event_count,
        .memory_instances = memory_pins,
        .range_table_roots = memory_first.table_roots,
        .execution_roots = &native_roots,
        .execution_sidecar_roots = &opcode_witness_roots,
        .execution_active_counts = &opcode_counts,
        .execution_range_table_roots = &opcode_table_roots,
        .execution_extension_roots = &external_roots,
        .execution_extension_active_counts = &external_counts,
        .execution_extension_range_table_roots = &external_table_roots,
        .provider_roots = &.{},
        .complete_pins = .{ .expected_job = job, .initial_rw_anchor = anchor.bytes, .program_root = data_first.program_root.?.bytes, .outer_recursive_key_id = @splat(1), .forest_roster_digest = @splat(2) },
    };
    statement.seal = try seal_mod.SourceSeal.initBoundWithExtension(
        base,
        source.register_mask,
        source_digest,
        2,
        @intCast(memory_pins.len),
        memory_first.plan.digest,
        try statement.firstRoundDigest(a),
        external_plan.digest,
    );

    var capture = try capture_mod.Capture.init(a, memory_pins.len, memory_first.table_roots.len);
    defer capture.deinit();
    try producer.proveSecondPass(Cpu, a, replay_source.asSource(), &memory_first, statement, config, capture.sink());
    for (&executions) |*item| try item.prove(statement.seal, &pool);
    var opcode_table_proof = try table_api.prove(a, &opcode_table_first, &opcode_counter, opcode_plan.shards[0], statement.seal, opcode_table_roots[0]);
    defer opcode_table_proof.deinit(a);
    var external_table_proof = try table_api.prove(a, &external_table_first, &external_counter, external_plan.shards[0], statement.seal, external_table_roots[0]);
    defer external_table_proof.deinit(a);
    const opcode_table_wire = [_]batch.SerializedTableProof{.{ .stark_bytes = try capture.encode(opcode_table_proof.stark), .claim = opcode_table_proof.claim }};
    const external_table_wire = [_]batch.SerializedTableProof{.{ .stark_bytes = try capture.encode(external_table_proof.stark), .claim = external_table_proof.claim }};
    var execution_wire: [2]@import("block_execution_batch_receiver_v2.zig").Wire = undefined;
    var extension_wire: [2]batch.SerializedExternalProof = undefined;
    var execution_pins: [2]batch.EthereumShaExecutionPin(Cpu) = undefined;
    for (&executions, 0..) |*item, i| {
        execution_wire[i] = item.opcodeWire();
        extension_wire[i] = item.externalWire(@intCast(i)).?;
        execution_pins[i] = .{ .prepared = item.prepared, .expected_key_id = item.prepared.id, .statement = leaf_statements[i] };
    }
    const wire = batch.SerializedBatch{
        .memory = capture.memories,
        .range_tables = capture.tables,
        .execution_range_tables = &opcode_table_wire,
        .execution = &execution_wire,
        .execution_extensions = &extension_wire,
        .execution_extension_range_tables = &external_table_wire,
        .initial_sources = &.{},
    };
    const public_initial = batch.PublicInitialSource{
        .pin = source.pin,
        .registers = segments[0].base.entry_cpu.regs,
        .files = source_files,
        .roster = &source_entries,
    };
    var verified = try batch.verifyCoreOwnedWithExtension(Cpu, a, statement, wire, &execution_pins, public_initial, config);
    defer verified.deinit(a);
    try std.testing.expectEqual(event_count, verified.summary.event_count);
    try callback(a, View{
        .config = config,
        .statement = statement,
        .wire = wire,
        .execution_pins = &execution_pins,
        .public_initial = public_initial,
        .receipts = verified.executions,
        .segments = &segments,
        .executions = &executions,
        .verified = verified.summary,
        .core_elapsed_ns = timer.read(),
    });
}

fn mergeCounters(a: std.mem.Allocator, executions: *[2]execution_mod.Execution, comptime extension: bool) !counter_mod.Counter {
    var result = try counter_mod.Counter.init(a, .range_check_8_8);
    errdefer result.deinit(a);
    for (executions) |*item| {
        const source = if (extension) item.externalCounter().? else item.opcodeCounter();
        if (source.values.len != result.values.len) return error.InvalidExecutionRangeCounter;
        for (result.values, source.values) |*value, addend| value.* = value.add(addend);
    }
    return result;
}

test "block-v4 two precompile segments fresh verify one execution memory core" {
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const callback = struct {
        fn check(_: std.mem.Allocator, view: View) !void {
            try std.testing.expectEqual(@as(usize, 2), view.receipts.len);
            try std.testing.expect(view.statement.execution_extension_active_counts[0] > 0);
            try std.testing.expect(view.statement.execution_extension_active_counts[1] > 0);
        }
    };
    try withFixture(config, callback.check);
}
