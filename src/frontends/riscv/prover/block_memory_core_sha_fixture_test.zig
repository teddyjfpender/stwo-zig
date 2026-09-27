const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Artifact = @import("block_execution_sha_artifact_v2.zig");
const Replay = @import("block_memory_replay.zig").Replay;
const producer = @import("block_memory_batch_produce_v2.zig");
const batch = @import("block_memory_batch_verify_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const execution_shard = @import("block_execution_range_shard_v2.zig");
const external = @import("block_execution_external_trace_v2.zig");
const ExternalArtifact = @import("block_execution_sha_external_artifact_v2.zig");
const roster = @import("block_memory_source_roster_v2.zig");
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const io = @import("../recursion/blake3_public_io.zig");

/// All borrowed fields remain valid only while `withCoherentCoreFixture` is
/// executing its callback. A combined recursion test can reuse the exact
/// serialized native/sidecar and memory/table artifacts without rebuilding
/// a second, subtly different block core.
pub const FixtureView = struct {
    config: core.pcs.PcsConfig,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    execution_pin: batch.EthereumShaExecutionPin(Cpu),
    public_initial: batch.PublicInitialSource,
    verified: batch.VerifiedBlockCore,
    execution_receipt: *const @import("block_execution_sidecar_batch_v2.zig").VerifiedExecutionReceipt,
    owner: *Profile.Witness,
    prepared: *Native.ForBackend(Cpu).PreparedVerifier,
    segment: *@import("../runner/result.zig").EthereumShaSegmentResult,
    pool: *engine.work_pool.WorkPool,
};

const Source = @import("block_memory_core_capture_test.zig").Source;
const Capture = @import("block_memory_core_capture_test.zig").Capture;

pub fn withCoherentCoreFixture(config: core.pcs.PcsConfig, comptime callback: anytype) !void {
    return withCoreFixture(config, false, false, callback);
}

/// Keeps the original SHA/Keccak/SHA calls and their caller memory effects.
/// The callback runs only after the extension-bound core fresh-verifies.
pub fn withExtendedCoreFixture(config: core.pcs.PcsConfig, comptime callback: anytype) !void {
    return withCoreFixture(config, true, false, callback);
}

/// Exercise the signer and Keccak caller relations in the same sorted-memory
/// and first-touch closure as the existing SHA/Keccak fixture.
pub fn withSignerCoreFixture(config: core.pcs.PcsConfig, comptime callback: anytype) !void {
    return withCoreFixture(config, true, true, callback);
}

fn withCoreFixture(config: core.pcs.PcsConfig, comptime with_precompiles: bool, comptime with_signer: bool, comptime callback: anytype) !void {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    var diagnostic = if (with_signer)
        fixture.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1)
    else
        fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    // Exercise the complete receiver's SHA-profile plumbing while the
    // extension-access sidecar is being added. The separate unmodified
    // SHA/Keccak/SHA fixture exposed 103 missing extension access tuples.
    if (!with_precompiles) {
        for (3..6) |instruction| std.mem.writeInt(u32, diagnostic[640 + instruction * 4 ..][0..4], 0x0002_8393, .little); // ADDI x7,x5,0.
    }
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    // The seventh fetch observes the unretired self-loop completion after six
    // retired instructions. A budget of six yields an incomplete segment.
    var segment = try session.startSegment(if (with_signer) 8 else 7);
    defer segment.deinit();
    if (!segment.base.isComplete()) return error.IncompleteShaCoreFixtureSegment;
    var owner = try Profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    const prepared = try Native.ForBackend(Cpu).PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();
    const data = &owner.native.statement.public_data;
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = @intCast(segment.base.cycle_count) };
    var standalone_opcode: Artifact.ForBackend(Cpu) = undefined;
    if (!with_precompiles) standalone_opcode = try Artifact.ForBackend(Cpu).init(a, &owner, prepared, frame, 0, config);
    defer if (!with_precompiles) standalone_opcode.deinit();
    var combined_artifact: ?ExternalArtifact.ForBackend(Cpu) = if (with_precompiles)
        try ExternalArtifact.ForBackend(Cpu).init(a, &owner, prepared, frame, 0, config)
    else
        null;
    defer if (combined_artifact) |*artifact| artifact.deinit();
    const execution_first = if (with_precompiles) &combined_artifact.?.opcode else &standalone_opcode;

    var replay = try Replay.initFromSnapshot(a, tmp.dir, segment.base.entry_cpu.regs, &segment.base.rw_memory, 256);
    defer replay.deinit();
    try replay.append(frame, segment.base.state_chain_tracker.accesses.items);
    var sorted = try replay.finish();
    sorted.deinit();
    const event_count = replay.spooler.event_count;
    const extension_count = if (with_precompiles)
        try @import("block_execution_external_trace_v2.zig").expectedEventCount(&owner.statement)
    else
        @as(u64, 0);
    if (event_count != execution_first.event_count + extension_count) {
        std.debug.print("segment cycles={d} complete={} tracker={d} sidecar={d}\n", .{ segment.base.cycle_count, segment.base.isComplete(), event_count, execution_first.event_count });
        for (segment.base.state_chain_tracker.accesses.items, 0..) |access, i|
            std.debug.print("access[{d}] space={d} addr={x} clk={d} value={x}\n", .{ i, access.addr_space, access.addr, access.clk, access.value });
    }
    try std.testing.expectEqual(execution_first.event_count + extension_count, event_count);
    var source = Source{ .replay = &replay };
    var memory_first = try producer.collectFirstPass(Cpu, a, source.asSource(), event_count, 1 << 12, 8, config);
    defer memory_first.deinit();

    var image = try tmp.dir.createFile("image.bin", .{ .read = true, .truncate = true });
    defer image.close();
    var touch = try tmp.dir.createFile("touch.bin", .{ .read = true, .truncate = true });
    defer touch.close();
    var image_count: u64 = 0;
    for (replay.words) |word| {
        if (word.value == 0 or word.source == .program_root) continue;
        var record: [8]u8 = undefined;
        std.mem.writeInt(u32, record[0..4], word.address, .little);
        std.mem.writeInt(u32, record[4..8], word.value, .little);
        try image.writeAll(&record);
        image_count += 1;
    }
    var first_touches = try replay.firstTouches();
    defer first_touches.deinit();
    var register_mask: u32 = 0;
    while (try first_touches.next()) |item| {
        if (item.source == .program_root) return error.ProgramFirstTouchNeedsAuthenticatedProvider;
        var record: [10]u8 = undefined;
        record[0] = item.space;
        std.mem.writeInt(u32, record[1..5], item.address, .little);
        std.mem.writeInt(u32, record[5..9], item.value, .little);
        record[9] = @intFromEnum(item.source);
        try touch.writeAll(&record);
        if (item.source == .register) register_mask |= @as(u32, 1) << @intCast(item.address);
    }
    const rw_root = try replay.initialRwRoot();
    const fallback_pin = fallback.Pin{ .initial_rw_root = rw_root, .layout = replay.layout.?, .image_count = image_count, .first_touch_count = first_touches.count };
    const files = fallback.Files{ .nonzero_image = image, .first_touches = touch };
    const rw_digest = try fallback.digestRoster(fallback_pin, files);
    const source_entries = [_]roster.Entry{
        .{ .family = .public_rw_fallback, .index = 0, .digest = rw_digest },
        .{ .family = .program, .index = 0, .digest = roster.programDescriptor(data.program_root.?.bytes) },
        .{ .family = .hash, .index = 0, .digest = roster.hashDescriptor(0, prepared.plan_id, prepared.id) },
    };
    const source_digest = try roster.digest(&source_entries);

    var execution_plan = try execution_shard.plan(a, &.{execution_first.event_count});
    defer execution_plan.deinit(a);
    const table_api = table.ForBackend(Cpu);
    var execution_table_first = try table_api.commitFirstRound(a, &execution_first.counter, execution_plan.shards[0], config);
    defer execution_table_first.deinit(a);
    const extension_counts = [_]u64{extension_count};
    var extension_plan: ?execution_shard.Plan = if (with_precompiles)
        try execution_shard.plan(a, &extension_counts)
    else
        null;
    defer if (extension_plan) |*plan| plan.deinit(a);
    var extension_table_first: ?table.ForBackend(Cpu).FirstRound = if (with_precompiles)
        try table_api.commitFirstRound(a, combined_artifact.?.externalCounter(), extension_plan.?.shards[0], config)
    else
        null;
    defer if (extension_table_first) |*first| first.deinit(a);
    const memory_pins = try a.alloc(batch.MemoryPin, memory_first.claims.len);
    defer a.free(memory_pins);
    for (memory_pins, memory_first.claims, memory_first.memory_roots) |*pin, claim, roots| pin.* = .{ .claim = claim, .roots = roots };
    const native_roots = [_]batch.Roots{execution_first.native_roots};
    const witness_roots = [_]batch.Roots{.{ execution_first.witnessRoot(), @splat(0) }};
    const execution_counts = [_]u64{execution_first.event_count};
    const execution_table_roots = [_]batch.Roots{execution_table_first.roots};
    var extension_roots: [1]@import("block_memory_source_seal_v2.zig").FirstRoundEntry = undefined;
    var extension_table_roots: [1]batch.Roots = undefined;
    if (with_precompiles) {
        extension_roots[0] = .{ .family = .execution_extension_witness, .index = 0, .roots = .{ combined_artifact.?.externalWitnessRoot(), @splat(0) } };
        extension_table_roots[0] = extension_table_first.?.roots;
    }

    const anchor = rw_root;
    const entry = try span.MachineState.init(data.initial_pc, data.initial_regs, anchor, .{ .bytes = @splat(0) });
    const exit_state = try span.MachineState.init(data.final_pc, data.final_regs, anchor, .{ .bytes = @splat(0) });
    const input_digest = try io.input(data);
    const output_digest = try io.output(data);
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), data.program_root.?, entry, exit_state, input_digest, output_digest, data.clock);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, data.clock, entry, exit_state, .{ .digest = input_digest }, .{ .digest = output_digest });
    const segment_statement = try span.SpanStatement.segmentLeaf(job, 0, executed);
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(41), .instance_count = 1 };
    var statement = batch.PinnedStatement{
        .seal = try @import("block_memory_source_seal_v2.zig").SourceSeal.init(base, register_mask, source_digest),
        .expected_events = event_count,
        .memory_instances = memory_pins,
        .range_table_roots = memory_first.table_roots,
        .execution_roots = &native_roots,
        .execution_sidecar_roots = &witness_roots,
        .execution_active_counts = &execution_counts,
        .execution_range_table_roots = &execution_table_roots,
        .execution_extension_roots = if (with_precompiles) &extension_roots else &.{},
        .execution_extension_active_counts = if (with_precompiles) &extension_counts else &.{},
        .execution_extension_range_table_roots = if (with_precompiles) &extension_table_roots else &.{},
        .provider_roots = &.{},
        .complete_pins = .{ .expected_job = job, .initial_rw_anchor = anchor.bytes, .program_root = data.program_root.?.bytes, .outer_recursive_key_id = @splat(1), .forest_roster_digest = @splat(2) },
    };
    statement.seal = if (with_precompiles)
        try @import("block_memory_source_seal_v2.zig").SourceSeal.initBoundWithExtension(base, register_mask, source_digest, 1, @intCast(memory_pins.len), memory_first.plan.digest, try statement.firstRoundDigest(a), extension_plan.?.digest)
    else
        try @import("block_memory_source_seal_v2.zig").SourceSeal.initBound(base, register_mask, source_digest, 1, @intCast(memory_pins.len), memory_first.plan.digest, try statement.firstRoundDigest(a));

    var capture = try Capture.init(a, memory_pins.len, memory_first.table_roots.len);
    defer capture.deinit();
    try producer.proveSecondPass(Cpu, a, source.asSource(), &memory_first, statement, config, capture.sink());
    var standalone_serialized: Artifact.Serialized = undefined;
    if (!with_precompiles) standalone_serialized = try execution_first.proveAndSerialize(&owner, prepared, statement.seal, &pool);
    defer if (!with_precompiles) standalone_serialized.deinit(a);
    var combined_serialized: ?ExternalArtifact.Serialized = if (with_precompiles)
        try combined_artifact.?.proveAndSerialize(&owner, prepared, statement.seal, &pool)
    else
        null;
    defer if (combined_serialized) |*artifact| artifact.deinit(a);
    var execution_table_proof = try table_api.prove(a, &execution_table_first, &execution_first.counter, execution_plan.shards[0], statement.seal, execution_table_roots[0]);
    defer execution_table_proof.deinit(a);
    const execution_table_bytes = try capture.encode(execution_table_proof.stark);
    const execution_table_wire = [_]batch.SerializedTableProof{.{ .stark_bytes = execution_table_bytes, .claim = execution_table_proof.claim }};
    var extension_wire: [1]@import("block_memory_batch_wire_v3.zig").SerializedExternalProof = undefined;
    var extension_table_wire: [1]batch.SerializedTableProof = undefined;
    if (with_precompiles) {
        extension_wire[0] = .{ .instance_index = 0, .stark_bytes = combined_serialized.?.external_stark, .claims = combined_serialized.?.external_claims };
        var extension_table_proof = try table_api.prove(a, &extension_table_first.?, combined_artifact.?.externalCounter(), extension_plan.?.shards[0], statement.seal, extension_table_roots[0]);
        defer extension_table_proof.deinit(a);
        extension_table_wire[0] = .{ .stark_bytes = try capture.encode(extension_table_proof.stark), .claim = extension_table_proof.claim };
    }
    const execution_wire = [_]@import("block_execution_batch_receiver_v2.zig").Wire{
        if (with_precompiles) combined_serialized.?.opcodeWire() else standalone_serialized.wire(),
    };
    const wire = batch.SerializedBatch{ .memory = capture.memories, .range_tables = capture.tables, .execution_range_tables = &execution_table_wire, .execution = &execution_wire, .execution_extensions = if (with_precompiles) &extension_wire else &.{}, .execution_extension_range_tables = if (with_precompiles) &extension_table_wire else &.{}, .initial_sources = &.{} };
    const execution_pin = [_]batch.EthereumShaExecutionPin(Cpu){.{ .prepared = prepared, .expected_key_id = prepared.id, .statement = segment_statement }};
    const public_initial = batch.PublicInitialSource{
        .pin = fallback_pin,
        .registers = segment.base.entry_cpu.regs,
        .files = files,
        .roster = &source_entries,
    };
    var owned = if (with_precompiles)
        try batch.verifyCoreOwnedWithExtension(Cpu, a, statement, wire, &execution_pin, public_initial, config)
    else
        try batch.verifyCoreOwned(Cpu, a, statement, wire, &execution_pin, public_initial, config);
    defer owned.deinit(a);
    const verified = owned.summary;
    try std.testing.expectEqual(event_count, verified.event_count);
    try std.testing.expectEqual(first_touches.count, verified.first_touch_count);
    try callback(a, FixtureView{
        .config = config,
        .statement = statement,
        .wire = wire,
        .execution_pin = execution_pin[0],
        .public_initial = public_initial,
        .verified = verified,
        .execution_receipt = &owned.executions[0],
        .owner = &owner,
        .prepared = prepared,
        .segment = &segment,
        .pool = &pool,
    });
}

test "coherent Ethereum SHA profile base execution and sorted memory core fresh receiver" {
    const use = struct {
        fn accept(_: std.mem.Allocator, view: FixtureView) !void {
            try std.testing.expectEqual(@as(u64, 11), view.verified.event_count);
        }
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    try withCoherentCoreFixture(config, use.accept);
}
