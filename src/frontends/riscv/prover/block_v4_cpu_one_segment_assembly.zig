//! Production-facing small CPU block-v4 assembly from the ordinary Ethereum
//! SHA runner. The caller pins the public job, native key, manifest and outer
//! roster independently; this module assembles and freshly verifies the core.
//! Multi-segment/full-block streaming uses the same first-round producers but
//! requires a replayable execution source and staged proof files.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const ExternalArtifact = @import("block_execution_sha_external_artifact_v2.zig");
const Replay = @import("block_memory_replay.zig").Replay;
const producer = @import("block_memory_batch_produce_v2.zig");
const source_mod = @import("block_v4_public_source_assembly.zig");
const capture_mod = @import("block_v4_small_proof_capture.zig");
const batch = @import("block_memory_batch_verify_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const execution_shard = @import("block_execution_range_shard_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const manifest = @import("block_commitment_manifest.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const io = @import("../recursion/blake3_public_io.zig");

pub const Trusted = struct {
    job: span.JobContext,
    base_seal: manifest.Sealed,
    native_key_id: [32]u8,
    /// Independently admitted recursive key/forest pins. The core receiver
    /// checks the job, while the complete receiver later verifies these pins.
    outer_key_id: [32]u8,
    forest_roster_digest: [32]u8,
};
pub const Options = struct {
    max_cycles: u32,
    memory_instance_capacity: u32 = 1 << 20,
    memory_minimum_log_size: u32 = 8,
    spool_chunk_events: usize = 1 << 18,
};
pub const Metrics = struct {
    execution_events: u64,
    opcode_events: u64,
    extension_events: u64,
    memory_instances: usize,
    first_touch_keys: u64,
    public_image_bytes: u64,
    public_first_touch_bytes: u64,
    /// B3SHART1 plus Postcard STARK byte arrays; excludes separate claims,
    /// pinned statements, and public initial-image files.
    stark_payload_bytes: u64,
    elapsed_ns: u64,
    tracked_peak_bytes: u64,
};
pub const View = struct {
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    execution_pin: batch.EthereumShaExecutionPin(Cpu),
    public_initial: batch.PublicInitialSource,
    verified: batch.VerifiedBlockCore,
    metrics: Metrics,
};
const Source = struct {
    replay: *Replay,
    fn open(context: *anyopaque) anyerror!@import("../air/block/memory_transition.zig").Reader {
        const self: *Source = @ptrCast(@alignCast(context));
        return self.replay.reopenSortedTransitions();
    }
    fn asSource(self: *Source) producer.SortedSource {
        return .{ .context = self, .open = open };
    }
};

/// Callback borrows all proof bytes, public files and prepared verification
/// data. It may invoke the canonical recursive receiver before this returns.
pub fn withAssembledCore(a: std.mem.Allocator, dir: std.fs.Dir, pool: *engine.work_pool.WorkPool, elf: []const u8, input: []const u8, expected_output: []const u8, trusted: Trusted, config: core.pcs.PcsConfig, options: Options, tracked_peak: ?*engine.host_budget_allocator.SharedHostBudget, comptime callback: anytype) !void {
    if (options.max_cycles == 0 or options.max_cycles > 1 << 22 or
        trusted.job.segment_count != 1 or trusted.base_seal.instance_count == 0)
        return error.InvalidSmallBlockAssemblyScope;
    try trusted.job.validate();
    var timer = try std.time.Timer.start();
    var session = try runner.EthereumShaExecutionSession.init(a, elf, .{
        .input = input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var segment = try session.startSegment(options.max_cycles);
    defer segment.deinit();
    if (!segment.base.isComplete() or segment.base.segment_index != 0 or
        segment.base.output == null or !std.mem.eql(u8, segment.base.output.?, expected_output))
        return error.SmallBlockExecutionOutputMismatch;
    const leaf = try v3.leaf(trusted.job, &segment.base);
    var owner = try Profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    const prepared = try Native.ForBackend(Cpu).PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
    defer prepared.deinit();
    try prepared.validate(trusted.native_key_id);
    const data = &owner.native.statement.public_data;
    if (!std.meta.eql(data.program_root.?, trusted.job.complete.program) or
        !std.meta.eql(try io.input(data), trusted.job.complete.public_input) or
        !std.meta.eql(try io.output(data), trusted.job.complete.public_output) or
        data.clock != trusted.job.complete.total_cycles)
        return error.UntrustedSmallBlockPublicJob;
    const frame = @import("../air/block/memory_event.zig").Frame{
        .clock_frame = .leaf_local,
        .global_first_cycle = segment.base.global_first_cycle,
        .cycle_count = @intCast(segment.base.cycle_count),
    };
    var execution = try ExternalArtifact.ForBackend(Cpu).init(a, &owner, prepared, frame, 0, config);
    defer execution.deinit();
    const opcode_count = execution.opcodeEventCount();
    const external_count = try execution.externalEventCount();
    var replay = try Replay.initFromSnapshot(a, dir, segment.base.entry_cpu.regs, &segment.base.rw_memory, options.spool_chunk_events);
    defer replay.deinit();
    try replay.appendResult(&segment.base);
    var finished = try replay.finish();
    finished.deinit();
    const event_count = replay.spooler.event_count;
    if (event_count != try std.math.add(u64, opcode_count, external_count))
        return error.SmallBlockAccessCensusMismatch;
    try @import("block_v4_small_access_audit.zig").check(a, frame, segment.base.state_chain_tracker.accesses.items, execution.opcode.traces, execution.traces);
    var source = Source{ .replay = &replay };
    var memory_first = try producer.collectFirstPass(Cpu, a, source.asSource(), event_count, options.memory_instance_capacity, options.memory_minimum_log_size, config);
    defer memory_first.deinit();
    const hashes = [_]source_mod.HashPin{.{ .plan_id = prepared.plan_id, .key_id = trusted.native_key_id }};
    var public = try source_mod.prepare(a, dir, &replay, trusted.job.complete.initial_state.rw_memory.bytes, trusted.job.complete.program.bytes, &hashes);
    defer public.deinit();
    var opcode_plan = try execution_shard.plan(a, &.{opcode_count});
    defer opcode_plan.deinit(a);
    var extension_plan = try execution_shard.plan(a, &.{external_count});
    defer extension_plan.deinit(a);
    const table_api = table.ForBackend(Cpu);
    var opcode_table_first = try table_api.commitFirstRound(a, execution.opcodeCounter(), opcode_plan.shards[0], config);
    defer opcode_table_first.deinit(a);
    var extension_table_first = try table_api.commitFirstRound(a, execution.externalCounter(), extension_plan.shards[0], config);
    defer extension_table_first.deinit(a);
    const memory_pins = try a.alloc(batch.MemoryPin, memory_first.claims.len);
    defer a.free(memory_pins);
    for (memory_pins, memory_first.claims, memory_first.memory_roots) |*pin, claim, roots|
        pin.* = .{ .claim = claim, .roots = roots };
    const native_roots = [_]batch.Roots{execution.nativeRoots()};
    const opcode_witness = [_]batch.Roots{.{ execution.opcodeWitnessRoot(), @splat(0) }};
    const opcode_counts = [_]u64{opcode_count};
    const opcode_tables = [_]batch.Roots{opcode_table_first.roots};
    const extension_roots = [_]seal_mod.FirstRoundEntry{.{ .family = .execution_extension_witness, .index = 0, .roots = .{ execution.externalWitnessRoot(), @splat(0) } }};
    const extension_counts = [_]u64{external_count};
    const extension_tables = [_]batch.Roots{extension_table_first.roots};
    var statement = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(trusted.base_seal, public.register_mask, public.digest),
        .expected_events = event_count,
        .memory_instances = memory_pins,
        .range_table_roots = memory_first.table_roots,
        .execution_roots = &native_roots,
        .execution_sidecar_roots = &opcode_witness,
        .execution_active_counts = &opcode_counts,
        .execution_range_table_roots = &opcode_tables,
        .execution_extension_roots = &extension_roots,
        .execution_extension_active_counts = &extension_counts,
        .execution_extension_range_table_roots = &extension_tables,
        .provider_roots = &.{},
        .complete_pins = .{ .expected_job = trusted.job, .initial_rw_anchor = public.pin.initial_rw_root.bytes, .program_root = trusted.job.complete.program.bytes, .outer_recursive_key_id = trusted.outer_key_id, .forest_roster_digest = trusted.forest_roster_digest },
    };
    statement.seal = try seal_mod.SourceSeal.initBoundWithExtension(trusted.base_seal, public.register_mask, public.digest, 1, @intCast(memory_pins.len), memory_first.plan.digest, try statement.firstRoundDigest(a), extension_plan.digest);
    var capture = try capture_mod.Capture.init(a, memory_pins.len, memory_first.table_roots.len);
    defer capture.deinit();
    try producer.proveSecondPass(Cpu, a, source.asSource(), &memory_first, statement, config, capture.sink());
    var serialized = try execution.proveAndSerialize(&owner, prepared, statement.seal, pool);
    defer serialized.deinit(a);
    var opcode_table_proof = try table_api.prove(a, &opcode_table_first, execution.opcodeCounter(), opcode_plan.shards[0], statement.seal, opcode_tables[0]);
    defer opcode_table_proof.deinit(a);
    const opcode_table_bytes = try capture.encode(opcode_table_proof.stark);
    var extension_table_proof = try table_api.prove(a, &extension_table_first, execution.externalCounter(), extension_plan.shards[0], statement.seal, extension_tables[0]);
    defer extension_table_proof.deinit(a);
    const extension_table_bytes = try capture.encode(extension_table_proof.stark);
    const execution_wire = [_]@import("block_execution_batch_receiver_v2.zig").Wire{serialized.opcodeWire()};
    const extension_wire = [_]batch.SerializedExternalProof{.{ .instance_index = 0, .stark_bytes = serialized.external_stark, .claims = serialized.external_claims }};
    const opcode_table_wire = [_]batch.SerializedTableProof{.{ .stark_bytes = opcode_table_bytes, .claim = opcode_table_proof.claim }};
    const extension_table_wire = [_]batch.SerializedTableProof{.{ .stark_bytes = extension_table_bytes, .claim = extension_table_proof.claim }};
    const wire = batch.SerializedBatch{ .memory = capture.memory, .range_tables = capture.tables, .execution_range_tables = &opcode_table_wire, .execution = &execution_wire, .execution_extensions = &extension_wire, .execution_extension_range_tables = &extension_table_wire, .initial_sources = &.{} };
    const execution_pin = [_]batch.EthereumShaExecutionPin(Cpu){.{ .prepared = prepared, .expected_key_id = trusted.native_key_id, .statement = leaf }};
    const public_initial = batch.PublicInitialSource{ .pin = public.pin, .registers = public.registers, .files = public.files(), .roster = public.entries };
    var owned = try batch.verifyCoreOwnedWithExtension(Cpu, a, statement, wire, &execution_pin, public_initial, config);
    defer owned.deinit(a);
    const stark_payload_bytes = try std.math.add(u64, try std.math.add(u64, capture.total_bytes, opcode_table_bytes.len + extension_table_bytes.len), serialized.opcode.native_artifact.len + serialized.opcode.sidecar_stark.len + serialized.external_stark.len);
    try callback(View{ .statement = statement, .wire = wire, .execution_pin = execution_pin[0], .public_initial = public_initial, .verified = owned.summary, .metrics = .{ .execution_events = event_count, .opcode_events = opcode_count, .extension_events = external_count, .memory_instances = memory_pins.len, .first_touch_keys = public.pin.first_touch_count, .public_image_bytes = try public.image.getEndPos(), .public_first_touch_bytes = try public.touches.getEndPos(), .stark_payload_bytes = stark_payload_bytes, .elapsed_ns = timer.read(), .tracked_peak_bytes = if (tracked_peak) |budget| budget.snapshot().peak_live_bytes else 0 } });
}
