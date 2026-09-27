//! Bounded CPU assembly of a pinned multi-segment Ethereum-SHA block core.
//! The caller owns the executed segments and independently supplies every key
//! and public job pin; this function never treats proof bytes as authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Segment = @import("../runner/result.zig").EthereumShaSegmentResult;
const Replay = @import("block_memory_replay.zig").Replay;
const source_mod = @import("block_v4_public_source_assembly.zig");
const execution_mod = @import("block_v4_cpu_multi_execution_assembly.zig");
const tables_mod = @import("block_v4_cpu_multi_tables_assembly.zig");
const producer = @import("block_memory_batch_produce_v2.zig");
const Capture = @import("block_v4_cpu_staged_capture.zig").Capture;
const StagedExecution = @import("block_v4_cpu_staged_execution.zig");
const batch = @import("block_memory_batch_verify_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const manifest = @import("block_commitment_manifest.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");

pub const Trusted = struct {
    job: span.JobContext,
    base_seal: manifest.Sealed,
    native_key_ids: []const [32]u8,
    outer_key_id: [32]u8,
    forest_roster_digest: [32]u8,
};
pub const Options = struct {
    memory_instance_capacity: u32 = 1 << 20,
    memory_minimum_log_size: u32 = 8,
    spool_chunk_events: usize = 1 << 18,
    max_segments: usize = 1024,
    /// Prove sorted memory/tables alongside execution after the shared
    /// first-round statement is sealed. Callers must use a thread-safe,
    /// globally budgeted allocator when enabling this CPU schedule.
    parallel_families: bool = false,
};
pub const Metrics = struct {
    segments: usize,
    execution_events: u64,
    opcode_events: u64,
    external_events: u64,
    memory_instances: usize,
    first_touch_keys: u64,
    public_image_bytes: u64,
    public_first_touch_bytes: u64,
    stark_payload_bytes: u64,
    elapsed_ns: u64,
    tracked_peak_bytes: ?u64,
};
pub const View = struct {
    config: core.pcs.PcsConfig,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    execution_pins: []const batch.EthereumShaExecutionPin(Cpu),
    public_initial: batch.PublicInitialSource,
    verified: batch.VerifiedBlockCore,
    receipts: []const @import("block_execution_sidecar_batch_v2.zig").VerifiedExecutionReceipt,
    /// Borrowed leaf proof inputs. The callback can derive recursive proofs
    /// and invoke the canonical complete receiver before these are released.
    segments: []Segment,
    executions: []execution_mod.Execution,
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

/// This bounded in-memory proof view is valid only during `callback`. The
/// caller may persist it or invoke the canonical complete receiver there.
/// For mainnet-scale jobs a file-backed proof sink/streaming receiver remains
/// necessary; the public initial image is already written to `dir`.
pub fn withAssembledSegments(a: std.mem.Allocator, dir: std.fs.Dir, pool: *engine.work_pool.WorkPool, segments: []Segment, trusted: Trusted, config: core.pcs.PcsConfig, options: Options, tracked_peak: ?*engine.host_budget_allocator.SharedHostBudget, comptime callback: anytype) !void {
    if (segments.len < 2 or segments.len > options.max_segments or options.max_segments > 1024 or
        trusted.native_key_ids.len != segments.len or trusted.job.segment_count != @as(u32, @intCast(segments.len)) or
        trusted.base_seal.instance_count != @as(u32, @intCast(segments.len)))
        return error.InvalidMultiSegmentAssemblyScope;
    try trusted.job.validate();
    var timer = try std.time.Timer.start();
    const executions = try a.alloc(execution_mod.Execution, segments.len);
    defer a.free(executions);
    var execution_count: usize = 0;
    defer for (executions[0..execution_count]) |*item| item.deinit();
    const leaves = try a.alloc(span.SpanStatement, segments.len);
    defer a.free(leaves);
    const hashes = try a.alloc(source_mod.HashPin, segments.len);
    defer a.free(hashes);
    const opcode_counts = try a.alloc(u64, segments.len);
    defer a.free(opcode_counts);
    const external_counts = try a.alloc(u64, segments.len);
    defer a.free(external_counts);
    var opcode_total: u64 = 0;
    var external_total: u64 = 0;
    for (segments, executions, leaves, hashes, opcode_counts, external_counts, 0..) |*segment, *execution, *leaf, *hash, *opcode_count, *external_count, i| {
        if (segment.base.segment_index != @as(u32, @intCast(i)) or
            segment.base.isComplete() != (i == segments.len - 1)) return error.InvalidMultiSegmentContinuity;
        leaf.* = try v3.leaf(trusted.job, &segment.base);
        execution.* = try execution_mod.Execution.init(a, segment, @intCast(i), config, trusted.native_key_ids[i]);
        execution_count += 1;
        hash.* = .{ .plan_id = execution.prepared.plan_id, .key_id = trusted.native_key_ids[i] };
        opcode_count.* = execution.opcodeCount();
        external_count.* = try execution.externalCount();
        opcode_total = try std.math.add(u64, opcode_total, opcode_count.*);
        external_total = try std.math.add(u64, external_total, external_count.*);
    }
    var replay = try Replay.initFromSnapshot(a, dir, segments[0].base.entry_cpu.regs, &segments[0].base.rw_memory, options.spool_chunk_events);
    defer replay.deinit();
    for (segments) |*segment| try replay.appendResult(&segment.base);
    var sorted = try replay.finish();
    sorted.deinit();
    const event_count = replay.spooler.event_count;
    if (event_count != try std.math.add(u64, opcode_total, external_total))
        return error.MultiSegmentAccessCensusMismatch;
    var source = Source{ .replay = &replay };
    var memory_first = try producer.collectFirstPass(Cpu, a, source.asSource(), event_count, options.memory_instance_capacity, options.memory_minimum_log_size, config);
    defer memory_first.deinit();
    var public = try source_mod.prepare(a, dir, &replay, trusted.job.complete.initial_state.rw_memory.bytes, trusted.job.complete.program.bytes, hashes);
    defer public.deinit();
    var opcode_tables = try tables_mod.Tables.init(a, executions, opcode_counts, false, config);
    defer opcode_tables.deinit();
    var extension_tables: ?tables_mod.Tables = if (external_total == 0) null else try tables_mod.Tables.init(a, executions, external_counts, true, config);
    defer if (extension_tables) |*value| value.deinit();
    const memory_pins = try a.alloc(batch.MemoryPin, memory_first.claims.len);
    defer a.free(memory_pins);
    for (memory_pins, memory_first.claims, memory_first.memory_roots) |*pin, claim, roots|
        pin.* = .{ .claim = claim, .roots = roots };
    const native_roots = try a.alloc(batch.Roots, segments.len);
    defer a.free(native_roots);
    const opcode_witness = try a.alloc(batch.Roots, segments.len);
    defer a.free(opcode_witness);
    var external_root_count: usize = 0;
    for (external_counts) |count| external_root_count += @intFromBool(count != 0);
    const external_roots = try a.alloc(seal_mod.FirstRoundEntry, external_root_count);
    defer a.free(external_roots);
    var next_external: usize = 0;
    for (executions, native_roots, opcode_witness, external_counts, 0..) |*execution, *native, *witness, count, i| {
        native.* = execution.nativeRoots();
        witness.* = .{ execution.opcodeWitnessRoot(), @splat(0) };
        if (count == 0) continue;
        external_roots[next_external] = .{ .family = .execution_extension_witness, .index = @intCast(i), .roots = .{ execution.externalWitnessRoot().?, @splat(0) } };
        next_external += 1;
    }
    var statement = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(trusted.base_seal, public.register_mask, public.digest),
        .expected_events = event_count,
        .memory_instances = memory_pins,
        .range_table_roots = memory_first.table_roots,
        .execution_roots = native_roots,
        .execution_sidecar_roots = opcode_witness,
        .execution_active_counts = opcode_counts,
        .execution_range_table_roots = opcode_tables.roots,
        .execution_extension_roots = external_roots,
        .execution_extension_active_counts = if (extension_tables == null) &.{} else external_counts,
        .execution_extension_range_table_roots = if (extension_tables) |value| value.roots else &.{},
        .provider_roots = &.{},
        .complete_pins = .{ .expected_job = trusted.job, .initial_rw_anchor = public.pin.initial_rw_root.bytes, .program_root = trusted.job.complete.program.bytes, .outer_recursive_key_id = trusted.outer_key_id, .forest_roster_digest = trusted.forest_roster_digest },
    };
    const first_digest = try statement.firstRoundDigest(a);
    statement.seal = if (extension_tables) |value|
        try seal_mod.SourceSeal.initBoundWithExtension(trusted.base_seal, public.register_mask, public.digest, @intCast(segments.len), @intCast(memory_pins.len), memory_first.plan.digest, first_digest, value.plan.digest)
    else
        try seal_mod.SourceSeal.initBound(trusted.base_seal, public.register_mask, public.digest, @intCast(segments.len), @intCast(memory_pins.len), memory_first.plan.digest, first_digest);
    var capture = try Capture.init(a, dir, memory_pins.len, memory_first.table_roots.len);
    defer capture.deinit();
    try producer.proveSecondPass(Cpu, a, source.asSource(), &memory_first, statement, config, capture.sink());
    var execution_stage = try StagedExecution.Sink.init(a, dir, segments.len);
    defer execution_stage.deinit();
    for (executions, 0..) |*execution, index| {
        try execution.prove(statement.seal, pool);
        try execution_stage.write(index, execution.opcodeWire(), execution.externalWire(@intCast(index)));
        execution.releaseSerialized();
    }
    try opcode_tables.prove(statement.seal, &capture);
    if (extension_tables) |*value| try value.prove(statement.seal, &capture);
    var loaded = try capture.load();
    defer loaded.deinit();
    const execution_wire = try a.alloc(@import("block_execution_batch_receiver_v2.zig").Wire, segments.len);
    defer a.free(execution_wire);
    const execution_loaded = try a.alloc(StagedExecution.Loaded, segments.len);
    defer a.free(execution_loaded);
    var execution_loaded_count: usize = 0;
    defer for (execution_loaded[0..execution_loaded_count]) |*item| item.deinit();
    const execution_pins = try a.alloc(batch.EthereumShaExecutionPin(Cpu), segments.len);
    defer a.free(execution_pins);
    const external_wire = try a.alloc(batch.SerializedExternalProof, external_roots.len);
    defer a.free(external_wire);
    next_external = 0;
    const payload_bytes = try std.math.add(u64, capture.total_bytes, execution_stage.total_bytes);
    for (executions, execution_wire, execution_pins, 0..) |*execution, *wire, *pin, i| {
        execution_loaded[i] = try execution_stage.load(i);
        execution_loaded_count += 1;
        wire.* = execution_loaded[i].wire;
        pin.* = .{ .prepared = execution.prepared, .expected_key_id = trusted.native_key_ids[i], .statement = leaves[i] };
        if (execution_loaded[i].extension) |external| {
            external_wire[next_external] = external;
            next_external += 1;
        }
    }
    const wire = batch.SerializedBatch{ .memory = loaded.memory, .range_tables = loaded.tables, .execution_range_tables = opcode_tables.wires, .execution = execution_wire, .execution_extensions = external_wire, .execution_extension_range_tables = if (extension_tables) |value| value.wires else &.{}, .initial_sources = &.{} };
    const public_initial = batch.PublicInitialSource{ .pin = public.pin, .registers = public.registers, .files = public.files(), .roster = public.entries };
    var verified = if (extension_tables != null)
        try batch.verifyCoreOwnedWithExtension(Cpu, a, statement, wire, execution_pins, public_initial, config)
    else
        try batch.verifyCoreOwned(Cpu, a, statement, wire, execution_pins, public_initial, config);
    defer verified.deinit(a);
    try callback(View{ .config = config, .statement = statement, .wire = wire, .execution_pins = execution_pins, .public_initial = public_initial, .verified = verified.summary, .receipts = verified.executions, .segments = segments, .executions = executions, .metrics = .{ .segments = segments.len, .execution_events = event_count, .opcode_events = opcode_total, .external_events = external_total, .memory_instances = memory_pins.len, .first_touch_keys = public.pin.first_touch_count, .public_image_bytes = try public.image.getEndPos(), .public_first_touch_bytes = try public.touches.getEndPos(), .stark_payload_bytes = payload_bytes, .elapsed_ns = timer.read(), .tracked_peak_bytes = if (tracked_peak) |value| value.snapshot().peak_live_bytes else null } });
}
