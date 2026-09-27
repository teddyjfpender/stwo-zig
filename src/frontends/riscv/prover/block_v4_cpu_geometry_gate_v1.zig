//! Read-only block-v4 first-round geometry admission. It commits the actual
//! execution, sorted-memory and byte-table columns, but proves nothing and
//! issues no complete-block authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("block_v4_cpu_runner_source.zig");
const first_mod = @import("block_v4_cpu_streaming_first_round.zig");
const memory_mod = @import("block_memory_batch_produce_v2.zig");
const tables_mod = @import("block_v4_cpu_streaming_tables.zig");
const statement_mod = @import("block_v4_cpu_streaming_statement.zig");
const source_mod = @import("block_v4_public_source_assembly.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const Replay = @import("block_memory_replay.zig").Replay;

pub const Report = struct {
    scope: []const u8 = "read_only_first_round_geometry_no_proofs",
    proof_verified: bool = false,
    geometry_committed: bool = true,
    manifest_sha256: [32]u8,
    statement_sha256: [32]u8,
    segments: usize,
    cycles: u64,
    memory_events: u64,
    opcode_events: u64,
    external_events: u64,
    memory_instances: usize,
    max_memory_log_size: u32,
    allocated_memory_rows: u64,
    memory_range_shards: usize,
    opcode_range_shards: usize,
    external_range_shards: usize,
    initial_nonzero_image_bytes: u64,
    first_touch_roster_bytes: u64,
    first_touch_count: u64,
    source_roster_digest: [32]u8,
    first_round_roster_digest: [32]u8,
    memory_range_plan_digest: [32]u8,
    opcode_range_plan_digest: [32]u8,
    external_range_plan_digest: [32]u8,
    elapsed_ns: u64,
    tracked_work_peak_bytes: usize,
};

const Sorted = struct {
    replay: *Replay,
    fn open(context: *anyopaque) anyerror!@import("../air/block/memory_transition.zig").Reader {
        const self: *Sorted = @ptrCast(@alignCast(context));
        return self.replay.reopenSortedTransitions();
    }
    fn source(self: *Sorted) memory_mod.SortedSource {
        return .{ .context = self, .open = open };
    }
};

/// The caller must supply an independently hash-admitted candidate manifest.
/// `source` is fresh, with its `.first` pass unopened. The staging directory
/// must be empty and remains a provisional public input, not a proof bundle.
pub fn run(a: std.mem.Allocator, dir: std.fs.Dir, budget: *engine.host_budget_allocator.SharedHostBudget, source: *runner.Source, trusted: trusted_mod.Trusted, manifest_sha256: [32]u8, config: core.pcs.PcsConfig, options: trusted_mod.Options) !Report {
    if (!std.meta.eql(source.job, trusted.job) or
        source.schedule.segments != trusted.base_seal.instance_count or
        trusted.native_key_ids.len != @as(usize, source.schedule.segments))
        return error.UntrustedGeometryGateRoster;
    var timer = try std.time.Timer.start();
    reportStage(budget, &timer, "first-round-start");
    var first = try first_mod.collect(a, dir, source, trusted.native_key_ids, config, options.spool_chunk_events);
    defer first.deinit();
    reportStage(budget, &timer, "execution-first-round-complete");
    var sorted = Sorted{ .replay = first.replay };
    var memory_first = try memory_mod.collectFirstPass(Cpu, a, sorted.source(), first.event_count, options.memory_instance_capacity, options.memory_minimum_log_size, config);
    defer memory_first.deinit();
    reportStage(budget, &timer, "memory-first-round-complete");
    const hashes = try a.alloc(source_mod.HashPin, first.entries.len);
    defer a.free(hashes);
    for (first.entries, hashes) |entry, *hash| hash.* = entry.hash_pin;
    var public = try source_mod.prepare(a, dir, first.replay, trusted.job.complete.initial_state.rw_memory.bytes, trusted.job.complete.program.bytes, hashes);
    defer public.deinit();
    reportStage(budget, &timer, "public-source-complete");
    var opcode_tables = try tables_mod.Tables.init(a, &first.opcode_plan, first.opcode_counters.items, config);
    defer opcode_tables.deinit();
    var external_tables: ?tables_mod.Tables = if (first.external_events == 0) null else try tables_mod.Tables.init(a, &first.external_plan, first.external_counters.items, config);
    defer if (external_tables) |*value| value.deinit();
    reportStage(budget, &timer, "range-tables-complete");
    var bound = try statement_mod.bind(a, trusted, &first, &memory_first, &public, &opcode_tables, if (external_tables) |*value| value else null);
    defer bound.deinit();
    var admitted = try bound.value.validate(a);
    defer admitted.deinit(a);
    try bound.value.requireExecutionSidecars(a);
    reportStage(budget, &timer, "statement-admitted");
    const statement_bytes = try std.json.Stringify.valueAlloc(a, bound.value, .{});
    defer a.free(statement_bytes);
    const statement_hash = runner.sha256(statement_bytes);
    var max_log: u32 = 0;
    var rows: u64 = 0;
    for (memory_first.claims) |claim| {
        max_log = @max(max_log, claim.log_size);
        rows = try std.math.add(u64, rows, @as(u64, 1) << @intCast(claim.log_size));
    }
    const report = Report{
        .manifest_sha256 = manifest_sha256,
        .statement_sha256 = statement_hash,
        .segments = first.entries.len,
        .cycles = trusted.job.complete.total_cycles,
        .memory_events = first.event_count,
        .opcode_events = first.opcode_events,
        .external_events = first.external_events,
        .memory_instances = memory_first.claims.len,
        .max_memory_log_size = max_log,
        .allocated_memory_rows = rows,
        .memory_range_shards = memory_first.plan.shards.len,
        .opcode_range_shards = first.opcode_plan.shards.len,
        .external_range_shards = first.external_plan.shards.len,
        .initial_nonzero_image_bytes = try std.math.mul(u64, public.pin.image_count, 8),
        .first_touch_roster_bytes = try std.math.mul(u64, public.pin.first_touch_count, 10),
        .first_touch_count = public.pin.first_touch_count,
        .source_roster_digest = public.digest,
        .first_round_roster_digest = bound.value.seal.first_round_roster_digest,
        .memory_range_plan_digest = memory_first.plan.digest,
        .opcode_range_plan_digest = first.opcode_plan.digest,
        .external_range_plan_digest = first.external_plan.digest,
        .elapsed_ns = timer.read(),
        .tracked_work_peak_bytes = budget.snapshot().peak_live_bytes,
    };
    var statement_file = try dir.createFile("geometry-statement-candidate-v1.json", .{ .exclusive = true });
    defer statement_file.close();
    errdefer dir.deleteFile("geometry-statement-candidate-v1.json") catch {};
    try statement_file.writeAll(statement_bytes);
    try statement_file.sync();
    const report_bytes = try std.json.Stringify.valueAlloc(a, report, .{});
    defer a.free(report_bytes);
    var report_file = try dir.createFile("geometry-report-v1.json", .{ .exclusive = true });
    defer report_file.close();
    errdefer dir.deleteFile("geometry-report-v1.json") catch {};
    try report_file.writeAll(report_bytes);
    try report_file.sync();
    return report;
}

fn reportStage(budget: *engine.host_budget_allocator.SharedHostBudget, timer: *std.time.Timer, stage: []const u8) void {
    const snapshot = budget.snapshot();
    std.debug.print("BLOCK_V4_GEOMETRY_STAGE stage={s} elapsed_ns={d} live_bytes={d} tracked_peak_bytes={d}\n", .{
        stage, timer.read(), snapshot.live_bytes, snapshot.peak_live_bytes,
    });
}

test "read-only geometry gate commits a small exact source without proving" {
    const backing = std.testing.allocator;
    const candidate_mod = @import("block_v4_cpu_candidate_roster_v1.zig");
    var instructions: [20]u32 = @splat(0x00000013);
    instructions[0] = 0x00100137;
    instructions[1] = 0x00100193;
    instructions[13] = 0x00312223;
    instructions[14] = 0x00312423;
    instructions[17] = 0x00312023;
    instructions[18] = 0x0000006f;
    instructions[19] = @import("../isa/sha256_compression_v1.zig").encode(5, 6);
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, .rv32im_zkvm_ethereum_sha_v1);
    const oracle = [_]u8{1};
    const schedule = "[5,4,4,5]";
    var candidate = try candidate_mod.derive(backing, .{ .elf = &elf, .public_input = &.{}, .oracle = &oracle, .schedule_json = schedule, .expected_schedule_sha256 = runner.sha256(schedule), .max_segment_cycles = 6 });
    defer candidate.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 4 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var source = try runner.Source.initWithSchedule(a, &elf, &.{}, &oracle, 6, config, candidate.wire.source, schedule);
    defer source.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const report = try run(a, tmp.dir, budget, &source, candidate.wire.trusted, candidate.report.manifest_sha256, config, .{});
    try std.testing.expectEqual(@as(usize, 4), report.segments);
    try std.testing.expect(report.memory_events > 0);
    try std.testing.expect(report.memory_instances > 0);
    try std.testing.expect(report.geometry_committed and !report.proof_verified);
    const statement = try tmp.dir.readFileAlloc(a, "geometry-statement-candidate-v1.json", 2 * 1024 * 1024);
    defer a.free(statement);
    try std.testing.expectEqual(report.statement_sha256, runner.sha256(statement));
}
