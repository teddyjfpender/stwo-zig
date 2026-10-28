//! One real nine-segment job, reused across exact batch partitions. Global
//! provider obligations stay open; these batches are not a complete block root.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Segment = @import("../../runner/result.zig").SegmentResult;
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
const proof = @import("../block_v5_native_execution_proof_v3.zig");
const Api = proof.ForBackend(Cpu);
const seals = @import("../block_v5_source_seal_v1.zig");
const catalogs = @import("../block_v5_native_template_catalog_v1.zig");
const prep = @import("../../recursion/block_v6_native_batch_prepare_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const bench = @import("block_v6_native_batch_proof_test.zig");
const spans = @import("../../recursion/block_v5_pc_clock_span_v1.zig");
const MAX_SEGMENTS = 9;

test "block-v6 scaling heterogeneous nine-segment job q8" {
    try run(.diagnostic_q8_pow0, 2);
}

test "block-v6 scaling heterogeneous nine-segment job canonical q70 pow26" {
    const steps = if (std.posix.getenv("STWO_NATIVE_BATCH_STEPS")) |raw| try std.fmt.parseInt(u32, raw, 10) else 64;
    if (steps < 2 or steps > 4096 or steps % 2 != 0) return error.InvalidNativeBatchBenchmarkSteps;
    try run(.csp_q70_pow26, steps);
}

test "block-v6 schedule q70 pow26 experimental fold2" {
    try run(.experimental_q70_pow26_fold2, 64);
}
test "block-v6 schedule q70 pow26 experimental fold4" {
    try run(.experimental_q70_pow26_fold4, 64);
}

fn run(selected: Profile, base_steps: u32) !void {
    var sizes: [MAX_SEGMENTS]u32 = undefined;
    for (&sizes, 0..) |*size, i| size.* = base_steps * @as(u32, @intCast(1 + i % 2));
    _ = try runJob(selected, base_steps, &sizes, false);
}

/// Same native proof implementation for segmentation and batching experiments.
/// Returned digest checks observed guest endpoints only; it is not proof authority.
pub fn runJob(selected: Profile, base_steps: u32, sizes: []const u32, tiling: bool) ![32]u8 {
    if (sizes.len == 0 or sizes.len > MAX_SEGMENTS or (!tiling and sizes.len != MAX_SEGMENTS)) return error.InvalidNativeJobSize;
    for (sizes) |size| if (size == 0 or size % 2 != 0) return error.InvalidNativeJobSize;
    const COUNT = sizes.len;
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(std.testing.allocator, 40 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var timer = try std.time.Timer.start();
    // ADDI x1,x1,1; JAL x0,-4. Real mutable register state crosses every
    // segment boundary. Alternating segment sizes exercise distinct templates.
    const instructions = [_]u32{ 0x00108093, 0xffdff06f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segments: [MAX_SEGMENTS]Segment = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    var fixtures: [MAX_SEGMENTS]Fixture = undefined;
    var fixture_count: usize = 0;
    defer for (fixtures[0..fixture_count]) |*item| item.deinit();
    var rounds: [MAX_SEGMENTS]Api.FirstRound = undefined;
    var round_count: usize = 0;
    defer for (rounds[0..round_count]) |*round| round.deinit(a);
    var records: [MAX_SEGMENTS]catalogs.Record = undefined;
    var counts: [seals.family_count]u32 = @splat(0);
    counts[@intFromEnum(seals.Family.program) - 1] = 1;
    counts[@intFromEnum(seals.Family.execution) - 1] = @intCast(COUNT);
    counts[@intFromEnum(seals.Family.execution_sidecar) - 1] = @intCast(COUNT);
    counts[@intFromEnum(seals.Family.program_request) - 1] = @intCast(COUNT);
    counts[@intFromEnum(seals.Family.memory) - 1] = 1;
    var pins = seals.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = selected.config(), .counts = counts };
    var cycles: u64 = 0;
    for (0..COUNT) |index| {
        const steps = sizes[index];
        segments[index] = if (index == 0) try session.startSegment(steps) else try session.resumeSegment(segments[index - 1].continuation.?, steps);
        segment_count += 1;
        try std.testing.expectEqual(steps, segments[index].cycle_count);
        cycles += steps;
        fixtures[index] = try Fixture.init(a, &segments[index], pins);
        fixture_count += 1;
        rounds[index] = try Api.commitFirstRound(a, fixtures[index].owner, fixtures[index].pin, pins.config, .rv32im_zkvm_v1, @intCast(index));
        round_count += 1;
        records[index] = .{ .index = @intCast(index), .template_id = rounds[index].template_id, .geometry_digest = rounds[index].template.geometry_digest, .fixed_root = rounds[index].roots[0] };
    }
    if (!tiling) try std.testing.expect(!std.meta.eql(rounds[0].template_id, rounds[1].template_id));
    const catalog = catalogs.Admission{ .records = records[0..COUNT] };
    pins.native_template_catalog_digest = try catalog.digest();
    var entries: [3 * MAX_SEGMENTS + 2]seals.Entry = undefined;
    entries[0] = .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } };
    for (rounds[0..COUNT], 0..) |*round, index| entries[1 + index] = round.entry();
    for ([_]seals.Family{ .execution_sidecar, .program_request }, 0..) |family, group| {
        for (0..COUNT) |index| entries[1 + COUNT + group * COUNT + index] = .{
            .family = family,
            .index = @intCast(index),
            .instance_id = @splat(@intCast(32 + group * COUNT + index)),
            .roots = .{ @splat(11), @splat(12) },
        };
    }
    entries[3 * COUNT + 1] = .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } };
    const sealed = try seals.seal(pins, entries[0 .. 3 * COUNT + 2]);
    var captures: [MAX_SEGMENTS]prep.Capture = undefined;
    var capture_count: usize = 0;
    defer for (captures[0..capture_count]) |*capture| capture.deinit();
    var policies: [MAX_SEGMENTS]prep.NativeAdmission = undefined;
    var policy_count: usize = 0;
    defer for (policies[0..policy_count]) |*policy| policy.deinit();
    var capture_pointers: [MAX_SEGMENTS]*const prep.Capture = undefined;
    var policy_pointers: [MAX_SEGMENTS]*const prep.NativeAdmission = undefined;
    for (0..COUNT) |index| {
        const native = try Api.proveWithCatalog(a, &rounds[index], sealed, pins, entries[0 .. 3 * COUNT + 2], catalog);
        captures[index] = try Api.verifyCaptureOwnedWithCatalog(a, native, &fixtures[index].owner.statement, fixtures[index].pin, rounds[index].template, rounds[index].template_id, .rv32im_zkvm_v1, @intCast(index), sealed, pins, entries[0 .. 3 * COUNT + 2], catalog);
        capture_count += 1;
        policies[index] = try prep.NativeAdmission.init(a, &fixtures[index].owner.statement, fixtures[index].pin, rounds[index].template, rounds[index].template_id, @intCast(index), sealed, pins, entries[0 .. 3 * COUNT + 2], catalog);
        policy_count += 1;
        capture_pointers[index] = &captures[index];
        policy_pointers[index] = &policies[index];
    }
    // Compare execution, not segmentation-dependent transcript identities or
    // leaf-local predecessor clocks. Exact endpoint values are hashed below.
    var semantic = core.channel.blake3.Channel{};
    semantic.mixU32s(&instructions);
    semantic.mixU64(cycles);
    semantic.mixU32s(&.{ segments[0].entry_cpu.pc, segments[COUNT - 1].exit_cpu.pc });
    semantic.mixU32s(&segments[0].entry_cpu.regs);
    semantic.mixU32s(&segments[COUNT - 1].exit_cpu.regs);
    try std.testing.expectEqual(@as(u32, @intCast(cycles / 2)), segments[COUNT - 1].exit_cpu.regs[1]);
    for ([_]usize{ 0, COUNT - 1 }, 0..) |index, side| {
        semantic.mixU64(segments[index].rw_memory.words.len);
        for (segments[index].rw_memory.words) |word| {
            semantic.mixU32s(&.{ word.addr, if (side == 0) word.initial_word else word.final_word });
            try std.testing.expectEqual(word.initial_word, word.final_word);
        }
    }
    const execution_digest = semantic.digestBytes();
    var native_cells: u64 = 0;
    var native_max_log: u32 = 0;
    const template = @import("../block_v5_native_template_protocol_v3.zig");
    for (fixtures[0..COUNT]) |item| {
        inline for (.{ template.ColumnTree.fixed, template.ColumnTree.main, template.ColumnTree.interaction }) |tree| {
            const logs = try template.columnLogs(a, &item.owner.statement, item.owner.external_retirements, tree);
            defer a.free(logs);
            for (logs) |log| {
                native_cells += @as(u64, 1) << @intCast(log);
                native_max_log = @max(native_max_log, log);
            }
        }
    }
    const native_peak_bytes = budget.snapshot().peak_live_bytes;
    const native_ns = timer.read();
    std.debug.print("BLOCK_V6_SCALE_SOURCE profile={s} segments={d} cycles={d} base_steps={d} native_ns={d} native_cells={d} native_max_log={d} native_peak_bytes={d} workers=8 globals_open=true\n", .{ @tagName(selected), COUNT, cycles, base_steps, native_ns, native_cells, native_max_log, native_peak_bytes });
    if (tiling and COUNT <= 8) {
        const result = try bench.qualifyMeasured(a, policy_pointers[0..COUNT], capture_pointers[0..COUNT], selected, native_ns);
        try std.testing.expectEqual(cycles, result.span.last_cycle);
        std.debug.print("BLOCK_V6_TILE verified=true profile={s} segments={d} cycles={d} execution_digest={s} native_ns={d} recursive_ns={d} phase_sum_ns={d} air_cells={d} g_rows={d} root_bytes={d} charged_peak_bytes={d} globals_open=true\n", .{ @tagName(selected), COUNT, cycles, std.fmt.bytesToHex(execution_digest, .lower), native_ns, result.recursive_ns, native_ns + result.recursive_ns, result.costs.cells, result.costs.g_rows, result.proof_bytes, budget.snapshot().peak_live_bytes });
        return execution_digest;
    }
    if (tiling or selected == .experimental_q70_pow26_fold2 or selected == .experimental_q70_pow26_fold4 or std.process.hasEnvVarConstant("STWO_NATIVE_BATCH_ROOT_ONLY")) {
        var left = try bench.qualifyRetained(a, policy_pointers[0..8], capture_pointers[0..8], selected, 0);
        defer left.deinit();
        var right = try bench.qualifyRetained(a, policy_pointers[8..9], capture_pointers[8..9], selected, 0);
        defer right.deinit();
        const output = try spans.merge(&.{ left.measurement.span, right.measurement.span });
        try std.testing.expectEqual(@as(u32, @intCast(COUNT)), output.segment_count);
        try std.testing.expectEqual(cycles, output.last_cycle);
        std.debug.print("BLOCK_V6_SCALE_ROOT_INPUT profile={s} native_ns={d} batch8_ns={d} batch8_cells={d} complete_root=false\n", .{ @tagName(selected), native_ns, left.measurement.recursive_ns + right.measurement.recursive_ns, left.measurement.costs.cells + right.measurement.costs.cells });
        const upper = try @import("block_v6_native_batch_upper_test_support.zig").qualify(a, selected, &left, &right, output);
        if (tiling) {
            const recursive_ns = left.measurement.recursive_ns + right.measurement.recursive_ns + upper.recursive_ns;
            std.debug.print("BLOCK_V6_TILE verified=true profile={s} segments={d} cycles={d} execution_digest={s} native_ns={d} recursive_ns={d} phase_sum_ns={d} air_cells={d} g_rows={d} root_bytes={d} charged_peak_bytes={d} globals_open=true\n", .{ @tagName(selected), COUNT, cycles, std.fmt.bytesToHex(execution_digest, .lower), native_ns, recursive_ns, native_ns + recursive_ns, left.measurement.costs.cells + right.measurement.costs.cells + upper.costs.cells, left.measurement.costs.g_rows + right.measurement.costs.g_rows + upper.costs.g_rows, upper.proof_bytes, budget.snapshot().peak_live_bytes });
        }
        return execution_digest;
    }
    var measured: [5]bench.Measurement = undefined;
    var retained: [5]bench.Retained = undefined;
    var retained_count: usize = 0;
    defer for (retained[0..retained_count]) |*item| item.deinit();
    const ranges = [_][2]usize{ .{ 0, 4 }, .{ 4, 8 }, .{ 8, 9 }, .{ 0, 8 }, .{ 3, 6 } };
    for (ranges, &measured, 0..) |range, *result, i| {
        std.debug.print("BLOCK_V6_SCALE_BATCH profile={s} first={d} count={d}\n", .{ @tagName(selected), range[0], range[1] - range[0] });
        retained[i] = try bench.qualifyRetained(a, policy_pointers[range[0]..range[1]], capture_pointers[range[0]..range[1]], selected, 0);
        retained_count += 1;
        result.* = retained[i].measurement;
        try std.testing.expectEqual(range[0], result.span.first_index);
    }
    // Host bookkeeping checks only: these do not turn the batch proofs into
    // a recursively verified job root. The upper verifier is a separate gate.
    const fours = try spans.merge(&.{ measured[0].span, measured[1].span, measured[2].span });
    const eights = try spans.merge(&.{ measured[3].span, measured[2].span });
    try std.testing.expectEqualDeep(fours, eights);
    try std.testing.expectEqual(@as(u32, @intCast(COUNT)), fours.segment_count);
    try std.testing.expectEqual(cycles, fours.last_cycle);
    try std.testing.expectError(error.DiscontinuousV5PcClockSpan, spans.merge(&.{ measured[0].span, measured[2].span }));
    try std.testing.expectError(error.DiscontinuousV5PcClockSpan, spans.merge(&.{ measured[1].span, measured[0].span }));
    std.debug.print("BLOCK_V6_SCALE_PARTITIONS profile={s} native_ns={d} batch4_ns={d} batch8_ns={d} batch4_cells={d} batch8_cells={d} complete_root=false\n", .{ @tagName(selected), native_ns, measured[0].recursive_ns + measured[1].recursive_ns + measured[2].recursive_ns, measured[3].recursive_ns + measured[2].recursive_ns, measured[0].costs.cells + measured[1].costs.cells + measured[2].costs.cells, measured[3].costs.cells + measured[2].costs.cells });
    if (std.process.hasEnvVarConstant("STWO_NATIVE_BATCH_UPPER"))
        _ = try @import("block_v6_native_batch_upper_test_support.zig").qualify(a, selected, &retained[3], &retained[2], eights);
    return execution_digest;
}
