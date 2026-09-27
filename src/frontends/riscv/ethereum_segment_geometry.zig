//! Admission-only sizing of real block segments. This does not produce a proof.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const runner = @import("runner/mod.zig");
const columns = @import("prover/blake3_commitment_columns.zig");
const plan_mod = @import("prover/blake3_commitment_plan.zig");

pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.smp_allocator);
    defer std.process.argsFree(std.heap.smp_allocator, args);
    if (args.len != 6 and args.len != 7) return error.ExpectedElfInputOracleMaximumCyclesTargetIndex;
    const limit = try std.fmt.parseInt(u32, args[4], 10);
    const target: ?u32 = if (std.mem.eql(u8, args[5], "all")) null else try std.fmt.parseInt(u32, args[5], 10);
    if (limit == 0 or limit > 1 << 22) return error.InvalidSegmentBudget;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 8 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var schedule_override: ?@import("runner/segment_schedule_override.zig").Owned = if (args.len == 7) try @import("runner/segment_schedule_override.zig").Owned.read(a, args[6]) else null;
    defer if (schedule_override) |*owned| owned.deinit();
    const override = if (schedule_override) |*owned| owned else null;
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    switch (try runner.elf_loader.requestedExecutionProfile(elf)) {
        .rv32im_zkvm_ethereum_v1 => try run(.rv32im_zkvm_ethereum_v1, a, budget, elf, input, oracle, limit, target, override),
        .rv32im_zkvm_ethereum_sha_v1 => try run(.rv32im_zkvm_ethereum_sha_v1, a, budget, elf, input, oracle, limit, target, override),
        else => return error.UnsupportedEthereumBlockProfile,
    }
}
fn run(comptime profile: @import("isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, budget: *engine.host_budget_allocator.SharedHostBudget, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, target: ?u32, override: ?*const @import("runner/segment_schedule_override.zig").Owned) !void {
    const sha = profile == .rv32im_zkvm_ethereum_sha_v1;
    const Session = if (sha) runner.EthereumShaExecutionSession else runner.EthereumExecutionSession;
    var timer = try std.time.Timer.start();
    var pre = try @import("prover/blake3_execution_preflight.zig").runEthereumForProfile(profile, a, elf, input, oracle, limit);
    if (override) |owned| pre.schedule = try owned.scheduleExact(pre.last.cycle, limit, pre.required_terminal_cycles);
    if (target) |index| if (index >= pre.schedule.segments) return error.InvalidSegmentIndex;
    var session = try Session.init(a, elf, .{ .input = input, .strict_completion = true, .stop_on_halt_flag = true, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(try pre.schedule.budget(0));
    var live = true;
    defer if (live) segment.deinit();
    var all_fit = true;
    var checked: u32 = 0;
    var maximum_rows: columns.Counts = @splat(0);
    for (0..pre.schedule.segments) |i| {
        const index: u32 = @intCast(i);
        if (segment.base.global_first_cycle != try pre.schedule.firstCycle(index) or segment.base.cycle_count != try pre.schedule.budget(index)) return error.ReplayScheduleMismatch;
        const last = index + 1 == pre.schedule.segments;
        if (segment.base.isComplete() != last) return error.ReplayCompletionMismatch;
        if (last and !std.mem.eql(u8, segment.base.output orelse return error.MissingOutput, oracle)) return error.ReplayOutputMismatch;
        if (target == null or target.? == index) {
            const counts = try reportSegment(profile, a, budget, &segment, pre.schedule.segments, limit, index, &timer);
            for (counts, &maximum_rows) |count, *maximum| {
                maximum.* = @max(maximum.*, count);
                if (count > @as(usize, 1) << @intCast(@import("prover/blake3_commitment_geometry.zig").MAX_LOG_SIZE)) all_fit = false;
            }
            checked += 1;
            if (target != null) return;
        }
        if (last) break;
        const continuation = segment.base.continuation orelse return error.MissingContinuation;
        segment.deinit();
        live = false;
        segment = try session.resumeSegment(continuation, try pre.schedule.budget(index + 1));
        live = true;
    }
    if (checked != pre.schedule.segments) return error.IncompleteGeometryScan;
    const summary = try std.json.Stringify.valueAlloc(a, .{
        .kind = "summary",
        .proof_verified = false,
        .segments_checked = checked,
        .cycles = pre.last.cycle,
        .all_commitment_traces_fit = all_fit,
        .maximum_commitment_rows = maximum_rows,
        .maximum_hash_log = @import("prover/blake3_commitment_geometry.zig").MAX_LOG_SIZE,
        .sizing_peak_bytes = budget.snapshot().peak_live_bytes,
        .sizing_ns = timer.read(),
    }, .{});
    defer a.free(summary);
    try std.fs.File.stdout().writeAll(summary);
    try std.fs.File.stdout().writeAll("\n");
}
fn reportSegment(comptime profile: @import("isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, budget: *engine.host_budget_allocator.SharedHostBudget, segment: anytype, segments: u32, limit: u32, target: u32, timer: *std.time.Timer) !columns.Counts {
    const sha = profile == .rv32im_zkvm_ethereum_sha_v1;
    var io = try @import("prover/blake3_segment_public.zig").Owned.init(a, &segment.base);
    defer io.deinit();
    const tapes = if (sha) &segment.extension else segment;
    const sources = if (sha) .{ segment.base.execution_trace.rows.items, tapes.keccakf_execution_rows.rows(), tapes.signer_recovery_execution_rows.rows(), tapes.sha_calls.records() } else .{ segment.base.execution_trace.rows.items, tapes.keccakf_execution_rows.rows(), tapes.signer_recovery_execution_rows.rows() };
    var memory = try @import("prover/blake3_commitment_witness.zig").build(a, @import("air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = profile }, sources, &segment.base.rw_memory, @import("prover/commitment_program_witness.zig").completionFetch(io.data.completion), 100);
    defer memory.deinit();
    try memory.bindPublic(&io.data);
    var plan = try memory.plan(a);
    defer plan.deinit();
    const admission = try plan_mod.Admission.init(&plan, try plan.identity());
    const counts = try columns.rowCounts(a, admission);
    var fits = true;
    for (counts) |count| if (count > @as(usize, 1) << @intCast(@import("prover/blake3_commitment_geometry.zig").MAX_LOG_SIZE)) {
        fits = false;
    };
    const report = try std.json.Stringify.valueAlloc(a, .{
        .proof_verified = false,
        .scope = "commitment trace geometry only; prover and recursive memory remain unqualified",
        .segments = segments,
        .target = target,
        .maximum_cycles = limit,
        .cycles = segment.base.cycle_count,
        .global_first_cycle = segment.base.global_first_cycle,
        .keccak_calls = tapes.keccakf_calls.len(),
        .recovery_calls = tapes.signer_recovery_calls.len(),
        .sha_calls = if (sha) tapes.sha_calls.len() else 0,
        .commitment_rows = counts,
        .commitment_trace_fits = fits,
        .sizing_peak_bytes = budget.snapshot().peak_live_bytes,
        .sizing_ns = timer.read(),
        .maximum_hash_log = @import("prover/blake3_commitment_geometry.zig").MAX_LOG_SIZE,
    }, .{});
    defer a.free(report);
    var out = std.fs.File.stdout();
    try out.writeAll(report);
    try out.writeAll("\n");
    return counts;
}
