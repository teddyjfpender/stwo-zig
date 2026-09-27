//! Fast host-only census of every real block memory access and first-touch key.
//! No proof is produced; the roster is a planning input for separately proved
//! initial-value providers and never establishes memory authority on its own.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const runner = @import("runner/mod.zig");
const preflight = @import("prover/blake3_execution_preflight.zig");
const Replay = @import("prover/block_memory_replay.zig").Replay;
const InitialSource = @import("prover/block_memory_replay.zig").InitialSource;

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 7 and args.len != 8)
        return error.ExpectedElfInputOracleMaxCyclesRosterReportOptionalSchedule;
    const max_cycles = try std.fmt.parseInt(u32, args[4], 10);
    if (max_cycles == 0 or max_cycles > 1 << 22) return error.InvalidSegmentBudget;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 16 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    var schedule_override: ?@import("runner/segment_schedule_override.zig").Owned = if (args.len == 8)
        try @import("runner/segment_schedule_override.zig").Owned.read(a, args[7])
    else
        null;
    defer if (schedule_override) |*schedule| schedule.deinit();
    const override = if (schedule_override) |*schedule| schedule else null;
    switch (try runner.elf_loader.requestedExecutionProfile(elf)) {
        .rv32im_zkvm_ethereum_v1 => try run(.rv32im_zkvm_ethereum_v1, a, budget, args[5], args[6], elf, input, oracle, max_cycles, override),
        .rv32im_zkvm_ethereum_sha_v1 => try run(.rv32im_zkvm_ethereum_sha_v1, a, budget, args[5], args[6], elf, input, oracle, max_cycles, override),
        else => return error.UnsupportedEthereumBlockProfile,
    }
}

fn run(
    comptime profile: @import("isa/execution_profile.zig").ExecutionProfile,
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    roster_path: []const u8,
    report_path: []const u8,
    elf: []const u8,
    input: []const u8,
    oracle: []const u8,
    max_cycles: u32,
    override: ?*const @import("runner/segment_schedule_override.zig").Owned,
) !void {
    const Session = if (profile == .rv32im_zkvm_ethereum_sha_v1)
        runner.EthereumShaExecutionSession
    else
        runner.EthereumExecutionSession;
    var timer = try std.time.Timer.start();
    var pre = try preflight.runEthereumForProfile(profile, a, elf, input, oracle, max_cycles);
    if (override) |schedule| pre.schedule = try schedule.scheduleExact(pre.last.cycle, max_cycles, pre.required_terminal_cycles);
    var session = try Session.init(a, elf, .{
        .input = input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var current = try session.startSegment(try pre.schedule.budget(0));
    var live = true;
    defer if (live) current.deinit();
    const spool_path = try std.fmt.allocPrint(a, "{s}.spool", .{roster_path});
    defer a.free(spool_path);
    try std.fs.cwd().makeDir(spool_path);
    defer std.fs.cwd().deleteTree(spool_path) catch {};
    var spool_dir = try std.fs.cwd().openDir(spool_path, .{});
    defer spool_dir.close();
    var replay = try Replay.initFromSnapshot(a, spool_dir, current.base.entry_cpu.regs, &current.base.rw_memory, 1 << 18);
    defer replay.deinit();
    if (!std.meta.eql(try replay.initialRwRoot(), pre.first.machine.rw_memory))
        return error.BlockInitialRwRootMismatch;
    var initial_rw_nonzero: u64 = 0;
    var initial_program_nonzero: u64 = 0;
    const initial_roster_path = try std.fmt.allocPrint(a, "{s}.initial-nonzero.bin", .{roster_path});
    defer a.free(initial_roster_path);
    var initial_roster = try std.fs.cwd().createFile(initial_roster_path, .{ .exclusive = true });
    defer initial_roster.close();
    var initial_roster_hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (replay.words) |word| {
        if (word.value == 0) continue;
        if (word.source == .program_root) {
            initial_program_nonzero += 1;
            continue;
        }
        initial_rw_nonzero += 1;
        var record: [8]u8 = undefined;
        std.mem.writeInt(u32, record[0..4], word.address, .little);
        std.mem.writeInt(u32, record[4..8], word.value, .little);
        try initial_roster.writeAll(&record);
        initial_roster_hash.update(&record);
    }
    try initial_roster.sync();
    for (0..pre.schedule.segments) |slot| {
        const index: u32 = @intCast(slot);
        if (current.base.segment_index != index or current.base.global_first_cycle != try pre.schedule.firstCycle(index) or
            current.base.cycle_count != try pre.schedule.budget(index)) return error.ReplayScheduleMismatch;
        const last = index + 1 == pre.schedule.segments;
        if (current.base.isComplete() != last) return error.ReplayCompletionMismatch;
        if (last and !std.mem.eql(u8, current.base.output orelse return error.MissingOutput, oracle))
            return error.ReplayOutputMismatch;
        try replay.appendResult(&current.base);
        if (last) break;
        const continuation = current.base.continuation orelse return error.MissingContinuation;
        current.deinit();
        live = false;
        current = try session.resumeSegment(continuation, try pre.schedule.budget(index + 1));
        live = true;
    }
    const event_count = replay.spooler.event_count;
    var sorted = try replay.finish();
    sorted.deinit();
    var first_touches = try replay.firstTouches();
    defer first_touches.deinit();
    var file = try std.fs.cwd().createFile(roster_path, .{ .exclusive = true });
    defer file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [10 * 1024]u8 = undefined;
    var buffered: usize = 0;
    var counts: [4]u64 = @splat(0);
    var register_mask: u32 = 0;
    while (try first_touches.next()) |item| {
        var record: [10]u8 = undefined;
        record[0] = item.space;
        std.mem.writeInt(u32, record[1..5], item.address, .little);
        std.mem.writeInt(u32, record[5..9], item.value, .little);
        record[9] = @intFromEnum(item.source);
        @memcpy(buffer[buffered..][0..10], &record);
        buffered += 10;
        if (buffered == buffer.len) {
            try file.writeAll(&buffer);
            hasher.update(&buffer);
            buffered = 0;
        }
        counts[@intFromEnum(item.source)] += 1;
        if (item.source == .register) register_mask |= @as(u32, 1) << @intCast(item.address);
    }
    if (buffered != 0) {
        try file.writeAll(buffer[0..buffered]);
        hasher.update(buffer[0..buffered]);
    }
    try file.sync();
    const report = try std.json.Stringify.valueAlloc(a, .{
        .scope = "host-only execution replay and sorted first-touch roster; no STARK proof",
        .proof_verified = false,
        .execution_profile = @tagName(profile),
        .segments = pre.schedule.segments,
        .cycles = pre.last.cycle,
        .memory_events = event_count,
        .first_touch_keys = first_touches.count,
        .register_mask = register_mask,
        .initial_snapshot_nonzero_rw_words = initial_rw_nonzero,
        .initial_snapshot_nonzero_program_words = initial_program_nonzero,
        .initial_snapshot_nonzero_rw_roster = initial_roster_path,
        .initial_snapshot_nonzero_rw_roster_sha256 = std.fmt.bytesToHex(initial_roster_hash.finalResult(), .lower),
        .source_counts = .{
            .register = counts[@intFromEnum(InitialSource.register)],
            .rw_root = counts[@intFromEnum(InitialSource.rw_root)],
            .public_input_in_rw_root = counts[@intFromEnum(InitialSource.public_input)],
            .program_root = counts[@intFromEnum(InitialSource.program_root)],
        },
        .record_format = "10 bytes: space u8, address LE u32, initial value LE u32, source enum u8",
        .roster_sha256 = std.fmt.bytesToHex(hasher.finalResult(), .lower),
        .elapsed_ns = timer.read(),
        .peak_tracked_bytes = budget.snapshot().peak_live_bytes,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    var report_file = try std.fs.cwd().createFile(report_path, .{ .exclusive = true });
    defer report_file.close();
    try report_file.writeAll(report);
    try report_file.sync();
}
