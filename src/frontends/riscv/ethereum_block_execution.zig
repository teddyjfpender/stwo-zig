//! Bounded full-validator execution preflight. This command makes no proof claim.
const std = @import("std");
const runner = @import("runner/mod.zig");
const Schedule = @import("runner/balanced_schedule.zig").Schedule;
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 6 or args.len > 8) return error.ExpectedElfInputOracleReportSegmentCyclesOptionalPcProfile;
    const collect_hints = args.len == 8;
    if (collect_hints and !std.mem.eql(u8, args[6], "collect-evm-hints")) return error.InvalidCollectionMode;
    const limit = try std.fmt.parseInt(u32, args[5], 10);
    if (limit == 0 or limit > 1 << 22) return error.InvalidSegmentBudget;
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const expected = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(expected);
    switch (try runner.elf_loader.requestedExecutionProfile(elf)) {
        .rv32im_zkvm_ethereum_v1 => try runForProfile(.rv32im_zkvm_ethereum_v1, a, args, elf, input, expected, limit, collect_hints),
        .rv32im_zkvm_ethereum_sha_v1 => try runForProfile(.rv32im_zkvm_ethereum_sha_v1, a, args, elf, input, expected, limit, collect_hints),
        else => return error.UnsupportedEthereumBlockProfile,
    }
}
fn runForProfile(comptime profile: @import("isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, args: []const [:0]u8, elf: []const u8, input: []const u8, expected: []const u8, limit: u32, collect_hints: bool) !void {
    const sha = profile == .rv32im_zkvm_ethereum_sha_v1;
    const Session = if (sha) runner.EthereumShaExecutionSession else runner.EthereumExecutionSession;
    var session = try Session.init(a, elf, .{
        .input = input,
        .stop_on_halt_flag = true,
        .strict_completion = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var timer = try std.time.Timer.start();
    var pc_counts = std.AutoHashMap(u32, u64).init(a);
    defer pc_counts.deinit();
    var profiled_cycles: u64 = 0;
    var cycles: u64 = 0;
    var keccak: u64 = 0;
    var recovery: u64 = 0;
    var sha_calls: u64 = 0;
    var segments: u32 = 0;
    var current = try session.startSegment(limit);
    var current_alive = true;
    defer if (current_alive) current.deinit();
    while (true) {
        const base = &current.base;
        if (base.segment_index != segments or base.global_first_cycle != cycles + 1)
            return error.ExecutionDiscontinuity;
        if (args.len == 7) for (base.execution_trace.rows.items) |row| {
            const entry = try pc_counts.getOrPut(row.pc);
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
            profiled_cycles += 1;
        };
        cycles = try std.math.add(u64, cycles, base.cycle_count);
        segments = try std.math.add(u32, segments, 1);
        const calls = if (sha) &current.extension else &current;
        keccak += calls.keccakf_calls.len();
        if (sha) sha_calls += calls.sha_calls.len();
        if (std.process.hasEnvVarConstant("STWO_ETHEREUM_RECOVERY_LOCATIONS")) {
            for (calls.signer_recovery_calls.records(), 0..) |call, index| {
                std.debug.print("BLOCK_RECOVERY ordinal={d} global_cycle={d} local_cycle={d} pc={d}\n", .{ recovery + index + 1, base.global_first_cycle + call.execution_clock - 1, call.execution_clock, call.pc });
            }
        }
        recovery += calls.signer_recovery_calls.len();
        std.debug.print("BLOCK_EXECUTION segments={d} cycles={d} keccak={d} recovery={d} sha256_compression={d} elapsed_ns={d}\n", .{ segments, cycles, keccak, recovery, sha_calls, timer.read() });
        if (base.continuation) |continuation| {
            // Continuation is a value; all trace/snapshot allocations are freed
            // before the next segment starts.
            current.deinit();
            current_alive = false;
            current = try session.resumeSegment(continuation, limit);
            current_alive = true;
        } else {
            const output = base.output orelse return error.MissingOutput;
            if (!base.isComplete()) return error.BlockOutputMismatch;
            if (collect_hints) {
                if (expected.len != 43 or output.len < 55 or !std.mem.eql(u8, output[0..43], expected) or !std.mem.eql(u8, output[43..51], "STWECR01")) return error.BlockOutputMismatch;
                const count = std.mem.readInt(u32, output[51..55], .little);
                const bytes = try std.math.divCeil(usize, count, 8);
                if (output.len != 55 + bytes) return error.InvalidRecoveryHintFooter;
                if (count % 8 != 0 and output[output.len - 1] >> @as(u3, @intCast(count % 8)) != 0) return error.InvalidRecoveryHintFooter;
                var collected = try std.fs.cwd().createFile(args[7], .{ .exclusive = true });
                defer collected.close();
                try collected.writeAll(output);
                try collected.sync();
            } else if (!std.mem.eql(u8, output, expected)) return error.BlockOutputMismatch;
            break;
        }
    }
    if (args.len == 7) {
        if (profiled_cycles + keccak + recovery + sha_calls != cycles) return error.IncompletePcProfile;
        const Entry = struct { pc: u32, instructions: u64 };
        const entries = try a.alloc(Entry, pc_counts.count());
        defer a.free(entries);
        var it = pc_counts.iterator();
        var at: usize = 0;
        while (it.next()) |entry| : (at += 1) entries[at] = .{ .pc = entry.key_ptr.*, .instructions = entry.value_ptr.* };
        const encoded = try std.json.Stringify.valueAlloc(a, .{ .base_instructions = profiled_cycles, .keccak_calls = keccak, .recovery_calls = recovery, .sha256_compression_calls = sha_calls, .cycles = cycles, .elf_sha256 = digest(elf), .entries = entries }, .{});
        defer a.free(encoded);
        var profile_file = try std.fs.cwd().createFile(args[6], .{ .exclusive = true });
        defer profile_file.close();
        try profile_file.writeAll(encoded);
        try profile_file.sync();
    }
    const schedule = try Schedule.init(cycles, limit);
    const report = try std.json.Stringify.valueAlloc(a, .{
        .execution_verified = true,
        .execution_profile = @tagName(profile),
        .pc_profiled = args.len == 7,
        .recovery_hint_collection = collect_hints,
        .proof_verified = false,
        .cycles = cycles,
        .segments = segments,
        .planned_proof_segments = schedule.segments,
        .max_segment_cycles = limit,
        .keccak_calls = keccak,
        .recovery_calls = recovery,
        .sha256_compression_calls = sha_calls,
        .elapsed_ns = timer.read(),
        .elf_sha256 = digest(elf),
        .input_sha256 = digest(input),
        .output_sha256 = digest(expected),
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    var file = try std.fs.cwd().createFile(args[4], .{ .exclusive = true });
    defer file.close();
    try file.writeAll(report);
    try file.sync();
}
fn digest(bytes: []const u8) [64]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return std.fmt.bytesToHex(result, .lower);
}
