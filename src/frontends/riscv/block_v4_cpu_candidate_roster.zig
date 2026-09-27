//! Read-only candidate-key roster command. Its outputs require an independent
//! SHA-256 pin before they can serve as trusted block-v4 policy.
const std = @import("std");
const candidate = @import("prover/block_v4_cpu_candidate_roster_v1.zig");
const manifest = @import("prover/block_v4_cpu_trusted_manifest_v1.zig");

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 8 or args.len > 11) return error.ExpectedElfInputOracleMaxCyclesScheduleSha256OutputDirOptionalProbePrefixHostGiBAndTargetIndex;
    const max_cycles = try std.fmt.parseInt(u32, args[4], 10);
    if (max_cycles == 0 or max_cycles > 1 << 22) return error.InvalidSegmentBudget;
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    const schedule = try std.fs.cwd().readFileAlloc(a, args[5], 1024 * 1024);
    defer a.free(schedule);
    const raw_probe: u32 = if (args.len >= 9) try std.fmt.parseInt(u32, args[8], 10) else 0;
    const probe_prefix: ?u32 = if (raw_probe == 0) null else raw_probe;
    const host_gib: usize = if (args.len >= 10) try std.fmt.parseInt(usize, args[9], 10) else 16;
    if (host_gib < 1 or host_gib > 64) return error.InvalidCandidateHostLimit;
    const target_index: ?u32 = if (args.len == 11) try std.fmt.parseInt(u32, args[10], 10) else null;
    var roster = candidate.derive(a, .{
        .elf = elf,
        .public_input = input,
        .oracle = oracle,
        .schedule_json = schedule,
        .expected_schedule_sha256 = try manifest.parseSha256Hex(args[6]),
        .max_segment_cycles = max_cycles,
        .host_limit_bytes = host_gib * 1024 * 1024 * 1024,
        .progress = progress,
        .probe_prefix_keys = probe_prefix,
        .probe_only_index = target_index,
    }) catch |err| {
        if (err == error.CandidatePrefixProbeComplete) {
            std.debug.print("BLOCK_V4_CANDIDATE_PROBE_COMPLETE keys={d} no_manifest=true\n", .{probe_prefix.?});
            return;
        }
        if (err == error.CandidateTargetProbeComplete) {
            std.debug.print("BLOCK_V4_CANDIDATE_TARGET_COMPLETE index={d} no_manifest=true\n", .{target_index.?});
            return;
        }
        return err;
    };
    defer roster.deinit();
    try std.fs.cwd().makePath(args[7]);
    var dir = try std.fs.cwd().openDir(args[7], .{});
    defer dir.close();
    try roster.write(dir);
    const hash = std.fmt.bytesToHex(roster.report.manifest_sha256, .lower);
    std.debug.print("BLOCK_V4_CANDIDATE_ROSTER scope={s} segments={d} cycles={d} elapsed_ns={d} tracked_work_peak_bytes={d} manifest_sha256={s}\n", .{
        roster.report.scope,      roster.report.segment_count,           roster.report.total_cycles,
        roster.report.elapsed_ns, roster.report.tracked_work_peak_bytes, &hash,
    });
}

fn progress(completed: u32, total: u32) void {
    if (completed % 16 == 0 or completed == total)
        std.debug.print("BLOCK_V4_CANDIDATE_PROGRESS completed={d} total={d}\n", .{ completed, total });
}
