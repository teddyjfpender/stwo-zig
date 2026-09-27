//! Detached canonical block-v4 CPU verification from caller-pinned policies.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const bundle = @import("prover/block_v4_cpu_bundle_rehydrate_v1.zig");
const manifest = @import("prover/block_v4_cpu_trusted_manifest_v1.zig");
const policy = @import("prover/block_v4_cpu_trusted_recursion_v1.zig");
const receiver = @import("prover/block_v4_cpu_streaming_file_receiver_v1.zig");
const rss = @import("prover/block_v4_cpu_cli_rss_v1.zig");

pub fn main() !void {
    var total_timer = try std.time.Timer.start();
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    // ELF INPUT ORACLE MAX_CYCLES SCHEDULE BUNDLE_DIR BUNDLE_SHA
    // CANDIDATE_MANIFEST CANDIDATE_SHA FINAL_MANIFEST FINAL_SHA POLICY_SHA
    if (args.len != 13) return error.ExpectedBlockV4DetachedVerifyArguments;
    const max_cycles = std.fmt.parseInt(u32, args[4], 10) catch return error.InvalidBlockV4SegmentBudget;
    if (max_cycles == 0 or max_cycles > 1 << 22) return error.InvalidBlockV4SegmentBudget;
    const bundle_sha = try manifest.parseSha256Hex(args[7]);
    const candidate_sha = try manifest.parseSha256Hex(args[9]);
    const final_sha = try manifest.parseSha256Hex(args[11]);
    const policy_sha = try manifest.parseSha256Hex(args[12]);
    const host = try engine.host_budget_allocator.SharedHostBudget.create(backing, 40 * 1024 * 1024 * 1024);
    defer host.destroy();
    const a = host.allocator();
    const cwd = std.fs.cwd();
    const elf = try readBounded(a, cwd, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try readBounded(a, cwd, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try readBounded(a, cwd, args[3], 1024 * 1024);
    defer a.free(oracle);
    const schedule_json = try readBounded(a, cwd, args[5], 1024 * 1024);
    defer a.free(schedule_json);
    var dir = try cwd.openDir(args[6], .{});
    defer dir.close();
    var independent_policy = try policy.read(a, dir, policy_sha);
    defer independent_policy.deinit();
    const candidate_file = receiver.ManifestFile{ .dir = cwd, .path = args[8], .expected_sha256 = candidate_sha };
    const final_file = receiver.ManifestFile{ .dir = cwd, .path = args[10], .expected_sha256 = final_sha };
    var final = try manifest.read(a, cwd, args[10], final_sha);
    defer final.deinit();
    if (!std.meta.eql(independent_policy.view().job, final.trusted().job) or
        !std.meta.eql(independent_policy.view().forest_digest, final.trusted().forest_roster_digest) or
        !std.meta.eql(independent_policy.view().outer.expected_key_id, final.trusted().outer_key_id))
        return error.UntrustedBlockV4RecursionPolicy;
    var timer = try std.time.Timer.start();
    const result = try bundle.verifyCanonical(a, dir, bundle_sha, candidate_file, final_file, .{
        .elf = elf,
        .input = input,
        .oracle = oracle,
        .schedule_json = schedule_json,
        .max_segment_cycles = max_cycles,
    }, independent_policy.view().pins());
    const report = try std.json.Stringify.valueAlloc(a, .{
        .complete_block_verified = result == .complete_block_verified,
        .security = "CSP q70 PoW26",
        .detached_receiver_ns = timer.read(),
        .total_ns = total_timer.read(),
        .tracked_peak_bytes = host.snapshot().peak_live_bytes,
        .peak_rss_bytes = try rss.peakBytes(),
        .bundle_sha256 = std.fmt.bytesToHex(bundle_sha, .lower),
        .final_manifest_sha256 = std.fmt.bytesToHex(final_sha, .lower),
        .recursion_policy_sha256 = std.fmt.bytesToHex(policy_sha, .lower),
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}

fn readBounded(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, max: usize) ![]u8 {
    var file = try dir.openFile(name, .{});
    defer file.close();
    return file.readToEndAlloc(a, max);
}
