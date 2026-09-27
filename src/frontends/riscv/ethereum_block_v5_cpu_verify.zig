//! Fresh complete verification without ELF replay or producer memory.
//! Arguments are independent public/file pins followed by INPUT and BUNDLE_DIR:
//! POLICY_SHA BUNDLE_SHA FOREST_SHA JOB_ID SOURCE_IMAGE PROGRAM INITIAL_RW FINAL_RW INPUT DIR.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Stack = @import("prover/block_v5_cpu_canonical_stack_v1.zig");
const Detached = Stack.Detached;
const Parent = @import("recursion/blake3_execution_parent_protocol.zig");
const hex = @import("prover/block_v4_cpu_trusted_manifest_v1.zig").parseSha256Hex;
pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 11) return error.ExpectedEightIndependentPinsInputAndBundleDirectory;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 16 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var input_file = try std.fs.cwd().openFile(args[9], .{});
    defer input_file.close();
    const input = try input_file.readToEndAlloc(a, 64 * 1024 * 1024);
    defer a.free(input);
    var dir = try std.fs.cwd().openDir(args[10], .{});
    defer dir.close();
    const profile = Parent.Profile.csp_q70_pow26;
    const options = Stack.ProductOptions.options(profile, 1024, 4);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = options.workers });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var timer = try std.time.Timer.start();
    const verified = try Detached.verify(a, dir, input, .{
        .receiver_policy_sha256 = try hex(args[1]),
        .bundle_manifest_sha256 = try hex(args[2]),
        .forest_manifest_sha256 = try hex(args[3]),
        .identity = .{ .job_id = try hex(args[4]), .source_image_digest = try hex(args[5]), .program_root = try hex(args[6]), .initial_rw_root = try hex(args[7]), .final_rw_root = try hex(args[8]), .config = profile.config() },
    }, .{ .metadata = options.metadata, .store = options.store, .forest = options.manifest });
    const report = try std.json.Stringify.valueAlloc(a, .{ .format_version = Stack.REPORT_VERSION, .architecture = Stack.ARCHITECTURE, .complete_block_verified = true, .fresh_process = true, .verification_ns = timer.read(), .peak_rss_bytes = try @import("prover/block_v4_cpu_cli_rss_v1.zig").peakBytes(), .tracked_peak_bytes = budget.snapshot().peak_live_bytes, .verification = verified }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
