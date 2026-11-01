//! Explicit benchmark tool only; parameters do not come from proof metadata.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Image = @import("word16_qualification/sail_image.zig");
const Run = @import("word16_qualification/om_sail.zig");
const Recycler = @import("rv64_large_block_recycler.zig").LargeBlockRecycler;
pub fn main() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, 4 << 30);
    defer recycler.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(recycler.allocator(), 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedModeConfigDirectory;
    const proving = std.mem.eql(u8, args[1], "prove-control") or std.mem.eql(u8, args[1], "prove-candidate");
    const candidate = std.mem.eql(u8, args[1], "prove-candidate") or std.mem.eql(u8, args[1], "verify-candidate");
    if (!proving and !std.mem.eql(u8, args[1], "verify-control") and !std.mem.eql(u8, args[1], "verify-candidate")) return error.ExpectedModeConfigDirectory;
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Image.Config, a, raw, .{});
    defer parsed.deinit();
    if (parsed.value.workers == 0 or parsed.value.workers > @import("word16_global_execution/services/schedule.zig").MAX_TOTAL_WORKERS) return error.InvalidOracleWorkers;
    var image = try Image.Owner.init(a, parsed.value);
    defer image.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = parsed.value.workers, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var verification: ?Run.Verification = null;
    if (proving) try Run.prove(a, &image, args[3], candidate) else verification = try Run.verify(a, &image, args[3], candidate);
    try @import("word16_qualification/csp_execution.zig").stdout(a, .{ .verification = verification, .requested_budget = budget.snapshot(), .recycler_cache_cap_bytes = @as(u64, 4) << 30, .recycler = recycler.stats(), .security_qualified = false });
}
