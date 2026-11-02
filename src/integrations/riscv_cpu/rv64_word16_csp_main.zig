//! Explicit CSP ABI; no Ethereum config reinterpretation or legacy proof path.
const std = @import("std");
const Image = @import("word16_qualification/csp_image.zig");
const Execution = @import("word16_qualification/csp_execution.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 3 and std.mem.eql(u8, args[1], "--inspect-proof")) return @import("word16_qualification/csp_execution.zig").stdout(a, try @import("word16_execution/pcs_metrics.zig").inspectFile(a, args[2]));
    if (args.len != 4) return error.ExpectedProveOrVerifyConfigDirectory;
    const experiment = std.mem.eql(u8, args[1], "--prove-fold4") or std.mem.eql(u8, args[1], "--verify-fold4");
    const proving = std.mem.eql(u8, args[1], "--prove") or std.mem.eql(u8, args[1], "--prove-fold4");
    if (!proving and !std.mem.eql(u8, args[1], "--verify") and !std.mem.eql(u8, args[1], "--verify-fold4")) return error.ExpectedProveOrVerifyConfigDirectory;
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Image.Config, a, raw, .{});
    defer parsed.deinit();
    var image = try Image.Owner.init(a, parsed.value);
    defer image.deinit();
    const Work = @import("stwo_prover_engine").work_pool;
    var pool: Work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = parsed.value.workers, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const Suite = @import("word16_execution/pcs_suite.zig").Suite;
    const suite = if (experiment) Suite.experimentalFold4() else Suite.production();
    if (proving) try Execution.proveWithSuite(a, &image, args[3], suite) else try Execution.verifyWithSuite(a, &image, args[3], suite);
}
