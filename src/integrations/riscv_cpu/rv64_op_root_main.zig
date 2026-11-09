//! Explicit experimental OP R5 physical-root producer and root-only receiver.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("rv64_ethereum_request.zig");
const Native = @import("poseidon2_outer/pure_p2_op_runtime.zig");
const Recursion = @import("poseidon2_outer/pure_p2_op_recursion.zig");
const Receiver = @import("poseidon2_outer/pure_p2_op_root_runtime.zig");

pub fn main() !void {
    const base = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, args);
    if (args.len < 5 or args.len > 6 or (!std.mem.eql(u8, args[1], "prove") and !std.mem.eql(u8, args[1], "verify"))) {
        std.debug.print("usage: rv64-op-root <prove|verify> config.json source-directory root-directory [resources.json]\n", .{});
        return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
    }
    const raw = try std.fs.cwd().readFileAlloc(base, args[2], 16384);
    defer base.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, base, raw, .{});
    defer config.deinit();
    var resources: Native.Resources = .{};
    var parsed_resources: ?std.json.Parsed(Native.Resources) = null;
    defer if (parsed_resources) |*parsed| parsed.deinit();
    if (args.len == 6) {
        const bytes = try std.fs.cwd().readFileAlloc(base, args[5], 16384);
        defer base.free(bytes);
        parsed_resources = try std.json.parseFromSlice(Native.Resources, base, bytes, .{});
        resources = parsed_resources.?.value;
    }
    if (resources.live_bytes == 0) return error.InvalidOpNativeResources;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(base, resources.live_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = if (config.value.workers != 0) config.value.workers else 8 });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        const profile = @import("poseidon2_outer/op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
        if (std.mem.eql(u8, args[1], "prove")) {
            // The source directory includes native proofs on this path. All
            // pending nodes and the final root/sidecar/templates are retained.
            var result = try Recursion.proveDirectory(a, config.value, args[3], profile, resources, .{ .artifact_directory = args[4] });
            defer result.deinit();
        } else {
            // This path loads source declarations and public RAM cells only;
            // it neither opens nor verifies native-op.bin.
            _ = try Receiver.verifyDirectory(a, config.value, args[3], args[4], profile, resources, .{});
        }
    }
    const final = budget.snapshot();
    if (final.live_bytes != 0) return error.OpRootResourceLeak;
    std.debug.print("OP_ROOT_TEARDOWN live_bytes=0 external_bytes=0 peak_bytes={}\n", .{final.peak_live_bytes});
}
