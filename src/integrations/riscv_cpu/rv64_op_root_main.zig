//! Explicit experimental OP physical-root producer and root-only receiver.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("rv64_ethereum_request.zig");
const Native = @import("poseidon2_outer/pure_p2_op_runtime.zig");
const Recursion = @import("poseidon2_outer/pure_p2_op_recursion.zig");
const Receiver = @import("poseidon2_outer/pure_p2_op_root_runtime.zig");
const R6 = @import("poseidon2_outer/native_omul/recursion.zig");
const R6Receiver = @import("poseidon2_outer/native_omul/root_runtime.zig");
const R7 = @import("poseidon2_outer/native_dot/execution_collect.zig");
const R7Receiver = @import("poseidon2_outer/native_dot/execution_runtime.zig");
const Options = @import("poseidon2_outer/root_cli_options.zig");
const usage = "usage: rv64-op-root [--r6|--r7] [--truth-local-gkr] [--miller-local-gkr] [--miller-cache-mib=N|--miller-prover-cache-mib=N] <prove|verify> config.json source-directory root-directory [resources.json]\n";

pub fn main() !void {
    const base = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, args);
    if (args.len < 5 or args.len > 10) {
        std.debug.print(usage, .{});
        return error.ExpectedOpRootModeConfigSourceAndRootDirectory;
    }
    var words: [9][]const u8 = undefined;
    for (args[1..], words[0 .. args.len - 1]) |arg, *word| word.* = arg;
    const command = Options.parse(words[0 .. args.len - 1]) catch |err| {
        std.debug.print(usage, .{});
        return err;
    };
    const raw = try std.fs.cwd().readFileAlloc(base, command.config, 16384);
    defer base.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, base, raw, .{});
    defer config.deinit();
    const source_suite: ?@import("poseidon2_outer/pure_p2_source_suite.zig").Suite = if (command.miller_local_gkr)
        .{ .truth = if (command.truth_local_gkr) .local_gkr else .classic, .miller = .local_gkr }
    else
        null;
    const native_options = Native.Options{ .source_suite = source_suite, .truth_local_gkr = source_suite == null and command.truth_local_gkr };
    var resources: Native.Resources = .{};
    var parsed_resources: ?std.json.Parsed(Native.Resources) = null;
    defer if (parsed_resources) |*parsed| parsed.deinit();
    if (command.resources) |path| {
        const bytes = try std.fs.cwd().readFileAlloc(base, path, 16384);
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
        if (command.mode == .prove) {
            // The source directory includes native proofs on this path. All
            // pending nodes and the final root/sidecar/templates are retained.
            if (command.r7) {
                var result = try R7.proveDirectory(a, config.value, command.source, profile, resources, native_options, .{ .artifact_directory = command.root });
                defer result.deinit();
            } else if (command.r6) {
                var result = try R6.proveDirectoryWithOptions(a, config.value, command.source, profile, resources, native_options, .{ .artifact_directory = command.root, .miller_cache_bytes = command.miller_prover_cache_bytes });
                defer result.deinit();
                if (result.miller_cache) |cache| std.debug.print("OP_ROOT_MILLER_PROVER_CACHE limit_bytes={} classes={} hits={} misses={} borrowed_leaves={} fallbacks={} peak_requested_bytes={}\n", .{ command.miller_prover_cache_bytes, cache.classes, cache.hits, cache.misses, cache.borrowed_leaves, cache.fallbacks, cache.peak_requested_bytes });
            } else {
                var result = try Recursion.proveDirectory(a, config.value, command.source, profile, resources, .{ .artifact_directory = command.root });
                defer result.deinit();
            }
        } else {
            // This path loads source declarations and public RAM cells only;
            // it neither opens nor verifies native-op.bin.
            if (command.r7) {
                _ = try R7Receiver.verifyDirectory(a, config.value, command.source, command.root, profile, resources, native_options, .{});
            } else if (command.r6) {
                const result = try R6Receiver.verifyDirectoryWithOptions(a, config.value, command.source, command.root, profile, resources, native_options, .{ .miller_cache_bytes = command.miller_cache_bytes });
                if (result.miller_cache) |cache| std.debug.print("OP_ROOT_MILLER_VERIFIER_CACHE limit_bytes={} classes={} hits={} misses={} borrowed_leaves={} fallbacks={} peak_requested_bytes={}\n", .{ command.miller_cache_bytes, cache.classes, cache.hits, cache.misses, cache.borrowed_leaves, cache.fallbacks, cache.peak_requested_bytes });
            } else {
                _ = try Receiver.verifyDirectory(a, config.value, command.source, command.root, profile, resources, .{});
            }
        }
    }
    const final = budget.snapshot();
    if (final.live_bytes != 0) return error.OpRootResourceLeak;
    std.debug.print("OP_ROOT_TEARDOWN live_bytes=0 external_bytes=0 peak_bytes={}\n", .{final.peak_live_bytes});
}
