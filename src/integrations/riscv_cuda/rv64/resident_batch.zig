//! Same native producer, many requests, one GPU pool and bounded immutable setup.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = CPU.rv64_ethereum_gkr_main;
const Pool = @import("resident_pool.zig").Pool;
const Router = @import("resident_router.zig");
const ReadyPolicy = @import("resident_ready_policy.zig");
const Block = struct { request: []const u8, jobs: []const u8 = "-", prefix_count: u32 = 0, expected_cpu_segments: usize };
const Manifest = struct {
    schema: []const u8,
    blocks: std.json.ArrayHashMap(Block),
    execution_order: []const u64,
    resources: std.json.Value,
    repeat: u8 = 1,
    profile: []const u8 = "conjectured128_b2_q108_p20_fold4",
    immutable_host_key_bytes: usize = 4 << 30,
    immutable_device_bytes: u64 = 512 << 20,
    combined_immutable_device_bytes: u64 = 2 << 30,
    combined_host_bytes: usize = 48 << 30,
    recursion_mode: ReadyPolicy.Mode = .serial,
    recursion_device_fixed_candidate: bool = false,
    recursion_worker_budget: usize = 0,
    recursion_max_pending_authorities: usize = 17,
};
pub fn run(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, output: []const u8) !void {
    return runMode(a, library, manifest_path, output, false);
}
pub fn runCombined(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, output: []const u8) !void {
    return runMode(a, library, manifest_path, output, true);
}
fn runMode(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, output: []const u8, comptime combined: bool) !void {
    const raw = try std.fs.cwd().readFileAlloc(a, manifest_path, 1 << 20);
    defer a.free(raw);
    var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const manifest = parsed.value;
    try @import("serial_fixed_policy.zig").validate(combined, @tagName(manifest.recursion_mode), manifest.recursion_device_fixed_candidate);
    const ready_mode = combined and manifest.recursion_mode == .ready_candidate;
    if (!combined and manifest.recursion_mode != .serial) return error.ReadyRecursionRequiresCombinedBatch;
    const manifest_sha256 = blk: {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
        break :blk digest;
    };
    if (!std.mem.eql(u8, manifest.schema, "rv64-ethereum-basket-inputs/v1") or manifest.execution_order.len == 0 or manifest.execution_order.len > 256 or manifest.repeat == 0 or manifest.repeat > 16) return error.InvalidResidentBatchManifest;
    // This entry never admits the host-retained comparison route.
    if (std.process.hasEnvVarConstant("STWO_RV64_GPU_HOST_RETAINED") or !std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE") or !std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING")) return error.ResidentBatchRequiresDevicePipeline;
    if (manifest.resources != .object or (manifest.resources.object.get("park_main") orelse return error.ResidentPipelineCannotParkMain) != .bool or manifest.resources.object.get("park_main").?.bool) return error.ResidentPipelineCannotParkMain;
    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var first_name: [24]u8 = undefined;
    const first = manifest.blocks.map.get(try std.fmt.bufPrint(&first_name, "{d}", .{manifest.execution_order[0]})) orelse return error.MissingResidentBatchBlock;
    if (combined) {
        _ = try ReadyPolicy.workers(manifest.recursion_mode, config.ids, manifest.recursion_worker_budget, manifest.recursion_max_pending_authorities);
        if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_CAPS")) @memset(config.caps, 28 << 30);
        for (config.caps) |cap| if (cap > 28 << 30 or manifest.combined_immutable_device_bytes == 0 or manifest.combined_immutable_device_bytes > cap) return error.InvalidCombinedBatchBudget;
        if (manifest.combined_host_bytes == 0 or manifest.immutable_host_key_bytes > manifest.combined_host_bytes) return error.InvalidCombinedBatchBudget;
        for (manifest.execution_order) |block| {
            var name: [24]u8 = undefined;
            const item = manifest.blocks.map.get(try std.fmt.bufPrint(&name, "{d}", .{block})) orelse return error.MissingResidentBatchBlock;
            if (item.prefix_count != 0 or !std.mem.eql(u8, item.jobs, "-")) return error.CombinedRequiresCompleteDirectExecution;
            try config.validatePlan(cpuCount(item));
        }
    }
    const budget: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget = if (combined) try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, manifest.combined_host_bytes) else null;
    defer if (budget) |owner| owner.destroy();
    var recycler = Main.Recycler.init(if (budget) |owner| owner.allocator() else std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    const base = recycler.allocator();
    var session = try Main.ResidentSession.init(base, manifest.immutable_host_key_bytes);
    defer session.deinit();
    const pool = try Pool.createWithBinding(if (combined) base else a, library, config, cpuCount(first), true);
    defer pool.deinit();
    try pool.stages().requireFullyResident();
    var outer: if (combined) ?@import("outer_source.zig").Context else void = if (combined) (if (ready_mode) null else try @import("outer_source.zig").Context.init(base, &pool.devices[0].native, &pool.devices[0].trace, &pool.devices[0].composition)) else {};
    defer if (combined) {
        if (outer) |*context| context.deinit();
    };
    const ready: if (combined) ?*@import("resident_ready.zig").Context else void = if (combined) (if (ready_mode) try @import("resident_ready.zig").Context.createWithDeviceFixed(base, pool, config.ids, manifest.recursion_worker_budget, manifest.recursion_max_pending_authorities, manifest.recursion_device_fixed_candidate) else null) else {};
    defer if (combined) {
        if (ready) |context| context.deinit();
    };
    const factory = if (combined) (if (outer) |*context| (if (manifest.recursion_device_fixed_candidate) try context.factoryWithDeviceFixed() else try context.factoryForTraceOnly()) else null) else {};
    try std.fs.cwd().makePath(output);
    if (manifest.recursion_device_fixed_candidate) {
        var root_dir = try std.fs.cwd().openDir(output, .{ .iterate = true });
        defer root_dir.close();
        const original = try root_dir.createFile("resident-device-fixed-manifest.json", .{ .exclusive = true });
        defer original.close();
        try original.writeAll(raw);
        try std.posix.fsync(original.handle);
        try std.posix.fsync(root_dir.fd);
    }
    if (ready_mode) {
        // Preserve the exact authored producer manifest, not an operationally
        // rewritten request. External plan pins and emitted hash bind it.
        var directory = try std.fs.cwd().openDir(output, .{ .iterate = true });
        defer directory.close();
        const manifest_file = try directory.createFile("resident-ready-manifest.json", .{ .exclusive = true });
        defer manifest_file.close();
        try manifest_file.writeAll(raw);
        try std.posix.fsync(manifest_file.handle);
        try std.posix.fsync(directory.fd);
    }
    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    defer a.free(resource_json);
    const parent = std.fs.path.dirname(manifest_path) orelse ".";
    for (0..manifest.repeat) |trial| {
        var seen = std.AutoHashMap(u64, void).init(a);
        defer seen.deinit();
        const trial_name = try std.fmt.allocPrint(a, "trial-{d}", .{trial});
        defer a.free(trial_name);
        const trial_directory = try std.fs.path.join(a, &.{ output, trial_name });
        defer a.free(trial_directory);
        try std.fs.cwd().makePath(trial_directory);
        for (manifest.execution_order, 0..) |block, iteration| {
            if (seen.contains(block)) return error.DuplicateResidentBatchBlock;
            try seen.put(block, {});
            var name_buf: [24]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "{d}", .{block});
            const item = manifest.blocks.map.get(name) orelse return error.MissingResidentBatchBlock;
            if (item.expected_cpu_segments == 0 or !std.mem.eql(u8, item.jobs, "-")) return error.ResidentBatchRequiresDirectCapture;
            try pool.router.replan(cpuCount(item));
            const directory = try std.fs.path.join(a, &.{ trial_directory, name });
            defer a.free(directory);
            try std.fs.cwd().makeDir(directory);
            const resources = try std.fs.path.join(a, &.{ directory, "resources.json" });
            defer a.free(resources);
            const file = try std.fs.cwd().createFile(resources, .{});
            try file.writeAll(resource_json);
            file.close();
            const request = try std.fs.path.resolve(a, &.{ parent, item.request });
            defer a.free(request);
            const proof = try std.fs.path.join(a, &.{ directory, "proof" });
            defer a.free(proof);
            const prefix = try std.fmt.allocPrint(a, "{d}", .{item.prefix_count});
            defer a.free(prefix);
            const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request, "-", proof, prefix, resources };
            var args: [parts.len][:0]u8 = undefined;
            var made: usize = 0;
            defer for (args[0..made]) |arg| a.free(arg);
            for (parts, &args) |part, *arg| {
                arg.* = try a.dupeZ(u8, part);
                made += 1;
            }
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo/rv64/resident/block-transaction/v1\x00");
            hash.update(request);
            const request_bytes = try std.fs.cwd().readFileAlloc(a, request, 16384);
            defer a.free(request_bytes);
            hash.update(request_bytes);
            var transaction: [16]u8 = undefined;
            std.mem.writeInt(u64, transaction[0..8], trial, .little);
            std.mem.writeInt(u64, transaction[8..16], iteration, .little);
            hash.update(&transaction);
            const identity = hash.finalResult();
            for (pool.devices, config.caps) |*device, cap| try device.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = if (combined) manifest.combined_immutable_device_bytes else manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
            var timer = try std.time.Timer.start();
            if (combined) {
                // Same producer and live authority handoff; every trial is fresh.
                a.free(args[3]);
                args[3] = try a.dupeZ(u8, "produce-and-recurse-candidate");
                try Main.runCombinedResidentArgsWithExecution(&recycler, &args, pool.stages(), &session, .{
                    .factory = factory,
                    .ready = if (ready) |context| context.options() else null,
                    .physical_devices = config.ids,
                    .producer_manifest_sha256 = manifest_sha256,
                });
            } else try Main.runWithResidentArgs(&recycler, &args, pool.stages(), &session);
            for (pool.devices) |*device| try device.native.endBlock(identity);
            const request_wall_ns = timer.read();
            if (combined) {
                const report_path = try std.fs.path.join(base, &.{ proof, "report.json" });
                defer base.free(report_path);
                const bytes = try std.fs.cwd().readFileAlloc(base, report_path, 8 << 20);
                defer base.free(bytes);
                const summary = try std.json.parseFromSlice(struct { cpu_proofs: usize, completed_ethereum_block: bool }, base, bytes, .{ .ignore_unknown_fields = true });
                defer summary.deinit();
                if (summary.value.cpu_proofs != item.expected_cpu_segments or !summary.value.completed_ethereum_block) return error.CombinedBatchCoverageMismatch;
                const combined_path = try std.fs.path.join(base, &.{ proof, "combined-report.json" });
                defer base.free(combined_path);
                const combined_bytes = try std.fs.cwd().readFileAlloc(base, combined_path, 8 << 20);
                defer base.free(combined_bytes);
                const combined_audit = try std.json.parseFromSlice(struct { recursion_execution: std.json.Value, fixed_setup_backend: []const u8 }, base, combined_bytes, .{ .ignore_unknown_fields = true });
                defer combined_audit.deinit();
                const entry = try std.json.Stringify.valueAlloc(base, .{ .schema = 1, .accepted = true, .request_wall_ns = request_wall_ns, .device_lifecycle_audit = "all request leases released", .device_byte_cap = config.caps[0], .physical_device_ids = config.ids, .device_byte_caps = config.caps, .recursion_mode = @tagName(manifest.recursion_mode), .recursion_execution = combined_audit.value.recursion_execution, .fixed_setup_backend = combined_audit.value.fixed_setup_backend, .recursion_worker_budget = if (ready_mode) manifest.recursion_worker_budget else null, .producer_manifest_sha256 = manifest_sha256, .hardware_parallel_qualified = false, .immutable_device_bytes = manifest.combined_immutable_device_bytes, .host_byte_cap = manifest.combined_host_bytes, .trial = trial, .block = block, .fresh_production = true }, .{ .whitespace = .indent_2 });
                defer base.free(entry);
                try @import("combined_publication.zig").write(proof, entry);
            }
            std.debug.print("GPU_RESIDENT_BLOCK block={} trial={} iteration={} request_wall_ns={} cached_host_keys={} host_key_cache_hits={} host_key_cache_misses={} host_key_cache_evictions={} gpu_contexts={}\n", .{ block, trial, iteration, request_wall_ns, session.keyCount(), session.hits, session.misses, session.evictions, pool.devices.len });
        }
    }
}

fn cpuCount(item: Block) usize {
    return if (item.prefix_count == 0) item.expected_cpu_segments else @min(item.prefix_count, item.expected_cpu_segments);
}
