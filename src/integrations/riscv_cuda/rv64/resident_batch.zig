//! Same native producer, many requests, one GPU pool and bounded immutable setup.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = CPU.rv64_ethereum_gkr_main;
const Pool = @import("resident_pool.zig").Pool;
const Router = @import("resident_router.zig");
const Block = struct { request: []const u8, jobs: []const u8 = "-", prefix_count: u32 = 0, expected_cpu_segments: usize };
const Manifest = struct {
    schema: []const u8,
    blocks: std.json.ArrayHashMap(Block),
    execution_order: []const u64,
    resources: std.json.Value,
    profile: []const u8 = "conjectured128_b2_q108_p20_fold4",
    immutable_host_key_bytes: usize = 4 << 30,
    immutable_device_bytes: u64 = 256 << 20,
};
pub fn run(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, output: []const u8) !void {
    const raw = try std.fs.cwd().readFileAlloc(a, manifest_path, 1 << 20);
    defer a.free(raw);
    var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const manifest = parsed.value;
    if (!std.mem.eql(u8, manifest.schema, "rv64-ethereum-basket-inputs/v1") or manifest.execution_order.len == 0 or manifest.execution_order.len > 256) return error.InvalidResidentBatchManifest;
    // This entry never admits the host-retained comparison route.
    if (std.process.hasEnvVarConstant("STWO_RV64_GPU_HOST_RETAINED") or !std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_TRACE") or !std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_BINDING")) return error.ResidentBatchRequiresDevicePipeline;
    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var first_name: [24]u8 = undefined;
    const first = manifest.blocks.map.get(try std.fmt.bufPrint(&first_name, "{d}", .{manifest.execution_order[0]})) orelse return error.MissingResidentBatchBlock;
    const pool = try Pool.createWithBinding(a, library, config, first.expected_cpu_segments, true);
    defer pool.deinit();
    var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    const base = recycler.allocator();
    var session = try Main.ResidentSession.init(base, manifest.immutable_host_key_bytes);
    defer session.deinit();
    try std.fs.cwd().makePath(output);
    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    defer a.free(resource_json);
    const parent = std.fs.path.dirname(manifest_path) orelse ".";
    var seen = std.AutoHashMap(u64, void).init(a);
    defer seen.deinit();
    for (manifest.execution_order, 0..) |block, iteration| {
        if (seen.contains(block)) return error.DuplicateResidentBatchBlock;
        try seen.put(block, {});
        var name_buf: [24]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{d}", .{block});
        const item = manifest.blocks.map.get(name) orelse return error.MissingResidentBatchBlock;
        if (item.expected_cpu_segments == 0 or !std.mem.eql(u8, item.jobs, "-")) return error.ResidentBatchRequiresDirectCapture;
        try pool.router.replan(item.expected_cpu_segments);
        const directory = try std.fs.path.join(a, &.{ output, name });
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
        const identity = hash.finalResult();
        for (pool.devices, config.caps) |*device, cap| try device.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
        var timer = try std.time.Timer.start();
        try Main.runWithResidentArgs(&recycler, &args, pool.stages(), &session);
        for (pool.devices) |*device| try device.native.endBlock(identity);
        std.debug.print("GPU_RESIDENT_BLOCK block={} iteration={} request_wall_ns={} cached_host_keys={} host_key_cache_hits={} host_key_cache_misses={} gpu_contexts={}\n", .{ block, iteration, timer.read(), session.keyCount(), session.hits, session.misses, pool.devices.len });
    }
}
