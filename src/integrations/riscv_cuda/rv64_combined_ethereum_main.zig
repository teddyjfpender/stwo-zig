//! Native GPU proving and current OM31 recursion under one independently derived
//! authority and one persistent device context. Device failures are terminal.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("rv64/resident_router.zig");
const Outer = @import("rv64/outer_source.zig");
fn env(a: std.mem.Allocator, name: []const u8) !?[]u8 {
    return std.process.getEnvVarOwned(a, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
}
fn outputDirectory(args: []const [:0]const u8) ![]const u8 {
    const mode: usize = if (args.len > 1 and std.mem.eql(u8, args[1], "--security-profile")) 3 else 1;
    if (args.len != mode + 6 or !std.mem.eql(u8, args[mode], "produce-and-recurse-candidate")) return error.ExpectedCombinedModeConfigJobsOutputCountResources;
    return args[mode + 3];
}
fn publishEntryReport(path: []const u8, json: []const u8) !void {
    return @import("rv64/combined_publication.zig").write(path, json);
}
pub fn main() !void {
    var timer = try std.time.Timer.start();
    const a = std.heap.page_allocator;
    const library = (try env(a, "STWO_RV64_GPU_LIBRARY")) orelse return error.CombinedRequiresNativeLibrary;
    defer a.free(library);
    if (std.process.hasEnvVarConstant("STWO_RV64_GPU_HOST_RETAINED")) return error.CombinedRequiresFullyResidentNative;
    const arguments = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, arguments);
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "combined-batch")) {
        if (arguments.len != 4) return error.ExpectedCombinedBatchManifestAndOutput;
        return @import("rv64/resident_batch.zig").runCombined(a, library, arguments[2], arguments[3]);
    }
    if (arguments.len >= 2 and std.mem.eql(u8, arguments[1], "combined-serve")) {
        if (arguments.len != 4) return error.ExpectedCombinedServeManifestAndSpool;
        // M8 job runtime (STWO_RV64_M8_JOBS=1). Unset keeps today's path unchanged.
        const jobs = @import("rv64/jobs/mod.zig");
        if (try jobs.selected()) return jobs.serve(a, library, arguments[2], arguments[3]);
        return @import("rv64/resident_batch.zig").runServe(a, library, arguments[2], arguments[3]);
    }
    const planned_text = (try env(a, "STWO_RV64_GPU_PLANNED_CPU_WORKERS")) orelse return error.CombinedRequiresResidentPlan;
    defer a.free(planned_text);
    const planned = std.fmt.parseUnsigned(usize, planned_text, 10) catch return error.InvalidResidentPlan;
    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    if (config.ids.len != 1) return error.MultiGpuCombinedRecursionNotImplemented;
    if (!std.process.hasEnvVarConstant("STWO_RV64_GPU_DEVICE_CAPS")) config.caps[0] = 28 << 30;
    if (config.caps[0] > 28 << 30) return error.CombinedDeviceBudgetExceedsQualifiedCap;
    const host_text = try env(a, "STWO_RV64_RECURSION_HOST_BYTES");
    defer if (host_text) |v| a.free(v);
    const host_bytes = if (host_text) |v| std.fmt.parseUnsigned(usize, v, 10) catch return error.InvalidCombinedHostBudget else 48 << 30;

    const output_path = try outputDirectory(arguments);
    // Identity binds this lifecycle to the explicit request and command. Actual
    // proof scopes continue to bind authenticated statement/FIXED/MAIN roots.
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64-combined-request-v1");
    for (arguments[1..]) |arg| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, arg.len, .little);
        hash.update(&length);
        hash.update(arg);
    }
    var identity: [32]u8 = undefined;
    hash.final(&identity);
    const pool = try Pool.createWithBinding(a, library, config, planned, true);
    defer pool.deinit();
    const device = &pool.devices[0];
    try device.native.beginBlock(identity, .{ .device_bytes = config.caps[0], .immutable_bytes = 2 << 30, .max_scopes = config.scope_limit });
    var outer = try Outer.Context.init(a, &device.native, &device.trace, &device.composition);
    defer outer.deinit();
    const gpu_init_ns = timer.read();
    std.log.info("GPU_COMBINED device={} cap_bytes={} immutable_bytes={} host_bytes={}; live native authority handoff; no CPU proving fallback", .{ config.ids[0], config.caps[0], @as(usize, 2 << 30), host_bytes });
    try CPU.rv64_ethereum_gkr_main.mainWithResidentPipelineAndRecursion(pool.stages(), try outer.factoryForTraceOnly(), host_bytes);
    try device.native.endBlock(identity);
    const full_entry_ns = timer.read();
    const entry_report = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .accepted = true, .gpu_init_ns = gpu_init_ns, .full_entry_ns = full_entry_ns, .native_authority_handoff = "live in process; no reload or reconstruction", .device_byte_cap = config.caps[0], .immutable_device_bytes = @as(u64, 2 << 30), .host_byte_cap = host_bytes, .device_lifecycle_audit = "all request leases released", .scope = "Entry wall includes native GPU pool initialization, native capture/proving/verification/publication and fresh GPU recursion; excludes operating-system process startup." }, .{ .whitespace = .indent_2 });
    defer a.free(entry_report);
    try publishEntryReport(output_path, entry_report);
    std.log.info("GPU_COMBINED_COMPLETE gpu_init_ns={} full_entry_ns={}", .{ gpu_init_ns, full_entry_ns });
}

test "combined output dispatch preserves the native producer argument contract" {
    const plain = [_][:0]const u8{ "combined", "produce-and-recurse-candidate", "config", "-", "out", "0", "resources" };
    try std.testing.expectEqualStrings("out", try outputDirectory(&plain));
    const selected = [_][:0]const u8{ "combined", "--security-profile", "conjectured128_b2_q108_p20_fold4", "produce-and-recurse-candidate", "config", "-", "out", "0", "resources" };
    try std.testing.expectEqualStrings("out", try outputDirectory(&selected));
    try std.testing.expectError(error.ExpectedCombinedModeConfigJobsOutputCountResources, outputDirectory(plain[0..6]));
}

test "combined entry publication uses a descriptor that supports durability" {
    const a = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realpathAlloc(a, ".");
    defer a.free(path);
    try publishEntryReport(path, "{\"accepted\":true}");
    try std.testing.expectError(error.PathAlreadyExists, publishEntryReport(path, "{\"accepted\":false}"));
    const bytes = try temporary.dir.readFileAlloc(a, "combined-entry.json", 1024);
    defer a.free(bytes);
    try std.testing.expectEqualStrings("{\"accepted\":true}", bytes);
}
