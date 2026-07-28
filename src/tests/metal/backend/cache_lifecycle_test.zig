const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const shared_runtime = @import("stwo_metal_backend").shared_runtime;

extern fn stwo_zig_metal_eval_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    arguments: *const [14]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

const library_count = 9;
const pipeline_count = 65;
const function_name = "stwo_zig_cache_probe";
const archive_cache_env: [:0]const u8 = "STWO_ZIG_METAL_CACHE_DIR";

const layout: metal.EvalLayout = .{
    .trace_offsets = 0,
    .interaction_offsets = 0,
    .base_params = 0,
    .ext_params = 0,
    .random_coeffs = 0,
    .denom_inv = 0,
    .coordinates = .{ 0, 0, 0, 0 },
    .row_count = 2,
    .trace_log_size = 0,
    .domain_log_size = 0,
    .rc_base = 0,
};

fn sourceFor(allocator: std.mem.Allocator, value: usize) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\#include <metal_stdlib>
        \\using namespace metal;
        \\kernel void stwo_zig_cache_probe(
        \\    device uint *output [[buffer(0)]],
        \\    uint index [[thread_position_in_grid]]) {{
        \\    if (index == 0) output[0] = {d};
        \\}}
    ,
        .{value},
    );
}

fn pipelineSource(allocator: std.mem.Allocator) ![]u8 {
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    try writer.writeAll("#include <metal_stdlib>\nusing namespace metal;\n");
    for (0..pipeline_count) |index| {
        try writer.print(
            "kernel void stwo_zig_cache_pipeline_{d}(device uint *output [[buffer(0)]], uint i [[thread_position_in_grid]]) {{ if (i == 0) output[0] = {d}; }}\n",
            .{ index, index },
        );
    }
    return source.toOwnedSlice(allocator);
}

fn installTemporaryArchiveStore(
    allocator: std.mem.Allocator,
    temporary: *std.testing.TmpDir,
) ![:0]u8 {
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const cache = try std.fs.path.join(allocator, &.{ root, "archive-store" });
    defer allocator.free(cache);
    const cache_z = try allocator.dupeZ(u8, cache);
    errdefer allocator.free(cache_z);
    if (setenv(archive_cache_env.ptr, cache_z.ptr, 1) != 0) return error.EnvironmentMutationFailed;
    return cache_z;
}

fn archiveDirectory(allocator: std.mem.Allocator, cache: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ cache, "archives" });
}

fn onlyArchivePath(allocator: std.mem.Allocator, cache: []const u8) ![]u8 {
    const directory_path = try archiveDirectory(allocator, cache);
    defer allocator.free(directory_path);
    var directory = try std.fs.openDirAbsolute(directory_path, .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    var result: ?[]u8 = null;
    while (try iterator.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".binarchive")) continue;
        if (result != null) return error.UnexpectedArchiveCount;
        result = try std.fs.path.join(allocator, &.{ directory_path, entry.name });
    }
    return result orelse error.MissingArchive;
}

fn expectNoArchiveTemporaries(allocator: std.mem.Allocator, cache: []const u8) !void {
    const directory_path = try archiveDirectory(allocator, cache);
    defer allocator.free(directory_path);
    var directory = try std.fs.openDirAbsolute(directory_path, .{ .iterate = true });
    defer directory.close();
    var iterator = directory.iterate();
    while (try iterator.next()) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".stwo-zig-"));
    }
}

test "metal: shared runtime rejects shutdown while resident resources are live" {
    const before = shared_runtime.lifecycleSnapshot().live_resident_resources;
    shared_runtime.retainResidentResource();
    defer shared_runtime.releaseResidentResource();

    try std.testing.expectEqual(
        before + 1,
        shared_runtime.lifecycleSnapshot().live_resident_resources,
    );
    try std.testing.expectError(error.ResidentResourcesLive, shared_runtime.shutdown());
}

test "metal: shared runtime rejects shutdown while a call holds a lease" {
    try shared_runtime.initialize(std.testing.allocator, .source_jit);
    var lease = try shared_runtime.acquireExisting();
    var lease_active = true;
    defer {
        if (lease_active) lease.deinit();
        shared_runtime.shutdown() catch unreachable;
    }

    try std.testing.expectError(error.RuntimeBusy, shared_runtime.shutdown());
    lease.deinit();
    lease_active = false;
}

test "metal: dynamic library and pipeline caches are bounded across teardown" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const cache = try installTemporaryArchiveStore(allocator, &temporary);
    defer allocator.free(cache);
    defer _ = unsetenv(archive_cache_env.ptr);
    {
        var runtime = try metal.Runtime.init();
        defer runtime.deinit();

        var libraries: [library_count]metal.EvalLibrary = undefined;
        var initialized: usize = 0;
        defer for (libraries[0..initialized]) |*library| library.deinit();

        const first_source = try sourceFor(allocator, 0);
        defer allocator.free(first_source);
        libraries[0] = try runtime.compileEvalLibrary(first_source);
        initialized = 1;

        var retained_plan = try runtime.prepareEvalFromLibrary(libraries[0], function_name, layout);
        defer retained_plan.deinit();

        var foreign_runtime = try metal.Runtime.init();
        defer foreign_runtime.deinit();
        var foreign_arguments = [_]u32{0} ** 14;
        foreign_arguments[10] = layout.row_count;
        var foreign_message = [_]u8{0} ** 256;
        try std.testing.expectEqual(
            @as(?*anyopaque, null),
            stwo_zig_metal_eval_prepare_library(
                foreign_runtime.handle,
                libraries[0].handle,
                function_name.ptr,
                function_name.len,
                &foreign_arguments,
                &foreign_message,
                foreign_message.len,
            ),
        );
        try std.testing.expect(std.mem.indexOf(u8, &foreign_message, "different runtime or device") != null);
        const foreign_stats = foreign_runtime.pipelineCacheStats();
        try std.testing.expectEqual(@as(u64, 0), foreign_stats.pipeline_cache_entries);

        for (1..library_count) |index| {
            const source = try sourceFor(allocator, index);
            defer allocator.free(source);
            libraries[index] = try runtime.compileEvalLibrary(source);
            initialized += 1;
        }

        const after_eviction = runtime.pipelineCacheStats();
        try std.testing.expectEqual(after_eviction.library_cache_entry_limit, after_eviction.library_cache_entries);
        try std.testing.expectEqual(@as(u64, 1), after_eviction.library_cache_evictions);
        try std.testing.expectEqual(@as(u64, 1), after_eviction.pipeline_cache_invalidations);
        try std.testing.expectEqual(@as(u64, 0), after_eviction.pipeline_cache_entries);
        try std.testing.expect(after_eviction.library_cache_bytes <= after_eviction.library_cache_byte_limit);
        try std.testing.expect(after_eviction.library_cache_peak_bytes <= after_eviction.library_cache_byte_limit);
        try std.testing.expect(after_eviction.pipeline_cache_peak_bytes <= after_eviction.pipeline_cache_byte_limit);

        const newest_source = try sourceFor(allocator, library_count - 1);
        defer allocator.free(newest_source);
        var cache_hit = try runtime.compileEvalLibrary(newest_source);
        defer cache_hit.deinit();
        const after_hit = runtime.pipelineCacheStats();
        try std.testing.expectEqual(after_eviction.library_cache_entries, after_hit.library_cache_entries);
        try std.testing.expectEqual(after_eviction.library_cache_hits + 1, after_hit.library_cache_hits);

        var restored_plan = try runtime.prepareEvalFromLibrary(libraries[0], function_name, layout);
        defer restored_plan.deinit();
        var pipeline_hit = try runtime.prepareEvalFromLibrary(libraries[0], function_name, layout);
        defer pipeline_hit.deinit();
        const after_restore = runtime.pipelineCacheStats();
        try std.testing.expectEqual(@as(u64, 1), after_restore.pipeline_cache_entries);
        try std.testing.expectEqual(after_hit.pipeline_cache_hits + 1, after_restore.pipeline_cache_hits);

        const pipeline_source = try pipelineSource(allocator);
        defer allocator.free(pipeline_source);
        var pipeline_library = try runtime.compileEvalLibrary(pipeline_source);
        defer pipeline_library.deinit();
        var plans: [pipeline_count]metal.EvalPlan = undefined;
        var plan_count: usize = 0;
        defer for (plans[0..plan_count]) |*plan| plan.deinit();
        for (0..pipeline_count) |index| {
            const name = try std.fmt.allocPrint(allocator, "stwo_zig_cache_pipeline_{d}", .{index});
            defer allocator.free(name);
            plans[index] = try runtime.prepareEvalFromLibrary(pipeline_library, name, layout);
            plan_count += 1;
        }
        const after_pipeline_eviction = runtime.pipelineCacheStats();
        try std.testing.expectEqual(
            after_pipeline_eviction.pipeline_cache_entry_limit,
            after_pipeline_eviction.pipeline_cache_entries,
        );
        try std.testing.expect(after_pipeline_eviction.pipeline_cache_evictions > after_restore.pipeline_cache_evictions);
        try std.testing.expect(after_pipeline_eviction.pipeline_cache_bytes <= after_pipeline_eviction.pipeline_cache_byte_limit);
        try std.testing.expect(after_pipeline_eviction.pipeline_cache_peak_bytes <= after_pipeline_eviction.pipeline_cache_byte_limit);
    }

    var fresh_runtime = try metal.Runtime.init();
    defer fresh_runtime.deinit();
    const fresh = fresh_runtime.pipelineCacheStats();
    try std.testing.expectEqual(@as(u64, 0), fresh.library_cache_entries);
    try std.testing.expectEqual(@as(u64, 0), fresh.pipeline_cache_entries);
    try std.testing.expectEqual(@as(u64, 0), fresh.library_cache_peak_entries);
    try std.testing.expectEqual(@as(u64, 0), fresh.pipeline_cache_peak_entries);
    try std.testing.expect(fresh.library_cache_entry_limit > 0);
    try std.testing.expect(fresh.pipeline_cache_entry_limit > 0);

    const deterministic_source = try sourceFor(allocator, 0);
    defer allocator.free(deterministic_source);
    var first_library = try fresh_runtime.compileEvalLibrary(deterministic_source);
    defer first_library.deinit();
    var second_library = try fresh_runtime.compileEvalLibrary(deterministic_source);
    defer second_library.deinit();
    const after_library_hit = fresh_runtime.pipelineCacheStats();
    try std.testing.expectEqual(@as(u64, 1), after_library_hit.library_cache_entries);
    try std.testing.expectEqual(@as(u64, 1), after_library_hit.library_cache_hits);

    var archive_plan = try fresh_runtime.prepareEvalFromLibrary(first_library, function_name, layout);
    defer archive_plan.deinit();
    const after_archive_hit = fresh_runtime.pipelineCacheStats();
    try std.testing.expectEqual(@as(u64, 1), after_archive_hit.binary_archive_hits);
    try std.testing.expectEqual(@as(u64, 0), after_archive_hit.direct_compiles);
    const disk = fresh_runtime.archiveStoreStats();
    try std.testing.expectEqual(@as(u32, 1), disk.abi_version);
    try std.testing.expectEqual(@as(u32, @sizeOf(metal.ArchiveStoreStatsV1)), disk.struct_size);
    try std.testing.expectEqual(@as(u64, 1), disk.archive_disk_hits);
    try std.testing.expectEqual(@as(u64, 0), disk.archive_disk_misses);
    try std.testing.expect(disk.archive_disk_entries <= disk.archive_disk_entry_limit);
    try std.testing.expect(disk.archive_disk_bytes <= disk.archive_disk_byte_limit);
    try expectNoArchiveTemporaries(allocator, cache);
}

test "metal: corrupt archive is quarantined and rebuilt without failing proving" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const cache = try installTemporaryArchiveStore(allocator, &temporary);
    defer allocator.free(cache);
    defer _ = unsetenv(archive_cache_env.ptr);

    const source = try sourceFor(allocator, 71);
    defer allocator.free(source);
    {
        var runtime = try metal.Runtime.init();
        defer runtime.deinit();
        var library = try runtime.compileEvalLibrary(source);
        defer library.deinit();
        var plan = try runtime.prepareEvalFromLibrary(library, function_name, layout);
        defer plan.deinit();
        const stats = runtime.archiveStoreStats();
        try std.testing.expectEqual(@as(u64, 1), stats.archive_disk_misses);
        try std.testing.expectEqual(@as(u64, 1), stats.archive_publication_successes);
    }

    const archive_path = try onlyArchivePath(allocator, cache);
    defer allocator.free(archive_path);
    var corrupt = try std.fs.createFileAbsolute(archive_path, .{ .truncate = true });
    try corrupt.writeAll("not a Metal binary archive");
    corrupt.close();

    {
        var runtime = try metal.Runtime.init();
        defer runtime.deinit();
        var library = try runtime.compileEvalLibrary(source);
        defer library.deinit();
        var plan = try runtime.prepareEvalFromLibrary(library, function_name, layout);
        defer plan.deinit();
        const pipeline = runtime.pipelineCacheStats();
        const store = runtime.archiveStoreStats();
        try std.testing.expectEqual(@as(u64, 1), pipeline.direct_compiles);
        try std.testing.expectEqual(@as(u64, 1), store.archive_disk_misses);
        try std.testing.expectEqual(@as(u64, 1), store.archive_disk_rebuilds);
        try std.testing.expectEqual(@as(u64, 1), store.archive_disk_quarantines);
        try std.testing.expectEqual(@as(u64, 1), store.archive_publication_successes);
        try std.testing.expectEqual(@as(u64, 1), store.archive_quarantine_entries);
    }

    {
        var runtime = try metal.Runtime.init();
        defer runtime.deinit();
        var library = try runtime.compileEvalLibrary(source);
        defer library.deinit();
        var plan = try runtime.prepareEvalFromLibrary(library, function_name, layout);
        defer plan.deinit();
        try std.testing.expectEqual(@as(u64, 1), runtime.archiveStoreStats().archive_disk_hits);
        try std.testing.expectEqual(@as(u64, 1), runtime.pipelineCacheStats().binary_archive_hits);
        try std.testing.expectEqual(@as(u64, 0), runtime.pipelineCacheStats().direct_compiles);
    }
    try expectNoArchiveTemporaries(allocator, cache);
}

test "metal: stale runtime archives merge before atomic publication" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const cache = try installTemporaryArchiveStore(allocator, &temporary);
    defer allocator.free(cache);
    defer _ = unsetenv(archive_cache_env.ptr);
    const source =
        \\#include <metal_stdlib>
        \\using namespace metal;
        \\kernel void cache_merge_a(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { if (i == 0) out[0] = 1; }
        \\kernel void cache_merge_b(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { if (i == 0) out[0] = 2; }
    ;

    var first = try metal.Runtime.init();
    defer first.deinit();
    var second = try metal.Runtime.init();
    defer second.deinit();
    var first_library = try first.compileEvalLibrary(source);
    defer first_library.deinit();
    var stale_library = try second.compileEvalLibrary(source);
    defer stale_library.deinit();
    var plan_a = try first.prepareEvalFromLibrary(first_library, "cache_merge_a", layout);
    defer plan_a.deinit();
    var plan_b = try second.prepareEvalFromLibrary(stale_library, "cache_merge_b", layout);
    defer plan_b.deinit();

    var verifier = try metal.Runtime.init();
    defer verifier.deinit();
    var verifier_library = try verifier.compileEvalLibrary(source);
    defer verifier_library.deinit();
    var verify_a = try verifier.prepareEvalFromLibrary(verifier_library, "cache_merge_a", layout);
    defer verify_a.deinit();
    var verify_b = try verifier.prepareEvalFromLibrary(verifier_library, "cache_merge_b", layout);
    defer verify_b.deinit();
    const stats = verifier.pipelineCacheStats();
    try std.testing.expectEqual(@as(u64, 2), stats.binary_archive_hits);
    try std.testing.expectEqual(@as(u64, 0), stats.direct_compiles);
    try std.testing.expectEqual(@as(u64, 1), verifier.archiveStoreStats().archive_disk_hits);
}

test "metal: archive store enforces deterministic count and byte caps" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const cache = try installTemporaryArchiveStore(allocator, &temporary);
    defer allocator.free(cache);
    defer _ = unsetenv(archive_cache_env.ptr);
    const archives = try archiveDirectory(allocator, cache);
    defer allocator.free(archives);
    try std.fs.makeDirAbsolute(cache);
    try std.fs.makeDirAbsolute(archives);
    const fixed_time: i128 = 1_700_000_000 * std.time.ns_per_s;
    for (0..130) |index| {
        const name = try std.fmt.allocPrint(allocator, "stwo-zig-eval-cache-v2-{x:0>64}.binarchive", .{index});
        defer allocator.free(name);
        const path = try std.fs.path.join(allocator, &.{ archives, name });
        defer allocator.free(path);
        var file = try std.fs.createFileAbsolute(path, .{});
        try file.writeAll("x");
        try file.updateTimes(fixed_time, fixed_time);
        file.close();
    }
    const source = try sourceFor(allocator, 91);
    defer allocator.free(source);
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var library = try runtime.compileEvalLibrary(source);
    defer library.deinit();
    const stats = runtime.archiveStoreStats();
    try std.testing.expectEqual(stats.archive_disk_entry_limit, stats.archive_disk_entries);
    try std.testing.expectEqual(@as(u64, 2), stats.archive_disk_evictions);
    const oldest = try std.fs.path.join(allocator, &.{ archives, "stwo-zig-eval-cache-v2-0000000000000000000000000000000000000000000000000000000000000000.binarchive" });
    defer allocator.free(oldest);
    try std.testing.expectError(error.FileNotFound, std.fs.openFileAbsolute(oldest, .{}));

    for (0..5) |index| {
        const name = try std.fmt.allocPrint(allocator, "stwo-zig-eval-cache-v2-byte-{d}.binarchive", .{index});
        defer allocator.free(name);
        const path = try std.fs.path.join(allocator, &.{ archives, name });
        defer allocator.free(path);
        var file = try std.fs.createFileAbsolute(path, .{});
        try file.setEndPos(120 * 1024 * 1024);
        try file.updateTimes(fixed_time, fixed_time);
        file.close();
    }
    var byte_runtime = try metal.Runtime.init();
    defer byte_runtime.deinit();
    const byte_stats = byte_runtime.archiveStoreStats();
    // The query is side-effect free; compiling forces locked maintenance.
    var byte_library = try byte_runtime.compileEvalLibrary(source);
    defer byte_library.deinit();
    const maintained = byte_runtime.archiveStoreStats();
    try std.testing.expect(maintained.archive_disk_bytes <= maintained.archive_disk_byte_limit);
    try std.testing.expect(maintained.archive_disk_evictions > byte_stats.archive_disk_evictions);
}

test "metal: invalid archive cache override bypasses persistence without failing proving" {
    const invalid: [:0]const u8 = "relative/cache/path";
    if (setenv(archive_cache_env.ptr, invalid.ptr, 1) != 0) return error.EnvironmentMutationFailed;
    defer _ = unsetenv(archive_cache_env.ptr);
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const source = try sourceFor(std.testing.allocator, 113);
    defer std.testing.allocator.free(source);
    var library = try runtime.compileEvalLibrary(source);
    defer library.deinit();
    var plan = try runtime.prepareEvalFromLibrary(library, function_name, layout);
    defer plan.deinit();
    const pipeline = runtime.pipelineCacheStats();
    const store = runtime.archiveStoreStats();
    try std.testing.expectEqual(@as(u64, 1), pipeline.direct_compiles);
    try std.testing.expect(store.archive_disk_rejections >= 1);
    try std.testing.expect(store.archive_persistence_bypasses >= 1);
    try std.testing.expectEqual(@as(u64, 0), store.archive_publication_successes);
}
