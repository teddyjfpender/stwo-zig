const std = @import("std");
const engine = @import("stwo_prover_engine");
const Full = @import("../rv64_full.zig");
const CacheModule = @import("pure_p2_setup_cache.zig");
const Runtime = @import("pure_p2_op_runtime.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
const a = std.testing.allocator;
const profile = Profile.op_target_b4_q72_p0_fold4_v1;

test "OP immutable setup cache owns source views and refuses wrong authority with bounded leases" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 1 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var cache = try CacheModule.Cache.init(alloc, path, .{ .heap_bytes = 512 << 20, .disk_bytes = 512 << 20, .mapped_bytes = 32 << 20, .entries = 1, .metadata_bytes = 16 << 20 });
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    var source = try Full.ProgramAuthority.initForOpWord16(alloc, .{ .base = 4096, .words = &.{ 0x00108093, 0x00108093 } }, .bytes_v1);
    var source_alive = true;
    defer if (source_alive) source.deinit();
    var first = try cache.acquire(&source, .{ .cpu_log = 5 }, .{}, profile);
    defer first.deinit();
    try std.testing.expectEqual(@as(u64, 1), cache.snapshot().misses);
    try std.testing.expectEqual(@as(usize, 1), cache.snapshot().entries);
    var second = try cache.acquire(&source, .{ .cpu_log = 5 }, .{}, profile);
    try std.testing.expect(first.setup() == second.setup() and first.key() == second.key());
    try std.testing.expectEqual(@as(u64, 1), cache.snapshot().hits);
    second.deinit();
    try std.testing.expectError(error.UnqualifiedOpSetup, cache.acquire(&source, .{ .cpu_log = 5 }, .{}, .reference_b2_q24_p0));
    try std.testing.expectError(error.OpSetupCacheEntryLimit, cache.acquire(&source, .{ .cpu_log = 6 }, .{}, profile));
    var other = try Full.ProgramAuthority.initForOpWord16(alloc, .{ .base = 4096, .words = &.{ 0x00208093, 0x00108093 } }, .bytes_v1);
    defer other.deinit();
    try std.testing.expectError(error.OpSetupCacheEntryLimit, cache.acquire(&other, .{ .cpu_log = 5 }, .{}, profile));
    var session = try cache.enterRequest(alloc, 1 << 30, 64 << 20);
    try std.testing.expectEqual(@as(usize, 512 << 20), session.disk_bytes);
    try std.testing.expectEqual(@as(usize, 32 << 20), session.mapped_bytes);
    try std.testing.expectError(error.OpSetupCacheRequestBusy, cache.enterRequest(alloc, 1 << 30, 64 << 20));
    session.deinit();
    try std.testing.expectError(error.OpSetupCacheResourcePartition, cache.enterRequest(alloc, 512 << 20, 64 << 20));
    source.deinit();
    source_alive = false;
    // Lease-owned cache state and copied executable data survive both request
    // source destruction and the cache handle itself; no Image is retained.
    cache.deinit();
    cache_alive = false;
    try first.key().requireForOp(first.setup(), profile);
    try std.testing.expectEqual(@as(u32, 0x00108093), first.setup().materials.program.words[0]);
}

test "OP real source cache reuses immutable setup across two complete requests with fresh receiver" {
    const request_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_REQUEST") orelse return error.SkipZigTest;
    const baseline_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_BUNDLE") orelse return error.SkipZigTest;
    const Request = @import("../rv64_ethereum_request.zig");
    const bytes = try std.fs.cwd().readFileAlloc(a, request_path, 16384);
    defer a.free(bytes);
    const parsed = try std.json.parseFromSlice(Request.Config, a, bytes, .{});
    defer parsed.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 32 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const cache_path = try std.fs.path.join(a, &.{ root, "immutable" });
    defer a.free(cache_path);
    var cache = try CacheModule.Cache.init(alloc, cache_path, .{ .heap_bytes = 4 << 30, .disk_bytes = 16 << 30, .mapped_bytes = 1 << 30, .entries = 64, .metadata_bytes = 256 << 20 });
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    const limits = Runtime.Resources{};
    const first = try std.fs.path.join(a, &.{ root, "request-0" });
    defer a.free(first);
    const second = try std.fs.path.join(a, &.{ root, "request-1" });
    defer a.free(second);
    var timer = try std.time.Timer.start();
    try Runtime.produceDirectoryWithCache(alloc, parsed.value, first, profile, limits, &cache);
    const first_ns = timer.read();
    const cold = cache.snapshot();
    try std.testing.expect(cold.misses > 0 and cold.entries > 0 and cold.active_leases == 0 and cold.mapped_bytes == 0);
    timer.reset();
    try Runtime.produceDirectoryWithCache(alloc, parsed.value, second, profile, limits, &cache);
    const second_ns = timer.read();
    const warm = cache.snapshot();
    try std.testing.expectEqual(cold.misses, warm.misses);
    try std.testing.expectEqual(cold.entries, warm.entries);
    try std.testing.expect(warm.hits > cold.hits and warm.active_leases == 0 and warm.mapped_bytes == 0);
    const p0 = try std.fs.path.join(a, &.{ first, "native-op.bin" });
    defer a.free(p0);
    const p1 = try std.fs.path.join(a, &.{ second, "native-op.bin" });
    defer a.free(p1);
    const old = try std.fs.path.join(a, &.{ baseline_path, "native-op.bin" });
    defer a.free(old);
    const b0 = try std.fs.cwd().readFileAlloc(a, p0, limits.bundle_bytes);
    defer a.free(b0);
    const b1 = try std.fs.cwd().readFileAlloc(a, p1, limits.bundle_bytes);
    defer a.free(b1);
    const control = try std.fs.cwd().readFileAlloc(a, old, limits.bundle_bytes);
    defer a.free(control);
    try std.testing.expectEqualSlices(u8, control, b0);
    try std.testing.expectEqualSlices(u8, b0, b1);
    // This receiver deliberately imports no producer cache and derives authority
    // afresh. The long-lived cache is an optimization, never trust transfer.
    try Runtime.verifyDirectory(alloc, parsed.value, second, profile, limits);
    try Runtime.verifyDirectoryWithCache(alloc, parsed.value, second, profile, limits, &cache);
    // Same immutable key, different request frame: an old proof cannot be
    // replayed just because the fresh receiver's setup lookup hits.
    var dir = try std.fs.cwd().openDir(second, .{});
    defer dir.close();
    const raw_metadata = try dir.readFileAlloc(a, "native-op.json", 4 << 20);
    defer a.free(raw_metadata);
    const metadata = try std.json.parseFromSlice(Runtime.Metadata, a, raw_metadata, .{});
    defer metadata.deinit();
    @constCast(metadata.value.requests)[0].cpu.final_registers[1] ^= 1;
    const altered = try std.json.Stringify.valueAlloc(a, metadata.value, .{ .whitespace = .indent_2 });
    defer a.free(altered);
    var file = try dir.createFile("native-op.json", .{ .truncate = true });
    try file.writeAll(altered);
    file.close();
    try std.testing.expect(std.meta.isError(Runtime.verifyDirectoryWithCache(alloc, parsed.value, second, profile, limits, &cache)));
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().active_leases);
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().mapped_bytes);
    std.debug.print("OP_IMMUTABLE_REUSE cold_ns={} warm_ns={} entries={} hits={} misses={} parked={} heap={} exact_bytes={} fresh=true replay_rejected=true\n", .{ first_ns, second_ns, warm.entries, warm.hits, warm.misses, warm.parked_bytes, warm.heap.live_bytes, b0.len });
    cache.deinit();
    cache_alive = false;
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}

test "OP independent receiver setup cache bootstraps from source and rejects replay on a hit" {
    const request_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_REQUEST") orelse return error.SkipZigTest;
    const baseline_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_BUNDLE") orelse return error.SkipZigTest;
    const Request = @import("../rv64_ethereum_request.zig");
    const config_bytes = try std.fs.cwd().readFileAlloc(a, request_path, 16384);
    defer a.free(config_bytes);
    const parsed = try std.json.parseFromSlice(Request.Config, a, config_bytes, .{});
    defer parsed.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 32 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const cache_path = try std.fs.path.join(a, &.{ root, "receiver-owned" });
    defer a.free(cache_path);
    var cache = try CacheModule.Cache.init(alloc, cache_path, .{ .heap_bytes = 4 << 30, .disk_bytes = 16 << 30, .mapped_bytes = 1 << 30, .entries = 64, .metadata_bytes = 256 << 20 });
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    // Only the proof bundle and public source declarations cross this boundary.
    // No producer Cache, key object, root registry or parked file is imported.
    var source = try std.fs.cwd().openDir(baseline_path, .{});
    defer source.close();
    for ([_][]const u8{ "native-op.bin", "native-op.json", "cells.bin" }) |name| try source.copyFile(name, temp.dir, name, .{});
    const limits = Runtime.Resources{};
    var timer = try std.time.Timer.start();
    try Runtime.verifyDirectoryWithCache(alloc, parsed.value, root, profile, limits, &cache);
    const cold_ns = timer.read();
    const cold = cache.snapshot();
    try std.testing.expect(cold.misses > 0 and cold.hits == 0 and cold.active_leases == 0 and cold.mapped_bytes == 0);
    timer.reset();
    try Runtime.verifyDirectoryWithCache(alloc, parsed.value, root, profile, limits, &cache);
    const warm_ns = timer.read();
    const warm = cache.snapshot();
    try std.testing.expectEqual(cold.misses, warm.misses);
    try std.testing.expect(warm.hits > 0 and warm.active_leases == 0 and warm.mapped_bytes == 0);
    const raw_metadata = try temp.dir.readFileAlloc(a, "native-op.json", 4 << 20);
    defer a.free(raw_metadata);
    const metadata = try std.json.parseFromSlice(Runtime.Metadata, a, raw_metadata, .{});
    defer metadata.deinit();
    @constCast(metadata.value.requests)[0].cpu.final_registers[1] ^= 1;
    const altered = try std.json.Stringify.valueAlloc(a, metadata.value, .{ .whitespace = .indent_2 });
    defer a.free(altered);
    var file = try temp.dir.createFile("native-op.json", .{ .truncate = true });
    try file.writeAll(altered);
    file.close();
    try std.testing.expect(std.meta.isError(Runtime.verifyDirectoryWithCache(alloc, parsed.value, root, profile, limits, &cache)));
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().active_leases);
    std.debug.print("OP_FRESH_SETUP_REUSE cold_ns={} warm_ns={} entries={} hits={} misses={} imported_producer_cache=false replay_rejected=true\n", .{ cold_ns, warm_ns, warm.entries, warm.hits, warm.misses });
    cache.deinit();
    cache_alive = false;
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}

fn exerciseOwnedViews(comptime mapped_last: bool) !void {
    const W = @import("pure_p2_worker_protocol.zig").W;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 1 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var cache = try CacheModule.Cache.init(alloc, path, .{ .heap_bytes = 512 << 20, .disk_bytes = 512 << 20, .mapped_bytes = 512 << 20, .entries = 1, .metadata_bytes = 16 << 20 });
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    var source = try Full.ProgramAuthority.initForOpWord16(alloc, .{ .base = 4096, .words = &.{0x00108093} }, .bytes_v1);
    var source_alive = true;
    defer if (source_alive) source.deinit();
    var class = try cache.acquire(&source, .{ .cpu_log = 5 }, .{}, profile);
    var class_alive = true;
    defer if (class_alive) class.deinit();
    var request = try cache.enterRequest(alloc, 1 << 30, 1 << 30);
    var request_alive = true;
    defer if (request_alive) request.deinit();
    var shape = try W.Prover.init(alloc, profile.config());
    var shape_alive = true;
    defer if (shape_alive) shape.deinit(alloc);
    var mapped = try W.Prover.init(alloc, profile.config());
    var mapped_alive = true;
    defer if (mapped_alive) mapped.deinit(alloc);
    var channel0 = W.Channel.init();
    var channel1 = W.Channel.init();
    const expected_root = class.key().root;
    try class.key().append(alloc, &shape, &channel0);
    try class.key().append(alloc, &mapped, &channel1);
    try class.key().materialize(alloc, &mapped);
    try std.testing.expectEqual(@as(usize, 2), cache.snapshot().owned_views);
    try std.testing.expect(cache.snapshot().mapped_bytes > 0);
    class.deinit();
    class_alive = false;
    request.deinit();
    request_alive = false;
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().active_leases);
    // Returning the request token cannot reopen its quota while an owned PCS
    // view still exists. This also covers a shape-only view after unmapping.
    try std.testing.expectError(error.OpSetupCacheRequestBusy, cache.enterRequest(alloc, 1 << 30, 1 << 30));
    source.deinit();
    source_alive = false;
    cache.deinit();
    cache_alive = false;
    // Neither a Cache nor EntryLease nor RequestLease survives this point.
    // Both independently owned PCS objects still have live storage authority.
    try std.testing.expectEqualSlices(u8, &expected_root, &shape.trees.items[0].root());
    try std.testing.expectEqualSlices(u8, &expected_root, &mapped.trees.items[0].root());
    try std.testing.expect(shape.trees.items[0].commitment.layers_parked);
    try std.testing.expect(!mapped.trees.items[0].commitment.layers_parked);
    try std.testing.expect(mapped.trees.items[0].coefficients.?[0].coeffs.len > 0);
    if (mapped_last) {
        shape.deinit(alloc);
        shape_alive = false;
        try std.testing.expectEqualSlices(u8, &expected_root, &mapped.trees.items[0].root());
        mapped.deinit(alloc);
        mapped_alive = false;
    } else {
        mapped.deinit(alloc);
        mapped_alive = false;
        try std.testing.expectEqualSlices(u8, &expected_root, &shape.trees.items[0].root());
        shape.deinit(alloc);
        shape_alive = false;
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}

test "OP immutable setup owned shape and mapped PCS views retain cache state through teardown" {
    try exerciseOwnedViews(true);
    try exerciseOwnedViews(false);
}
