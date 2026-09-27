//! Pure geometry/budget/admission/fault fixtures. No commitment or proof runs.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Helper = @import("block_v5_native_capacity_fixed_cache_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Fixture = @import("block_v5_native_capacity_transport_fixture_v1.zig");
const Cache = Helper.ForBackend(Cpu).Cache;
const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_v1;

fn metadata(a: std.mem.Allocator) !void {
    var shape = Fixture.shape(4);
    const template = try Protocol.Template.fromShape(&shape, 0, Fixture.config, profile, @splat(17));
    const pin = Helper.Expected{ .template = template, .template_id = try template.identity() };
    var request = (try Helper.preflight(a, &shape, 0, Fixture.config, profile, .{}, pin)) orelse return error.TestExpectedMetadata;
    defer request.deinit();
    try std.testing.expect(try request.matches(template, pin.template_id));
    try std.testing.expect(request.retained_bytes > 0);
    try std.testing.expectEqualSlices(u32, &.{ 2, 2 }, request.logs);
    // Genuine same-capacity counts: both 4 and 3 require log2. A count
    // crossing the power-of-two boundary must use another capacity template.
    shape.component_descs[0].n_rows = 3;
    shape.total_steps = 3;
    shape.public_data.clock = 3;
    var shorter = (try Helper.preflight(a, &shape, 0, Fixture.config, profile, .{}, pin)) orelse return error.TestExpectedMetadata;
    defer shorter.deinit();
    try std.testing.expectEqualDeep(request.capacity_digest, shorter.capacity_digest);
    try std.testing.expectEqualSlices(u32, request.logs, shorter.logs);
    try std.testing.expectEqual(request.retained_bytes, shorter.retained_bytes);
    var noncanonical = shape;
    noncanonical.component_descs[0].n_rows = 2;
    noncanonical.total_steps = 2;
    noncanonical.public_data.clock = 2;
    // Deliberately retain log2: an empty cache budget cannot authorize a
    // padded source or mask the independently validated statement failure.
    try std.testing.expectError(error.InvalidStatement, Helper.preflight(a, &noncanonical, 0, Fixture.config, profile, .{ .max_retained_bytes = 0 }, pin));
    const other = try Protocol.Template.fromShape(&shape, 0, Fixture.config, .rv32im_zkvm_ethereum_sha_v1, @splat(17));
    try std.testing.expect(!(try request.matches(other, try other.identity())));
    var changed = template;
    changed.fixed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityFixedCache, request.matches(changed, pin.template_id));
    const changed_id = try changed.identity();
    // A staged independent root cannot be silently replaced by a cache owner.
    try std.testing.expectError(error.UntrustedNativeCapacityFixedCache, request.matches(changed, changed_id));
}
test "capacity fixed cache: exact capacity metadata reuses logical counts and authenticates expected root" {
    try metadata(std.testing.allocator);
}
test "capacity fixed cache: metadata allocation faults never publish a partial owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, metadata, .{});
}

fn cold(a: std.mem.Allocator) !void {
    var shape = Fixture.shape(3);
    const template = try Protocol.Template.fromShape(&shape, 0, Fixture.config, profile, @splat(17));
    const pin = Helper.Expected{ .template = template, .template_id = try template.identity() };
    var cache = try Cache.init(a, .{ .max_retained_bytes = 0 });
    defer cache.deinit() catch @panic("pure cache fixture retained ownership");
    // Zero/small configured budgets select a genuine cold caller path without
    // constructing a fake fixed owner. acquire returns no token or authority.
    try std.testing.expect((try cache.acquire(a, &shape, 0, Fixture.config, profile, pin)) == null);
    try std.testing.expect(cache.owner == null and !cache.busy and cache.generation == 0);
    var wrong = pin;
    wrong.template_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, cache.acquire(a, &shape, 0, Fixture.config, profile, wrong));
    var config = Fixture.config;
    config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedNativeCapacityFixedCache, cache.acquire(a, &shape, 0, config, profile, pin));
    try std.testing.expect(cache.owner == null and !cache.busy);
}
test "capacity fixed cache: disabled cache falls back only after independent staged admission validates" {
    try cold(std.testing.allocator);
}
test "capacity fixed cache: cold-cap metadata faults propagate OOM without owner or busy token" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cold, .{});
}

test "capacity fixed cache: malformed caps allocator phase and generation never become cold misses" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidNativeCapacityFixedCacheLimits, Cache.init(a, .{ .max_log = 25 }));
    try std.testing.expectError(error.InvalidNativeCapacityFixedCacheLimits, Cache.init(a, .{ .max_columns = 2 * Protocol.MAX_SHARDS + 1 }));
    var shape = Fixture.shape(3);
    var cache = try Cache.init(a, .{});
    defer if (cache.live) {
        // The injected marker below is a phase counterexample, not a real PCS
        // lease. Reset it solely for fixture cleanup after rejection.
        cache.busy = false;
        cache.deinit() catch @panic("pure cache fixture retained ownership");
    };
    try std.testing.expectError(error.NativeCapacityFixedCacheAllocatorMismatch, cache.acquire(std.heap.page_allocator, &shape, 0, Fixture.config, profile, null));
    cache.busy = true;
    try std.testing.expectError(error.NativeCapacityFixedCacheBusy, cache.acquire(a, &shape, 0, Fixture.config, profile, null));
    try std.testing.expectError(error.NativeCapacityFixedCacheBusy, cache.deinit());
    try std.testing.expect(cache.live and cache.busy);
    cache.busy = false;
    cache.generation = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, cache.acquire(a, &shape, 0, Fixture.config, profile, null));
    try std.testing.expect(cache.owner == null and !cache.busy);
    try cache.deinit();
    try std.testing.expectError(error.InvalidNativeCapacityFixedCachePhase, cache.acquire(a, &shape, 0, Fixture.config, profile, null));
}

test "capacity fixed cache: low log and column caps remain cold with exact valid source geometry" {
    const a = std.testing.allocator;
    var shape = Fixture.shape(3);
    try std.testing.expect((try Helper.preflight(a, &shape, 0, Fixture.config, profile, .{ .max_log = 1 }, null)) == null);
    try std.testing.expect((try Helper.preflight(a, &shape, 0, Fixture.config, profile, .{ .max_columns = 1 }, null)) == null);
    // Malformed source is never masked by a deliberate zero cache budget.
    shape.component_descs[0].n_rows = 0;
    var accepted = Helper.preflight(a, &shape, 0, Fixture.config, profile, .{ .max_retained_bytes = 0 }, null) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    if (accepted) |*request| request.deinit();
    return error.TestExpectedMalformedSourceRejection;
}

test "capacity fixed cache: genuine acquisition release and collector bodies retained without invocation" {
    inline for (.{ &Cache.acquire, &Cache.deinit, &Helper.ForBackend(Cpu).Lease.release, &@import("block_v5_cpu_collect_v1.zig").ForCapacity(true).collect }) |body| std.mem.doNotOptimizeAway(body);
}
