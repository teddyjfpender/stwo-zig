const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Cache = @import("../block_v5_native_recursive_setup_cache_v1.zig").ForBackend(Cpu);
const Bus = @import("../../recursion/block_v5_recursive_public_bus_v1.zig");
const Storage = @import("../../recursion/air/blake3_parent_row_storage.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig");
const M = core.fields.m31.M31;

fn consumingFailure(comptime preflight: bool) !void {
    const a = std.testing.allocator;
    for ([_]enum { request_lock, cache_lock, security }{ .request_lock, .cache_lock, .security }) |failure| {
        var cache = try Cache.init(a, .{ .profile = .diagnostic_q8_pow0, .aggregate_host_byte_limit = 1024 * 1024, .worker_options = .{ .worker_count = 1, .host_byte_limit = 1024 * 1024, .retained_scratch_limit = 0 } });
        defer cache.deinit();
        var rows = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
        inline for (Storage.Airs, 0..) |_, i| rows.fixed[i] = &.{};
        var owns_rows = true;
        defer if (owns_rows) rows.deinit();
        rows.main[0] = try a.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, 1);
        rows.main[0][0] = .{ .log_size = 1, .values = &.{} };
        rows.main[0][0].values = try a.dupe(M, &.{ M.zero(), M.one() });
        rows.fixed[0] = try a.alloc(Storage.FixedRow(Storage.Airs[0]), 1);
        rows.fixed[0][0] = @splat(M.zero());
        const wire = Bus.Wire{ .circuit = 1500, .wire = 0, .uses = 1, .source = .compensation, .coordinate = 0 };
        const wires = try a.dupe(Bus.Wire, &.{wire});
        var prepared = Bus.Prepared{ .allocator = a, .recursive = .{ .rows = rows, .context = .{ .child_key_id = @splat(11), .child_config = Profile.PCS_CONFIG, .graph_ids = @splat(@splat(13)), .transcript_plan_id = @splat(17) } }, .wires = wires, .values = undefined };
        owns_rows = false;
        defer prepared.deinit();
        if (failure == .request_lock) cache.requests.lock();
        defer if (failure == .request_lock) cache.requests.unlock();
        if (failure == .cache_lock) cache.busy.lock();
        defer if (failure == .cache_lock) cache.busy.unlock();
        if (failure == .security) prepared.recursive.context.child_config.fri_config.n_queries += 1;
        const expected = if (failure == .security) error.V5NativeSetupCacheSecurityMismatch else error.V5NativeSetupCacheAlreadyLeased;
        var notifications: usize = 0;
        const Before = struct {
            fn check(raw: *anyopaque, _: @import("../../recursion/block_v5_reusable_native_parent_protocol_v1.zig").Key, _: [32]u8, _: []const Bus.Wire) anyerror!void {
                const calls: *usize = @ptrCast(@alignCast(raw));
                calls.* += 1;
                return error.UnexpectedFixturePreflight;
            }
        };
        if (preflight)
            try std.testing.expectError(expected, cache.provePreparedConsumingWithPreflight(&prepared, &notifications, Before.check))
        else
            try std.testing.expectError(expected, cache.provePreparedConsuming(&prepared));
        try std.testing.expectEqual(@as(usize, 0), notifications);
        inline for (Storage.Airs, 0..) |_, i| {
            try std.testing.expectEqual(@as(usize, 0), prepared.recursive.rows.main[i].len);
            try std.testing.expectEqual(@as(usize, 0), prepared.recursive.rows.fixed[i].len);
        }
        // Encoding/routing metadata has a different owner and survives row
        // release. The outer Prepared.deinit is still idempotently safe.
        try std.testing.expect(prepared.wires.ptr == wires.ptr);
        try std.testing.expectEqualDeep(wire, prepared.wires[0]);
        try std.testing.expectEqualDeep([_]u8{11} ** 32, prepared.recursive.context.child_key_id);
        try std.testing.expectEqual(@as(usize, 0), cache.stats.misses);
    }
}

test "block-v5 consuming native cache releases rows on lease and admission failure" {
    try consumingFailure(false);
}
test "supplemental worker reuse: rejected joined setup releases rows without preflight notification" {
    try consumingFailure(true);
}
