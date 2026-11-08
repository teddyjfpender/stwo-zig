const std = @import("std");

test "fixed precommit scope promotion is exact and failure atomic" {
    const Service = @import("../pcs_native.zig");
    const Abi = @import("../pcs_native_abi.zig");
    const State = struct {
        refuse: bool = true,
        calls: usize = 0,
        fn validate(_: *anyopaque, lease: *const Abi.Lease, scope: *const [8]u32) callconv(.c) c_int {
            return if (lease.kind == 2 and lease.count == 64 and lease.context_token == 17 and lease.generation == 23 and scope[0] == 1) 0 else 1;
        }
        fn rebind(raw: *anyopaque, lease: *const Abi.Lease, old: *const [8]u32, next: *const [8]u32) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            if (self.refuse or validate(raw, lease, old) != 0 or next[0] != 2) return 1;
            return 0;
        }
    };
    var state = State{};
    var context: Service.Context = undefined;
    context.cache = .empty;
    context.cache_mutex = .{};
    context.session = &state;
    context.lease_validate = State.validate;
    defer {
        for (context.cache.items) |*entry| entry.extra.deinit(std.heap.page_allocator);
        context.cache.deinit(std.heap.page_allocator);
    }
    const old: [8]u32 = .{ 1, 0, 0, 0, 0, 0, 0, 0 };
    const next: [8]u32 = .{ 2, 0, 0, 0, 0, 0, 0, 0 };
    const lease = Abi.Lease{ .words = @ptrFromInt(4096), .count = 64, .context_token = 17, .generation = 23, .kind = 2 };
    try context.cache.append(std.heap.page_allocator, .{ .scope = old, .lease = lease, .columns = &.{} });
    try context.cache.append(std.heap.page_allocator, .{ .scope = next, .lease = .{ .words = @ptrFromInt(8192), .count = 128, .context_token = 17, .generation = 24, .kind = 2 }, .columns = &.{} });
    try std.testing.expectError(error.InvalidFixedScopePromotion, context.promoteSingleRetained(old, old, State.rebind));
    try std.testing.expectError(error.MissingFixedCoefficientScope, context.promoteSingleRetained(.{ 9, 0, 0, 0, 0, 0, 0, 0 }, next, State.rebind));
    context.cache.items[0].lease.generation = 22;
    try std.testing.expectError(error.InvalidRetainedCoefficientLease, context.promoteSingleRetained(old, next, State.rebind));
    context.cache.items[0].lease = lease;
    try std.testing.expectError(error.InvalidFixedScopePromotion, context.promoteSingleRetained(old, next, State.rebind));
    try std.testing.expectEqual(@as(usize, 2), context.cache.items.len);
    try std.testing.expectEqual(@as(usize, 0), context.cache.items[1].extra.items.len);
    state.refuse = false;
    try context.promoteSingleRetained(old, next, State.rebind);
    try std.testing.expectEqual(@as(usize, 1), context.cache.items.len);
    try std.testing.expectEqual(next, context.cache.items[0].scope);
    try std.testing.expectEqual(@as(usize, 1), context.cache.items[0].extra.items.len);
    try std.testing.expectEqual(lease, context.cache.items[0].extra.items[0]);
    try std.testing.expectError(error.MissingFixedCoefficientScope, context.promoteSingleRetained(old, next, State.rebind));
}
