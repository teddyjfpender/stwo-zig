//! GKR projection temporaries end at the joined projection barrier. Their
//! memory need not coexist with the product-tree/sumcheck workspace.
const std = @import("std");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
pub fn peakWords(metadata: usize, fractions: usize, source: usize, twiddles: usize, workspace: usize, keep_coefficients: bool) !usize {
    const retained = if (keep_coefficients) source else 0;
    const projection = try std.math.add(usize, try std.math.add(usize, retained, source), twiddles);
    const traversal = try std.math.add(usize, retained, workspace);
    return std.math.add(usize, try std.math.add(usize, metadata, fractions), @max(projection, traversal));
}
/// Caller must join all readers first. Remove custody only after a successful
/// native release; a failed release remains available to terminal cleanup.
pub fn retire(ctx: *SC.Context, leases: *std.ArrayList(Native.Lease), value: Slice) !void {
    for (leases.items, 0..) |*lease, i| {
        if (lease.words == null or @intFromPtr(lease.words.?) != value.address or lease.count != value.len or lease.context_token != value.owner or lease.generation != value.generation) continue;
        if (lease.kind != 0 or lease.reserved != 0) return error.ProjectionTemporaryNotOwned;
        try ctx.release(lease);
        _ = leases.swapRemove(i);
        return;
    }
    return error.ProjectionTemporaryNotOwned;
}

test "projection peak excludes retired evaluations and preserves published coefficients" {
    try std.testing.expectEqual(@as(usize, 123), try peakWords(1, 2, 100, 20, 110, false));
    try std.testing.expectEqual(@as(usize, 223), try peakWords(1, 2, 100, 20, 110, true));
    try std.testing.expectEqual(@as(usize, 203), try peakWords(1, 2, 100, 20, 200, false));
    try std.testing.expectError(error.Overflow, peakWords(1, 2, std.math.maxInt(usize), 1, 0, false));
}
test "projection retirement checks exact custody and keeps failed native releases owned" {
    const State = struct {
        fail: bool = true,
        releases: usize = 0,
        fn validate(_: *anyopaque, pointer: [*]const u32, words: u64, token: u64, generation: u64, scope: *const [8]u32) callconv(.c) c_int {
            return @intFromBool(@intFromPtr(pointer) != 4096 or words != 64 or token != 7 or generation != 11 or !std.mem.allEqual(u32, scope, 3));
        }
        fn release(raw: *anyopaque, lease: *Native.Lease) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.fail) return 1;
            self.releases += 1;
            lease.* = .{};
            return 0;
        }
    };
    var state = State{};
    const api = SC.Api{ .allocate = undefined, .release = State.release, .validate_range = State.validate, .upload = undefined, .download = undefined, .sync = undefined, .lane_stream = undefined };
    var ctx = SC.Context{ .session = &state, .native_context = &state, .token = 7, .scope = @splat(3), .api = &api };
    var leases: std.ArrayList(Native.Lease) = .empty;
    defer leases.deinit(std.testing.allocator);
    try leases.append(std.testing.allocator, .{ .words = @ptrFromInt(4096), .count = 64, .context_token = 7, .generation = 11 });
    const value = try ctx.borrow(leases.items[0]);
    var wrong = value;
    wrong.generation += 1;
    try std.testing.expectError(error.ProjectionTemporaryNotOwned, retire(&ctx, &leases, wrong));
    try std.testing.expectError(error.ProjectionTemporaryNotOwned, retire(&ctx, &leases, try value.sub(0, 32)));
    leases.items[0].kind = 2;
    try std.testing.expectError(error.ProjectionTemporaryNotOwned, retire(&ctx, &leases, value));
    leases.items[0].kind = 0;
    ctx.scope = @splat(4);
    try std.testing.expectError(error.InvalidDeviceAddress, retire(&ctx, &leases, value));
    ctx.scope = @splat(3);
    try std.testing.expectError(error.CudaReleaseFailed, retire(&ctx, &leases, value));
    try std.testing.expectEqual(@as(usize, 1), leases.items.len);
    state.fail = false;
    try retire(&ctx, &leases, value);
    try std.testing.expectEqual(@as(usize, 0), leases.items.len);
    try std.testing.expectEqual(@as(usize, 1), state.releases);
    try std.testing.expectError(error.ProjectionTemporaryNotOwned, retire(&ctx, &leases, value));
}
