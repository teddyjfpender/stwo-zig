//! Proof-owned no-copy Metal views over cached commitments' evaluated columns.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Runtime = @import("../runtime.zig").Runtime;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;

extern fn stwo_zig_metal_cached_column_view_v1(
    runtime: *anyopaque,
    columns: [*]const [*]const u32,
    lengths: [*]const usize,
    count: u32,
    backings: [*]const [*]const u32,
    backing_lengths: [*]const usize,
    backing_count: u32,
    log_size: u32,
    message: [*]u8,
    message_len: usize,
) ?*anyopaque;
extern fn stwo_zig_metal_tree_destroy(tree: *anyopaque) void;
extern fn stwo_zig_metal_cached_column_view_is_unified(runtime: *anyopaque) bool;

pub const View = struct {
    handle: *anyopaque,
    reservation: Budget.ExternalReservation,

    pub fn deinit(self: *View) void {
        stwo_zig_metal_tree_destroy(self.handle);
        self.reservation.deinit();
        self.* = undefined;
    }
};

pub fn create(
    runtime: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []const M31,
    backings: ?[]const []M31,
    log_size: u32,
) !View {
    const regions = backings orelse &.{};
    if (columns.len == 0 or columns.len > std.math.maxInt(u32) or
        regions.len > std.math.maxInt(u32) or log_size >= 31)
        return error.InvalidCachedColumnGeometry;
    const pointers = try allocator.alloc([*]const u32, columns.len);
    defer allocator.free(pointers);
    const lengths = try allocator.alloc(usize, columns.len);
    defer allocator.free(lengths);
    for (columns, pointers, lengths) |column, *pointer, *length| {
        pointer.* = @ptrCast(column.ptr);
        length.* = column.len;
    }
    const backing_pointers = try allocator.alloc([*]const u32, regions.len);
    defer allocator.free(backing_pointers);
    const backing_lengths = try allocator.alloc(usize, regions.len);
    defer allocator.free(backing_lengths);
    var copied_bytes: u64 = 0;
    const unified = stwo_zig_metal_cached_column_view_is_unified(runtime.handle);
    for (regions, backing_pointers, backing_lengths) |region, *pointer, *length| {
        pointer.* = @ptrCast(region.ptr);
        length.* = region.len;
        const bytes = try std.math.mul(u64, region.len, @sizeOf(M31));
        if (!unified or @intFromPtr(region.ptr) % std.heap.pageSize() != 0 or bytes % std.heap.pageSize() != 0)
            copied_bytes = try std.math.add(u64, copied_bytes, bytes);
    }
    if (regions.len == 0) for (columns) |column| {
        copied_bytes = try std.math.add(u64, copied_bytes, try std.math.mul(u64, column.len, @sizeOf(M31)));
    };
    var reservation = if (Budget.fromAllocator(allocator)) |budget|
        try budget.reserveExternal(copied_bytes)
    else
        Budget.ExternalReservation.unbudgeted(copied_bytes);
    errdefer reservation.deinit();
    var message: [1024]u8 = @splat(0);
    const handle = stwo_zig_metal_cached_column_view_v1(
        runtime.handle,
        pointers.ptr,
        lengths.ptr,
        @intCast(columns.len),
        backing_pointers.ptr,
        backing_lengths.ptr,
        @intCast(regions.len),
        log_size,
        &message,
        message.len,
    ) orelse {
        std.log.err("cached Metal column admission failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return error.CachedMetalColumnAdmissionFailed;
    };
    return .{ .handle = handle, .reservation = reservation };
}
