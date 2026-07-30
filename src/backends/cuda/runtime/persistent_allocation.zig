//! Protected fixed-address allocations retained across proof requests.

const std = @import("std");
const runtime_error = @import("error.zig");

pub fn allocate(
    comptime Api: type,
    context: anytype,
    words: usize,
) runtime_error.Error!@TypeOf(context.*).Buffer {
    if (context.active_stage != null or
        context.live_buffers != context.persistent_buffers or
        !context.synchronized or context.capture_active)
    {
        return error.InvalidState;
    }
    const bytes = std.math.mul(usize, words, @sizeOf(u32)) catch
        return error.SizeOverflow;
    const next_bytes = std.math.add(
        usize,
        context.persistent_bytes,
        bytes,
    ) catch return error.SizeOverflow;
    const buffer = try allocateRegistered(Api, context, words);
    context.persistent_buffers += 1;
    context.persistent_bytes = next_bytes;
    try context.sync();
    return buffer;
}

pub fn allocateRegistered(
    comptime Api: type,
    context: anytype,
    words: usize,
) runtime_error.Error!@TypeOf(context.*).Buffer {
    if (words == 0) return error.EmptyAllocation;
    _ = Api;
    const handle = context.handle orelse return error.ContextClosed;
    const bytes = std.math.mul(usize, words, @sizeOf(u32)) catch
        return error.SizeOverflow;
    var raw: ?[*]u32 = null;
    try context.allocateRaw(words, &raw);
    context.synchronized = false;
    const pointer = raw orelse return error.NullDevicePointer;
    if (context.live_buffers == context.allocations.len) {
        _ = context.freeRaw(pointer);
        return error.AllocationRegistryFull;
    }
    const generation = context.next_allocation_generation;
    context.next_allocation_generation = std.math.add(
        u64,
        generation,
        1,
    ) catch {
        _ = context.freeRaw(pointer);
        return error.AllocationRegistryFull;
    };
    context.allocations[context.live_buffers] = .{
        .address = @intFromPtr(pointer),
        .bytes = bytes,
        .generation = generation,
    };
    context.live_buffers += 1;
    return .{
        .pointer = pointer,
        .words = words,
        .owner = @intFromPtr(handle),
        .generation = generation,
    };
}

pub fn free(
    comptime Api: type,
    context: anytype,
    buffer: anytype,
) runtime_error.Error!void {
    const handle = context.handle orelse return error.ContextClosed;
    if (buffer.words == 0 or buffer.owner != @intFromPtr(handle) or
        buffer.generation == 0)
    {
        return error.ContextMismatch;
    }
    const bytes = try buffer.bytes();
    const address = @intFromPtr(buffer.pointer);
    var allocation_index: ?usize = null;
    for (context.allocations[0..context.live_buffers], 0..) |item, index| {
        if (item.address == address and item.bytes == bytes and
            item.generation == buffer.generation)
        {
            allocation_index = index;
            break;
        }
    }
    if (allocation_index == null) return error.ContextMismatch;
    if (context.active_stage != null or
        context.live_buffers != context.persistent_buffers or
        context.capture_active)
    {
        return error.InvalidState;
    }
    _ = Api;
    try runtime_error.check(context.freeRaw(buffer.pointer));
    context.synchronized = false;
    context.live_buffers -= 1;
    context.persistent_buffers -= 1;
    context.persistent_bytes -= bytes;
    // Registry indices are not handles, so idle cached arenas may free in LRU
    // order while the live registry remains compact.
    if (allocation_index.? != context.live_buffers) {
        context.allocations[allocation_index.?] =
            context.allocations[context.live_buffers];
    }
    context.allocations[context.live_buffers] = .{};
    buffer.words = 0;
    buffer.owner = 0;
    buffer.generation = 0;
    try context.sync();
}
