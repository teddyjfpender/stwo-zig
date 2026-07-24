//! Opaque, context-owned CUDA columns.

const std = @import("std");
const context_module = @import("context.zig");
const native_api = @import("../abi/runtime.zig");
const runtime_error = @import("error.zig");

pub fn DeviceSlice(comptime F: type) type {
    requireFieldLayout(F);
    return struct {
        const Self = @This();

        address: usize,
        len: usize,
        owner: usize,

        pub fn sub(self: Self, first: usize, count: usize) runtime_error.Error!Self {
            if (first > self.len or count > self.len - first) return error.SizeOverflow;
            const byte_offset = std.math.mul(usize, first, @sizeOf(F)) catch
                return error.SizeOverflow;
            return .{
                .address = std.math.add(usize, self.address, byte_offset) catch
                    return error.SizeOverflow,
                .len = count,
                .owner = self.owner,
            };
        }

        pub fn cast(self: Self, comptime G: type) runtime_error.Error!DeviceSlice(G) {
            requireFieldLayout(G);
            const bytes = std.math.mul(usize, self.len, @sizeOf(F)) catch
                return error.SizeOverflow;
            if (self.address % @alignOf(G) != 0 or bytes % @sizeOf(G) != 0)
                return error.InvalidDeviceAddress;
            return .{
                .address = self.address,
                .len = bytes / @sizeOf(G),
                .owner = self.owner,
            };
        }

        /// Device address for an exact native ABI call. It is never a host slice.
        pub fn devicePointer(self: Self) *anyopaque {
            return @ptrFromInt(self.address);
        }
    };
}

pub const NativeBaseFieldColumn = DeviceColumnFor(
    context_module.ContextFor(native_api),
    u32,
);

pub fn DeviceColumnFor(comptime Context: type, comptime F: type) type {
    requireFieldLayout(F);
    return struct {
        const Self = @This();

        buffer: Context.Buffer,
        len: usize,

        pub fn allocate(
            context: *Context,
            len: usize,
        ) runtime_error.Error!Self {
            if (len == 0) return error.EmptyAllocation;
            const words = std.math.mul(usize, len, @sizeOf(F) / @sizeOf(u32)) catch
                return error.SizeOverflow;
            return .{
                .buffer = try context.allocate(words),
                .len = len,
            };
        }

        pub fn fromHost(
            context: *Context,
            values: []const F,
        ) runtime_error.Error!Self {
            var result = try Self.allocate(context, values.len);
            errdefer context.free(&result.buffer) catch {};
            const word_count = std.math.mul(
                usize,
                values.len,
                @sizeOf(F) / @sizeOf(u32),
            ) catch return error.SizeOverflow;
            const words: [*]const u32 = @ptrCast(@alignCast(values.ptr));
            try context.upload(result.buffer, words[0..word_count]);
            return result;
        }

        pub fn copyFrom(
            self: Self,
            context: *Context,
            source: Self,
        ) runtime_error.Error!void {
            if (self.len != source.len) return error.SizeOverflow;
            try context.copyDevice(self.buffer, source.buffer, self.buffer.words);
        }

        pub fn slice(self: Self) DeviceSlice(F) {
            return .{
                .address = @intFromPtr(self.buffer.pointer),
                .len = self.len,
                .owner = self.buffer.owner,
            };
        }

        pub fn deinit(self: *Self, context: *Context) runtime_error.Error!void {
            try context.free(&self.buffer);
            self.len = 0;
        }
    };
}

fn requireFieldLayout(comptime F: type) void {
    if (@sizeOf(F) == 0 or @sizeOf(F) % @sizeOf(u32) != 0 or @alignOf(F) < @alignOf(u32)) {
        @compileError("CUDA column elements must be non-empty, u32-word-aligned layouts");
    }
}

test "device slice arithmetic never creates a host slice" {
    const Slice = DeviceSlice(u32);
    const whole = Slice{ .address = 0x1000, .len = 16, .owner = 7 };
    const middle = try whole.sub(3, 5);
    try std.testing.expectEqual(@as(usize, 0x100c), middle.address);
    try std.testing.expectEqual(@as(usize, 5), middle.len);
    try std.testing.expectEqual(@as(usize, 7), middle.owner);
    try std.testing.expect(!@hasDecl(Slice, "toHost"));
    try std.testing.expect(!@hasDecl(Slice, "items"));
}

test "device slice casts preserve byte extent and reject bad alignment" {
    const words = DeviceSlice(u32){
        .address = 0x1000,
        .len = 16,
        .owner = 7,
    };
    const wide = try words.cast(u64);
    try std.testing.expectEqual(@as(usize, 8), wide.len);
    try std.testing.expectEqual(words.address, wide.address);
    try std.testing.expectEqual(words.owner, wide.owner);

    var misaligned = words;
    misaligned.address += @sizeOf(u32);
    try std.testing.expectError(error.InvalidDeviceAddress, misaligned.cast(u64));
}
