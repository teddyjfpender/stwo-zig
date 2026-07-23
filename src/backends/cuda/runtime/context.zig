//! Proof-owned CUDA stream, pool, opaque buffers, and transfer accounting.

const std = @import("std");
const native_api = @import("../abi/runtime.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const NativeContext = ContextFor(native_api);

pub fn ContextFor(comptime Api: type) type {
    return struct {
        const Self = @This();

        handle: ?*anyopaque,
        stream: *anyopaque,
        device: u32,
        lane_count: u32,
        live_buffers: usize = 0,
        counters: telemetry.Counters = .{},

        pub const Buffer = struct {
            pointer: [*]u32,
            words: usize,
            owner: usize,

            pub fn bytes(self: Buffer) runtime_error.Error!usize {
                return std.math.mul(usize, self.words, @sizeOf(u32)) catch
                    error.SizeOverflow;
            }
        };

        pub fn open() runtime_error.Error!Self {
            var raw_handle: ?*anyopaque = null;
            try runtime_error.check(Api.stwo_exec_context_create(&raw_handle));
            const handle = raw_handle orelse return error.NullExecutionContext;
            errdefer _ = Api.stwo_exec_context_destroy(handle);

            var raw_stream: ?*anyopaque = null;
            try runtime_error.check(Api.stwo_exec_context_stream(handle, &raw_stream));
            const stream = raw_stream orelse return error.NullExecutionStream;
            var device: c_int = -1;
            try runtime_error.check(Api.stwo_exec_context_device(handle, &device));
            if (device < 0) return error.InvalidDeviceOrdinal;
            var lane_count: u32 = 0;
            try runtime_error.check(Api.stwo_exec_context_lane_count(handle, &lane_count));
            return .{
                .handle = handle,
                .stream = stream,
                .device = @intCast(device),
                .lane_count = lane_count,
            };
        }

        pub fn close(self: *Self) runtime_error.Error!void {
            const handle = self.handle orelse return error.ContextClosed;
            if (self.live_buffers != 0) return error.DeviceBufferLive;
            try runtime_error.check(Api.stwo_exec_context_destroy(handle));
            self.handle = null;
        }

        pub fn allocate(self: *Self, words: usize) runtime_error.Error!Buffer {
            if (words == 0) return error.EmptyAllocation;
            const handle = try self.requireHandle();
            const bytes = std.math.mul(usize, words, @sizeOf(u32)) catch
                return error.SizeOverflow;
            var raw: ?[*]u32 = null;
            try runtime_error.check(Api.stwo_exec_context_alloc_u32(handle, words, &raw));
            const pointer = raw orelse return error.NullDevicePointer;
            self.live_buffers += 1;
            self.counters.allocation(bytes);
            return .{
                .pointer = pointer,
                .words = words,
                .owner = @intFromPtr(handle),
            };
        }

        pub fn free(self: *Self, buffer: *Buffer) runtime_error.Error!void {
            const handle = try self.requireOwner(buffer.*);
            try runtime_error.check(Api.stwo_exec_context_free_u32(handle, buffer.pointer));
            self.counters.free(try buffer.bytes());
            self.live_buffers -= 1;
            buffer.words = 0;
            buffer.owner = 0;
        }

        pub fn upload(
            self: *Self,
            destination: Buffer,
            source: []const u32,
        ) runtime_error.Error!void {
            if (source.len > destination.words) return error.SizeOverflow;
            const handle = try self.requireOwner(destination);
            const bytes = std.math.mul(usize, source.len, @sizeOf(u32)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_h2d_async(
                handle,
                destination.pointer,
                source.ptr,
                bytes,
            ));
            self.counters.h2d_bytes += @intCast(bytes);
        }

        pub fn copyDevice(
            self: *Self,
            destination: Buffer,
            source: Buffer,
            words: usize,
        ) runtime_error.Error!void {
            if (words > destination.words or words > source.words) return error.SizeOverflow;
            const handle = try self.requireOwner(destination);
            _ = try self.requireOwner(source);
            const bytes = std.math.mul(usize, words, @sizeOf(u32)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_d2d_async(
                handle,
                destination.pointer,
                source.pointer,
                bytes,
            ));
            self.counters.d2d_bytes += @intCast(bytes);
        }

        /// The sole host-read API. It is named for the final proof boundary so
        /// intermediate proving code cannot acquire a generic device download.
        pub fn readProofWords(
            self: *Self,
            destination: []u32,
            source: Buffer,
        ) runtime_error.Error!void {
            if (destination.len > source.words) return error.SizeOverflow;
            const handle = try self.requireOwner(source);
            const bytes = std.math.mul(usize, destination.len, @sizeOf(u32)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_d2h_async(
                handle,
                destination.ptr,
                source.pointer,
                bytes,
            ));
            self.counters.d2h_proof_bytes += @intCast(bytes);
        }

        pub fn fill(
            self: *Self,
            destination: Buffer,
            value: u32,
        ) runtime_error.Error!void {
            const handle = try self.requireOwner(destination);
            try runtime_error.check(Api.stwo_exec_context_fill_u32_async(
                handle,
                destination.pointer,
                value,
                destination.words,
            ));
            self.counters.fill_words += @intCast(destination.words);
        }

        pub fn joinLanes(self: *Self) runtime_error.Error!void {
            try runtime_error.check(Api.stwo_exec_context_join_all_lanes(
                try self.requireHandle(),
            ));
            self.counters.lane_joins += 1;
        }

        pub fn sync(self: *Self) runtime_error.Error!void {
            try runtime_error.check(Api.stwo_exec_context_sync(try self.requireHandle()));
            self.counters.sync_calls += 1;
        }

        pub fn poolCurrent(self: *Self) runtime_error.Error!struct {
            used: usize,
            reserved: usize,
        } {
            var used: usize = 0;
            var reserved: usize = 0;
            try runtime_error.check(Api.stwo_exec_context_pool_current(
                try self.requireHandle(),
                &used,
                &reserved,
            ));
            return .{ .used = used, .reserved = reserved };
        }

        pub fn recordKernels(self: *Self, count: u64) runtime_error.Error!void {
            if (count == 0) return error.KernelPathUnused;
            self.counters.kernel_launches += count;
        }

        pub fn recordGraphs(self: *Self, count: u64) runtime_error.Error!void {
            if (count == 0) return error.KernelPathUnused;
            self.counters.graph_launches += count;
        }

        fn requireHandle(self: *Self) runtime_error.Error!*anyopaque {
            return self.handle orelse error.ContextClosed;
        }

        fn requireOwner(self: *Self, buffer: Buffer) runtime_error.Error!*anyopaque {
            const handle = try self.requireHandle();
            if (buffer.words == 0 or buffer.owner != @intFromPtr(handle))
                return error.ContextMismatch;
            return handle;
        }
    };
}

test "context owns buffers and accounts only explicit transfers" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_words: [16]u32 = [_]u32{0} ** 16;

        fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            out.* = 4;
            return 0;
        }
        fn stwo_exec_context_alloc_u32(_: *anyopaque, _: usize, out: *?[*]u32) c_int {
            out.* = &device_words;
            return 0;
        }
        fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            return 0;
        }
        fn stwo_exec_context_memcpy_h2d_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_memcpy_d2d_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_memcpy_d2h_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_fill_u32_async(
            _: *anyopaque,
            _: [*]u32,
            _: u32,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_join_all_lanes(_: *anyopaque) c_int {
            return 0;
        }
        fn stwo_exec_context_sync(_: *anyopaque) c_int {
            return 0;
        }
        fn stwo_exec_context_pool_current(
            _: *anyopaque,
            used: *usize,
            reserved: *usize,
        ) c_int {
            used.* = 0;
            reserved.* = 4096;
            return 0;
        }
    };

    const Context = ContextFor(Fake);
    var context = try Context.open();
    var buffer = try context.allocate(16);
    try context.upload(buffer, &.{ 1, 2, 3, 4 });
    try context.fill(buffer, 7);
    var proof_words: [4]u32 = undefined;
    try context.readProofWords(&proof_words, buffer);
    try context.recordKernels(3);
    try context.free(&buffer);
    try context.close();
    try std.testing.expectEqual(@as(u64, 64), context.counters.peak_live_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.h2d_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.d2h_proof_bytes);
    try std.testing.expect(context.counters.isResident());
}

test "context rejects close with a live device buffer" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_word: u32 = 0;

        fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            out.* = 0;
            return 0;
        }
        fn stwo_exec_context_alloc_u32(_: *anyopaque, _: usize, out: *?[*]u32) c_int {
            out.* = @ptrCast(&device_word);
            return 0;
        }
        fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            return 0;
        }
    };

    const Context = ContextFor(Fake);
    var context = try Context.open();
    var buffer = try context.allocate(1);
    try std.testing.expectError(error.DeviceBufferLive, context.close());
    try context.free(&buffer);
    try context.close();
}
