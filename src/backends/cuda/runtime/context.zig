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
        active_stage: ?telemetry.Stage = null,
        next_stage_index: usize = 0,
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
            if (self.active_stage != null) return error.StageAlreadyActive;
            try runtime_error.check(Api.stwo_exec_context_destroy(handle));
            self.handle = null;
        }

        pub fn beginStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            _ = try self.requireHandle();
            if (self.active_stage != null) return error.StageAlreadyActive;
            if (self.next_stage_index >= telemetry.all_stages.len or
                telemetry.all_stages[self.next_stage_index] != stage)
            {
                return error.StageOrderViolation;
            }
            self.active_stage = stage;
        }

        pub fn endStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const active = self.active_stage orelse return error.StageNotActive;
            if (active != stage) return error.StageOrderViolation;
            const stage_counters = self.counters.stages[stage.index()];
            if (stage.requiresKernel() and
                stage_counters.kernel_launches == 0 and
                stage_counters.graph_launches == 0)
            {
                return error.KernelPathUnused;
            }
            self.counters.complete(stage);
            self.active_stage = null;
            self.next_stage_index += 1;
        }

        pub fn stagesComplete(self: Self) bool {
            return self.active_stage == null and
                self.next_stage_index == telemetry.all_stages.len and
                self.counters.stagesCompleteExactlyOnce();
        }

        pub fn allocate(self: *Self, words: usize) runtime_error.Error!Buffer {
            if (self.active_stage != .ingress)
                return error.AllocationOutsideIngress;
            if (words == 0) return error.EmptyAllocation;
            const handle = try self.requireHandle();
            const bytes = std.math.mul(usize, words, @sizeOf(u32)) catch
                return error.SizeOverflow;
            var raw: ?[*]u32 = null;
            try runtime_error.check(Api.stwo_exec_context_alloc_u32(handle, words, &raw));
            const pointer = raw orelse return error.NullDevicePointer;
            self.live_buffers += 1;
            self.counters.allocation(self.active_stage, bytes);
            return .{
                .pointer = pointer,
                .words = words,
                .owner = @intFromPtr(handle),
            };
        }

        pub fn free(self: *Self, buffer: *Buffer) runtime_error.Error!void {
            const handle = try self.requireOwner(buffer.*);
            try runtime_error.check(Api.stwo_exec_context_free_u32(handle, buffer.pointer));
            self.counters.free(self.active_stage, try buffer.bytes());
            self.live_buffers -= 1;
            buffer.words = 0;
            buffer.owner = 0;
        }

        pub fn upload(
            self: *Self,
            destination: Buffer,
            source: []const u32,
        ) runtime_error.Error!void {
            if (self.active_stage != .ingress)
                return error.HostWriteOutsideIngress;
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
            self.counters.h2d(self.active_stage, bytes);
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
            self.counters.d2d(self.active_stage, bytes);
        }

        pub fn devicePointer(
            self: *Self,
            buffer: Buffer,
            minimum_words: usize,
        ) runtime_error.Error![*]u32 {
            _ = try self.requireOwner(buffer);
            if (minimum_words == 0 or buffer.words < minimum_words)
                return error.SizeOverflow;
            return buffer.pointer;
        }

        pub fn deviceSlicePointer(
            self: *Self,
            comptime F: type,
            slice: anytype,
            minimum_elements: usize,
        ) runtime_error.Error![*]F {
            const handle = try self.requireHandle();
            if (minimum_elements == 0 or
                slice.len < minimum_elements or
                slice.owner != @intFromPtr(handle) or
                slice.address == 0 or
                slice.address % @alignOf(F) != 0)
            {
                return error.InvalidDeviceAddress;
            }
            return @ptrFromInt(slice.address);
        }

        pub fn requireStage(
            self: *Self,
            expected: telemetry.Stage,
        ) runtime_error.Error!void {
            _ = try self.requireHandle();
            if (self.active_stage != expected) return error.StageOrderViolation;
        }

        /// The sole host-read API. It is named for the final proof boundary so
        /// intermediate proving code cannot acquire a generic device download.
        pub fn readProofWords(
            self: *Self,
            destination: []u32,
            source: Buffer,
        ) runtime_error.Error!void {
            const stage = self.active_stage orelse
                return error.HostReadOutsideProofAssembly;
            if (stage != .proof_assembly)
                return error.HostReadOutsideProofAssembly;
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
            self.counters.proofRead(stage, bytes);
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
            self.counters.fill(self.active_stage, destination.words);
        }

        pub fn joinLanes(self: *Self) runtime_error.Error!void {
            try runtime_error.check(Api.stwo_exec_context_join_all_lanes(
                try self.requireHandle(),
            ));
            self.counters.join(self.active_stage);
        }

        pub fn sync(self: *Self) runtime_error.Error!void {
            try runtime_error.check(Api.stwo_exec_context_sync(try self.requireHandle()));
            self.counters.sync(self.active_stage);
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
            const stage = self.active_stage orelse return error.StageNotActive;
            self.counters.kernels(stage, count);
        }

        pub fn recordGraphs(self: *Self, count: u64) runtime_error.Error!void {
            if (count == 0) return error.KernelPathUnused;
            const stage = self.active_stage orelse return error.StageNotActive;
            self.counters.graphs(stage, count);
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
    try context.beginStage(.ingress);
    var buffer = try context.allocate(16);
    try context.upload(buffer, &.{ 1, 2, 3, 4 });
    try context.fill(buffer, 7);
    const owned_slice = .{
        .address = @intFromPtr(buffer.pointer),
        .len = buffer.words,
        .owner = buffer.owner,
    };
    try std.testing.expectEqual(
        @intFromPtr(buffer.pointer),
        @intFromPtr(try context.deviceSlicePointer(u32, owned_slice, 16)),
    );
    var foreign_slice = owned_slice;
    foreign_slice.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, foreign_slice, 1),
    );
    try context.endStage(.ingress);
    try context.beginStage(.trace_commit);
    try context.recordKernels(3);
    try context.endStage(.trace_commit);
    try std.testing.expectError(
        error.StageOrderViolation,
        context.beginStage(.proof_assembly),
    );
    inline for (.{
        telemetry.Stage.constraint_evaluation,
        telemetry.Stage.oods,
        telemetry.Stage.quotient,
        telemetry.Stage.fri_commit,
        telemetry.Stage.pow,
        telemetry.Stage.decommit,
    }) |stage| {
        try context.beginStage(stage);
        try context.recordKernels(1);
        try context.endStage(stage);
    }
    try context.beginStage(.proof_assembly);
    var proof_words: [4]u32 = undefined;
    try context.readProofWords(&proof_words, buffer);
    try context.free(&buffer);
    try context.endStage(.proof_assembly);
    try context.close();
    try std.testing.expectEqual(@as(u64, 64), context.counters.peak_live_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.h2d_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.d2h_proof_bytes);
    try std.testing.expect(context.counters.isResident());
    try std.testing.expect(context.counters.stagesCompleteExactlyOnce());
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
    try context.beginStage(.ingress);
    var buffer = try context.allocate(1);
    try std.testing.expectError(error.DeviceBufferLive, context.close());
    try context.free(&buffer);
    try context.endStage(.ingress);
    try context.close();
}

test "context rejects late allocation and host writes" {
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
            out.* = 1;
            return 0;
        }
        fn stwo_exec_context_alloc_u32(_: *anyopaque, _: usize, out: *?[*]u32) c_int {
            out.* = @ptrCast(&device_word);
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
    };

    const Context = ContextFor(Fake);
    var context = try Context.open();
    try std.testing.expectError(error.AllocationOutsideIngress, context.allocate(1));
    try context.beginStage(.ingress);
    var buffer = try context.allocate(1);
    try context.endStage(.ingress);
    try std.testing.expectError(
        error.HostWriteOutsideIngress,
        context.upload(buffer, &.{1}),
    );
    try context.free(&buffer);
    try context.close();
}
