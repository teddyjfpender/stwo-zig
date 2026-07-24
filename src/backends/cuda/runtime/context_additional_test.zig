const std = @import("std");
const ContextFor = @import("context.zig").ContextFor;
const telemetry = @import("telemetry.zig");

test "context rejects late allocation and host writes" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_word: u32 = 0;

        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        pub fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        pub fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            out.* = 1;
            return 0;
        }
        pub fn stwo_exec_context_alloc_u32(
            _: *anyopaque,
            _: usize,
            out: *?[*]u32,
        ) c_int {
            out.* = @ptrCast(&device_word);
            return 0;
        }
        pub fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_memcpy_h2d_async(
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
    try std.testing.expectError(
        error.AllocationOutsideIngress,
        context.allocate(1),
    );
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

test "context rejects close with a live device buffer" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_word: u32 = 0;

        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        pub fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        pub fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            out.* = 1;
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            return 0;
        }
        pub fn stwo_exec_context_alloc_u32(
            _: *anyopaque,
            _: usize,
            out: *?[*]u32,
        ) c_int {
            out.* = @ptrCast(&device_word);
            return 0;
        }
        pub fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
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

test "context abort releases live allocations from an active stage" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_word: u32 = 0;
        var frees: usize = 0;
        var destroys: usize = 0;
        var sync_calls: usize = 0;

        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            destroys += 1;
            return 0;
        }
        pub fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        pub fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        pub fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            out.* = 1;
            return 0;
        }
        pub fn stwo_exec_context_alloc_u32(
            _: *anyopaque,
            _: usize,
            out: *?[*]u32,
        ) c_int {
            out.* = @ptrCast(&device_word);
            return 0;
        }
        pub fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            frees += 1;
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            sync_calls += 1;
            return 0;
        }
    };

    const Context = ContextFor(Fake);
    var context = try Context.open();
    try context.beginStage(.ingress);
    _ = try context.allocate(1);
    try context.abort();
    try std.testing.expectEqual(@as(usize, 1), Fake.frees);
    try std.testing.expectEqual(@as(usize, 1), Fake.destroys);
    try std.testing.expectEqual(@as(usize, 1), Fake.sync_calls);
    try std.testing.expectEqual(@as(u64, 1), context.counters.sync_calls);
    try std.testing.expectEqual(@as(usize, 0), context.live_buffers);
    try std.testing.expectEqual(@as(?telemetry.Stage, null), context.active_stage);
    try std.testing.expect(context.handle == null);
}
