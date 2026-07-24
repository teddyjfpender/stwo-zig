const std = @import("std");
const ContextFor = @import("context.zig").ContextFor;

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
