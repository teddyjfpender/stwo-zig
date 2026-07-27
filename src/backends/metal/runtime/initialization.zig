//! Runtime construction through source compilation or an authenticated metallib.

const std = @import("std");

extern fn stwo_zig_metal_runtime_create(
    source: [*:0]const u8,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
extern fn stwo_zig_metal_runtime_create_full(
    source: [*:0]const u8,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
extern fn stwo_zig_metal_runtime_create_from_metallib(
    path: [*]const u8,
    path_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
extern fn stwo_zig_metal_runtime_create_from_metallib_data(
    bytes: [*]const u8,
    byte_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
extern fn stwo_zig_metal_runtime_create_from_metallib_data_on_device(
    device: ?*anyopaque,
    bytes: [*]const u8,
    byte_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;

pub fn Initialization(comptime MetalError: type) type {
    return struct {
        pub fn fromSource(source: [*:0]const u8) MetalError!*anyopaque {
            var message: [1024]u8 = [_]u8{0} ** 1024;
            return stwo_zig_metal_runtime_create(source, &message, message.len) orelse {
                std.log.err("Metal initialization failed: {s}", .{std.mem.sliceTo(&message, 0)});
                return MetalError.RuntimeInitializationFailed;
            };
        }

        pub fn fromFullSource(source: [*:0]const u8) MetalError!*anyopaque {
            var message: [1024]u8 = [_]u8{0} ** 1024;
            return stwo_zig_metal_runtime_create_full(source, &message, message.len) orelse {
                std.log.err("Full Metal initialization failed: {s}", .{std.mem.sliceTo(&message, 0)});
                return MetalError.RuntimeInitializationFailed;
            };
        }

        pub fn fromMetallib(path: []const u8) MetalError!*anyopaque {
            if (path.len == 0) return MetalError.RuntimeInitializationFailed;
            var message: [1024]u8 = [_]u8{0} ** 1024;
            return stwo_zig_metal_runtime_create_from_metallib(
                path.ptr,
                path.len,
                &message,
                message.len,
            ) orelse {
                std.log.err("Metal AOT initialization failed: {s}", .{std.mem.sliceTo(&message, 0)});
                return MetalError.RuntimeInitializationFailed;
            };
        }

        pub fn fromMetallibData(bytes: []const u8) MetalError!*anyopaque {
            if (bytes.len == 0) return MetalError.RuntimeInitializationFailed;
            var message: [1024]u8 = [_]u8{0} ** 1024;
            return stwo_zig_metal_runtime_create_from_metallib_data(
                bytes.ptr,
                bytes.len,
                &message,
                message.len,
            ) orelse {
                std.log.err("Metal AOT data initialization failed: {s}", .{std.mem.sliceTo(&message, 0)});
                return MetalError.RuntimeInitializationFailed;
            };
        }

        /// Constructs a runtime on one caller-selected Metal device.
        ///
        /// A null device fails through the same production initializer. This
        /// keeps missing-device behavior deterministic without process-global
        /// environment switches or mutable test hooks.
        pub fn fromMetallibDataOnDevice(
            device: ?*anyopaque,
            bytes: []const u8,
        ) MetalError!*anyopaque {
            if (bytes.len == 0) return MetalError.RuntimeInitializationFailed;
            var message: [1024]u8 = [_]u8{0} ** 1024;
            return stwo_zig_metal_runtime_create_from_metallib_data_on_device(
                device,
                bytes.ptr,
                bytes.len,
                &message,
                message.len,
            ) orelse return MetalError.RuntimeInitializationFailed;
        }
    };
}
