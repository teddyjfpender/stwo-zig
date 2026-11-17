//! Resident transcript initialization, absorption and challenge draws.
const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const ResidentBuffer = runtime.ResidentBuffer;
pub fn transcriptInit(self: *Runtime, arena: ResidentBuffer, state_base: u32) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_transcript_init, .{state_base});
}

pub fn transcriptMix(self: *Runtime, arena: ResidentBuffer, state_base: u32, source_base: u32, source_words: u32) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_transcript_mix(self.handle, arena.handle, state_base, source_base, source_words, &gpu_ms, &message, message.len)) {
        std.log.err("Metal transcript mix failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn transcriptCall(self: *Runtime, arena: ResidentBuffer, comptime call: anytype, args: anytype) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!@call(.auto, call, .{ self.handle, arena.handle } ++ args ++ .{ &gpu_ms, &message, message.len })) {
        std.log.err("Metal transcript operation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn transcriptDrawSecure(self: *Runtime, arena: ResidentBuffer, state_base: u32, destination_base: u32, felt_count: u32) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_transcript_draw_secure, .{ state_base, destination_base, felt_count });
}

pub fn transcriptDrawQueries(self: *Runtime, arena: ResidentBuffer, state_base: u32, destination_base: u32, log_domain_size: u32, query_count: u32) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_transcript_draw_queries, .{ state_base, destination_base, log_domain_size, query_count });
}

pub const Blake3TranscriptOperation = enum(u32) { words = 1, felts = 2, integer = 3, root = 4, draw_secure = 5 };
pub fn blake3Transcript(self: *Runtime, arena: ResidentBuffer, state_base: u32, data_base: u32, count: u32, operation: Blake3TranscriptOperation) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = @splat(0);
    if (!ffi.stwo_zig_metal_blake3_transcript_v1(self.handle, arena.handle, state_base, data_base, count, @intFromEnum(operation), &gpu_ms, &message, message.len)) return MetalError.CommitmentFailed;
    return gpu_ms;
}
