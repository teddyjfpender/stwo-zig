//! Best-effort current-owner advice only. Accepted advice bytes are not resident
//! bytes, completed I/O, or a host-memory reservation.
const std = @import("std");
const builtin = @import("builtin");
pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;
pub const Result = struct {
    requested_bytes: usize = 0,
    advised_bytes: usize = 0,
    failed: bool = false,
    unsupported: bool = false,
    /// A parked MAIN has already been restored for proving. The worker must
    /// not repeat its later restore; failed advice does not invalidate the map.
    ready: bool = false,
};
pub fn boundedLength(mapping_bytes: usize, cap: usize) usize {
    return std.mem.alignBackward(usize, @min(mapping_bytes, cap), std.heap.page_size_min);
}
pub fn advise(memory: []align(std.heap.page_size_min) u8, cap: usize) Result {
    if (comptime !supported) return .{ .unsupported = true };
    const bytes = boundedLength(memory.len, cap);
    if (bytes == 0) return .{ .ready = true };
    std.posix.madvise(memory.ptr, bytes, std.posix.MADV.WILLNEED) catch return .{ .requested_bytes = bytes, .failed = true, .ready = true };
    return .{ .requested_bytes = bytes, .advised_bytes = bytes, .ready = true };
}
