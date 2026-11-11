//! Bump allocator for FFT temporary buffers.
//!
//! Pre-maps a large virtual memory region. Allocations are O(1) bump-pointer
//! advances. reset() rewinds to zero for reuse across commit rounds.
//! No individual free() calls needed — the entire region is released on deinit().

const std = @import("std");

pub const FftPoolAllocator = struct {
    buffer: []align(std.heap.page_size_min) u8,
    offset: usize,

    pub fn init(max_bytes: usize) !FftPoolAllocator {
        // Round up to page size
        const page_size = std.heap.page_size_min;
        const aligned_size = std.mem.alignForward(usize, max_bytes, page_size);

        const buf = try std.posix.mmap(
            null,
            aligned_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        return .{ .buffer = buf, .offset = 0 };
    }

    pub fn deinit(self: *FftPoolAllocator) void {
        std.posix.munmap(self.buffer);
        self.* = undefined;
    }

    /// Reset the bump pointer to zero. All previous allocations become invalid.
    pub fn reset(self: *FftPoolAllocator) void {
        self.offset = 0;
    }

    /// Return how many bytes have been allocated.
    pub fn bytesUsed(self: FftPoolAllocator) usize {
        return self.offset;
    }

    /// Get a std.mem.Allocator interface for this pool.
    pub fn allocator(self: *FftPoolAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const self: *FftPoolAllocator = @ptrCast(@alignCast(ctx));
        const align_bytes = alignment.toByteUnits();
        const aligned_offset = std.mem.alignForward(usize, self.offset, align_bytes);

        if (aligned_offset + len > self.buffer.len) return null; // OOM

        const result = self.buffer.ptr + aligned_offset;
        self.offset = aligned_offset + len;
        return result;
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false; // Bump allocator doesn't support resize
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null; // Bump allocator doesn't support remap
    }

    fn free(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
        // No-op: bump allocator doesn't free individual allocations
    }
};

test "fft_pool: basic allocation" {
    var pool = try FftPoolAllocator.init(1024 * 1024); // 1MB
    defer pool.deinit();

    const alloc = pool.allocator();
    const buf1 = try alloc.alloc(u32, 256);
    try std.testing.expectEqual(@as(usize, 256), buf1.len);

    const buf2 = try alloc.alloc(u32, 512);
    try std.testing.expectEqual(@as(usize, 512), buf2.len);

    // Verify they don't overlap
    try std.testing.expect(@intFromPtr(buf2.ptr) >= @intFromPtr(buf1.ptr) + 256 * 4);

    pool.reset();
    try std.testing.expectEqual(@as(usize, 0), pool.bytesUsed());
}

test "fft_pool: reset and reuse" {
    var pool = try FftPoolAllocator.init(64 * 1024);
    defer pool.deinit();

    const alloc = pool.allocator();
    _ = try alloc.alloc(u8, 32 * 1024);
    try std.testing.expect(pool.bytesUsed() >= 32 * 1024);

    pool.reset();
    try std.testing.expectEqual(@as(usize, 0), pool.bytesUsed());

    // Can allocate again from the start
    _ = try alloc.alloc(u8, 32 * 1024);
    try std.testing.expect(pool.bytesUsed() >= 32 * 1024);
}
