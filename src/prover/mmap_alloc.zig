//! Allocator using explicit mmap with OS page management hints.
//!
//! Provides MADV_SEQUENTIAL for linear access patterns (Merkle layer hashing)
//! and MADV_DONTNEED to release physical pages without unmapping.

const std = @import("std");
const builtin = @import("builtin");

/// Explicit disk-backed storage; separate from anonymous mappings and their
/// destructive page-release hints below.
pub const FileBackedAllocator = @import("file_backed_allocator.zig").FileBackedAllocator;

pub const MmapAllocator = struct {
    /// Get a std.mem.Allocator backed by mmap with sequential hint.
    pub fn allocator() std.mem.Allocator {
        return .{
            .ptr = undefined,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free_fn,
            },
        };
    }

    fn alloc(_: *anyopaque, len: usize, _: std.mem.Alignment, _: usize) ?[*]u8 {
        if (len == 0) return @as([*]u8, @ptrFromInt(page_size)); // sentinel

        const total = std.mem.alignForward(usize, len, page_size);

        if (comptime builtin.os.tag == .macos or builtin.os.tag == .linux) {
            const buf = std.posix.mmap(
                null,
                total,
                std.posix.PROT.READ | std.posix.PROT.WRITE,
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            ) catch return null;

            // Hint: this memory will be accessed sequentially
            adviseSequential(buf.ptr, total);

            return buf.ptr;
        }

        // Fallback for other platforms
        return std.heap.page_allocator.vtable.alloc(std.heap.page_allocator.ptr, len, .@"1", 0);
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free_fn(_: *anyopaque, buf: []u8, _: std.mem.Alignment, _: usize) void {
        if (buf.len == 0) return;
        const total = std.mem.alignForward(usize, buf.len, page_size);

        if (comptime builtin.os.tag == .macos or builtin.os.tag == .linux) {
            const slice: []align(std.heap.page_size_min) u8 = @alignCast(buf.ptr[0..total]);
            std.posix.munmap(slice);
        } else {
            std.heap.page_allocator.vtable.free(std.heap.page_allocator.ptr, buf, .@"1", 0);
        }
    }
};

/// Hint to the OS that memory will be accessed sequentially.
pub fn adviseSequential(ptr: [*]u8, len: usize) void {
    if (comptime builtin.os.tag == .linux) {
        const aligned_ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(ptr);
        std.posix.madvise(aligned_ptr, len, std.posix.MADV.SEQUENTIAL) catch {};
    }
    if (comptime builtin.os.tag == .macos) {
        const aligned_ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(ptr);
        std.posix.madvise(aligned_ptr, len, std.posix.MADV.SEQUENTIAL) catch {};
    }
}

/// Release physical pages without unmapping virtual addresses.
/// The next access will trigger a page fault and get zeroed pages.
pub fn adviseDontNeed(ptr: [*]u8, len: usize) void {
    if (comptime builtin.os.tag == .linux) {
        const aligned_ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(ptr);
        std.posix.madvise(aligned_ptr, len, std.posix.MADV.DONTNEED) catch {};
    }
    if (comptime builtin.os.tag == .macos) {
        // macOS equivalent: MADV_FREE lets the OS reclaim pages lazily
        const aligned_ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(ptr);
        std.posix.madvise(aligned_ptr, len, std.posix.MADV.FREE) catch {};
    }
}

// ---------------------------------------------------------------------------
// Page-aligned release / prefetch helpers
// ---------------------------------------------------------------------------

const page_size: usize = std.heap.page_size_min;

const AlignedRange = struct {
    ptr: [*]align(page_size) u8,
    len: usize,
};

/// Align a raw pointer range inward to page boundaries.
/// Returns a zero-length range if the input is too small to contain a full page.
fn alignToPageBoundaries(ptr: [*]u8, len: usize) AlignedRange {
    const addr = @intFromPtr(ptr);
    // Round start up to the next page boundary.
    const aligned_start = std.mem.alignForward(usize, addr, page_size);
    const end = addr + len;
    if (aligned_start >= end) return .{ .ptr = @ptrFromInt(page_size), .len = 0 };
    // Round length down to a page multiple.
    const aligned_len = std.mem.alignBackward(usize, end - aligned_start, page_size);
    if (aligned_len == 0) return .{ .ptr = @ptrFromInt(page_size), .len = 0 };
    return .{
        .ptr = @ptrFromInt(aligned_start),
        .len = aligned_len,
    };
}

fn releaseAdvice() u32 {
    if (comptime builtin.os.tag.isDarwin()) {
        return std.posix.MADV.FREE;
    }
    return std.posix.MADV.DONTNEED;
}

fn willneedAdvice() u32 {
    return std.posix.MADV.WILLNEED;
}

fn doMadvise(ptr: [*]align(page_size) u8, len: usize, advice: u32) !void {
    return std.posix.madvise(ptr, len, advice);
}

/// Release physical pages backing a memory region with inward page alignment.
pub fn releasePages(ptr: [*]u8, len: usize) void {
    const aligned = alignToPageBoundaries(ptr, len);
    if (aligned.len == 0) return;
    doMadvise(aligned.ptr, aligned.len, releaseAdvice()) catch {};
}

/// Hint to the kernel that the given memory region will be accessed soon.
pub fn prefetchPages(ptr: [*]u8, len: usize) void {
    const aligned = alignToPageBoundaries(ptr, len);
    if (aligned.len == 0) return;
    doMadvise(aligned.ptr, aligned.len, willneedAdvice()) catch {};
}

/// Release pages backing a typed slice.
pub fn releasePagesSlice(comptime T: type, slice: []T) void {
    if (slice.len == 0) return;
    const byte_ptr: [*]u8 = @ptrCast(slice.ptr);
    const byte_len = slice.len * @sizeOf(T);
    releasePages(byte_ptr, byte_len);
}

/// Prefetch pages for a typed slice.
pub fn prefetchPagesSlice(comptime T: type, slice: []T) void {
    if (slice.len == 0) return;
    const byte_ptr: [*]u8 = @ptrCast(slice.ptr);
    const byte_len = slice.len * @sizeOf(T);
    prefetchPages(byte_ptr, byte_len);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "mmap_alloc: basic alloc and free" {
    const a = MmapAllocator.allocator();
    const buf = try a.alloc(u8, 4096);
    try std.testing.expectEqual(@as(usize, 4096), buf.len);
    a.free(buf);
}

test "mmap_alloc: large allocation" {
    const a = MmapAllocator.allocator();
    const buf = try a.alloc(u32, 1024 * 1024); // 4MB
    buf[0] = 42;
    buf[1023 * 1024] = 99;
    try std.testing.expectEqual(@as(u32, 42), buf[0]);
    try std.testing.expectEqual(@as(u32, 99), buf[1023 * 1024]);
    a.free(buf);
}

test "releasePages on page-aligned mmap region" {
    const alloc = std.heap.page_allocator;
    const size = page_size * 4;
    const mem = try alloc.alloc(u8, size);
    defer alloc.free(mem);

    @memset(mem, 0xAB);
    releasePages(mem.ptr, mem.len);

    if (comptime !builtin.os.tag.isDarwin()) {
        for (mem) |byte| {
            try std.testing.expectEqual(@as(u8, 0), byte);
        }
    }
}

test "releasePagesSlice on typed data" {
    const alloc = std.heap.page_allocator;
    const count = page_size / @sizeOf(u64) * 2;
    const data = try alloc.alloc(u64, count);
    defer alloc.free(data);

    for (data) |*v| v.* = 0xDEAD_BEEF;
    releasePagesSlice(u64, data);

    if (comptime !builtin.os.tag.isDarwin()) {
        for (data) |v| {
            try std.testing.expectEqual(@as(u64, 0), v);
        }
    }
}

test "prefetchPages does not crash" {
    const alloc = std.heap.page_allocator;
    const size = page_size * 2;
    const mem = try alloc.alloc(u8, size);
    defer alloc.free(mem);

    @memset(mem, 0x42);
    prefetchPages(mem.ptr, mem.len);

    for (mem) |byte| {
        try std.testing.expectEqual(@as(u8, 0x42), byte);
    }
}

test "releasePages with sub-page region is no-op" {
    var buf: [64]u8 = undefined;
    @memset(&buf, 0x11);
    releasePages(&buf, buf.len);
    for (buf) |byte| {
        try std.testing.expectEqual(@as(u8, 0x11), byte);
    }
}

test "releasePagesSlice with empty slice is no-op" {
    const empty: []u32 = &[_]u32{};
    releasePagesSlice(u32, empty);
}
