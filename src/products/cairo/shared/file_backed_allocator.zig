//! Opt-in Linux CPU capacity mode. Large allocations have temporary file backing;
//! field values, ownership, AIRs and proof parameters are unchanged.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const PageSlice = []align(std.heap.page_size_min) u8;

const State = struct {
    mutex: std.Thread.Mutex = .{},
    mappings: std.AutoHashMapUnmanaged(usize, PageSlice) = .empty,
    sequence: u64 = 0,
    live_bytes: usize = 0,
    peak_bytes: usize = 0,
    threshold: usize = 1024 * 1024,
    cooling_live_threshold: usize = 512 * 1024 * 1024,
    cooling_interval: usize = 64 * 1024 * 1024,
    allocated_since_cooling: usize = 0,
    cooling_count: usize = 0,

    fn allocator(self: *State) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret: usize) ?[*]u8 {
        const self: *State = @ptrCast(@alignCast(ctx));
        if (len < self.threshold and alignment.toByteUnits() <= std.heap.pageSize())
            return std.heap.smp_allocator.rawAlloc(len, alignment, ret);
        if (comptime builtin.os.tag != .linux) return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.live_bytes >= self.cooling_live_threshold and self.allocated_since_cooling >= self.cooling_interval) {
            var existing = self.mappings.valueIterator();
            while (existing.next()) |pages| {
                // Shared mappings retain their contents in the backing inode.
                // Flush first, then drop PTEs; clean file-cache pages are
                // reclaimable without system swap. Concurrent users keep the
                // ordinary coherent MAP_SHARED view.
                std.posix.msync(pages.*, std.posix.MSF.SYNC) catch return null;
                std.posix.madvise(pages.ptr, pages.len, std.posix.MADV.DONTNEED) catch return null;
            }
            self.allocated_since_cooling = 0;
            self.cooling_count += 1;
        }
        const padding = alignment.toByteUnits() - 1;
        const padded = std.math.add(usize, len, padding) catch return null;
        const size = std.math.add(usize, padded, std.heap.pageSize() - 1) catch return null;
        const map_len = std.mem.alignBackward(usize, size, std.heap.pageSize());
        self.sequence += 1;
        var name_buffer: [160]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buffer, "/tmp/stwo-cairo-backing-{d}-{d}", .{
            std.os.linux.getpid(), self.sequence,
        }) catch return null;
        const file = std.fs.cwd().createFile(name, .{ .read = true, .exclusive = true, .mode = 0o600 }) catch return null;
        defer file.close();
        // Unlink immediately: kernel ownership lasts until the final unmap,
        // including process failure; no persistent temporary paths accumulate.
        std.fs.cwd().deleteFile(name) catch return null;
        file.setEndPos(map_len) catch return null;
        // Reserve backing blocks before exposing writable pages, so disk-full
        // fails allocation rather than producing SIGBUS during witness writes.
        if (std.posix.errno(std.os.linux.fallocate(file.handle, 0, 0, @intCast(map_len))) != .SUCCESS)
            return null;
        const pages = std.posix.mmap(null, map_len, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED }, file.handle, 0) catch return null;
        const address = std.mem.alignForward(usize, @intFromPtr(pages.ptr), alignment.toByteUnits());
        self.mappings.put(std.heap.smp_allocator, address, pages) catch {
            std.posix.munmap(pages);
            return null;
        };
        self.live_bytes += pages.len;
        self.allocated_since_cooling +|= pages.len;
        self.peak_bytes = @max(self.peak_bytes, self.live_bytes);
        return @ptrFromInt(address);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret: usize) bool {
        const self: *State = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        const mapped = self.mappings.contains(@intFromPtr(memory.ptr));
        self.mutex.unlock();
        if (mapped or new_len >= self.threshold) return false;
        return std.heap.smp_allocator.rawResize(memory, alignment, new_len, ret);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self: *State = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        const mapped = self.mappings.contains(@intFromPtr(memory.ptr));
        self.mutex.unlock();
        if (mapped or new_len >= self.threshold) return null;
        return std.heap.smp_allocator.rawRemap(memory, alignment, new_len, ret);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret: usize) void {
        const self: *State = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        const removed = self.mappings.fetchRemove(@intFromPtr(memory.ptr));
        if (removed) |entry| self.live_bytes -= entry.value.len;
        self.mutex.unlock();
        if (removed) |entry| std.posix.munmap(entry.value) else std.heap.smp_allocator.rawFree(memory, alignment, ret);
    }

    const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
};

// Process lifetime matches the product's process-wide artifact caches. Their
// buffers may outlive one run() call, so never invalidate the allocator context.
var global: State = .{};

pub fn allocator() Allocator {
    return global.allocator();
}

pub fn report() void {
    global.mutex.lock();
    defer global.mutex.unlock();
    std.debug.print("cairo_file_backed_allocator peak_backing_bytes={d} live_backing_bytes={d} cooling_count={d}\n", .{
        global.peak_bytes, global.live_bytes, global.cooling_count,
    });
}

test "file backing preserves aligned data through realloc and releases ownership" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var state: State = .{ .threshold = 4096, .cooling_live_threshold = 0, .cooling_interval = 4096 };
    defer state.mappings.deinit(std.heap.smp_allocator);
    const a = state.allocator();
    var growing = try a.alloc(u8, 64);
    @memset(growing, 23);
    growing = try a.realloc(growing, 8192);
    for (growing[0..64]) |value| try std.testing.expectEqual(@as(u8, 23), value);
    try std.testing.expect(state.mappings.contains(@intFromPtr(growing.ptr)));
    a.free(growing);
    var bytes = try a.alignedAlloc(u8, .fromByteUnits(65536), 16384);
    @memset(bytes, 0x5a);
    bytes = try a.realloc(bytes, 32768);
    for (bytes[0..16384]) |value| try std.testing.expectEqual(@as(u8, 0x5a), value);
    try std.testing.expect(@intFromPtr(bytes.ptr) % 65536 == 0);
    try std.testing.expectEqual(@as(usize, 1), state.mappings.count());
    a.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), state.live_bytes);
    try std.testing.expectEqual(@as(usize, 0), state.mappings.count());
    try std.testing.expect(state.cooling_count > 0);
}

test "small and file-backed allocations coexist across threads" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var state: State = .{ .threshold = 4096 };
    defer state.mappings.deinit(std.heap.smp_allocator);
    const Work = struct {
        fn run(s: *State) void {
            const a = s.allocator();
            for (0..8) |_| {
                const small = a.alloc(u8, 31) catch @panic("allocation");
                const large = a.alloc(u8, 8192) catch @panic("allocation");
                @memset(large, 17);
                std.debug.assert(large[large.len - 1] == 17);
                a.free(large);
                a.free(small);
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Work.run, .{&state});
    for (threads) |thread| thread.join();
    try std.testing.expectEqual(@as(usize, 0), state.live_bytes);
    try std.testing.expectEqual(@as(usize, 0), state.mappings.count());
}
