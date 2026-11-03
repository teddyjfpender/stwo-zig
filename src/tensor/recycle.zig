//! Recycling allocator for large prover buffers.
//!
//! The prover allocates GBs of short-lived tables (LogUp-GKR layers, eq/E
//! tables, encoded rows). With the system allocator every large block is a
//! fresh mmap, so each proof pays first-touch zero-fill page faults on every
//! page, and on macOS those serialize in the kernel (measured: 1.9 s sys vs
//! 3.0 s user for mlp 9 11 12 at 12 threads; GKR stops scaling at ~4 threads).
//! This wrapper keeps freed blocks >= `threshold` bytes in exact-size free
//! lists (size rounded up to 16 KiB) and hands them back to later requests of
//! the same rounded size. A long-running prover that proves the same model
//! repeatedly therefore touches fresh pages only on its first proof.
//!
//! Thread-safe (one mutex; only taken for large blocks). Small blocks pass
//! straight through to the backing allocator. `trim()` releases all cached
//! blocks; `deinit()` trims. Memory held = live + cached (bounded by the peak
//! live footprint of one proof of the same shape).
const std = @import("std");

const Alignment = std.mem.Alignment;

pub const Recycler = struct {
    backing: std.mem.Allocator,
    threshold: usize = 1 << 20,
    mutex: std.Thread.Mutex = .{},
    /// rounded size -> stack of free blocks of exactly that size
    free_lists: std.AutoHashMapUnmanaged(usize, std.ArrayListUnmanaged([*]u8)) = .empty,
    cached_bytes: usize = 0,
    hits: usize = 0,
    misses: usize = 0,

    const PAGE: usize = 16 * 1024;
    const BIG_ALIGN = Alignment.fromByteUnits(PAGE);

    pub fn init(backing: std.mem.Allocator) Recycler {
        return .{ .backing = backing };
    }

    pub fn allocator(self: *Recycler) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn rounded(len: usize) usize {
        return std.mem.alignForward(usize, len, PAGE);
    }

    fn isBig(self: *const Recycler, len: usize, alignment: Alignment) bool {
        return len >= self.threshold and alignment.toByteUnits() <= PAGE;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Recycler = @ptrCast(@alignCast(ctx));
        if (!self.isBig(len, alignment)) return self.backing.rawAlloc(len, alignment, ret_addr);
        const size = rounded(len);
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.free_lists.getPtr(size)) |list| {
                if (list.pop()) |p| {
                    self.cached_bytes -= size;
                    self.hits += 1;
                    return p;
                }
            }
            self.misses += 1;
        }
        return self.backing.rawAlloc(size, BIG_ALIGN, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Recycler = @ptrCast(@alignCast(ctx));
        const was_big = self.isBig(memory.len, alignment);
        const is_big = self.isBig(new_len, alignment);
        if (!was_big and !is_big) return self.backing.rawResize(memory, alignment, new_len, ret_addr);
        // big blocks: in place only within the same rounded size
        return was_big and is_big and rounded(memory.len) == rounded(new_len);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Recycler = @ptrCast(@alignCast(ctx));
        if (resize(ctx, memory, alignment, new_len, ret_addr)) return memory.ptr;
        const was_big = self.isBig(memory.len, alignment);
        const is_big = self.isBig(new_len, alignment);
        if (!was_big and !is_big) return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
        return null; // caller falls back to alloc + copy + free
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *Recycler = @ptrCast(@alignCast(ctx));
        if (!self.isBig(memory.len, alignment)) return self.backing.rawFree(memory, alignment, ret_addr);
        const size = rounded(memory.len);
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = self.free_lists.getOrPut(self.backing, size) catch {
            self.backing.rawFree(memory.ptr[0..size], BIG_ALIGN, ret_addr);
            return;
        };
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        gop.value_ptr.append(self.backing, memory.ptr) catch {
            self.backing.rawFree(memory.ptr[0..size], BIG_ALIGN, ret_addr);
            return;
        };
        self.cached_bytes += size;
    }

    /// Release every cached block to the backing allocator.
    pub fn trim(self: *Recycler) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.free_lists.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.items) |p| self.backing.rawFree(p[0..e.key_ptr.*], BIG_ALIGN, @returnAddress());
            e.value_ptr.deinit(self.backing);
        }
        self.free_lists.clearAndFree(self.backing);
        self.cached_bytes = 0;
    }

    pub fn deinit(self: *Recycler) void {
        self.trim();
    }
};

test "recycler reuses large blocks and passes small ones through" {
    var r = Recycler.init(std.testing.allocator);
    defer r.deinit();
    r.threshold = 1 << 16;
    const a = r.allocator();
    const x = try a.alloc(u32, 100_000);
    const xp = x.ptr;
    x[5] = 7;
    a.free(x);
    try std.testing.expectEqual(@as(usize, 1), r.free_lists.count());
    const y = try a.alloc(u32, 100_001); // same rounded size -> same block
    try std.testing.expectEqual(xp, y.ptr);
    try std.testing.expectEqual(@as(usize, 1), r.hits);
    const s = try a.alloc(u8, 100); // small: backing
    a.free(s);
    const z = try a.alloc(u64, 1 << 15); // different size -> miss
    a.free(z);
    a.free(y);
    try std.testing.expectEqual(@as(usize, 2), r.misses);
    // realloc of a big block across size classes keeps contents
    var v = try a.alloc(u8, 1 << 17);
    v[0] = 42;
    v = try a.realloc(v, 1 << 18);
    try std.testing.expectEqual(@as(u8, 42), v[0]);
    a.free(v);
}
