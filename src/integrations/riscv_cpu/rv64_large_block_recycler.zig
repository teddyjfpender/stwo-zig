//! Recycles large host allocations across batch proofs. The standard smp
//! allocator maps and unmaps every block above 64 KiB, so each batch proof
//! page-faults its whole column working set again (about 4.8M faults and
//! 20 GB of zeroed pages per 2^22-step batch). This wrapper keeps freed large
//! blocks mapped in per-capacity free lists and hands them back on the next
//! request of the same rounded capacity. Returned memory is NOT zeroed, which
//! the allocator contract already permits. Thread-safe; bounded by `cap_bytes`.
const std = @import("std");

pub const LargeBlockRecycler = struct {
    child: std.mem.Allocator,
    cap_bytes: usize,
    mutex: std.Thread.Mutex = .{},
    free_blocks: std.AutoHashMapUnmanaged(usize, std.ArrayListUnmanaged([*]u8)) = .empty,
    live: std.AutoHashMapUnmanaged(usize, usize) = .empty,
    cached_bytes: usize = 0,
    reused_blocks: u64 = 0,
    mapped_blocks: u64 = 0,

    pub const threshold: usize = 256 * 1024;
    pub const granule: usize = 64 * 1024;

    pub fn init(child: std.mem.Allocator, cap_bytes: usize) LargeBlockRecycler {
        return .{ .child = child, .cap_bytes = cap_bytes };
    }

    /// Releases every cached block. Live blocks remain the caller's.
    pub fn deinit(self: *LargeBlockRecycler) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.free_blocks.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |ptr| self.child.rawFree(ptr[0..entry.key_ptr.*], .fromByteUnits(std.heap.page_size_min), @returnAddress());
            entry.value_ptr.deinit(self.child);
        }
        self.free_blocks.deinit(self.child);
        self.live.deinit(self.child);
        self.cached_bytes = 0;
    }

    pub const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    pub fn allocator(self: *LargeBlockRecycler) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn recyclable(len: usize, alignment: std.mem.Alignment) bool {
        return len >= threshold and alignment.toByteUnits() <= std.heap.page_size_min;
    }

    fn capacityFor(len: usize) usize {
        return (len + granule - 1) / granule * granule;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *LargeBlockRecycler = @ptrCast(@alignCast(ctx));
        if (!recyclable(len, alignment)) return self.child.rawAlloc(len, alignment, return_address);
        const capacity = capacityFor(len);
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.free_blocks.getPtr(capacity)) |list| {
                if (list.pop()) |ptr| {
                    self.cached_bytes -= capacity;
                    self.live.put(self.child, @intFromPtr(ptr), capacity) catch {
                        list.append(self.child, ptr) catch {};
                        self.cached_bytes += capacity;
                        return null;
                    };
                    self.reused_blocks += 1;
                    return ptr;
                }
            }
        }
        const ptr = self.child.rawAlloc(capacity, alignment, return_address) orelse return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.live.put(self.child, @intFromPtr(ptr), capacity) catch {
            self.child.rawFree(ptr[0..capacity], alignment, return_address);
            return null;
        };
        self.mapped_blocks += 1;
        return ptr;
    }

    // Invariant: a recycled block is never resized below `threshold`, so any
    // slice shorter than `threshold` cannot be ours and skips the lock. Small
    // allocations therefore keep the child's lock-free fast path.
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) bool {
        const self: *LargeBlockRecycler = @ptrCast(@alignCast(ctx));
        if (!recyclable(memory.len, alignment)) return self.child.rawResize(memory, alignment, new_len, return_address);
        if (self.capacityOf(memory.ptr)) |capacity| return new_len >= threshold and new_len <= capacity;
        return self.child.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
        const self: *LargeBlockRecycler = @ptrCast(@alignCast(ctx));
        if (!recyclable(memory.len, alignment)) return self.child.rawRemap(memory, alignment, new_len, return_address);
        if (self.capacityOf(memory.ptr)) |capacity| return if (new_len >= threshold and new_len <= capacity) memory.ptr else null;
        return self.child.rawRemap(memory, alignment, new_len, return_address);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *LargeBlockRecycler = @ptrCast(@alignCast(ctx));
        if (!recyclable(memory.len, alignment)) return self.child.rawFree(memory, alignment, return_address);
        self.mutex.lock();
        const owned = self.live.fetchRemove(@intFromPtr(memory.ptr));
        if (owned) |entry| {
            const capacity = entry.value;
            if (self.cached_bytes + capacity <= self.cap_bytes) {
                const list = self.free_blocks.getOrPut(self.child, capacity) catch null;
                if (list) |slot| {
                    if (!slot.found_existing) slot.value_ptr.* = .empty;
                    if (slot.value_ptr.append(self.child, memory.ptr)) |_| {
                        self.cached_bytes += capacity;
                        self.mutex.unlock();
                        return;
                    } else |_| {}
                }
            }
            self.mutex.unlock();
            self.child.rawFree(memory.ptr[0..capacity], alignment, return_address);
            return;
        }
        self.mutex.unlock();
        self.child.rawFree(memory, alignment, return_address);
    }

    fn capacityOf(self: *LargeBlockRecycler, ptr: [*]u8) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.live.get(@intFromPtr(ptr));
    }

    pub const Stats = struct { reused_blocks: u64, mapped_blocks: u64, cached_bytes: usize };
    pub fn stats(self: *LargeBlockRecycler) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .reused_blocks = self.reused_blocks, .mapped_blocks = self.mapped_blocks, .cached_bytes = self.cached_bytes };
    }
};

test "large blocks are recycled by rounded capacity, small blocks pass through, cap is respected" {
    var recycler = LargeBlockRecycler.init(std.testing.allocator, 8 * 1024 * 1024);
    defer recycler.deinit();
    const a = recycler.allocator();
    const first = try a.alloc(u8, 1_000_000);
    first[0] = 0xaa;
    const first_ptr = first.ptr;
    a.free(first);
    try std.testing.expectEqual(@as(u64, 1), recycler.stats().mapped_blocks);
    // Same rounded capacity comes back from the cache, dirty.
    const second = try a.alloc(u8, 1_000_000 - 5000);
    try std.testing.expect(second.ptr == first_ptr);
    try std.testing.expectEqual(@as(u8, 0xaa), second[0]);
    try std.testing.expectEqual(@as(u64, 1), recycler.stats().reused_blocks);
    // In-place shrink is accepted, growth beyond capacity is refused.
    try std.testing.expect(a.resize(second, 500_000));
    try std.testing.expect(!a.resize(second[0..500_000], 4_000_000));
    // Never shrink a recycled block below the threshold: ownership is decided by length.
    try std.testing.expect(!a.resize(second[0..500_000], 1024));
    a.free(second[0..500_000]);
    // Small allocations never enter the cache.
    const small = try a.alloc(u8, 1024);
    a.free(small);
    try std.testing.expectEqual(@as(usize, LargeBlockRecycler.capacityFor(1_000_000)), recycler.stats().cached_bytes);
    // Beyond the cap, blocks are returned to the child allocator.
    const big = try a.alloc(u8, 9 * 1024 * 1024);
    a.free(big);
    try std.testing.expectEqual(@as(usize, LargeBlockRecycler.capacityFor(1_000_000)), recycler.stats().cached_bytes);
}
