//! Recycles large host allocations across batch proofs. The standard smp
//! allocator maps and unmaps every block above 64 KiB, so each batch proof
//! page-faults its whole column working set again (about 4.8M faults and
//! 20 GB of zeroed pages per 2^22-step batch). This wrapper keeps freed large
//! blocks mapped in per-capacity free lists and hands them back on the next
//! request of the same rounded capacity. Returned memory is NOT zeroed, which
//! the allocator contract already permits. Thread-safe; cached free blocks are
//! bounded by `cap_bytes`, independently of live proof allocations and metadata.
const std = @import("std");

pub const LargeBlockRecycler = struct {
    const FreeBlocks = std.AutoHashMapUnmanaged(usize, std.ArrayListUnmanaged([*]u8));
    child: std.mem.Allocator,
    cap_bytes: usize,
    mutex: std.Thread.Mutex = .{},
    free_blocks: FreeBlocks = .empty,
    live: std.AutoHashMapUnmanaged(usize, usize) = .empty,
    cached_bytes: usize = 0,
    reused_blocks: u64 = 0,
    mapped_blocks: u64 = 0,

    pub const threshold: usize = 256 * 1024;
    pub const granule: usize = 64 * 1024;
    const block_alignment: std.mem.Alignment = .fromByteUnits(std.heap.page_size_min);

    pub fn init(child: std.mem.Allocator, cap_bytes: usize) LargeBlockRecycler {
        return .{ .child = child, .cap_bytes = cap_bytes };
    }

    /// Change the cache ceiling without changing any live allocation. If the
    /// old cache exceeds it, detach that cache through the existing joined
    /// ownership path. Concurrent alloc/free remain safe under the new ceiling.
    pub fn setCap(self: *LargeBlockRecycler, cap_bytes: usize) usize {
        self.mutex.lock();
        self.cap_bytes = cap_bytes;
        var detached: FreeBlocks = .empty;
        var released: usize = 0;
        if (self.cached_bytes > cap_bytes) {
            // Never publish cached_bytes > cap_bytes: free() uses this
            // invariant while computing the remaining cache allowance.
            detached = self.free_blocks;
            released = self.cached_bytes;
            self.free_blocks = .empty;
            self.cached_bytes = 0;
        }
        self.mutex.unlock();
        self.freeDetached(detached);
        return released;
    }

    /// Return cached free blocks to the child without touching live ownership.
    /// Concurrent alloc/free remain valid; blocks freed after the detach can
    /// populate the new cache. The returned byte count covers this detach only.
    pub fn releaseCached(self: *LargeBlockRecycler) usize {
        self.mutex.lock();
        const detached = self.free_blocks;
        const released = self.cached_bytes;
        self.free_blocks = .empty;
        self.cached_bytes = 0;
        self.mutex.unlock();
        self.freeDetached(detached);
        return released;
    }

    fn freeDetached(self: *LargeBlockRecycler, blocks: FreeBlocks) void {
        var detached = blocks;
        // Child calls need not hold the recycler lock. No live block appears
        // in detached, and detached metadata has a single owner.
        var it = detached.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |ptr| self.child.rawFree(ptr[0..entry.key_ptr.*], block_alignment, @returnAddress());
            entry.value_ptr.deinit(self.child);
        }
        detached.deinit(self.child);
    }

    /// Destroy metadata after callers have freed all allocations. For a phase
    /// boundary with live owners, use releaseCached instead.
    pub fn deinit(self: *LargeBlockRecycler) void {
        _ = self.releaseCached();
        self.mutex.lock();
        defer self.mutex.unlock();
        self.live.deinit(self.child);
    }

    pub const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    pub fn allocator(self: *LargeBlockRecycler) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn recyclable(len: usize, alignment: std.mem.Alignment) bool {
        return len >= threshold and alignment.toByteUnits() <= std.heap.page_size_min;
    }

    fn capacityFor(len: usize) ?usize {
        const rounded = std.math.add(usize, len, granule - 1) catch return null;
        return rounded / granule * granule;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *LargeBlockRecycler = @ptrCast(@alignCast(ctx));
        if (!recyclable(len, alignment)) return self.child.rawAlloc(len, alignment, return_address);
        const capacity = capacityFor(len) orelse return null;
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
        // Capacity-only bins must satisfy every admitted caller alignment.
        // Allocate and free with one child alignment, including on cache hits.
        const ptr = self.child.rawAlloc(capacity, block_alignment, return_address) orelse return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.live.put(self.child, @intFromPtr(ptr), capacity) catch {
            self.child.rawFree(ptr[0..capacity], block_alignment, return_address);
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
            if (self.cached_bytes <= self.cap_bytes and capacity <= self.cap_bytes - self.cached_bytes) {
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
            self.child.rawFree(memory.ptr[0..capacity], block_alignment, return_address);
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
    try std.testing.expectEqual(LargeBlockRecycler.capacityFor(1_000_000).?, recycler.stats().cached_bytes);
    // Beyond the cap, blocks are returned to the child allocator.
    const big = try a.alloc(u8, 9 * 1024 * 1024);
    a.free(big);
    try std.testing.expectEqual(LargeBlockRecycler.capacityFor(1_000_000).?, recycler.stats().cached_bytes);
}

test "cache ceiling changes preserve live backing ownership and content" {
    var recycler = LargeBlockRecycler.init(std.testing.allocator, 4 * 1024 * 1024);
    defer recycler.deinit();
    const a = recycler.allocator();
    const live = try a.alloc(u8, 1024 * 1024);
    @memset(live, 0xa7);
    const parked = try a.alloc(u8, 1024 * 1024);
    a.free(parked);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), recycler.setCap(0));
    try std.testing.expectEqual(@as(usize, 0), recycler.stats().cached_bytes);
    for (live) |byte| try std.testing.expectEqual(@as(u8, 0xa7), byte);
    a.free(live);
    try std.testing.expectEqual(@as(usize, 0), recycler.stats().cached_bytes);
    try std.testing.expectEqual(@as(usize, 0), recycler.setCap(2 * 1024 * 1024));
    const next = try a.alloc(u8, 1024 * 1024);
    a.free(next);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), recycler.stats().cached_bytes);
    try std.testing.expectEqual(@as(usize, 0), recycler.live.count());
}

test "cached capacity preserves stronger alignment and overflow is allocation failure" {
    var child = AlignmentChild{};
    var recycler = LargeBlockRecycler.init(child.allocator(), 4 * 1024 * 1024);
    defer recycler.deinit();
    const a = recycler.allocator();
    const first = try a.alloc(u8, LargeBlockRecycler.threshold);
    const ptr = first.ptr;
    a.free(first);
    const aligned = a.rawAlloc(LargeBlockRecycler.threshold, .fromByteUnits(4096), @returnAddress()) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(ptr), @intFromPtr(aligned));
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(aligned) % 4096);
    a.rawFree(aligned[0..LargeBlockRecycler.threshold], .fromByteUnits(4096), @returnAddress());
    try std.testing.expect(a.rawAlloc(std.math.maxInt(usize), .@"1", @returnAddress()) == null);
}

test "recycler metadata allocation failures preserve ownership" {
    // free() legitimately absorbs cache-metadata OOM and returns the block to
    // the child. Sweep every failure without requiring that OOM to escape.
    for (0..128) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        exerciseFailures(failing.allocator()) catch |err| try std.testing.expectEqual(error.OutOfMemory, err);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (!failing.has_induced_failure) return;
    }
    return error.IncompleteAllocationFailureSweep;
}

fn exerciseFailures(child: std.mem.Allocator) !void {
    var recycler = LargeBlockRecycler.init(child, 4 * 1024 * 1024);
    defer recycler.deinit();
    const a = recycler.allocator();
    {
        const first = try a.alloc(u8, LargeBlockRecycler.threshold + 1);
        defer a.free(first);
        first[0] = 7;
    }
    {
        const next = try a.alloc(u8, LargeBlockRecycler.threshold + 2);
        defer a.free(next);
        next[0] = 8;
        _ = recycler.releaseCached(); // must retain next's ownership, even after metadata OOM
        const other = try a.alloc(u8, 2 * LargeBlockRecycler.threshold);
        defer a.free(other);
    }
}

// A strict child catches mismatched rawFree alignment even when a platform's
// page allocator happens to tolerate it. Metadata allocations pass through.
const AlignmentChild = struct {
    large_ptr: ?[*]u8 = null,
    large_alignment: std.mem.Alignment = .@"1",
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const ptr = std.testing.allocator.rawAlloc(len, alignment, ra) orelse return null;
        if (len >= LargeBlockRecycler.threshold) {
            std.debug.assert(self.large_ptr == null);
            self.large_ptr = ptr;
            self.large_alignment = alignment;
        }
        return ptr;
    }
    fn resize(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        return std.testing.allocator.rawResize(memory, alignment, len, ra);
    }
    fn remap(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        return std.testing.allocator.rawRemap(memory, alignment, len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (memory.len >= LargeBlockRecycler.threshold) {
            std.debug.assert(self.large_ptr.? == memory.ptr and self.large_alignment == alignment);
            self.large_ptr = null;
        }
        std.testing.allocator.rawFree(memory, alignment, ra);
    }
};

test "recycler phase trim preserves live blocks and permits later reuse" {
    var recycler = LargeBlockRecycler.init(std.testing.allocator, 4 * 1024 * 1024);
    defer recycler.deinit();
    const a = recycler.allocator();
    const live = try a.alloc(u8, LargeBlockRecycler.threshold + 7);
    defer a.free(live);
    @memset(live, 0x5a);
    const cached = try a.alloc(u8, 2 * LargeBlockRecycler.threshold);
    a.free(cached);
    const before = recycler.stats();
    try std.testing.expectEqual(before.cached_bytes, recycler.releaseCached());
    try std.testing.expectEqual(@as(usize, 0), recycler.stats().cached_bytes);
    try std.testing.expectEqual(@as(usize, 1), recycler.live.count());
    for (live) |byte| try std.testing.expectEqual(@as(u8, 0x5a), byte);
    try std.testing.expect(a.resize(live, live.len));
    try std.testing.expectEqual(@as(usize, 0), recycler.releaseCached());
    const next = try a.alloc(u8, 2 * LargeBlockRecycler.threshold);
    const next_ptr = next.ptr;
    a.free(next);
    const reused = try a.alloc(u8, 2 * LargeBlockRecycler.threshold);
    defer a.free(reused);
    try std.testing.expectEqual(next_ptr, reused.ptr);
    try std.testing.expectEqual(before.mapped_blocks + 1, recycler.stats().mapped_blocks);
    try std.testing.expectEqual(before.reused_blocks + 1, recycler.stats().reused_blocks);
}

test "recycler phase trim removes mismatching full bins for next phase" {
    const size = LargeBlockRecycler.threshold;
    var recycler = LargeBlockRecycler.init(std.testing.allocator, 4 * size);
    defer recycler.deinit();
    const a = recycler.allocator();
    var capture: [4][]u8 = undefined;
    for (&capture) |*block| block.* = try a.alloc(u8, size);
    for (capture) |block| a.free(block);
    try std.testing.expectEqual(4 * size, recycler.stats().cached_bytes);
    // A full cache of other capacities prevents this phase's free from caching.
    const uncached = try a.alloc(u8, 2 * size);
    a.free(uncached);
    const maps = recycler.stats().mapped_blocks;
    try std.testing.expectEqual(4 * size, recycler.releaseCached());
    const first = try a.alloc(u8, 2 * size);
    a.free(first);
    const second = try a.alloc(u8, 2 * size);
    a.free(second);
    try std.testing.expectEqual(maps + 1, recycler.stats().mapped_blocks);
    try std.testing.expectEqual(@as(u64, 1), recycler.stats().reused_blocks);
}

test "recycler phase trim and live allocation traffic are concurrent safe" {
    var recycler = LargeBlockRecycler.init(std.testing.allocator, 4 * 1024 * 1024);
    defer recycler.deinit();
    const Worker = struct {
        a: std.mem.Allocator,
        recycler: *LargeBlockRecycler,
        failed: *std.atomic.Value(bool),
        done: *std.atomic.Value(usize),
        fn run(self: @This()) void {
            defer _ = self.done.fetchAdd(1, .release);
            for (0..64) |_| {
                const memory = self.a.alloc(u8, LargeBlockRecycler.threshold + 1) catch {
                    self.failed.store(true, .monotonic);
                    return;
                };
                @memset(memory, 0xa7);
                for (memory) |byte| if (byte != 0xa7) {
                    self.failed.store(true, .monotonic);
                    break;
                };
                self.a.free(memory);
                self.recycler.mutex.lock();
                if (self.recycler.cached_bytes > self.recycler.cap_bytes) self.failed.store(true, .monotonic);
                self.recycler.mutex.unlock();
            }
        }
    };
    var failed = std.atomic.Value(bool).init(false);
    var done = std.atomic.Value(usize).init(0);
    {
        var workers: [3]std.Thread = undefined;
        var spawned: usize = 0;
        defer for (workers[0..spawned]) |thread| thread.join();
        for (&workers) |*thread| {
            thread.* = try std.Thread.spawn(.{}, Worker.run, .{Worker{ .a = recycler.allocator(), .recycler = &recycler, .failed = &failed, .done = &done }});
            spawned += 1;
        }
        while (done.load(.acquire) < workers.len) {
            _ = recycler.setCap(0);
            _ = recycler.setCap(4 * 1024 * 1024);
            std.Thread.yield() catch {};
        }
    }
    try std.testing.expect(!failed.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), recycler.live.count());
    try std.testing.expect(recycler.stats().cached_bytes <= recycler.cap_bytes);
    _ = recycler.releaseCached();
}
