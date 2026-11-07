//! Opt-in scratch backing for large capture allocations. Small owners remain
//! in the normal heap. Captured values and their lifetime are unchanged.
const std = @import("std");
const Backing = @import("stwo_prover_engine").file_backed_allocator.FileBackedAllocator;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const threshold_bytes = 1 << 20;

pub const Options = struct {
    directory: []const u8,
    bytes: usize,

    pub fn validate(self: Options) !void {
        if (self.directory.len == 0 or std.mem.indexOfScalar(u8, self.directory, 0) != null or self.bytes < threshold_bytes)
            return error.InvalidEthereumCaptureSpill;
    }
};

pub const Owner = struct {
    heap: Allocator,
    backing: Backing,

    pub fn init(heap: Allocator, options: Options) !Owner {
        try options.validate();
        var backing = try Backing.init(options.directory);
        backing.limit_bytes = options.bytes;
        return .{ .heap = heap, .backing = backing };
    }

    pub fn deinit(self: *Owner) void {
        self.backing.deinit();
    }

    pub fn allocator(self: *Owner) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn mapped(len: usize, alignment: Alignment) bool {
        return len >= threshold_bytes and alignment.toByteUnits() <= std.heap.pageSize();
    }

    fn alloc(context: *anyopaque, len: usize, alignment: Alignment, ret: usize) ?[*]u8 {
        const self: *Owner = @ptrCast(@alignCast(context));
        const child = if (mapped(len, alignment)) self.backing.allocator() else self.heap;
        return child.rawAlloc(len, alignment, ret);
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: Alignment, len: usize, ret: usize) bool {
        const self: *Owner = @ptrCast(@alignCast(context));
        // Crossing tiers must allocate and copy. A successful in-place
        // resize would make free route the slice to the wrong allocator.
        if (mapped(memory.len, alignment) or mapped(len, alignment)) return false;
        return self.heap.rawResize(memory, alignment, len, ret);
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: Alignment, len: usize, ret: usize) ?[*]u8 {
        const self: *Owner = @ptrCast(@alignCast(context));
        if (mapped(memory.len, alignment) or mapped(len, alignment)) return null;
        return self.heap.rawRemap(memory, alignment, len, ret);
    }

    fn free(context: *anyopaque, memory: []u8, alignment: Alignment, ret: usize) void {
        const self: *Owner = @ptrCast(@alignCast(context));
        const child = if (mapped(memory.len, alignment)) self.backing.allocator() else self.heap;
        child.rawFree(memory, alignment, ret);
    }
};

test "capture spill preserves realloc across tiers and enforces its backing cap" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const heap = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const directory = try tmp.dir.realpathAlloc(heap, ".");
    defer heap.free(directory);
    var spill = try Owner.init(heap, .{ .directory = directory, .bytes = threshold_bytes });
    defer spill.deinit();
    const a = spill.allocator();
    var data = try a.alloc(u8, 4);
    defer a.free(data);
    @memcpy(data, "test");
    data = try a.realloc(data, threshold_bytes);
    try std.testing.expectEqualStrings("test", data[0..4]);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, threshold_bytes));
    data = try a.realloc(data, 4);
    try std.testing.expectEqualStrings("test", data);
    try std.testing.expectEqual(@as(usize, 0), spill.backing.live_bytes.load(.monotonic));
    try std.testing.expectEqual(@as(usize, threshold_bytes), spill.backing.peak_bytes.load(.monotonic));
    var entries = tmp.dir.iterate();
    try std.testing.expectEqual(null, try entries.next());
}
