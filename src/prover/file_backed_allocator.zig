//! Temporary shared mappings for retained proof columns that exceed host RAM.
//! Each allocation reserves disk space before mapping and immediately unlinks
//! its private file. The owner must outlive every allocation; no proof identity
//! or persisted artifact depends on these scratch files.
const std = @import("std");
const builtin = @import("builtin");

pub const FileBackedAllocator = struct {
    dir: std.fs.Dir,
    live_bytes: std.atomic.Value(usize) = .init(0),
    total_bytes: std.atomic.Value(usize) = .init(0),

    pub fn init(path: []const u8) !FileBackedAllocator {
        if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux)
            return error.FileBackedColumnsUnsupported;
        return .{ .dir = try std.fs.cwd().makeOpenPath(path, .{}) };
    }

    pub fn deinit(self: *FileBackedAllocator) void {
        std.debug.assert(self.live_bytes.load(.monotonic) == 0);
        self.dir.close();
        self.* = undefined;
    }

    pub fn allocator(self: *FileBackedAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const self: *FileBackedAllocator = @ptrCast(@alignCast(context));
        // mmap guarantees page alignment. Refuse unsupported over-alignment
        // before acquiring a file or mapping, rather than returning a bad pointer.
        if (alignment.toByteUnits() > std.heap.pageSize()) return null;
        return self.map(len) catch |err| {
            std.debug.print("FILE_BACKED_COLUMN_ALLOCATION_FAILED bytes={d} error={s}\n", .{ len, @errorName(err) });
            return null;
        };
    }

    fn map(self: *FileBackedAllocator, len: usize) ![*]u8 {
        const size = std.mem.alignBackward(usize, try std.math.add(usize, len, std.heap.pageSize() - 1), std.heap.pageSize());
        if (size == 0 or size > std.math.maxInt(i64)) return error.InvalidMappingLength;
        var random: [16]u8 = undefined;
        std.crypto.random.bytes(&random);
        const name = std.fmt.bytesToHex(random, .lower);
        const file = try self.dir.createFile(&name, .{ .read = true, .exclusive = true, .mode = 0o600 });
        defer file.close();
        // Unlink while the descriptor is live: failures and killed producers
        // cannot leave tens of GiB of abandoned named scratch files behind.
        self.dir.deleteFile(&name) catch |err| {
            self.dir.deleteFile(&name) catch {};
            return err;
        };
        try reserve(file, size);
        try file.setEndPos(size);
        const memory = try std.posix.mmap(null, size, std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED }, file.handle, 0);
        _ = self.live_bytes.fetchAdd(size, .monotonic);
        _ = self.total_bytes.fetchAdd(size, .monotonic);
        return memory.ptr;
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(context: *anyopaque, memory: []u8, _: std.mem.Alignment, _: usize) void {
        const self: *FileBackedAllocator = @ptrCast(@alignCast(context));
        const size = std.mem.alignForward(usize, memory.len, std.heap.pageSize());
        std.posix.munmap(@alignCast(memory.ptr[0..size]));
        const previous = self.live_bytes.fetchSub(size, .monotonic);
        std.debug.assert(previous >= size);
    }
};

/// Reserve actual blocks, not just a sparse logical length: disk exhaustion
/// must return an allocation error before any caller writes into a mapping.
fn reserve(file: std.fs.File, len: usize) !void {
    if (comptime builtin.os.tag == .macos) {
        // Darwin sys/fcntl.h fstore_t, F_ALLOCATEALL and F_PEOFPOSMODE.
        const Store = extern struct { flags: u32 = 4, position_mode: i32 = 3, offset: i64 = 0, length: i64, bytes_allocated: i64 = 0 };
        var store: Store = .{ .length = @intCast(len) };
        while (true) {
            const result = std.c.fcntl(file.handle, std.posix.F.PREALLOCATE, @intFromPtr(&store));
            switch (std.posix.errno(result)) {
                .SUCCESS => return,
                .INTR => continue,
                .NOSPC, .DQUOT => return error.NoSpaceLeft,
                else => return error.FilePreallocationFailed,
            }
        }
    } else if (comptime builtin.os.tag == .linux) {
        while (true) {
            const result = std.os.linux.fallocate(file.handle, 0, 0, @intCast(len));
            switch (std.posix.errno(result)) {
                .SUCCESS => return,
                .INTR => continue,
                .NOSPC, .DQUOT => return error.NoSpaceLeft,
                else => return error.FilePreallocationFailed,
            }
        }
    } else return error.FileBackedColumnsUnsupported;
}

test "file backed columns survive writeback and reclaim advice without scratch files" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    var backing = try FileBackedAllocator.init(path);
    defer backing.deinit();
    const a = backing.allocator();
    {
        const data = try a.alloc(u32, 256 * 1024 + 1);
        defer a.free(data);
        for (data, 0..) |*word, index| word.* = @as(u32, @intCast(index)) *% 0xdeadbeef;
        const bytes = std.mem.sliceAsBytes(data);
        const memory: []align(std.heap.page_size_min) u8 = @alignCast(bytes.ptr[0..std.mem.alignForward(usize, bytes.len, std.heap.pageSize())]);
        try std.posix.msync(memory, std.posix.MSF.SYNC);
        // This is SHARED file storage; do not use the anonymous MADV_FREE helper.
        try std.posix.madvise(memory.ptr, memory.len, std.posix.MADV.DONTNEED);
        for (data, 0..) |word, index| try std.testing.expectEqual(@as(u32, @intCast(index)) *% 0xdeadbeef, word);
        var entries = tmp.dir.iterate();
        try std.testing.expectEqual(null, try entries.next());
        try std.testing.expect(backing.live_bytes.load(.monotonic) >= bytes.len);
    }
    try std.testing.expectEqual(@as(usize, 0), backing.live_bytes.load(.monotonic));
}

test "file backed columns reject impossible alignment before allocation" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    var backing = try FileBackedAllocator.init(path);
    defer backing.deinit();
    const a = backing.allocator();
    try std.testing.expectEqual(null, a.rawAlloc(16, .fromByteUnits(std.heap.pageSize() * 2), @returnAddress()));
    try std.testing.expectEqual(@as(usize, 0), backing.total_bytes.load(.monotonic));
}

test "file backed columns realloc preserves values and releases old mapping" {
    if (comptime builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    var backing = try FileBackedAllocator.init(path);
    defer backing.deinit();
    const a = backing.allocator();
    {
        var data = try a.alloc(u8, 37);
        defer a.free(data);
        @memset(data, 0xab);
        data = try a.realloc(data, std.heap.pageSize() * 2 + 1);
        try std.testing.expect(std.mem.allEqual(u8, data[0..37], 0xab));
        try std.testing.expectEqual(std.heap.pageSize() * 3, backing.live_bytes.load(.monotonic));
    }
    try std.testing.expectEqual(@as(usize, 0), backing.live_bytes.load(.monotonic));
}
