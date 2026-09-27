//! Bounded external sort of real block-memory events. This is witness
//! transport, not proof authority: the sorted rows still need a constrained
//! permutation, first-value admission and a verified complete census.
const std = @import("std");
const event_mod = @import("memory_event.zig");
const Event = event_mod.Event;
const record_bytes = 17;
const write_buffer_bytes = record_bytes * 1024;
const merge_fanout = 32;
const max_runs = 16_384;
const Run = struct { name: []const u8, count: u64 };
const Head = struct {
    event: Event,
    reader: usize,
    fn compare(_: void, left: Head, right: Head) std.math.Order {
        if (Event.lessThan({}, left.event, right.event)) return .lt;
        if (Event.lessThan({}, right.event, left.event)) return .gt;
        return std.math.order(left.reader, right.reader);
    }
};
pub const Statistics = struct {
    initial_runs: u32 = 0,
    merge_passes: u32 = 0,
    merged_records: u64 = 0,
    sort_buffer_bytes: usize = 0,
    /// Only successful sorter transport, including the raw event write.
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
};
pub const Reader = struct {
    file: std.fs.File,
    remaining: u64,
    offset: u64 = 0,
    buffer: [write_buffer_bytes]u8 = undefined,
    buffered: usize = 0,
    cursor: usize = 0,
    pub fn next(self: *Reader) !?Event {
        if (self.remaining == 0) return null;
        if (self.cursor == self.buffered) {
            const bytes: usize = @as(usize, @intCast(@min(self.remaining, write_buffer_bytes / record_bytes))) * record_bytes;
            if (try self.file.preadAll(self.buffer[0..bytes], self.offset) != bytes) return error.TruncatedMemoryRun;
            self.offset += bytes;
            self.buffered = bytes;
            self.cursor = 0;
        }
        var encoded: [record_bytes]u8 = undefined;
        @memcpy(&encoded, self.buffer[self.cursor..][0..record_bytes]);
        const item = try Event.decode(encoded);
        self.cursor += record_bytes;
        self.remaining -= 1;
        return item;
    }
    pub fn deinit(self: *Reader) void {
        self.file.close();
        self.* = undefined;
    }
};
const BufferedWriter = struct {
    file: std.fs.File,
    bytes: [write_buffer_bytes]u8 = undefined,
    len: usize = 0,
    pub fn append(self: *BufferedWriter, item: Event) !void {
        if (self.len == self.bytes.len) try self.flush();
        const encoded = item.encode();
        @memcpy(self.bytes[self.len..][0..record_bytes], &encoded);
        self.len += record_bytes;
    }
    pub fn flush(self: *BufferedWriter) !void {
        try self.file.writeAll(self.bytes[0..self.len]);
        self.len = 0;
    }
};
pub const Spool = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    raw: std.fs.File,
    raw_open: bool = true,
    pending: BufferedWriter,
    event_count: u64 = 0,
    chunk_events: usize,
    files: std.ArrayList([]const u8) = .empty,
    poisoned: bool = false,
    finished: bool = false,
    final_run_name: ?[]const u8 = null,
    statistics: Statistics = .{},
    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, chunk_events: usize) !Spool {
        if (chunk_events < 2 or chunk_events > 1 << 20) return error.InvalidMemoryChunkSize;
        const raw = try dir.createFile("memory-events.raw", .{ .exclusive = true });
        var result: Spool = .{ .a = a, .dir = dir, .raw = raw, .pending = .{ .file = raw }, .chunk_events = chunk_events };
        errdefer {
            raw.close();
            dir.deleteFile("memory-events.raw") catch {};
        }
        try result.files.append(a, "memory-events.raw");
        return result;
    }
    pub fn deinit(self: *Spool) void {
        if (self.raw_open) self.raw.close();
        for (self.files.items) |name| {
            self.dir.deleteFile(name) catch {};
            if (!std.mem.eql(u8, name, "memory-events.raw")) self.a.free(name);
        }
        self.files.deinit(self.a);
        self.* = undefined;
    }
    pub fn append(self: *Spool, item: Event) !void {
        if (self.poisoned or self.finished) return error.InvalidMemorySpoolPhase;
        try item.validate();
        const max_events = @as(u64, @intCast(self.chunk_events)) * max_runs;
        if (self.event_count >= max_events) {
            self.poisoned = true;
            return error.TooManyMemoryRuns;
        }
        self.pending.append(item) catch |err| {
            self.poisoned = true;
            return err;
        };
        self.event_count = std.math.add(u64, self.event_count, 1) catch {
            self.poisoned = true;
            return error.Overflow;
        };
    }
    pub fn appendSegment(self: *Spool, frame: event_mod.Frame, accesses: []const @import("../../runner/state_chain.zig").Access) !void {
        errdefer self.poisoned = true;
        for (accesses) |access| try self.append(try frame.project(access));
    }
    pub fn finish(self: *Spool) !Reader {
        if (self.poisoned or self.finished) return error.InvalidMemorySpoolPhase;
        errdefer self.poisoned = true;
        try self.pending.flush();
        self.raw.close();
        self.raw_open = false;
        if (self.event_count == 0) return error.EmptyMemorySpool;
        var source_reader = try openRun(self.dir, "memory-events.raw", self.event_count);
        defer source_reader.deinit();
        var chunk = try self.a.alloc(Event, self.chunk_events);
        defer self.a.free(chunk);
        const radix_threshold = 1024;
        const scratch = try self.a.alloc(Event, if (chunk.len >= radix_threshold) chunk.len else 0);
        defer self.a.free(scratch);
        self.statistics.sort_buffer_bytes = (chunk.len + scratch.len) * @sizeOf(Event);
        var runs: std.ArrayList(Run) = .empty;
        defer runs.deinit(self.a);
        var count: u64 = 0;
        while (count < self.event_count) {
            const n: usize = @intCast(@min(self.event_count - count, self.chunk_events));
            for (chunk[0..n]) |*item| item.* = (try source_reader.next()) orelse return error.TruncatedMemoryRun;
            if (n >= radix_threshold) {
                try @import("memory_radix_sort.zig").sort(chunk[0..n], scratch);
            } else std.sort.pdq(Event, chunk[0..n], {}, Event.lessThan);
            for (chunk[1..n], 1..) |item, i| if (!Event.lessThan({}, chunk[i - 1], item)) return error.DuplicateOrUnsortedMemoryEvent;
            const name = try self.newName(0, runs.items.len);
            var file = try self.dir.createFile(name, .{});
            defer file.close();
            var writer: BufferedWriter = .{ .file = file };
            for (chunk[0..n]) |item| try writer.append(item);
            try writer.flush();
            try runs.append(self.a, .{ .name = name, .count = n });
            count += n;
        }
        var pass: usize = 1;
        self.statistics.initial_runs = @intCast(runs.items.len);
        while (runs.items.len > 1) : (pass += 1) {
            var next: std.ArrayList(Run) = .empty;
            errdefer next.deinit(self.a);
            for (0..std.math.divCeil(usize, runs.items.len, merge_fanout) catch unreachable) |index| {
                const start = index * merge_fanout;
                const group = runs.items[start..@min(start + merge_fanout, runs.items.len)];
                // A final single run is already sorted. Carry its admitted
                // file forward instead of copying every event one more time.
                if (group.len == 1) {
                    try next.append(self.a, group[0]);
                    continue;
                }
                const name = try self.newName(pass, index);
                const merged = try self.merge(group, name);
                self.statistics.merged_records = try std.math.add(u64, self.statistics.merged_records, merged);
                try next.append(self.a, .{ .name = name, .count = merged });
                for (group) |old| self.dir.deleteFile(old.name) catch {};
            }
            runs.deinit(self.a);
            runs = next;
            self.statistics.merge_passes += 1;
        }
        // Each run and every merge already checked strict order. Re-reading the
        // final stream here would add one filesystem call per block access.
        const result = try openRun(self.dir, runs.items[0].name, self.event_count);
        self.final_run_name = runs.items[0].name;
        self.finished = true;
        const input_bytes = try std.math.mul(u64, self.event_count, record_bytes);
        const merge_bytes = try std.math.mul(u64, self.statistics.merged_records, record_bytes);
        self.statistics.bytes_read = try std.math.add(u64, input_bytes, merge_bytes);
        self.statistics.bytes_written = try std.math.add(u64, try std.math.mul(u64, input_bytes, 2), merge_bytes);
        return result;
    }
    /// Explicit empty sorted stream, used by RW-only replay. Legacy finish
    /// continues rejecting empty inputs. File length is checked on reopen.
    pub fn finishEmpty(self: *Spool) !Reader {
        if (self.poisoned or self.finished or self.event_count != 0) return error.InvalidMemorySpoolPhase;
        errdefer self.poisoned = true;
        try self.pending.flush();
        self.raw.close();
        self.raw_open = false;
        const reader = try openRun(self.dir, "memory-events.raw", 0);
        self.final_run_name = "memory-events.raw";
        self.finished = true;
        return reader;
    }
    /// Reopen the same admitted final run for a later proof phase. This lets
    /// the producer release each first-round PCS state before sealing the
    /// complete block roster, then replay the exact sorted events for proof
    /// generation without retaining all component traces in memory.
    pub fn reopenSorted(self: *const Spool) !Reader {
        if (!self.finished or self.poisoned) return error.InvalidMemorySpoolPhase;
        return openRun(self.dir, self.final_run_name orelse return error.InvalidMemorySpoolPhase, self.event_count);
    }
    fn newName(self: *Spool, pass: usize, index: usize) ![]const u8 {
        const name = try std.fmt.allocPrint(self.a, "memory-run-{d}-{d}.bin", .{ pass, index });
        errdefer self.a.free(name);
        const file = try self.dir.createFile(name, .{ .exclusive = true });
        file.close();
        errdefer self.dir.deleteFile(name) catch {};
        try self.files.append(self.a, name);
        return name;
    }
    fn merge(self: *Spool, group: []const Run, name: []const u8) !u64 {
        var file = try self.dir.createFile(name, .{});
        defer file.close();
        var writer: BufferedWriter = .{ .file = file };
        var inputs: [merge_fanout]Reader = undefined;
        var heads = std.PriorityQueue(Head, void, Head.compare).init(self.a, {});
        defer heads.deinit();
        try heads.ensureTotalCapacity(group.len);
        var opened: usize = 0;
        defer for (inputs[0..opened]) |*input| input.deinit();
        var total: u64 = 0;
        for (group, 0..) |run, i| {
            inputs[i] = try openRun(self.dir, run.name, run.count);
            opened += 1;
            total = try std.math.add(u64, total, run.count);
            try heads.add(.{ .event = (try inputs[i].next()) orelse return error.TruncatedMemoryRun, .reader = i });
        }
        var previous: ?Event = null;
        for (0..@as(usize, @intCast(total))) |_| {
            const head = heads.removeOrNull() orelse return error.TruncatedMemoryRun;
            const index = head.reader;
            const item = head.event;
            if (previous) |prior| if (!Event.lessThan({}, prior, item)) return error.DuplicateOrUnsortedMemoryEvent;
            try writer.append(item);
            previous = item;
            if (try inputs[index].next()) |next| try heads.add(.{ .event = next, .reader = index });
        }
        try writer.flush();
        if (heads.count() != 0) return error.InvalidMemoryRunLength;
        return total;
    }
};
fn openRun(dir: std.fs.Dir, name: []const u8, count: u64) !Reader {
    const file = try dir.openFile(name, .{});
    errdefer file.close();
    const expected = try std.math.mul(u64, count, record_bytes);
    if (try file.getEndPos() != expected) return error.InvalidMemoryRunLength;
    return .{ .file = file, .remaining = count };
}
test "memory spool heap merge carries singleton runs and records exact transport work" {
    const a = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var spool = try Spool.init(a, temporary.dir, 4);
    defer spool.deinit();
    const count = 129;
    var expected: [count]Event = undefined;
    for (&expected, 0..) |*event, index| {
        event.* = .{ .space = 1, .address = @intCast(0x2000 + 4 * (index % 17)), .clock = 4 * (count - index) + 1, .value = @intCast(index) };
        try spool.append(event.*);
    }
    std.sort.pdq(Event, &expected, {}, Event.lessThan);
    var reader = try spool.finish();
    defer reader.deinit();
    for (expected) |event| try std.testing.expectEqualDeep(event, (try reader.next()).?);
    try std.testing.expect((try reader.next()) == null);
    try std.testing.expectEqual(@as(u32, 33), spool.statistics.initial_runs);
    try std.testing.expectEqual(@as(u32, 2), spool.statistics.merge_passes);
    // First pass merges32 full runs; the one-record tail is carried. Second
    // pass merges all129 records, with no lost or surplus events.
    try std.testing.expectEqual(@as(u64, 128 + 129), spool.statistics.merged_records);
    try std.testing.expectEqual(@as(u64, (129 + 128 + 129) * record_bytes), spool.statistics.bytes_read);
    try std.testing.expectEqual(@as(u64, (129 * 2 + 128 + 129) * record_bytes), spool.statistics.bytes_written);
    var duplicate_dir = std.testing.tmpDir(.{});
    defer duplicate_dir.cleanup();
    var repeated = try Spool.init(a, duplicate_dir.dir, 4);
    defer repeated.deinit();
    for (expected[0 .. count - 1]) |event| try repeated.append(event);
    try repeated.append(expected[0]);
    try std.testing.expectError(error.DuplicateOrUnsortedMemoryEvent, repeated.finish());
    try std.testing.expectError(error.InvalidMemorySpoolPhase, repeated.reopenSorted());
}

test "bounded memory spool sorts across runs with exact coverage and rejects duplicate clocks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try Spool.init(std.testing.allocator, tmp.dir, 1300);
    defer spool.deinit();
    // Both the raw-source reader and the merge readers cross their 1024-record
    // buffer boundary while sorting two independently committed runs.
    for (0..2113) |back| {
        const i: u32 = @intCast(2112 - back);
        try spool.append(.{ .space = 1, .address = (i % 3) * 4, .clock = @as(u64, i / 3) * 4 + 1, .value = i });
    }
    var reader = try spool.finish();
    defer reader.deinit();
    var previous: ?Event = null;
    var count: usize = 0;
    while (try reader.next()) |item| {
        if (previous) |before| try std.testing.expect(Event.lessThan({}, before, item));
        previous = item;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2113), count);
    var replay = try spool.reopenSorted();
    defer replay.deinit();
    count = 0;
    while (try replay.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 2113), count);
    try std.testing.expectError(error.InvalidMemorySpoolPhase, spool.append(.{ .space = 1, .address = 0, .clock = 1, .value = 0 }));
    try tmp.dir.makeDir("duplicate");
    var duplicate_dir = try tmp.dir.openDir("duplicate", .{});
    defer duplicate_dir.close();
    var duplicate = try Spool.init(std.testing.allocator, duplicate_dir, 2);
    defer duplicate.deinit();
    try duplicate.append(.{ .space = 1, .address = 0, .clock = 1, .value = 0 });
    try duplicate.append(.{ .space = 1, .address = 0, .clock = 1, .value = 0 });
    try std.testing.expectError(error.DuplicateOrUnsortedMemoryEvent, duplicate.finish());
}

test "spool accepts real segment accesses and globally orders leaf-local clocks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try Spool.init(std.testing.allocator, tmp.dir, 2);
    defer spool.deinit();
    const Access = @import("../../runner/state_chain.zig").Access;
    const first = [_]Access{.{ .addr_space = 1, .addr = 4096, .clk = 5, .clk_prev = 0, .value = 7 }};
    const second = [_]Access{.{ .addr_space = 1, .addr = 4096, .clk = 1, .clk_prev = 0, .value = 8 }};
    try spool.appendSegment(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 }, &first);
    try spool.appendSegment(.{ .clock_frame = .leaf_local, .global_first_cycle = 3, .cycle_count = 2 }, &second);
    var sorted = try spool.finish();
    defer sorted.deinit();
    try std.testing.expectEqual(@as(u64, 5), (try sorted.next()).?.clock);
    try std.testing.expectEqual(@as(u64, 9), (try sorted.next()).?.clock);
    try std.testing.expect((try sorted.next()) == null);
}

test "run admission rejects truncated and surplus records before merge" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("run.bin", .{});
    defer file.close();
    const item = Event{ .space = 1, .address = 4096, .clock = 1, .value = 7 };
    try file.writeAll(&item.encode());
    try std.testing.expectError(error.InvalidMemoryRunLength, openRun(tmp.dir, "run.bin", 2));
    var run = try openRun(tmp.dir, "run.bin", 1);
    defer run.deinit();
    try std.testing.expectEqualDeep(item, (try run.next()).?);
    try std.testing.expectEqual(@as(?Event, null), try run.next());
    try file.writeAll(&item.encode());
    try std.testing.expectError(error.InvalidMemoryRunLength, openRun(tmp.dir, "run.bin", 1));
}
