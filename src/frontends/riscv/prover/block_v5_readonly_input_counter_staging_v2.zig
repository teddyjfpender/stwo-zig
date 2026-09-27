//! Bounded first-pass counter proposals. Completed groups stream to exclusive
//! files; readers verify independent byte/SHA/scope pins and load one provider
//! shard at a time. These pins have transport integrity, never proof authority.
const std = @import("std");
const Collection = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_v2.zig");
const Hash = std.crypto.hash.sha2.Sha256;
const HEADER_BYTES = 84;
const RECORD_BYTES = 6;
const BUFFER_BYTES = 16 * 1024;
pub const Limits = struct {
    counters: Collection.Limits = .{},
    max_group_file_bytes: u64 = 128 * 1024 * 1024,
    max_total_file_bytes: u64 = 1024 * 1024 * 1024,
};
pub const Pin = struct {
    group: Collection.Group,
    selection_digest: [32]u8,
    interval_count: u32,
    fragment_count: u64,
    bytes: u64,
    sha256: [32]u8,
    pub fn require(self: Pin, limits: Limits) !void {
        return requirePin(self, limits);
    }
};
pub fn name(index: u32, buffer: *[80]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "readonly-counter-group-{d}-v2.bin", .{index});
}
pub fn metadataBytes(groups: usize) !usize {
    return std.math.add(usize, @sizeOf(Writer), try std.math.mul(usize, groups, @sizeOf(Pin)));
}
pub const Writer = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    selection_digest: [32]u8,
    pins: []Pin,
    used: usize = 0,
    total_bytes: u64 = 0,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, selection_digest: [32]u8, groups: usize, limits: Limits) !Writer {
        if (groups == 0 or std.mem.allEqual(u8, &selection_digest, 0) or limits.max_group_file_bytes < HEADER_BYTES or limits.max_total_file_bytes < HEADER_BYTES) return error.InvalidReadonlyCounterStagingLimits;
        return .{ .a = a, .dir = dir, .selection_digest = selection_digest, .pins = try a.alloc(Pin, groups), .limits = limits };
    }
    /// Files remain independently pinned proposals in the caller-owned directory.
    pub fn deinit(self: *Writer) void {
        self.a.free(self.pins);
        self.* = undefined;
    }
    pub fn sink(self: *Writer) Collection.Sink {
        return .{ .context = self, .put_group = putGroup };
    }
    fn putGroup(raw: *anyopaque, view: Collection.GroupView) !void {
        const self: *Writer = @ptrCast(@alignCast(raw));
        if (self.used >= self.pins.len or view.group.index != self.used or view.counts.len > std.math.maxInt(u32)) return error.InvalidReadonlyCounterStagingOrder;
        try view.group.census.require(view.group.census.all_rw);
        if (view.group.source_count == 0 or view.counts.len == 0 or view.group.census.all_rw > self.limits.counters.max_group_events) return error.InvalidReadonlyCounterStagingPin;
        if (view.group.census.all_rw == 0) for (view.counts) |count| {
            if (count != 0) return error.StaleReadonlyCounterCensus;
        };
        var cursor = if (view.group.census.all_rw == 0) null else try Provider.FragmentCursor.init(view.counts, view.group.census.all_rw);
        var fragments: u64 = 0;
        if (cursor) |*owned| while (try owned.next()) |_| {
            fragments = try std.math.add(u64, fragments, 1);
        };
        const bytes = try std.math.add(u64, HEADER_BYTES, try std.math.mul(u64, fragments, RECORD_BYTES));
        const total_bytes = try std.math.add(u64, self.total_bytes, bytes);
        if (bytes > self.limits.max_group_file_bytes or total_bytes > self.limits.max_total_file_bytes) return error.ReadonlyCounterStagingResourceLimit;
        var pin = Pin{ .group = view.group, .selection_digest = self.selection_digest, .interval_count = @intCast(view.counts.len), .fragment_count = fragments, .bytes = bytes, .sha256 = undefined };
        var buffer: [80]u8 = undefined;
        const path = try name(view.group.index, &buffer);
        var file = try self.dir.createFile(path, .{ .exclusive = true });
        var open = true;
        defer if (open) file.close();
        errdefer self.dir.deleteFile(path) catch {};
        var writer = BufferedWriter{ .file = file };
        try writer.append(&header(pin));
        cursor = if (view.group.census.all_rw == 0) null else try Provider.FragmentCursor.init(view.counts, view.group.census.all_rw);
        if (cursor) |*owned| while (try owned.next()) |fragment| {
            var raw_record: [RECORD_BYTES]u8 = undefined;
            std.mem.writeInt(u32, raw_record[0..4], fragment.interval_index, .little);
            std.mem.writeInt(u16, raw_record[4..6], fragment.count, .little);
            try writer.append(&raw_record);
        };
        try writer.flush();
        pin.sha256 = writer.hash.finalResult();
        file.close();
        open = false;
        self.pins[self.used] = pin;
        self.used += 1;
        self.total_bytes = total_bytes;
    }
    pub fn records(self: *const Writer) []const Pin {
        return self.pins[0..self.used];
    }
};
const BufferedWriter = struct {
    file: std.fs.File,
    buffer: [BUFFER_BYTES]u8 = undefined,
    used: usize = 0,
    hash: Hash = .init(.{}),
    fn append(self: *BufferedWriter, bytes: []const u8) !void {
        self.hash.update(bytes);
        var rest = bytes;
        while (rest.len != 0) {
            const n = @min(rest.len, self.buffer.len - self.used);
            @memcpy(self.buffer[self.used..][0..n], rest[0..n]);
            self.used += n;
            rest = rest[n..];
            if (self.used == self.buffer.len) try self.flush();
        }
    }
    fn flush(self: *BufferedWriter) !void {
        try self.file.writeAll(self.buffer[0..self.used]);
        self.used = 0;
    }
};
fn header(pin: Pin) [HEADER_BYTES]u8 {
    var raw: [HEADER_BYTES]u8 = undefined;
    @memcpy(raw[0..8], "B5ICNT02");
    std.mem.writeInt(u32, raw[8..12], 2, .little);
    std.mem.writeInt(u32, raw[12..16], pin.group.index, .little);
    std.mem.writeInt(u32, raw[16..20], pin.group.first_source, .little);
    std.mem.writeInt(u32, raw[20..24], pin.group.source_count, .little);
    std.mem.writeInt(u64, raw[24..32], pin.group.census.all_rw, .little);
    std.mem.writeInt(u64, raw[32..40], pin.group.census.readonly, .little);
    std.mem.writeInt(u32, raw[40..44], pin.interval_count, .little);
    std.mem.writeInt(u64, raw[44..52], pin.fragment_count, .little);
    @memcpy(raw[52..84], &pin.selection_digest);
    return raw;
}
pub const ShardView = struct {
    a: std.mem.Allocator,
    first_fragment: u64,
    fragments: []Provider.Fragment,
    pub fn deinit(self: *ShardView) void {
        self.a.free(self.fragments);
        self.* = undefined;
    }
    pub fn chunkPin(self: *const ShardView, group_index: u32) !ChunkPin {
        if (self.fragments.len == 0 or self.fragments.len > Provider.MAX_FRAGMENTS) return error.InvalidReadonlyCounterChunk;
        const count: u32 = @intCast(self.fragments.len);
        var hash = chunkHash(group_index, self.first_fragment, count);
        for (self.fragments) |fragment| hash.update(&recordBytes(fragment));
        return .{ .group_index = group_index, .first_fragment = self.first_fragment, .fragment_count = count, .sha256 = hash.finalResult() };
    }
};
/// Derived only after the original complete group file passed its byte/SHA
/// checks. This allows parallel bounded replay without rehashing the same full
/// file for every shard. Transport integrity is never proof authority.
pub const ChunkPin = struct { group_index: u32, first_fragment: u64, fragment_count: u32, sha256: [32]u8 };
fn recordBytes(fragment: Provider.Fragment) [RECORD_BYTES]u8 {
    var raw: [RECORD_BYTES]u8 = undefined;
    std.mem.writeInt(u32, raw[0..4], fragment.interval_index, .little);
    std.mem.writeInt(u16, raw[4..6], fragment.count, .little);
    return raw;
}
fn chunkHash(group_index: u32, first: u64, count: u32) Hash {
    var hash = Hash.init(.{});
    hash.update("stwo-zig/block-v5/readonly-counter-chunk/v2\x00");
    var raw: [16]u8 = undefined;
    std.mem.writeInt(u32, raw[0..4], group_index, .little);
    std.mem.writeInt(u64, raw[4..12], first, .little);
    std.mem.writeInt(u32, raw[12..16], count, .little);
    hash.update(&raw);
    return hash;
}
fn requirePin(expected: Pin, limits: Limits) !void {
    try expected.group.census.require(expected.group.census.all_rw);
    if (expected.group.source_count == 0 or expected.group.census.all_rw > limits.counters.max_group_events or expected.group.census.all_rw >= @import("stwo_core").fields.m31.Modulus or
        expected.interval_count == 0 or expected.bytes != try std.math.add(u64, HEADER_BYTES, try std.math.mul(u64, expected.fragment_count, RECORD_BYTES)) or
        expected.bytes > limits.max_group_file_bytes or expected.bytes > limits.max_total_file_bytes or
        (expected.group.census.all_rw == 0) != (expected.fragment_count == 0)) return error.InvalidReadonlyCounterStagingPin;
}
fn decodeRecord(raw: *const [RECORD_BYTES]u8, interval_count: u32, previous: ?Provider.Fragment) !Provider.Fragment {
    const fragment = Provider.Fragment{ .interval_index = std.mem.readInt(u32, raw[0..4], .little), .count = std.mem.readInt(u16, raw[4..6], .little) };
    if (fragment.count == 0 or fragment.interval_index >= interval_count) return error.InvalidReadonlyProviderFragments;
    if (previous) |prior| if (fragment.interval_index < prior.interval_index or
        (fragment.interval_index == prior.interval_index and prior.count != 65535)) return error.InvalidReadonlyProviderFragments;
    return fragment;
}
/// Decode bounded batches rather than issuing one filesystem read per six-byte
/// fragment. The original sequential reader retains order/census across chunks.
fn readRecords(file: std.fs.File, fragments: []Provider.Fragment, interval_count: u32, previous: *?Provider.Fragment, total: *u64, expected_total: u64, hash: ?*Hash) !void {
    const records_per_batch = BUFFER_BYTES / RECORD_BYTES;
    var buffer: [records_per_batch * RECORD_BYTES]u8 = undefined;
    var at: usize = 0;
    while (at < fragments.len) {
        const n = @min(records_per_batch, fragments.len - at);
        const bytes = buffer[0 .. n * RECORD_BYTES];
        if (try file.readAll(bytes) != bytes.len) return error.StaleReadonlyCounterFile;
        if (hash) |digest| digest.update(bytes);
        for (fragments[at..][0..n], 0..) |*fragment, i| {
            const raw: *const [RECORD_BYTES]u8 = bytes[i * RECORD_BYTES ..][0..RECORD_BYTES];
            fragment.* = try decodeRecord(raw, interval_count, previous.*);
            total.* = try std.math.add(u64, total.*, fragment.count);
            if (total.* > expected_total) return error.StaleReadonlyCounterCensus;
            previous.* = fragment.*;
        }
        at += n;
    }
}
/// Reads exactly one previously pinned fragment chunk. Header, file size,
/// canonical encoding and the scope-bound chunk SHA are checked before return.
/// Other chunks are checked by their consumers; no full-file rehash per proof.
pub fn readChunk(a: std.mem.Allocator, dir: std.fs.Dir, expected: Pin, chunk: ChunkPin, limits: Limits) !ShardView {
    try requirePin(expected, limits);
    if (chunk.group_index != expected.group.index or chunk.fragment_count == 0 or chunk.fragment_count > Provider.MAX_FRAGMENTS or
        chunk.first_fragment >= expected.fragment_count or chunk.first_fragment % Provider.MAX_FRAGMENTS != 0 or
        chunk.fragment_count != @min(Provider.MAX_FRAGMENTS, expected.fragment_count - chunk.first_fragment) or
        std.mem.allEqual(u8, &chunk.sha256, 0)) return error.InvalidReadonlyCounterChunk;
    var name_buffer: [80]u8 = undefined;
    var file = try dir.openFile(try name(expected.group.index, &name_buffer), .{});
    defer file.close();
    if ((try file.stat()).size != expected.bytes) return error.StaleReadonlyCounterFile;
    var raw_header: [HEADER_BYTES]u8 = undefined;
    if (try file.readAll(&raw_header) != raw_header.len or !std.mem.eql(u8, &raw_header, &header(expected))) return error.StaleReadonlyCounterScope;
    const offset = try std.math.add(u64, HEADER_BYTES, try std.math.mul(u64, chunk.first_fragment, RECORD_BYTES));
    try file.seekTo(offset);
    const fragments = try a.alloc(Provider.Fragment, chunk.fragment_count);
    errdefer a.free(fragments);
    var hash = chunkHash(chunk.group_index, chunk.first_fragment, chunk.fragment_count);
    var previous: ?Provider.Fragment = null;
    var total: u64 = 0;
    try readRecords(file, fragments, expected.interval_count, &previous, &total, expected.group.census.all_rw, &hash);
    if (!std.meta.eql(hash.finalResult(), chunk.sha256)) return error.StaleReadonlyCounterChunk;
    return .{ .a = a, .first_fragment = chunk.first_fragment, .fragments = fragments };
}
pub const Reader = struct {
    file: std.fs.File,
    pin: Pin,
    consumed: u64 = 0,
    total: u64 = 0,
    previous: ?Provider.Fragment = null,
    pub fn open(dir: std.fs.Dir, expected: Pin, limits: Limits) !Reader {
        try requirePin(expected, limits);
        var name_buffer: [80]u8 = undefined;
        var file = try dir.openFile(try name(expected.group.index, &name_buffer), .{});
        errdefer file.close();
        const stat = try file.stat();
        if (stat.size != expected.bytes) return error.StaleReadonlyCounterFile;
        var hash = Hash.init(.{});
        var buffer: [BUFFER_BYTES]u8 = undefined;
        var bytes: u64 = 0;
        while (true) {
            const n = try file.read(&buffer);
            if (n == 0) break;
            bytes = try std.math.add(u64, bytes, n);
            if (bytes > expected.bytes) return error.StaleReadonlyCounterFile;
            hash.update(buffer[0..n]);
        }
        if (bytes != expected.bytes or !std.meta.eql(hash.finalResult(), expected.sha256)) return error.StaleReadonlyCounterFile;
        try file.seekTo(0);
        var raw: [HEADER_BYTES]u8 = undefined;
        if (try file.readAll(&raw) != raw.len or !std.mem.eql(u8, &raw, &header(expected))) return error.StaleReadonlyCounterScope;
        return .{ .file = file, .pin = expected };
    }
    pub fn deinit(self: *Reader) void {
        self.file.close();
        self.* = undefined;
    }
    /// Caller releases the previous shard before asking for another one.
    /// Malformed read poisons the cursor; only successful completion is usable.
    pub fn nextShard(self: *Reader, a: std.mem.Allocator) !?ShardView {
        if (self.consumed == self.pin.fragment_count) {
            if (self.total != self.pin.group.census.all_rw) return error.StaleReadonlyCounterCensus;
            return null;
        }
        if (self.consumed > self.pin.fragment_count) return error.ReadonlyCounterReaderPoisoned;
        const n: usize = @intCast(@min(Provider.MAX_FRAGMENTS, self.pin.fragment_count - self.consumed));
        const fragments = try a.alloc(Provider.Fragment, n);
        errdefer a.free(fragments);
        errdefer self.consumed = self.pin.fragment_count + 1;
        const first = self.consumed;
        try readRecords(self.file, fragments, self.pin.interval_count, &self.previous, &self.total, self.pin.group.census.all_rw, null);
        self.consumed += n;
        return .{ .a = a, .first_fragment = first, .fragments = fragments };
    }
};
