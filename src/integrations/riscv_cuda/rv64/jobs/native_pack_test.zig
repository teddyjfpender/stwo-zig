//! gn-pack TraceChunk v2 host tests: writer -> parser round trip across ring
//! buffers, and every structural refusal fails closed before any enqueue.
const std = @import("std");
const testing = std.testing;
const G = @import("gpu_native.zig");
const P = @import("native_pack.zig");

const Ring = struct {
    a: std.mem.Allocator,
    words: usize,
    chunks: std.ArrayListUnmanaged(G.TraceChunk) = .empty,
    buffers: std.ArrayListUnmanaged([]u32) = .empty,
    current: ?[]u32 = null,
    rows: u64 = 0,
    fn buffer(raw: *anyopaque) anyerror![]u32 {
        const self: *Ring = @ptrCast(@alignCast(raw));
        const b = try self.a.alloc(u32, self.words);
        try self.buffers.append(self.a, b);
        self.current = b;
        return b;
    }
    fn emit(raw: *anyopaque, words: usize, rows: u32, last: bool) anyerror!void {
        const self: *Ring = @ptrCast(@alignCast(raw));
        const b = self.current orelse return error.NoBuffer;
        self.current = null;
        try self.chunks.append(self.a, .{ .segment = 3, .sequence = @intCast(self.chunks.items.len), .first_row = self.rows, .rows = rows, .last = last, .words = b[0..words] });
        self.rows += rows;
    }
    fn writer(self: *Ring) G.ChunkWriter {
        return .{ .ctx = self, .buffer = buffer, .emit = emit };
    }
    fn deinit(self: *Ring) void {
        for (self.buffers.items) |b| self.a.free(b);
        self.buffers.deinit(self.a);
        self.chunks.deinit(self.a);
    }
    fn destroy(self: *Ring) void {
        const a = self.a;
        self.deinit();
        a.destroy(self);
    }
};

/// A small program: CPU-like launch over columns [0,4), a family over [4,6),
/// a table over [6,7); upload data larger than one ring buffer.
fn build(r: *Ring, data_words: usize) !void {
    var w = P.Writer.init(r.writer());
    const big = try r.a.alloc(u32, data_words);
    defer r.a.free(big);
    for (big, 0..) |*x, i| x.* = @truncate(i *% 2654435761);
    const scratch = try w.declare(1000, .zero);
    const input = try w.declare(big.len, .upload);
    try w.data(input, 0, big[0 .. big.len / 3]);
    try w.data(input, big.len / 3, big[big.len / 3 ..]);
    const rom = try w.persistent(64, @splat(9));
    try w.launch(.cpu_witness, .{ .metadata = 0, .rom = P.ref(rom, 0), .main = P.column(0), .counts16 = P.ref(scratch, 0), .counts8 = P.ref(scratch, 10), .rom_counts = P.ref(scratch, 20), .status = P.ref(scratch, 999), .count = 1, .log = 5, .rom_log = 5, .final_pc = 4, .pair_counts = 0 }, 0, 4);
    try w.status(P.ref(scratch, 999));
    try w.launch(.family, .{ .facts = P.ref(input, 0), .main = P.column(4), .range16 = P.ref(scratch, 0), .and_ = P.ref(scratch, 1), .shift = P.ref(scratch, 2), .status = P.ref(scratch, 999), .count = 1, .log = 5, .kind = 0 }, 4, 2);
    try w.launch(.copy, .{ .dst = P.ref(scratch, 100), .src = P.ref(scratch, 0), .words = 10 }, 0, 0);
    try w.launch(.table, .{ .counts = P.ref(scratch, 0), .pairs = 0, .main = P.column(6), .status = P.ref(scratch, 999), .log = 16, .kind = 0 }, 6, 1);
    try w.end(7, 1 << 5);
}

test "gn-pack v2: writer/parser round trip across ring buffers; data split exactly" {
    var r = Ring{ .a = testing.allocator, .words = 4096 };
    defer r.deinit();
    try build(&r, 10_000);
    try testing.expect(r.chunks.items.len >= 3);
    try testing.expectEqual(@as(u64, 32), r.rows); // all rows on the last chunk
    for (r.chunks.items[0 .. r.chunks.items.len - 1]) |c| try testing.expect(!c.last and c.rows == 0);
    var p = try P.Program.parse(testing.allocator, r.chunks.items, 7);
    defer p.deinit();
    try testing.expectEqual(@as(usize, 4), p.launches.items.len);
    try testing.expectEqual(@as(u64, 10_000), p.data_words);
    try testing.expectEqual(@as(usize, 1), p.status_len);
    // reassemble the upload buffer from its pieces
    const got = try testing.allocator.alloc(u32, 10_000);
    defer testing.allocator.free(got);
    for (p.pieces.items) |pc| @memcpy(got[@intCast(pc.offset)..][0..pc.host.len], pc.host);
    for (got, 0..) |x, i| try testing.expectEqual(@as(u32, @truncate(i *% 2654435761)), x);
    try testing.expectEqual(@as(usize, std.mem.alignForward(usize, 1000, 64) + std.mem.alignForward(usize, 10_000, 64)), p.arenaWords());
}

test "gn-pack v2: structural refusals (truncation, coverage, overlap, gaps, refs)" {
    const a = testing.allocator;
    var r = Ring{ .a = a, .words = 4096 };
    defer r.deinit();
    try build(&r, 10_000);
    const chunks = r.chunks.items;
    // wrong image width
    try testing.expectError(error.GnPackColumnCount, P.Program.parse(a, chunks, 8));
    // truncated: last chunk missing
    try testing.expectError(error.GnPackTruncated, P.Program.parse(a, chunks[0 .. chunks.len - 1], 7));
    // a lost middle chunk: the upload buffer has a gap
    const holed = try a.dupe(G.TraceChunk, chunks);
    defer a.free(holed);
    const middle = chunks.len / 2;
    std.mem.copyForwards(G.TraceChunk, holed[middle .. holed.len - 1], holed[middle + 1 ..]);
    try testing.expect(std.meta.isError(P.Program.parse(a, holed[0 .. holed.len - 1], 7)));
    // bad magic
    const last = chunks[chunks.len - 1];
    const copy = try a.dupe(u32, last.words);
    defer a.free(copy);
    var mutated = try a.dupe(G.TraceChunk, chunks);
    defer a.free(mutated);
    mutated[mutated.len - 1].words = copy;
    copy[0] ^= 1;
    try testing.expectError(error.GnPackChunkFormat, P.Program.parse(a, mutated, 7));
    copy[0] ^= 1;
    // a launch writing a column another launch writes (table -> column 5)
    var at: usize = P.chunk_header_words;
    while (at < copy[3]) : (at += copy[at + 1]) {
        if (copy[at] == @intFromEnum(P.Tag.launch) and copy[at + 2] == @intFromEnum(P.Op.table)) {
            copy[at + 4] = 5;
            const job: *align(4) P.Table = @ptrCast(copy[at + 6 ..].ptr);
            job.main = P.column(5);
            try testing.expectError(error.GnPackMainOverlap, P.Program.parse(a, mutated, 7));
            // a column nobody writes
            copy[at + 4] = 6;
            job.main = P.column(6);
            copy[at + 5] = 0;
            job.main = P.ref(2, 0);
            try testing.expectError(error.GnPackMainCoverage, P.Program.parse(a, mutated, 7));
            copy[at + 5] = 1;
            job.main = P.column(6);
            // a ref past its buffer
            job.counts = P.ref(2, 1000);
            try testing.expectError(error.GnPackRefOutOfRange, P.Program.parse(a, mutated, 7));
            job.counts = P.ref(77, 0);
            try testing.expectError(error.GnPackBufferNotDeclared, P.Program.parse(a, mutated, 7));
            job.counts = P.ref(2, 0);
        }
    }
    var ok = try P.Program.parse(a, mutated, 7);
    ok.deinit();
}

test "gn-pack v2: a non-v2 chunk is not mistaken for v2" {
    try testing.expect(!P.isV2(&.{ 1, 0, 0, 0, 0, 0, 0, 0 }));
    try testing.expect(P.isV2(&.{ P.magic, P.version, 0, 4 }));
}

test "gn-pack v2: status words are zeroed and checked; MAIN logs match the class" {
    const a = testing.allocator;
    var r = Ring{ .a = a, .words = 4096 };
    defer r.deinit();
    try build(&r, 100);
    var p = try P.Program.parse(a, r.chunks.items, 7);
    defer p.deinit();
    // build(): cpu_witness [0,4) log 5, family [4,6) log 5, table [6,7) log 16.
    try p.checkMainLogs(&.{ 5, 5, 5, 5, 5, 5, 16 });
    try testing.expectError(error.GnPackMainLog, p.checkMainLogs(&.{ 5, 5, 5, 5, 5, 6, 16 }));
    try testing.expectError(error.GnPackMainLog, p.checkMainLogs(&.{ 5, 5, 5, 5, 5, 5, 15 }));
    try testing.expectError(error.GnPackColumnCount, p.checkMainLogs(&.{ 5, 5, 5, 5, 5, 5 }));

    // A launch reporting into a word no status record lists.
    const unchecked = try statusVariant(a, false);
    defer unchecked.destroy();
    try testing.expectError(error.GnPackStatusUnchecked, P.Program.parse(a, unchecked.chunks.items, 7));
    // A status word in an upload buffer (its value would come from the host).
    const uploaded = try statusVariant(a, true);
    defer uploaded.destroy();
    try testing.expectError(error.GnPackStatusNotZeroed, P.Program.parse(a, uploaded.chunks.items, 7));
}

fn statusVariant(a: std.mem.Allocator, upload_status: bool) !*Ring {
    const r = try a.create(Ring);
    r.* = .{ .a = a, .words = 4096 };
    errdefer {
        r.deinit();
        a.destroy(r);
    }
    var w = P.Writer.init(r.writer());
    const scratch = try w.declare(1000, .zero);
    const up = try w.declare(4, .upload);
    try w.data(up, 0, &.{ 0, 0, 0, 0 });
    const status: P.Ref = if (upload_status) P.ref(up, 0) else P.ref(scratch, 999);
    try w.launch(.table, .{ .counts = P.ref(scratch, 0), .pairs = 0, .main = P.column(0), .status = if (upload_status) status else P.ref(scratch, 998), .log = 5, .kind = 0 }, 0, 7);
    try w.status(status);
    try w.end(7, 1 << 5);
    return r;
}
