//! Capture-side pinned-ring chunk writer; owns record growth and publication.
const std = @import("std");
const G = @import("gpu_native.zig");
const Schema = @import("native_pack.zig");
pub const Writer = struct {
    out: G.ChunkWriter,
    buf: []u32 = &.{},
    at: usize = 0,
    records: u32 = 0,
    launches: u32 = 0,
    buffers: u32 = 0,
    next_id: u16 = Schema.first_buffer,
    /// Totals (receipt): every word handed to `put`, data payload words.
    words_out: u64 = 0,
    data_words: u64 = 0,
    chunks: u32 = 0,
    /// Arena words Stage 1 allocates for the declared buffers (= Program.arenaWords).
    arena_words: u64 = 0,

    pub fn init(out: G.ChunkWriter) Writer {
        return .{ .out = out };
    }
    fn open(self: *Writer) !void {
        self.buf = try self.out.next();
        if (self.buf.len < Schema.chunk_header_words + Schema.record_header_words + 64) return error.GnPackRingBufferTooSmall;
        self.at = Schema.chunk_header_words;
        self.records = 0;
    }
    fn flush(self: *Writer, rows: u32, last: bool) !void {
        self.buf[0] = Schema.magic;
        self.buf[1] = Schema.version;
        self.buf[2] = self.records;
        self.buf[3] = @intCast(self.at);
        try self.out.put(self.at, rows, last);
        self.words_out += self.at;
        self.chunks += 1;
        self.buf = &.{};
        self.at = 0;
    }
    /// Room for a record of `body` words in the open buffer (opens/flushes).
    fn room(self: *Writer, body: usize) !void {
        if (self.buf.len == 0) try self.open();
        if (self.at + Schema.record_header_words + body > self.buf.len) {
            try self.flush(0, false);
            try self.open();
            if (Schema.record_header_words + body > self.buf.len - Schema.chunk_header_words) return error.GnPackRecordTooLarge;
        }
    }
    fn header(self: *Writer, tag: Schema.Tag, body: usize, a: u32, b: u32) void {
        self.buf[self.at..][0..4].* = .{ @intFromEnum(tag), @intCast(Schema.record_header_words + body), a, b };
        self.at += Schema.record_header_words;
        self.records += 1;
    }
    pub fn declare(self: *Writer, words: usize, init_kind: Schema.Init) !u16 {
        if (init_kind == .persistent) return error.GnPackUsePersistent;
        return self.declareKeyed(words, init_kind, null);
    }
    pub fn persistent(self: *Writer, words: usize, key: [8]u32) !u16 {
        return self.declareKeyed(words, .persistent, key);
    }
    fn declareKeyed(self: *Writer, words: usize, init_kind: Schema.Init, key: ?[8]u32) !u16 {
        if (self.next_id == Schema.max_buffers) return error.GnPackTooManyBuffers;
        const id = self.next_id;
        const body: usize = if (key != null) 10 else 2;
        try self.room(body);
        self.header(.declare, body, id, @intFromEnum(init_kind));
        const n: u64 = @max(words, 1);
        self.buf[self.at..][0..2].* = .{ @truncate(n), @truncate(n >> 32) };
        if (key) |k| @memcpy(self.buf[self.at + 2 ..][0..8], &k);
        self.at += body;
        self.next_id += 1;
        self.buffers += 1;
        if (init_kind != .persistent) self.arena_words += std.mem.alignForward(u64, n, 64);
        return id;
    }
    /// Data words into `buffer` at word `offset` (split across buffers).
    pub fn data(self: *Writer, buffer: u16, offset: usize, words: []const u32) !void {
        var done: usize = 0;
        while (done < words.len) {
            if (self.buf.len == 0) try self.open();
            if (self.at + Schema.record_header_words + 1 > self.buf.len) {
                try self.flush(0, false);
                try self.open();
            }
            const n = @min(words.len - done, self.buf.len - self.at - Schema.record_header_words);
            const off = offset + done;
            if (off > std.math.maxInt(u32)) return error.GnPackOffsetTooLarge;
            self.header(.data, n, buffer, @intCast(off));
            @memcpy(self.buf[self.at..][0..n], words[done..][0..n]);
            self.at += n;
            done += n;
            self.data_words += n;
        }
    }
    /// A data record of `n` words written in place by `fill` (no host copy):
    /// returns the ring slice to fill, at most `max` words (>= 1).
    pub fn reserve(self: *Writer, buffer: u16, offset: usize, max: usize) ![]u32 {
        if (self.buf.len == 0) try self.open();
        if (self.at + Schema.record_header_words + 64 > self.buf.len) {
            try self.flush(0, false);
            try self.open();
        }
        const n = @min(max, self.buf.len - self.at - Schema.record_header_words);
        if (offset > std.math.maxInt(u32)) return error.GnPackOffsetTooLarge;
        self.header(.data, n, buffer, @intCast(offset));
        const out = self.buf[self.at..][0..n];
        self.at += n;
        self.data_words += n;
        return out;
    }
    /// As `reserve`, in whole units of `unit` words (records never split a
    /// unit): at most `max_units` units, at least one.
    pub fn reserveUnits(self: *Writer, buffer: u16, offset: usize, max_units: usize, unit: usize) ![]u32 {
        if (self.buf.len == 0) try self.open();
        if (self.at + Schema.record_header_words + unit > self.buf.len) {
            try self.flush(0, false);
            try self.open();
            if (Schema.record_header_words + unit > self.buf.len - Schema.chunk_header_words) return error.GnPackRecordTooLarge;
        }
        const n = @min(max_units, (self.buf.len - self.at - Schema.record_header_words) / unit) * unit;
        if (offset > std.math.maxInt(u32)) return error.GnPackOffsetTooLarge;
        self.header(.data, n, buffer, @intCast(offset));
        const out = self.buf[self.at..][0..n];
        self.at += n;
        self.data_words += n;
        return out;
    }
    pub fn launch(self: *Writer, comptime op: Schema.Op, job: op.Type(), main_column: u32, main_columns: u32) !void {
        const n = Schema.opWords(op);
        try self.room(2 + n);
        self.header(.launch, 2 + n, @intFromEnum(op), 0);
        self.buf[self.at] = main_column;
        self.buf[self.at + 1] = main_columns;
        @memcpy(self.buf[self.at + 2 ..][0..n], std.mem.bytesAsSlice(u32, std.mem.asBytes(&job)));
        self.at += 2 + n;
        self.launches += 1;
    }
    pub fn status(self: *Writer, word: Schema.Ref) !void {
        try self.room(2);
        self.header(.status, 2, 0, 0);
        self.buf[self.at..][0..2].* = .{ @truncate(word), @truncate(word >> 32) };
        self.at += 2;
    }
    /// Close the segment: the end record and the last chunk (all `rows`).
    pub fn end(self: *Writer, columns: u32, rows: u64) !void {
        try self.room(3);
        self.header(.end, 3, self.launches, self.buffers);
        self.buf[self.at..][0..3].* = .{ columns, @truncate(rows), @truncate(rows >> 32) };
        self.at += 3;
        try self.flush(std.math.cast(u32, rows) orelse return error.GnPackRowsTooLarge, true);
    }
};

// ---------------------------------------------------------------------------
// Program (Stage-1 side): parse + validate, then enqueue
// ---------------------------------------------------------------------------
