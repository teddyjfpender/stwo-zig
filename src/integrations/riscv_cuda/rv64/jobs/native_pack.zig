//! M8 GPU-native compact trace ingress: TraceChunk format v2 and the Stage-1
//! device witness program (stream gn-pack; IO lever L0, rv64-m9-io-streaming.md
//! §4.2; design rv64-m8-gpu-native.md §3.2 item 1, inventory H4).
//!
//! v1 (`native_device_stage1.zig chunkRuns`) ships MAIN evaluation images and
//! puts column materialisation on the capture thread (7.38 GB per 24628607
//! request [D]). v2 ships what the legacy resident source uploads today: the
//! compact facts/events (`CompactRecord` + seeds, family `Fact`s, LS `Event`s,
//! public RAM `Cell`s, service call/word/row records) plus a launch program
//! that runs the EXISTING base-library `*_witness_on` kernels on the job's exec
//! stream (lane 0) straight into the segment's MAIN evaluation image. The
//! multiplicity ledgers and the status words never leave the device: the
//! table kernels read them in place and the status words feed the Stage-1
//! `witness_status` check (legacy downloaded both per segment).
//!
//! Chunk words (little-endian u32):
//!   header  [magic "GNP2", version 2, records, used words]
//!   record  [tag, words (incl. this 4-word header), a, b] ++ body
//!     declare  a = buffer id (>= 2), b = Init; body = [words lo, hi] (+ key[8] for .persistent)
//!     data     a = buffer id, b = word offset; body = the words (an upload
//!              buffer's data may span many records and chunks)
//!     launch   a = Op; body = [main column, main columns] ++ the op's job
//!              struct, pointer fields carrying a `Ref` (u64)
//!     status   a = 0; body = [ref lo, ref hi]: a device status word that must be 0
//!     end      a = launches, b = buffers; body = [image columns, rows lo, rows hi]
//!              (exactly once, last record of the segment's last chunk)
//!   `Ref` = (buffer << 48) | word offset; buffer 1 = the MAIN image, whose
//!   offset is a COLUMN index (resolved by the class's image offsets); 0 = null.
//!
//! The capture side (`native_pack_capture.zig`) writes this through the
//! pinned ring (`gpu_native.ChunkWriter`); Stage 1 parses it at job init (host,
//! O(records), over pinned ring memory only: no compute), refuses a malformed
//! stream before enqueueing anything, and enqueues: memsets of zero buffers,
//! h2d of every data record from the pinned ring, then the launches in order.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

pub const magic: u32 = 0x3250_4e47; // "GNP2"
/// Recorder file magic (rv64/gn_pack_record.zig, "GNPF").
pub const record_file_magic: u32 = 0x4650_4e47;
pub const version: u32 = 2;
pub const chunk_header_words: usize = 4;
pub const record_header_words: usize = 4;
pub const max_buffers: usize = 256;
pub const image_buffer: u16 = 1;
pub const first_buffer: u16 = 2;
pub const max_status: usize = 8;

pub const Tag = enum(u32) { declare = 1, data = 2, launch = 3, status = 4, end = 5 };
pub const Init = enum(u32) {
    /// Every word arrives in data records (tiled exactly once).
    upload = 0,
    /// memset 0 on device; data records may overwrite a prefix.
    zero = 1,
    /// Worker-persistent region keyed by `key` (the program ROM): filled
    /// once per GPU from the host words the `Roms` registry holds.
    persistent = 2,
    /// Device scratch fully written by a kernel before it is read.
    scratch = 3,
};

pub fn isV2(words: []const u32) bool {
    return words.len >= chunk_header_words and words[0] == magic;
}

pub const Ref = u64;
pub fn ref(buffer: u16, offset: usize) Ref {
    std.debug.assert(offset < (@as(u64, 1) << 48));
    return (@as(u64, buffer) << 48) | @as(u64, offset);
}
pub fn column(index: usize) Ref {
    return ref(image_buffer, index);
}
fn refBuffer(r: Ref) u16 {
    return @intCast(r >> 48);
}
fn refOffset(r: Ref) u64 {
    return r & ((@as(u64, 1) << 48) - 1);
}

// ---------------------------------------------------------------------------
// Launch ABI: the legacy base-library job structs, pointer fields as `Ref`.
// Sizes are pinned to the legacy definitions (core_witness.zig FamilyJob 64,
// MemoryJob 72, ArithmeticJob 72; bridge_witness.zig Job 80; bulk_sponge.zig
// BulkJob/SpongeJob; abi.zig CpuUnpack/CpuWitness).
// ---------------------------------------------------------------------------

pub const FamilyJob = extern struct {
    facts: Ref,
    main: Ref,
    range16: Ref,
    and_: Ref,
    shift: Ref,
    status: Ref,
    count: u32,
    log: u32,
    kind: u32,
    reserved: u32 = 0,
    pub const refs = .{ "facts", "main", "range16", "and_", "shift", "status" };
    pub const symbol = "stwo_rv64_family_witness_on";
};
pub const MemoryJob = extern struct {
    events: Ref,
    main: Ref,
    range16: Ref,
    range8: Ref,
    pairs: Ref,
    selection: Ref,
    status: Ref,
    count: u32,
    log: u32,
    dword: u32,
    fused_pairs: u32,
    pub const refs = .{ "events", "main", "range16", "range8", "pairs", "selection", "status" };
    pub const symbol = "stwo_rv64_memory_witness_on";
};
pub const ArithmeticJob = extern struct {
    requests: Ref,
    main: Ref,
    range16: Ref,
    range8: Ref,
    pairs: Ref,
    status: Ref,
    mul_support: Ref,
    count: u32,
    log: u32,
    division: u32,
    fused_pairs: u32,
    pub const refs = .{ "requests", "main", "range16", "range8", "pairs", "status", "mul_support" };
    pub const symbol = "stwo_rv64_arithmetic_witness_on";
};
pub const BridgeJob = extern struct {
    inputs: Ref,
    main: Ref,
    range16: Ref,
    range8: Ref,
    status: Ref,
    input_words: u64,
    main_words: u64,
    calls: u32,
    first_id: u32,
    log: u32,
    kind: u32,
    coordinates: u32,
    write_mask: u32,
    pub const refs = .{ "inputs", "main", "range16", "range8", "status" };
    pub const symbol = "stwo_rv64_bridge_witness_on";
};
pub const BulkJob = extern struct {
    calls: Ref,
    words: Ref,
    rows: Ref,
    pending: Ref,
    main: Ref,
    range16: Ref,
    jump_counts: Ref,
    status: Ref,
    count: u32,
    log: u32,
    kind: u32,
    call_count: u32,
    word_count: u32,
    pending_count: u32,
    pub const refs = .{ "calls", "words", "rows", "pending", "main", "range16", "jump_counts", "status" };
    pub const symbol = "stwo_rv64_bulk_witness_on";
};
pub const SpongeJob = extern struct {
    calls: Ref,
    words: Ref,
    outputs: Ref,
    rows: Ref,
    main: Ref,
    range16: Ref,
    range8: Ref,
    and_counts: Ref,
    status: Ref,
    count: u32,
    log: u32,
    kind: u32,
    first_id: u32,
    call_count: u32,
    word_count: u32,
    permutation_count: u32,
    reserved: u32 = 0,
    pub const refs = .{ "calls", "words", "outputs", "rows", "main", "range16", "range8", "and_counts", "status" };
    pub const symbol = "stwo_rv64_sponge_witness_on";
};
pub const CpuUnpack = extern struct {
    records: Ref,
    seeds: Ref,
    rom: Ref,
    metadata: Ref,
    status: Ref,
    count: u32,
    rom_log: u32,
    chunk_rows: u32,
    reserved: u32 = 0,
    pub const refs = .{ "records", "seeds", "rom", "metadata", "status" };
    pub const symbol = "stwo_rv64_cpu_unpack_on";
};
pub const CpuWitness = extern struct {
    metadata: Ref,
    rom: Ref,
    main: Ref,
    counts16: Ref,
    counts8: Ref,
    rom_counts: Ref,
    status: Ref,
    count: u32,
    log: u32,
    rom_log: u32,
    final_pc: u32,
    pair_counts: Ref,
    pub const refs = .{ "metadata", "rom", "main", "counts16", "counts8", "rom_counts", "status", "pair_counts" };
    pub const symbol = "stwo_rv64_cpu_witness_on";
};
/// stwo_rv64_boundary_witness_on(ctx, lane, cells, count, log, main, status)
pub const Boundary = extern struct {
    cells: Ref,
    main: Ref,
    status: Ref,
    count: u32,
    log: u32,
    pub const refs = .{ "cells", "main", "status" };
};
/// stwo_rv64_multiplicity_witness_on(ctx, lane, counts, pairs, log, kind, main, status)
pub const Table = extern struct {
    counts: Ref,
    pairs: Ref,
    main: Ref,
    status: Ref,
    log: u32,
    kind: u32,
    pub const refs = .{ "counts", "pairs", "main", "status" };
};
/// stwo_rv64_bulk_analyze_on(ctx, lane, calls, nc, words, nw, pending, np, jumps, status)
pub const BulkAnalyze = extern struct {
    calls: Ref,
    words: Ref,
    pending: Ref,
    jumps: Ref,
    status: Ref,
    call_count: u32,
    word_count: u32,
    pending_count: u32,
    reserved: u32 = 0,
    pub const refs = .{ "calls", "words", "pending", "jumps", "status" };
};
/// stwo_rv64_sponge_outputs_on(ctx, lane, in, out, n, status)
pub const SpongeOutputs = extern struct {
    inputs: Ref,
    outputs: Ref,
    status: Ref,
    count: u32,
    reserved: u32 = 0,
    pub const refs = .{ "inputs", "outputs", "status" };
};
/// d2d copy of `words` (legacy core ledger seeding from the CPU ledgers).
pub const Copy = extern struct {
    dst: Ref,
    src: Ref,
    words: u64,
    pub const refs = .{ "dst", "src" };
};

pub const Op = enum(u32) {
    family = 1,
    memory = 2,
    arithmetic = 3,
    bridge = 4,
    bulk = 5,
    sponge = 6,
    cpu_unpack = 7,
    cpu_witness = 8,
    boundary = 9,
    table = 10,
    bulk_analyze = 11,
    sponge_outputs = 12,
    copy = 13,
    pub fn Type(comptime op: Op) type {
        return switch (op) {
            .family => FamilyJob,
            .memory => MemoryJob,
            .arithmetic => ArithmeticJob,
            .bridge => BridgeJob,
            .bulk => BulkJob,
            .sponge => SpongeJob,
            .cpu_unpack => CpuUnpack,
            .cpu_witness => CpuWitness,
            .boundary => Boundary,
            .table => Table,
            .bulk_analyze => BulkAnalyze,
            .sponge_outputs => SpongeOutputs,
            .copy => Copy,
        };
    }
};

comptime {
    const sizes = .{ .{ FamilyJob, 64 }, .{ MemoryJob, 72 }, .{ ArithmeticJob, 72 }, .{ BridgeJob, 80 }, .{ BulkJob, 88 }, .{ SpongeJob, 104 }, .{ CpuUnpack, 56 }, .{ CpuWitness, 80 } };
    for (sizes) |s| if (@sizeOf(s[0]) != s[1]) @compileError("gn-pack launch ABI changed: " ++ @typeName(s[0]));
    for (std.enums.values(Op)) |op| if (@sizeOf(op.Type()) % 4 != 0) @compileError("gn-pack launch struct not word sized");
}

pub fn opWords(op: Op) usize {
    return switch (op) {
        inline else => |o| @sizeOf(o.Type()) / 4,
    };
}

// ---------------------------------------------------------------------------
// Writer (capture side): records into pinned ring buffers
// ---------------------------------------------------------------------------

/// Builds a segment's v2 chunk stream through `G.ChunkWriter` (pinned ring
/// buffers). Data larger than a buffer is split into several data records.
pub const Writer = struct {
    out: G.ChunkWriter,
    buf: []u32 = &.{},
    at: usize = 0,
    records: u32 = 0,
    launches: u32 = 0,
    buffers: u32 = 0,
    next_id: u16 = first_buffer,
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
        if (self.buf.len < chunk_header_words + record_header_words + 64) return error.GnPackRingBufferTooSmall;
        self.at = chunk_header_words;
        self.records = 0;
    }
    fn flush(self: *Writer, rows: u32, last: bool) !void {
        self.buf[0] = magic;
        self.buf[1] = version;
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
        if (self.at + record_header_words + body > self.buf.len) {
            try self.flush(0, false);
            try self.open();
            if (record_header_words + body > self.buf.len - chunk_header_words) return error.GnPackRecordTooLarge;
        }
    }
    fn header(self: *Writer, tag: Tag, body: usize, a: u32, b: u32) void {
        self.buf[self.at..][0..4].* = .{ @intFromEnum(tag), @intCast(record_header_words + body), a, b };
        self.at += record_header_words;
        self.records += 1;
    }
    pub fn declare(self: *Writer, words: usize, init_kind: Init) !u16 {
        if (init_kind == .persistent) return error.GnPackUsePersistent;
        return self.declareKeyed(words, init_kind, null);
    }
    pub fn persistent(self: *Writer, words: usize, key: [8]u32) !u16 {
        return self.declareKeyed(words, .persistent, key);
    }
    fn declareKeyed(self: *Writer, words: usize, init_kind: Init, key: ?[8]u32) !u16 {
        if (self.next_id == max_buffers) return error.GnPackTooManyBuffers;
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
            if (self.at + record_header_words + 1 > self.buf.len) {
                try self.flush(0, false);
                try self.open();
            }
            const n = @min(words.len - done, self.buf.len - self.at - record_header_words);
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
        if (self.at + record_header_words + 64 > self.buf.len) {
            try self.flush(0, false);
            try self.open();
        }
        const n = @min(max, self.buf.len - self.at - record_header_words);
        if (offset > std.math.maxInt(u32)) return error.GnPackOffsetTooLarge;
        self.header(.data, n, buffer, @intCast(offset));
        const out = self.buf[self.at..][0..n];
        self.at += n;
        self.data_words += n;
        return out;
    }
    pub fn launch(self: *Writer, comptime op: Op, job: op.Type(), main_column: u32, main_columns: u32) !void {
        const n = opWords(op);
        try self.room(2 + n);
        self.header(.launch, 2 + n, @intFromEnum(op), 0);
        self.buf[self.at] = main_column;
        self.buf[self.at + 1] = main_columns;
        @memcpy(self.buf[self.at + 2 ..][0..n], std.mem.bytesAsSlice(u32, std.mem.asBytes(&job)));
        self.at += 2 + n;
        self.launches += 1;
    }
    pub fn status(self: *Writer, word: Ref) !void {
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

pub const Buffer = struct {
    declared: bool = false,
    init: Init = .upload,
    words: u64 = 0,
    key: [8]u32 = @splat(0),
    covered: u64 = 0,
};
pub const Piece = struct { buffer: u16, offset: u64, host: []const u32 };
pub const Launch = struct { op: Op, main_column: u32, main_columns: u32, body: []const u32 };

pub const Program = struct {
    a: std.mem.Allocator,
    buffers: [max_buffers]Buffer = @splat(.{}),
    pieces: std.ArrayListUnmanaged(Piece) = .empty,
    launches: std.ArrayListUnmanaged(Launch) = .empty,
    status: [max_status]Ref = @splat(0),
    status_len: usize = 0,
    columns: u32 = 0,
    rows: u64 = 0,
    data_words: u64 = 0,
    chunk_words: u64 = 0,

    pub fn deinit(self: *Program) void {
        self.pieces.deinit(self.a);
        self.launches.deinit(self.a);
    }
    /// Device words the program's arena buffers take (64-word aligned each).
    pub fn arenaWords(self: *const Program) usize {
        var n: usize = 0;
        for (self.buffers) |b| if (b.declared and b.init != .persistent) {
            n += std.mem.alignForward(usize, @intCast(b.words), 64);
        };
        return n;
    }

    /// Parse and validate a segment's chunks against the class image (column
    /// count `columns`). Every refusal happens here, before any enqueue.
    pub fn parse(a: std.mem.Allocator, chunks: []const G.TraceChunk, columns: usize) !Program {
        var p = Program{ .a = a };
        errdefer p.deinit();
        var ended = false;
        var end_launches: u32 = 0;
        var end_buffers: u32 = 0;
        for (chunks, 0..) |ch, ci| {
            const w = ch.words;
            if (ended) return error.GnPackRecordAfterEnd;
            if (w.len < chunk_header_words or w[0] != magic or w[1] != version) return error.GnPackChunkFormat;
            const used = w[3];
            if (used < chunk_header_words or used > w.len) return error.GnPackChunkFormat;
            p.chunk_words += used;
            var at: usize = chunk_header_words;
            var n: u32 = 0;
            while (at < used) {
                if (ended) return error.GnPackRecordAfterEnd;
                if (used - at < record_header_words) return error.GnPackChunkFormat;
                const len = w[at + 1];
                if (len < record_header_words or len > used - at) return error.GnPackChunkFormat;
                const body = w[at + record_header_words .. at + len];
                const tag = std.meta.intToEnum(Tag, w[at]) catch return error.GnPackChunkFormat;
                const ra = w[at + 2];
                const rb = w[at + 3];
                switch (tag) {
                    .declare => {
                        if (ra < first_buffer or ra >= max_buffers) return error.GnPackBufferId;
                        const kind = std.meta.intToEnum(Init, rb) catch return error.GnPackChunkFormat;
                        const b = &p.buffers[ra];
                        if (b.declared) return error.GnPackBufferTwice;
                        if (body.len != (if (kind == .persistent) @as(usize, 10) else 2)) return error.GnPackChunkFormat;
                        b.* = .{ .declared = true, .init = kind, .words = @as(u64, body[0]) | (@as(u64, body[1]) << 32) };
                        if (b.words == 0 or b.words > (1 << 34)) return error.GnPackBufferSize;
                        if (kind == .persistent) @memcpy(&b.key, body[2..10]);
                    },
                    .data => {
                        const b = try p.declared(ra);
                        if (b.init == .persistent or b.init == .scratch) return error.GnPackDataIntoDeviceBuffer;
                        if (body.len == 0 or rb > b.words or body.len > b.words - rb) return error.GnPackDataOutOfRange;
                        b.covered += body.len;
                        p.data_words += body.len;
                        try p.pieces.append(a, .{ .buffer = @intCast(ra), .offset = rb, .host = body });
                    },
                    .launch => {
                        const op = std.meta.intToEnum(Op, ra) catch return error.GnPackUnknownOp;
                        if (body.len != 2 + opWords(op)) return error.GnPackChunkFormat;
                        try p.launches.append(a, .{ .op = op, .main_column = body[0], .main_columns = body[1], .body = body[2..] });
                    },
                    .status => {
                        if (body.len != 2) return error.GnPackChunkFormat;
                        if (p.status_len == max_status) return error.GnPackTooManyStatusWords;
                        p.status[p.status_len] = @as(u64, body[0]) | (@as(u64, body[1]) << 32);
                        p.status_len += 1;
                    },
                    .end => {
                        if (body.len != 3 or ci + 1 != chunks.len) return error.GnPackChunkFormat;
                        end_launches = ra;
                        end_buffers = rb;
                        p.columns = body[0];
                        p.rows = @as(u64, body[1]) | (@as(u64, body[2]) << 32);
                        ended = true;
                    },
                }
                at += len;
                n += 1;
            }
            if (n != w[2]) return error.GnPackChunkFormat;
        }
        if (!ended) return error.GnPackTruncated;
        if (p.columns != columns) return error.GnPackColumnCount;
        if (end_launches != p.launches.items.len) return error.GnPackTruncated;
        var n_declared: u32 = 0;
        for (p.buffers) |b| n_declared += @intFromBool(b.declared);
        if (n_declared != end_buffers) return error.GnPackTruncated;
        try p.validate();
        return p;
    }
    fn declared(self: *Program, id: u32) !*Buffer {
        if (id < first_buffer or id >= max_buffers or !self.buffers[id].declared) return error.GnPackBufferNotDeclared;
        return &self.buffers[id];
    }
    fn checkRef(self: *Program, r: Ref, nullable: bool) !void {
        if (r == 0) {
            if (!nullable) return error.GnPackNullRef;
            return;
        }
        const id = refBuffer(r);
        if (id == image_buffer) {
            if (refOffset(r) >= self.columns) return error.GnPackRefOutOfRange;
            return;
        }
        const b = try self.declared(id);
        if (refOffset(r) >= b.words) return error.GnPackRefOutOfRange;
    }
    fn validate(self: *Program) !void {
        // Upload buffers: data tiles them exactly (no gap: stale arena words;
        // no overlap: order-dependent contents). Zero buffers: no overlap.
        const Span = struct { buffer: u16, offset: u64, words: u64 };
        const spans = try self.a.alloc(Span, self.pieces.items.len);
        defer self.a.free(spans);
        for (self.pieces.items, spans) |pc, *s| s.* = .{ .buffer = pc.buffer, .offset = pc.offset, .words = pc.host.len };
        std.mem.sort(Span, spans, {}, struct {
            fn lt(_: void, x: Span, y: Span) bool {
                return if (x.buffer != y.buffer) x.buffer < y.buffer else x.offset < y.offset;
            }
        }.lt);
        var i: usize = 0;
        while (i < spans.len) {
            const id = spans[i].buffer;
            var at: u64 = 0;
            while (i < spans.len and spans[i].buffer == id) : (i += 1) {
                if (spans[i].offset < at) return error.GnPackDataOverlap;
                if (self.buffers[id].init == .upload and spans[i].offset != at) return error.GnPackDataGap;
                at = spans[i].offset + spans[i].words;
            }
            if (self.buffers[id].init == .upload and at != self.buffers[id].words) return error.GnPackDataGap;
        }
        for (self.buffers, 0..) |b, id| if (b.declared and b.init == .upload and b.covered == 0 and b.words != 0) {
            // A declared upload buffer with no data at all (gap over its words).
            _ = id;
            return error.GnPackDataGap;
        };
        // Launch refs and MAIN coverage (every image column written by exactly one launch).
        const cover = try self.a.alloc(u8, self.columns);
        defer self.a.free(cover);
        @memset(cover, 0);
        for (self.launches.items) |l| {
            switch (l.op) {
                inline else => |op| {
                    const T = op.Type();
                    const job = std.mem.bytesToValue(T, std.mem.sliceAsBytes(l.body));
                    inline for (T.refs) |name| try self.checkRef(@field(job, name), nullableRef(op, name));
                    if (op == .copy) {
                        const words = job.words;
                        inline for (.{ "dst", "src" }) |name| {
                            const r: Ref = @field(job, name);
                            if (refBuffer(r) == image_buffer) return error.GnPackCopyIntoImage;
                            if (words == 0 or words > self.buffers[refBuffer(r)].words - refOffset(r)) return error.GnPackRefOutOfRange;
                        }
                    }
                    if (@hasField(T, "main")) {
                        const m: Ref = job.main;
                        if (refBuffer(m) == image_buffer) {
                            if (refOffset(m) != l.main_column) return error.GnPackMainSpan;
                        } else if (l.main_columns != 0) return error.GnPackMainSpan;
                    } else if (l.main_columns != 0) return error.GnPackMainSpan;
                },
            }
            if (l.main_columns != 0) {
                if (l.main_column > self.columns or l.main_columns > self.columns - l.main_column) return error.GnPackMainSpan;
                for (cover[l.main_column..][0..l.main_columns]) |*c| {
                    if (c.* != 0) return error.GnPackMainOverlap;
                    c.* = 1;
                }
            }
        }
        for (cover) |c| if (c == 0) return error.GnPackMainCoverage;
        for (self.status[0..self.status_len]) |s| {
            try self.checkRef(s, false);
            if (refBuffer(s) == image_buffer) return error.GnPackStatusInImage;
        }
        if (self.status_len == 0) return error.GnPackNoStatus;
    }
};

/// Refs the legacy orchestration passes as null when the input is empty.
fn nullableRef(comptime op: Op, comptime name: []const u8) bool {
    return switch (op) {
        .family => std.mem.eql(u8, name, "facts"),
        .memory => std.mem.eql(u8, name, "events"),
        .arithmetic => std.mem.eql(u8, name, "requests") or std.mem.eql(u8, name, "mul_support"),
        .bridge => std.mem.eql(u8, name, "inputs"),
        .cpu_witness => std.mem.eql(u8, name, "metadata") or std.mem.eql(u8, name, "pair_counts"),
        .boundary => std.mem.eql(u8, name, "cells"),
        .table => std.mem.eql(u8, name, "pairs"),
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Device side
// ---------------------------------------------------------------------------

pub const KernelFn = *const fn (*anyopaque, u32, *const anyopaque) callconv(.c) c_int;
const BoundaryFn = *const fn (*anyopaque, u32, ?[*]const u32, u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
const TableFn = *const fn (*anyopaque, u32, [*]const u32, ?[*]const u32, u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
const AnalyzeFn = *const fn (*anyopaque, u32, [*]const u32, u32, [*]const u32, u32, [*]u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
const OutputsFn = *const fn (*anyopaque, u32, [*]const u32, [*]u32, u32, [*]u32) callconv(.c) c_int;
pub const MemsetFn = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
pub const D2dFn = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
/// stwo_rv64_jobs_copy_async(dst, src, bytes, kind 1 = h2d, stream) (jobs addon).
pub const H2dFn = *const fn (*anyopaque, *const anyopaque, usize, u32, *anyopaque) callconv(.c) c_int;

pub const Symbols = struct {
    family: KernelFn,
    memory: KernelFn,
    arithmetic: KernelFn,
    bridge: KernelFn,
    bulk: KernelFn,
    sponge: KernelFn,
    cpu_unpack: KernelFn,
    cpu_witness: KernelFn,
    boundary: BoundaryFn,
    table: TableFn,
    bulk_analyze: AnalyzeFn,
    sponge_outputs: OutputsFn,
    memset: MemsetFn,
    d2d: D2dFn,
    h2d: H2dFn,
    pub fn load(base: *std.DynLib, addon: *std.DynLib) !Symbols {
        return .{
            .family = try lookup(KernelFn, base, FamilyJob.symbol),
            .memory = try lookup(KernelFn, base, MemoryJob.symbol),
            .arithmetic = try lookup(KernelFn, base, ArithmeticJob.symbol),
            .bridge = try lookup(KernelFn, base, BridgeJob.symbol),
            .bulk = try lookup(KernelFn, base, BulkJob.symbol),
            .sponge = try lookup(KernelFn, base, SpongeJob.symbol),
            .cpu_unpack = try lookup(KernelFn, base, CpuUnpack.symbol),
            .cpu_witness = try lookup(KernelFn, base, CpuWitness.symbol),
            .boundary = try lookup(BoundaryFn, base, "stwo_rv64_boundary_witness_on"),
            .table = try lookup(TableFn, base, "stwo_rv64_multiplicity_witness_on"),
            .bulk_analyze = try lookup(AnalyzeFn, base, "stwo_rv64_bulk_analyze_on"),
            .sponge_outputs = try lookup(OutputsFn, base, "stwo_rv64_sponge_outputs_on"),
            .memset = try lookup(MemsetFn, base, "stwo_exec_context_memset_async"),
            .d2d = try lookup(D2dFn, base, "stwo_exec_context_memcpy_d2d_async"),
            .h2d = try lookup(H2dFn, addon, "stwo_rv64_jobs_copy_async"),
        };
    }
    fn lookup(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
        return lib.lookup(T, name) orelse error.MissingGnPackKernel;
    }
};

/// Host words of persistent buffers (the program ROM), by key; filled by the
/// capture-side serializer (install/warm or the first request of a program).
pub const Roms = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    map: std.AutoHashMapUnmanaged([8]u32, []const u32) = .empty,
    pub fn init(a: std.mem.Allocator) Roms {
        return .{ .a = a };
    }
    pub fn deinit(self: *Roms) void {
        var it = self.map.valueIterator();
        while (it.next()) |v| self.a.free(v.*);
        self.map.deinit(self.a);
    }
    /// Takes ownership of `words` (freed now if the key is already held).
    pub fn put(self: *Roms, key: [8]u32, words: []const u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = try self.map.getOrPut(self.a, key);
        if (gop.found_existing) {
            if (!std.mem.eql(u32, gop.value_ptr.*, words)) {
                self.a.free(words);
                return error.GnPackRomKeyMismatch;
            }
            self.a.free(words);
        } else gop.value_ptr.* = words;
    }
    pub fn has(self: *Roms, key: [8]u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.contains(key);
    }
    pub fn get(self: *Roms, key: [8]u32) ?[]const u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.get(key);
    }
};

pub fn persistentKey(key: [8]u32) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gn-pack-persistent-v1");
    h.update(std.mem.sliceAsBytes(&key));
    return h.finalResult();
}

fn cuda(status: c_int) !void {
    if (status != 0) return error.CudaEnqueueFailed;
}

/// Device buffers of one program run (stage: allocated; enqueue: filled).
pub const Bound = struct {
    devices: [max_buffers]?api.DeviceBuffer = @splat(null),
    /// Persistent regions this job filled (fresh) and must not re-fill.
    fresh: [max_buffers]bool = @splat(false),

    /// Phase 1 (Stager): arena buffers + persistent regions (ROM filled once
    /// per GPU from `roms`; a missing host copy fails closed).
    pub fn stage(self: *Bound, p: *const Program, s: *api.Stager, roms: ?*Roms) !void {
        for (p.buffers, 0..) |b, id| {
            if (!b.declared) continue;
            const words: usize = @intCast(b.words);
            if (b.init == .persistent) {
                const r = try s.persistent(persistentKey(b.key), words);
                if (r.fresh) {
                    const host = (roms orelse return error.GnPackRomNotHeld).get(b.key) orelse return error.GnPackRomNotHeld;
                    if (host.len != words) return error.GnPackRomShape;
                    try s.upload(r.buffer, host);
                }
                self.devices[id] = r.buffer;
                self.fresh[id] = r.fresh;
            } else self.devices[id] = try s.alloc(words);
        }
    }

    fn resolve(self: *const Bound, image: [*]u32, offsets: []const usize, r: Ref) u64 {
        if (r == 0) return 0;
        const id = refBuffer(r);
        const off = refOffset(r);
        if (id == image_buffer) return @intFromPtr(image + offsets[@intCast(off)]);
        return @intFromPtr(self.devices[id].?.ptr + @as(usize, @intCast(off)));
    }

    /// Phase 2, on `e`'s exec stream (lane 0): zero buffers, h2d of every
    /// data record from the pinned ring, then the launches in order. `image`
    /// is the MAIN evaluation image (class `image_offsets`, original order).
    pub fn enqueue(self: *const Bound, p: *const Program, sym: *const Symbols, e: *api.Enqueue, image: api.DeviceBuffer, offsets: []const usize) !void {
        const ectx = e.ctx();
        const stream = e.stream();
        if (offsets.len != p.columns) return error.GnPackColumnCount;
        for (p.buffers, 0..) |b, id| if (b.declared and b.init == .zero) {
            const d = self.devices[id] orelse return error.GnPackNotStaged;
            try cuda(sym.memset(ectx, @ptrCast(d.ptr), 0, d.words * 4));
        };
        for (p.pieces.items) |pc| {
            const d = self.devices[pc.buffer] orelse return error.GnPackNotStaged;
            const dst = try d.slice(@intCast(pc.offset), pc.host.len);
            try cuda(sym.h2d(@ptrCast(dst.ptr), @ptrCast(pc.host.ptr), pc.host.len * 4, 1, stream));
        }
        for (p.launches.items) |l| switch (l.op) {
            inline else => |op| {
                const T = op.Type();
                var job = std.mem.bytesToValue(T, std.mem.sliceAsBytes(l.body));
                inline for (T.refs) |name| @field(job, name) = self.resolve(image.ptr, offsets, @field(job, name));
                try self.call(op, sym, ectx, &job);
            },
        };
    }
    fn ptr(comptime P: type, v: u64) P {
        return @ptrFromInt(v);
    }
    fn optPtr(comptime P: type, v: u64) ?P {
        return if (v == 0) null else @ptrFromInt(v);
    }
    fn call(_: *const Bound, comptime op: Op, sym: *const Symbols, ectx: *anyopaque, job: *const op.Type()) !void {
        switch (op) {
            .family => try cuda(sym.family(ectx, 0, job)),
            .memory => try cuda(sym.memory(ectx, 0, job)),
            .arithmetic => try cuda(sym.arithmetic(ectx, 0, job)),
            .bridge => try cuda(sym.bridge(ectx, 0, job)),
            .bulk => try cuda(sym.bulk(ectx, 0, job)),
            .sponge => try cuda(sym.sponge(ectx, 0, job)),
            .cpu_unpack => try cuda(sym.cpu_unpack(ectx, 0, job)),
            .cpu_witness => try cuda(sym.cpu_witness(ectx, 0, job)),
            .boundary => try cuda(sym.boundary(ectx, 0, optPtr([*]const u32, job.cells), job.count, job.log, ptr([*]u32, job.main), ptr([*]u32, job.status))),
            .table => try cuda(sym.table(ectx, 0, ptr([*]const u32, job.counts), optPtr([*]const u32, job.pairs), job.log, job.kind, ptr([*]u32, job.main), ptr([*]u32, job.status))),
            .bulk_analyze => try cuda(sym.bulk_analyze(ectx, 0, ptr([*]const u32, job.calls), job.call_count, ptr([*]const u32, job.words), job.word_count, ptr([*]u32, job.pending), job.pending_count, ptr([*]u32, job.jumps), ptr([*]u32, job.status))),
            .sponge_outputs => try cuda(sym.sponge_outputs(ectx, 0, ptr([*]const u32, job.inputs), ptr([*]u32, job.outputs), job.count, ptr([*]u32, job.status))),
            .copy => try cuda(sym.d2d(ectx, ptr(*anyopaque, job.dst), ptr(*const anyopaque, job.src), @intCast(job.words * 4))),
        }
    }
    /// The program's status words (device), for the witness_status check.
    pub fn statusWords(self: *const Bound, p: *const Program, out: *[max_status]api.DeviceBuffer) ![]const api.DeviceBuffer {
        for (p.status[0..p.status_len], 0..) |s, i| {
            const d = self.devices[refBuffer(s)] orelse return error.GnPackNotStaged;
            out[i] = try d.slice(@intCast(refOffset(s)), 1);
        }
        return out[0..p.status_len];
    }
};

test {
    _ = @import("native_pack_test.zig");
}
