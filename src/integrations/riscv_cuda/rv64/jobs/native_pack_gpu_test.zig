//! gn-pack piece-only GPU harness on REAL recorded segments (opt-in):
//!   STWO_RV64_M8_GPU_BASE / STWO_RV64_M8_JOBS_LIBRARY (native_gpu_support_test.zig)
//!   STWO_RV64_M8_GN_PACK_RECORDS=<dir>[:<dir>...]  recorder output (rv64/gn_pack_record.zig)
//! Per recorded segment: the v2 chunk stream is copied into pinned buffers (the
//! capture ring's role), parsed, and run as ONE worker job: zero/h2d/launch
//! program into an arena MAIN image, CUDA events around it [M]; the image is
//! read back (test only) and every MAIN column's SHA-256 must equal the
//! legacy column's (byte identity), and every program status word must be 0.
//! Negatives on the first segment of each dir: a corrupted ALU fact fires
//! the ledger status word (witness_status would reject), a corrupted CPU
//! record fires the CPU status word, and a dropped chunk / a launch removed
//! from the program are refused at parse (nothing enqueued).
const std = @import("std");
const api = @import("api.zig");
const W = @import("worker.zig");
const G = @import("gpu_native.zig");
const P = @import("native_pack.zig");

const EventApi = struct {
    create: *const fn (*?*anyopaque, u32) callconv(.c) c_int,
    record: *const fn (*anyopaque, *anyopaque) callconv(.c) c_int,
    elapsed: *const fn (*f32, *anyopaque, *anyopaque) callconv(.c) c_int,
    destroy: *const fn (*anyopaque) callconv(.c) c_int,
    fn load(lib: *std.DynLib) !EventApi {
        return .{
            .create = lib.lookup(@FieldType(EventApi, "create"), "stwo_rv64_event_create") orelse return error.MissingCudaTimingSymbol,
            .record = lib.lookup(@FieldType(EventApi, "record"), "stwo_rv64_event_record") orelse return error.MissingCudaTimingSymbol,
            .elapsed = lib.lookup(@FieldType(EventApi, "elapsed"), "stwo_rv64_event_elapsed") orelse return error.MissingCudaTimingSymbol,
            .destroy = lib.lookup(@FieldType(EventApi, "destroy"), "stwo_rv64_event_destroy") orelse return error.MissingCudaTimingSymbol,
        };
    }
};

const Segment = struct {
    ordinal: u32,
    logs: []u32,
    offsets: []usize,
    image_words: usize,
    rows: u64,
    pack_ns: u64,
    compact_ns: u64,
    chunks: []G.TraceChunk,
    pinned: [][]u32,
    sha: [][32]u8,
};

const Probe = struct {
    p: *const P.Program,
    sym: *const P.Symbols,
    roms: *P.Roms,
    seg: *const Segment,
    events: *const EventApi,
    host_image: []u32,
    copy: P.H2dFn,
    bound: P.Bound = .{},
    ev: [2]?*anyopaque = .{ null, null },
    status: [P.max_status]u32 = @splat(0xffffffff),
    gpu_ms: f32 = -1,
    stage_ns: u64 = 0,
    enqueue_ns: u64 = 0,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(0x6b);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        const img = std.mem.alignForward(usize, self.seg.image_words, 64);
        return .{ .device_words = img + self.p.arenaWords() + 4096, .staged_words = self.p.arenaWords(), .slab_words = 64, .pinned_words = 1 << 12 };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        var t = try std.time.Timer.start();
        try self.bound.stage(self.p, s, self.roms);
        for (&self.ev) |*e| if (self.events.create(e, 0) != 0 or e.* == null) return error.CudaTimingFailed;
        self.stage_ns = t.read();
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        var t = try std.time.Timer.start();
        const stream = e.stream();
        if (self.events.record(self.ev[0].?, stream) != 0) return error.CudaTimingFailed;
        const img = try e.alloc(self.seg.image_words);
        if (self.sym.memset(e.ctx(), @ptrCast(img.ptr), 0, img.words * 4) != 0) return error.CudaEnqueueFailed;
        try self.bound.enqueue(self.p, self.sym, e, img, self.seg.offsets);
        if (self.events.record(self.ev[1].?, stream) != 0) return error.CudaTimingFailed;
        var sbuf: [P.max_status]api.DeviceBuffer = undefined;
        for (try self.bound.statusWords(self.p, &sbuf), 0..) |st, i| {
            if (self.sym.d2d(e.ctx(), @ptrCast(e.slab.device.ptr + i), @ptrCast(st.ptr), 4) != 0) return error.CudaEnqueueFailed;
        }
        self.enqueue_ns = t.read();
        // test-only readback of the whole image (pinned host)
        if (self.copy(@ptrCast(self.host_image.ptr), @ptrCast(img.ptr), img.words * 4, 2, stream) != 0) return error.CudaEnqueueFailed;
        e.free(img);
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        for (0..self.p.status_len) |i| self.status[i] = v.words[i];
        var ms: f32 = -1;
        if (self.events.elapsed(&ms, self.ev[0].?, self.ev[1].?) == 0) self.gpu_ms = ms;
        for (self.ev) |e| if (e) |x| {
            _ = self.events.destroy(x);
        };
    }
    pub fn abort(self: *Probe) void {
        for (self.ev) |e| if (e) |x| {
            _ = self.events.destroy(x);
        };
    }
};

const Done = struct {
    n: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.n.fetchAdd(1, .seq_cst);
    }
};
fn run(w: *W.Worker, probe: *Probe) !void {
    var done: Done = .{};
    try w.submit(api.Job.from(Probe, probe), .{ .ctx = &done, .done = Done.onDone });
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    if (done.err) |err| return err;
}

fn readU64(lo: u32, hi: u32) u64 {
    return @as(u64, lo) | (@as(u64, hi) << 32);
}

fn loadSegment(a: std.mem.Allocator, libs: anytype, dir: std.fs.Dir, ordinal: u32) !?Segment {
    var name_buf: [64]u8 = undefined;
    const bytes = dir.readFileAlloc(a, try std.fmt.bufPrint(&name_buf, "seg-{}.gnp", .{ordinal}), 1 << 34) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer a.free(bytes);
    const words: []const u32 = @alignCast(std.mem.bytesAsSlice(u32, bytes));
    if (words[0] != P.record_file_magic or words[1] != 1 or words[2] != ordinal) return error.BadRecording;
    const n_chunks = words[3];
    const columns = words[4];
    const logs = try a.dupe(u32, words[16..][0..columns]);
    const offsets = try a.alloc(usize, columns);
    var image: usize = 0;
    for (logs, offsets) |l, *o| {
        o.* = image;
        image += @as(usize, 1) << @intCast(l);
    }
    const chunks = try a.alloc(G.TraceChunk, n_chunks);
    const pinned = try a.alloc([]u32, n_chunks);
    var at: usize = 16 + columns;
    var first_row: u64 = 0;
    for (chunks, pinned, 0..) |*c, *pb, i| {
        const used = words[at];
        const rows = words[at + 1];
        const last = words[at + 2] != 0;
        at += 3;
        var host: ?*anyopaque = null;
        if (libs.ops.wait.host_alloc(@max(used, 1) * 4, &host) != 0 or host == null) return error.PinnedAllocationFailed;
        pb.* = @as([*]u32, @ptrCast(@alignCast(host.?)))[0..used];
        @memcpy(pb.*, words[at..][0..used]);
        at += used;
        c.* = .{ .segment = ordinal, .sequence = @intCast(i), .first_row = first_row, .rows = rows, .last = last, .words = pb.* };
        first_row += rows;
    }
    const sha_bytes = try dir.readFileAlloc(a, try std.fmt.bufPrint(&name_buf, "seg-{}.main.sha", .{ordinal}), 1 << 24);
    defer a.free(sha_bytes);
    if (sha_bytes.len != columns * 36) return error.BadRecording;
    const sha = try a.alloc([32]u8, columns);
    for (sha, 0..) |*s, i| {
        if (std.mem.readInt(u32, sha_bytes[i * 36 ..][0..4], .little) != logs[i]) return error.BadRecordingLogs;
        @memcpy(s, sha_bytes[i * 36 + 4 ..][0..32]);
    }
    return .{ .ordinal = ordinal, .logs = logs, .offsets = offsets, .image_words = image, .rows = readU64(words[5], words[6]), .pack_ns = readU64(words[7], words[8]), .compact_ns = readU64(words[9], words[10]), .chunks = chunks, .pinned = pinned, .sha = sha };
}

fn loadRoms(a: std.mem.Allocator, dir: std.fs.Dir, roms: *P.Roms) !void {
    var it = dir.iterate();
    while (try it.next()) |e| if (std.mem.startsWith(u8, e.name, "rom-")) {
        const bytes = try dir.readFileAlloc(a, e.name, 1 << 30);
        defer a.free(bytes);
        const words: []const u32 = @alignCast(std.mem.bytesAsSlice(u32, bytes));
        var key: [8]u32 = undefined;
        @memcpy(&key, words[0..8]);
        if (!roms.has(key)) try roms.put(key, try roms.a.dupe(u32, words[8..]));
    };
}

/// First data word of the buffer a given op's ref field points at.
fn firstDataWord(p: *const P.Program, comptime op: P.Op, comptime field: []const u8, offset_words: usize) ?*u32 {
    for (p.launches.items) |l| if (l.op == op) {
        const job = std.mem.bytesToValue(op.Type(), std.mem.sliceAsBytes(l.body));
        const r: u64 = @field(job, field);
        if (r == 0) continue;
        if (@hasField(op.Type(), "count")) if (job.count == 0) continue;
        const id: u16 = @intCast(r >> 48);
        const off = (r & ((@as(u64, 1) << 48) - 1)) + offset_words;
        for (p.pieces.items) |pc| if (pc.buffer == id and pc.offset <= off and off < pc.offset + pc.host.len) {
            return @constCast(&pc.host[@intCast(off - pc.offset)]);
        };
    };
    return null;
}

test "GPU: gn-pack v2 witness program on recorded real segments is byte-identical to the legacy MAIN; negatives fail closed" {
    const dirs = std.posix.getenv("STWO_RV64_M8_GN_PACK_RECORDS") orelse return error.SkipZigTest;
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("native_pack_gpu_test")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.heap.page_allocator;
    const sym = try P.Symbols.load(&gpu.libs.base, &gpu.libs.addon);
    const events = try EventApi.load(&gpu.libs.base);
    const copy = gpu.libs.addon.lookup(P.H2dFn, "stwo_rv64_jobs_copy_async") orelse return error.MissingSymbol;
    var it = std.mem.splitScalar(u8, dirs, ':');
    var total_columns: usize = 0;
    var total_equal: usize = 0;
    while (it.next()) |path| {
        var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
        defer dir.close();
        var roms = P.Roms.init(a);
        defer roms.deinit();
        try loadRoms(a, dir, &roms);
        var segs: std.ArrayListUnmanaged(Segment) = .empty;
        var ordinal: u32 = 0;
        while (try loadSegment(a, &gpu.libs, dir, ordinal)) |s| : (ordinal += 1) try segs.append(a, s);
        if (segs.items.len == 0) return error.NoRecordedSegments;
        var max_words: usize = 0;
        var programs = try a.alloc(P.Program, segs.items.len);
        for (segs.items, programs) |*s, *p| {
            var t = try std.time.Timer.start();
            p.* = try P.Program.parse(a, s.chunks, s.logs.len);
            const parse_ns = t.read();
            max_words = @max(max_words, std.mem.alignForward(usize, s.image_words, 64) + p.arenaWords() + (1 << 16));
            std.debug.print("GN_PACK_PROGRAM dir={s} seg={} chunks={} chunk_bytes={} data_bytes={} launches={} arena_bytes={} image_bytes={} parse_ns={} capture_pack_ns={} capture_compact_ns={}\n", .{ path, s.ordinal, s.chunks.len, p.chunk_words * 4, p.data_words * 4, p.launches.items.len, p.arenaWords() * 4, s.image_words * 4, parse_ns, s.pack_ns, s.compact_ns });
        }
        const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 2 * max_words + (1 << 24), .pinned_slot_words = 1 << 16, .max_outstanding = 2 });
        defer w.destroy();
        var max_image: usize = 0;
        for (segs.items) |s| max_image = @max(max_image, s.image_words);
        var hp: ?*anyopaque = null;
        if (gpu.libs.ops.wait.host_alloc(max_image * 4, &hp) != 0 or hp == null) return error.PinnedAllocationFailed;
        defer _ = gpu.libs.ops.wait.host_free(hp.?);
        const host_image = @as([*]u32, @ptrCast(@alignCast(hp.?)))[0..max_image];
        for (segs.items, programs) |*s, *p| {
            // warm + timed run (the first run fills the persistent ROM region)
            var gpu_ms: [2]f32 = undefined;
            var probe: Probe = undefined;
            for (0..2) |rep| {
                probe = .{ .p = p, .sym = &sym, .roms = &roms, .seg = s, .events = &events, .host_image = host_image[0..s.image_words], .copy = copy };
                try run(w, &probe);
                gpu_ms[rep] = probe.gpu_ms;
            }
            var equal: usize = 0;
            var first_bad: ?usize = null;
            for (s.logs, s.offsets, s.sha, 0..) |l, off, want, ci| {
                var d: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(host_image[off..][0 .. @as(usize, 1) << @intCast(l)]), &d, .{});
                if (std.mem.eql(u8, &d, &want)) equal += 1 else if (first_bad == null) {
                    first_bad = ci;
                }
            }
            var status_ok = true;
            for (probe.status[0..p.status_len]) |x| status_ok = status_ok and x == 0;
            std.debug.print("GN_PACK_PARITY dir={s} seg={} columns={} equal={} first_mismatch={?} status_ok={} status={any} gpu_ms_cold={d:.3} gpu_ms={d:.3} host_stage_ns={} host_enqueue_ns={} h2d_bytes={}\n", .{ path, s.ordinal, s.logs.len, equal, first_bad, status_ok, probe.status[0..p.status_len], gpu_ms[0], gpu_ms[1], probe.stage_ns, probe.enqueue_ns, p.data_words * 4 });
            total_columns += s.logs.len;
            total_equal += equal;
            try std.testing.expect(status_ok);
        }
        // Negatives on segment 0.
        {
            const s = &segs.items[0];
            const p = &programs[0];
            // (1) ALU fact result corrupted -> ledger status nonzero.
            if (firstDataWord(p, .family, "facts", 6)) |word| {
                word.* ^= 1;
                var probe = Probe{ .p = p, .sym = &sym, .roms = &roms, .seg = s, .events = &events, .host_image = host_image[0..s.image_words], .copy = copy };
                try run(w, &probe);
                word.* ^= 1;
                var fired = false;
                for (probe.status[0..p.status_len]) |x| fired = fired or x != 0;
                std.debug.print("GN_PACK_NEGATIVE kind=family_fact status={any} fired={}\n", .{ probe.status[0..p.status_len], fired });
                try std.testing.expect(fired);
            } else return error.NoFamilyFactToCorrupt;
            // (2) CPU compact record: rom_row past the program -> CPU status nonzero.
            if (firstDataWord(p, .cpu_unpack, "records", 2)) |word| {
                const saved = word.*;
                word.* = 0x7fffffff;
                var probe = Probe{ .p = p, .sym = &sym, .roms = &roms, .seg = s, .events = &events, .host_image = host_image[0..s.image_words], .copy = copy };
                try run(w, &probe);
                word.* = saved;
                var fired = false;
                for (probe.status[0..p.status_len]) |x| fired = fired or x != 0;
                std.debug.print("GN_PACK_NEGATIVE kind=cpu_record status={any} fired={}\n", .{ probe.status[0..p.status_len], fired });
                try std.testing.expect(fired);
            } else return error.NoCpuRecordToCorrupt;
            // (3) a dropped chunk / (4) a dropped launch: refused at parse.
            if (s.chunks.len > 1) {
                const fewer = try a.dupe(G.TraceChunk, s.chunks);
                std.mem.copyForwards(G.TraceChunk, fewer[0 .. fewer.len - 1], fewer[1..]);
                const r = P.Program.parse(a, fewer[0 .. fewer.len - 1], s.logs.len);
                std.debug.print("GN_PACK_NEGATIVE kind=dropped_chunk refused={}\n", .{std.meta.isError(r)});
                try std.testing.expect(std.meta.isError(r));
            }
            const last = s.chunks[s.chunks.len - 1].words;
            var at: usize = P.chunk_header_words;
            const words = @constCast(last);
            while (at < words[3]) : (at += words[at + 1]) if (words[at] == @intFromEnum(P.Tag.launch) and words[at + 2] == @intFromEnum(P.Op.table)) {
                words[at] = @intFromEnum(P.Tag.status) + 100;
                const r = P.Program.parse(a, s.chunks, s.logs.len);
                words[at] = @intFromEnum(P.Tag.launch);
                std.debug.print("GN_PACK_NEGATIVE kind=corrupt_record refused={}\n", .{std.meta.isError(r)});
                try std.testing.expect(std.meta.isError(r));
                break;
            };
        }
        for (programs) |*p| p.deinit();
        for (segs.items) |s| for (s.pinned) |pb| {
            _ = gpu.libs.ops.wait.host_free(pb.ptr);
        };
    }
    std.debug.print("GN_PACK_PARITY_TOTAL columns={} equal={}\n", .{ total_columns, total_equal });
    try std.testing.expectEqual(total_columns, total_equal);
}
