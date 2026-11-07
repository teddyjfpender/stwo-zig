//! gn-pack recorder on the LEGACY resident source (env-gated, default off):
//! STWO_RV64_M8_GN_PACK_RECORD=<dir> makes device_source.zig, per native
//! segment of the first request a process sees,
//!   1. run the v2 serializer (native_pack_capture.pack) on the SAME source
//!      request the legacy builds from (read-only, before the legacy consumes
//!      it) into in-memory 4 MiB chunks -> <dir>/seg-<n>.gnp (+ rom-<key>.bin);
//!   2. after the legacy device MAIN is complete, download every MAIN column
//!      and write its SHA-256 -> <dir>/seg-<n>.main.sha (and, with
//!      STWO_RV64_M8_GN_PACK_RECORD_MAIN=1, the raw words -> seg-<n>.main).
//! The piece-only GPU harness (jobs/native_pack_gpu_test.zig) replays seg-<n>.gnp
//! through the Stage-1 witness program and compares MAIN column by column.
//! Recording never changes the legacy result (it reads inputs and outputs).
//!
//! File seg-<n>.gnp (u32 LE): ["GNPF", 1, ordinal, chunks, columns, rows lo,
//! rows hi, pack_ns lo, pack_ns hi, compact_ns lo, compact_ns hi, reserved x5]
//! ++ logs[columns] ++ per chunk: [words, rows, last] ++ words.
//! File seg-<n>.main.sha: per column [log] ++ sha256 (8 words).
const std = @import("std");
const G = @import("jobs/gpu_native.zig");
const P = @import("jobs/native_pack.zig");
const PC = @import("jobs/native_pack_capture.zig");

pub const file_magic = P.record_file_magic;
pub const chunk_words: usize = 1 << 20; // 4 MiB, the driver ring buffer size

var mutex: std.Thread.Mutex = .{};
var roms_state: ?P.Roms = null;

pub fn directory() ?[]const u8 {
    return std.posix.getenv("STWO_RV64_M8_GN_PACK_RECORD");
}

const Mem = struct {
    a: std.mem.Allocator,
    chunks: std.ArrayListUnmanaged(Chunk) = .empty,
    current: ?[]u32 = null,
    const Chunk = struct { words: []u32, used: usize, rows: u32, last: bool };
    fn buffer(raw: *anyopaque) anyerror![]u32 {
        const self: *Mem = @ptrCast(@alignCast(raw));
        if (self.current != null) return error.GnPackRecordBufferTwice;
        self.current = try self.a.alloc(u32, chunk_words);
        return self.current.?;
    }
    fn emit(raw: *anyopaque, words: usize, rows: u32, last: bool) anyerror!void {
        const self: *Mem = @ptrCast(@alignCast(raw));
        const b = self.current orelse return error.GnPackRecordNoBuffer;
        self.current = null;
        try self.chunks.append(self.a, .{ .words = b, .used = words, .rows = rows, .last = last });
    }
    fn writer(self: *Mem) G.ChunkWriter {
        return .{ .ctx = self, .buffer = buffer, .emit = emit };
    }
    fn deinit(self: *Mem) void {
        for (self.chunks.items) |c| self.a.free(c.words);
        self.chunks.deinit(self.a);
        if (self.current) |b| self.a.free(b);
    }
};

pub const Recording = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    ordinal: usize,
    logs: []u32,
};

/// Before the legacy source build (the request is still unconsumed).
/// Null: recording off, or this segment was already recorded.
pub fn begin(a: std.mem.Allocator, req: PC.Stage.Request) ?*Recording {
    const path = directory() orelse return null;
    return beginIn(a, path, req) catch |err| {
        std.debug.print("GN_PACK_RECORD ordinal={} error={s}\n", .{ req.ordinal, @errorName(err) });
        return null;
    };
}

fn beginIn(a: std.mem.Allocator, path: []const u8, req: PC.Stage.Request) !?*Recording {
    mutex.lock();
    defer mutex.unlock();
    std.fs.cwd().makePath(path) catch {};
    var dir = try std.fs.cwd().openDir(path, .{});
    errdefer dir.close();
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "seg-{}.gnp", .{req.ordinal});
    if (dir.access(name, .{})) |_| {
        dir.close();
        return null;
    } else |_| {}
    if (roms_state == null) roms_state = P.Roms.init(std.heap.page_allocator);
    var mem = Mem{ .a = a };
    defer mem.deinit();
    const stats = try PC.pack(a, req, &roms_state.?, mem.writer(), null);
    const logs = try req.setup.logs(a, 1);
    errdefer a.free(logs);
    var file = try dir.createFile(name, .{});
    defer file.close();
    var header: [16]u32 = @splat(0);
    header[0] = file_magic;
    header[1] = 1;
    header[2] = @intCast(req.ordinal);
    header[3] = @intCast(mem.chunks.items.len);
    header[4] = @intCast(logs.len);
    header[5] = @truncate(stats.rows);
    header[6] = @truncate(stats.rows >> 32);
    header[7] = @truncate(stats.pack_ns);
    header[8] = @truncate(stats.pack_ns >> 32);
    header[9] = @truncate(stats.compact_ns);
    header[10] = @truncate(stats.compact_ns >> 32);
    try file.writeAll(std.mem.sliceAsBytes(&header));
    try file.writeAll(std.mem.sliceAsBytes(logs));
    for (mem.chunks.items) |c| {
        const h = [3]u32{ @intCast(c.used), c.rows, @intFromBool(c.last) };
        try file.writeAll(std.mem.sliceAsBytes(&h));
        try file.writeAll(std.mem.sliceAsBytes(c.words[0..c.used]));
    }
    // ROM once per key.
    const key = PC.romKey(&req.setup.materials.program);
    var rom_name: [96]u8 = undefined;
    const rn = try std.fmt.bufPrint(&rom_name, "rom-{x}.bin", .{std.mem.sliceAsBytes(&key)});
    if (dir.access(rn, .{})) |_| {} else |_| {
        const words = roms_state.?.get(key) orelse return error.GnPackRomNotHeld;
        var rf = try dir.createFile(rn, .{});
        defer rf.close();
        try rf.writeAll(std.mem.sliceAsBytes(&key));
        try rf.writeAll(std.mem.sliceAsBytes(words));
    }
    std.debug.print("GN_PACK_RECORD ordinal={} chunks={} chunk_bytes={} data_bytes={} launches={} buffers={} arena_bytes={} cpu_records={} pack_ns={} compact_ns={} rom_ns={} columns={}\n", .{ req.ordinal, stats.chunks, stats.chunk_words * 4, stats.data_words * 4, stats.launches, stats.buffers, stats.arena_words * 4, stats.cpu_records, stats.pack_ns, stats.compact_ns, stats.rom_ns, logs.len });
    const r = try a.create(Recording);
    r.* = .{ .a = a, .dir = dir, .ordinal = req.ordinal, .logs = logs };
    return r;
}

/// The legacy service context (pcs_native.zig Context: session, submit, library).
/// `columns`: the completed device MAIN (D.TraceColumn, evaluations).
pub fn finish(r: *Recording, service: anytype, columns: anytype) void {
    finishIn(r, service, columns) catch |err| std.debug.print("GN_PACK_RECORD ordinal={} main_error={s}\n", .{ r.ordinal, @errorName(err) });
    r.a.free(r.logs);
    r.dir.close();
    r.a.destroy(r);
}

fn finishIn(r: *Recording, service: anytype, columns: anytype) !void {
    const Download = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
    const Sync = *const fn (*anyopaque) callconv(.c) c_int;
    if (columns.len != r.logs.len) return error.GnPackRecordColumns;
    var total: usize = 0;
    for (columns, r.logs) |c, l| {
        if (c.log_size != l or c.encoding != .evaluations or c.device == null) return error.GnPackRecordColumnShape;
        total += @as(usize, 1) << @intCast(l);
    }
    const host = try r.a.alloc(u32, total);
    defer r.a.free(host);
    const Job = struct {
        host: []u32,
        cols: @TypeOf(columns),
        download: Download,
        sync: Sync,
        failed: bool = false,
        fn run(ctx: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(data.?));
            var at: usize = 0;
            for (self.cols) |c| {
                const n = c.device.?.count;
                if (self.download(ctx, @ptrCast(self.host[at..].ptr), @ptrCast(c.device.?.words), n * 4) != 0) return 1;
                at += n;
            }
            return self.sync(ctx);
        }
    };
    var job = Job{ .host = host, .cols = columns, .download = service.library.lookup(Download, "stwo_exec_context_memcpy_d2h_async") orelse return error.MissingSymbol, .sync = service.library.lookup(Sync, "stwo_exec_context_sync") orelse return error.MissingSymbol };
    if (service.submit(service.session, Job.run, &job) != 0) return error.GnPackRecordDownload;
    var name_buf: [64]u8 = undefined;
    var file = try r.dir.createFile(try std.fmt.bufPrint(&name_buf, "seg-{}.main.sha", .{r.ordinal}), .{});
    defer file.close();
    var at: usize = 0;
    for (r.logs) |l| {
        const n = @as(usize, 1) << @intCast(l);
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(host[at..][0..n]), &d, .{});
        try file.writeAll(std.mem.asBytes(&l));
        try file.writeAll(&d);
        at += n;
    }
    if (std.posix.getenv("STWO_RV64_M8_GN_PACK_RECORD_MAIN")) |v| if (std.mem.eql(u8, v, "1")) {
        var mf = try r.dir.createFile(try std.fmt.bufPrint(&name_buf, "seg-{}.main", .{r.ordinal}), .{});
        defer mf.close();
        try mf.writeAll(std.mem.sliceAsBytes(host));
    };
    std.debug.print("GN_PACK_RECORD ordinal={} main_columns={} main_bytes={}\n", .{ r.ordinal, r.logs.len, total * 4 });
}
