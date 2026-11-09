//! Metal (Apple GPU, unified memory) execution path for the tensor prover.
//!
//! Implements `accel.Accel`:
//!   * commitment: row encoding (circle FFT over the zero-padded rows) +
//!     Blake2s column leaves + Merkle parents, streamed over row chunks;
//!   * sumcheck: round sums (s(0), s(2), s(3)) and folds on the device; the
//!     transcript and round-message logic stay on the CPU (accel.zig).
//! Field arithmetic is exact, so the results are bit-identical to the CPU path.
//!
//! Kernel sources: the stwo-zig Metal backend's MSL includes and its
//! circle-transform / commitment translation units are embedded and compiled
//! with the tensor kernels (`kernels.metal`) into one library at init.
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const pcs = t.pcs;
const sc = t.sumcheck;
const Accel = t.accel.Accel;

const M31 = f.M31;
const QM31 = f.QM31;
const Hash = [32]u8;

// ---------------------------------------------------------------------------
// C ABI (runtime.m)

pub extern fn tm_create(source: [*:0]const u8, err: [*]u8, err_len: usize) ?*anyopaque;
pub extern fn tm_destroy(rt: *anyopaque) void;
pub extern fn tm_pipeline(rt: *anyopaque, name: [*:0]const u8, err: [*]u8, err_len: usize) ?*anyopaque;
pub extern fn tm_pipeline_max_threads(p: *anyopaque) u32;
pub extern fn tm_release(obj: *anyopaque) void;
pub extern fn tm_buffer_alloc(rt: *anyopaque, len: usize) ?*anyopaque;
pub extern fn tm_buffer_wrap(rt: *anyopaque, ptr: *anyopaque, len: usize) ?*anyopaque;
pub extern fn tm_buffer_contents(buf: *anyopaque) *anyopaque;
pub extern fn tm_cmd_begin(rt: *anyopaque) *anyopaque;
pub extern fn tm_cmd_pipeline(cmd: *anyopaque, p: *anyopaque) void;
pub extern fn tm_cmd_buffer(cmd: *anyopaque, index: u32, buf: *anyopaque, offset: usize) void;
pub extern fn tm_cmd_bytes(cmd: *anyopaque, index: u32, bytes: *const anyopaque, len: usize) void;
pub extern fn tm_cmd_threadgroup_memory(cmd: *anyopaque, index: u32, len: usize) void;
pub extern fn tm_cmd_dispatch(cmd: *anyopaque, gx: u32, gy: u32, gz: u32, tx: u32, ty: u32, tz: u32) void;
pub extern fn tm_cmd_end(cmd: *anyopaque, gpu_ms: *f64, err: [*]u8, err_len: usize) c_int;

pub const source: [:0]const u8 = @import("tensor_metal_shaders").source;

const POOL_MIN: usize = 1 << 20;
/// one-off huge buffers (e.g. the offline weight-key GKR layers) are not
/// pooled: they would crowd out the per-proof working set
const POOL_MAX: usize = 1 << 30;

/// Pool size classes: 8 classes per power of two (<= 12.5% slack).
fn sizeClass(len: usize) usize {
    const p2 = std.math.ceilPowerOfTwo(usize, len) catch return len;
    if (p2 <= (1 << 20)) return p2;
    const step = p2 / 16;
    return std.mem.alignForward(usize, len, step);
}

pub const Error = error{ MetalInit, MetalPipeline, MetalAlloc, MetalCommand };

// ---------------------------------------------------------------------------
// Device buffers over host memory.

pub const Buf = struct {
    handle: *anyopaque,
    /// host slice the buffer mirrors (null for device-only scratch)
    host: ?[]u8 = null,
    /// true when `handle` aliases `host` (no copies needed)
    aliased: bool = false,
    /// byte offset of `host` inside the (page-aligned) device buffer
    offset: usize = 0,
    /// capacity of a device-allocated buffer (pool bucket), 0 for views
    cap: usize = 0,

    pub fn ptr(self: Buf) [*]u8 {
        const base: [*]u8 = @ptrCast(tm_buffer_contents(self.handle));
        return base + self.offset;
    }
};

pub fn bind(cmd: *anyopaque, index: u32, b: Buf) void {
    tm_cmd_buffer(cmd, index, b.handle, b.offset);
}

pub const Stats = struct {
    commit_gpu_ms: f64 = 0,
    commit_calls: usize = 0,
    sc_gpu_ms: f64 = 0,
    matmul_gpu_ms: f64 = 0,
    matmul_calls: usize = 0,
    mle_gpu_ms: f64 = 0,
    mle_calls: usize = 0,
    weight_pass_gpu_ms: f64 = 0,
    weight_pass_calls: usize = 0,
    gkr_gpu_ms: f64 = 0,
    gkr_rounds: usize = 0,
    gkr_calls: usize = 0,
    sc_rounds: usize = 0,
    sc_calls: usize = 0,
    wrapped_bytes: usize = 0,
    copied_bytes: usize = 0,
    pool_hits: usize = 0,
};

pub const Gpu = struct {
    rt: *anyopaque,
    p_expand_i32: *anyopaque,
    p_expand_i8: *anyopaque,
    p_layer: *anyopaque,
    p_tail: *anyopaque,
    p_leaf: *anyopaque,
    p_parents: *anyopaque,
    p_sc_round: *anyopaque,
    p_sc_fold: *anyopaque,
    p_matmul: *anyopaque,
    p_matmul_simd: *anyopaque,
    p_pack_i8: *anyopaque,
    p_mle: *anyopaque,
    p_gkr_next: *anyopaque,
    p_gkr_sum: *anyopaque,
    p_gkr_fold: *anyopaque,
    p_gkr_fold_sum: *anyopaque,
    p_combine: *anyopaque,
    p_row_dots: *anyopaque,
    p_lazy_round0: *anyopaque,
    p_lazy_fold0: *anyopaque,
    /// GKR layers at most this size are summed / folded by the CPU directly in
    /// the shared (unified-memory) buffers, saving a device round trip.
    gkr_cpu_sum_max: usize = 1 << 9,
    /// lazy sumcheck sessions (claim batching, lazy factors) evaluate their
    /// implicit factors on the fly for this many rounds (1..3; larger values
    /// act as 3: the fold weights cover 2^3 corners) before the
    /// first fold materialises QM31 factors of 1/2^lazy_rounds the length
    lazy_rounds: u32 = 1,
    gkr_cpu_fold_max: usize = 1 << 10,
    /// fuse GKR device folds with the next round's sums. Off by default:
    /// measured 50 vs 45 ms device time per MLP proof (the rounds are
    /// arithmetic-bound, fusion only saves a re-read). Tests cover both.
    gkr_fused_fold_sum: bool = false,
    /// force the int32 matmul kernel (tests)
    matmul_int_only: bool = false,
    /// buffers whose release waits for the in-flight command to complete
    retired: std.ArrayList(Buf) = .empty,
    pool: std.ArrayList(struct { handle: *anyopaque, cap: usize }) = .empty,
    pooled_bytes: usize = 0,
    /// bytes kept in the buffer pool (0 disables pooling)
    pool_limit: usize = 3 << 30,
    page: usize,
    stats: Stats = .{},
    /// rows per streamed commitment chunk are capped so a chunk is <= this
    chunk_bytes: usize = 256 << 20,
    vt: Accel = undefined,

    pub fn init(a: std.mem.Allocator) !*Gpu {
        var err: [1024]u8 = undefined;
        @memset(&err, 0);
        const rt = tm_create(source.ptr, &err, err.len) orelse {
            std.log.err("metal: {s}", .{std.mem.sliceTo(&err, 0)});
            return Error.MetalInit;
        };
        errdefer tm_destroy(rt);
        const g = try a.create(Gpu);
        g.* = .{
            .rt = rt,
            .p_expand_i32 = try pipeline(rt, "tm_expand_i32"),
            .p_expand_i8 = try pipeline(rt, "tm_expand_i8"),
            .p_layer = try pipeline(rt, "stwo_zig_circle_rfft_layer"),
            .p_tail = try pipeline(rt, "tm_rfft_tail"),
            .p_leaf = try pipeline(rt, "tm_leaf_absorb"),
            .p_parents = try pipeline(rt, "stwo_zig_blake2s_parents_plain_sparse"),
            .p_sc_round = try pipeline(rt, "tm_sc_round"),
            .p_sc_fold = try pipeline(rt, "tm_sc_fold"),
            .p_matmul = try pipeline(rt, "tm_matmul_i32_i8"),
            .p_matmul_simd = try pipeline(rt, "tm_matmul_simd"),
            .p_pack_i8 = try pipeline(rt, "tm_pack_i8"),
            .p_mle = try pipeline(rt, "tm_mle_i32"),
            .p_gkr_next = try pipeline(rt, "tm_gkr_next"),
            .p_gkr_sum = try pipeline(rt, "tm_gkr_sum"),
            .p_gkr_fold = try pipeline(rt, "tm_gkr_fold"),
            .p_gkr_fold_sum = try pipeline(rt, "tm_gkr_fold_sum"),
            .p_combine = try pipeline(rt, "tm_combine_rows"),
            .p_row_dots = try pipeline(rt, "tm_row_dots"),
            .p_lazy_round0 = try pipeline(rt, "tm_lazy_round0"),
            .p_lazy_fold0 = try pipeline(rt, "tm_lazy_fold0"),
            .page = std.heap.pageSize(),
        };
        g.vt = .{
            .ctx = g,
            .commit_i32 = commitI32,
            .commit_i8 = commitI8,
            .sc_begin = scBegin,
            .sc_round = scRound,
            .sc_finish = scFinish,
            .sc_begin_lazy = scBeginLazy,
            .matmul_acc = matmulAcc,
            .mle_eval_i32 = mleEvalI32,
            .gkr_prove = gkrProve,
            .combine_i8 = combineI8,
            .combine_i32 = combineI32,
            .row_dots_i8 = rowDotsI8,
            .sc_abort = scAbort,
        };
        return g;
    }

    pub fn deinit(self: *Gpu, a: std.mem.Allocator) void {
        inline for (.{ "p_expand_i32", "p_expand_i8", "p_layer", "p_tail", "p_leaf", "p_parents", "p_sc_round", "p_sc_fold", "p_matmul", "p_matmul_simd", "p_pack_i8", "p_mle", "p_gkr_next", "p_gkr_sum", "p_gkr_fold", "p_gkr_fold_sum", "p_combine", "p_row_dots", "p_lazy_round0", "p_lazy_fold0" }) |name|
            tm_release(@field(self, name));
        self.releaseRetired();
        self.retired.deinit(std.heap.c_allocator);
        self.trim();
        self.pool.deinit(std.heap.c_allocator);
        tm_destroy(self.rt);
        a.destroy(self);
    }

    pub fn retire(self: *Gpu, b: Buf) !void {
        try self.retired.append(std.heap.c_allocator, b);
    }

    pub fn releaseRetired(self: *Gpu) void {
        for (self.retired.items) |b| self.free(b);
        self.retired.clearRetainingCapacity();
    }

    fn gkrProve(ctx: *anyopaque, a: std.mem.Allocator, ch: *t.transcript.Channel, inputs: []const t.accel.GkrInput) anyerror!t.accel.GkrResult {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        g.stats.gkr_calls += 1;
        var bytes: usize = 0;
        for (inputs) |in| bytes += in.den.len * 32;
        // A one-off huge batch (the offline weight-key proof over the whole
        // weight table) would leave the pool full of its layer sizes, which
        // the per-batch proofs never reuse: drop them afterwards.
        defer if (bytes > g.pool_limit / 2) g.trim();
        return @import("gkr.zig").proveBatch(g, a, ch, inputs);
    }

    pub fn accel(self: *Gpu) *const Accel {
        return &self.vt;
    }

    pub fn pipeline(rt: *anyopaque, name: [:0]const u8) !*anyopaque {
        var err: [1024]u8 = undefined;
        @memset(&err, 0);
        return tm_pipeline(rt, name.ptr, &err, err.len) orelse {
            std.log.err("metal pipeline {s}: {s}", .{ name, std.mem.sliceTo(&err, 0) });
            return Error.MetalPipeline;
        };
    }

    /// Device-allocated shared buffer. Large buffers come from a small
    /// size-class pool (8 classes per power of two), so repeated proofs do not pay first-touch
    /// page faults on fresh multi-hundred-MB allocations. Contents of a
    /// recycled buffer are arbitrary: every user writes before it reads.
    pub fn alloc(self: *Gpu, len: usize) !Buf {
        if (len >= POOL_MIN) {
            const cap = sizeClass(len);
            for (self.pool.items, 0..) |e, i| if (e.cap == cap) {
                _ = self.pool.swapRemove(i);
                self.pooled_bytes -= cap;
                self.stats.pool_hits += 1;
                return .{ .handle = e.handle, .cap = cap };
            };
            return .{ .handle = tm_buffer_alloc(self.rt, cap) orelse return Error.MetalAlloc, .cap = cap };
        }
        return .{ .handle = tm_buffer_alloc(self.rt, len) orelse return Error.MetalAlloc, .cap = len };
    }

    /// Returns a buffer (device-allocated or view) once no command uses it.
    pub fn free(self: *Gpu, b: Buf) void {
        if (b.aliased or b.cap < POOL_MIN or b.cap > POOL_MAX) return tm_release(b.handle);
        while (self.pooled_bytes + b.cap > self.pool_limit and self.pool.items.len > 0) {
            const old = self.pool.orderedRemove(0);
            self.pooled_bytes -= old.cap;
            tm_release(old.handle);
        }
        if (b.cap > self.pool_limit) return tm_release(b.handle);
        self.pool.append(std.heap.c_allocator, .{ .handle = b.handle, .cap = b.cap }) catch return tm_release(b.handle);
        self.pooled_bytes += b.cap;
    }

    /// Drops every pooled buffer.
    pub fn trim(self: *Gpu) void {
        for (self.pool.items) |e| tm_release(e.handle);
        self.pool.clearRetainingCapacity();
        self.pooled_bytes = 0;
    }

    /// Device view of host memory. Unified memory: the pages spanning `host`
    /// are wrapped without copying (every page holding a byte of a live
    /// allocation is mapped, so rounding to page bounds is safe); the device
    /// only touches bytes inside `host`. Falls back to a shared buffer, filled
    /// from host when `copy_in`, if wrapping fails.
    pub fn view(self: *Gpu, host: []u8, copy_in: bool) !Buf {
        if (host.len > 0) {
            const addr = @intFromPtr(host.ptr);
            const base = std.mem.alignBackward(usize, addr, self.page);
            const end_addr = std.mem.alignForward(usize, addr + host.len, self.page);
            if (tm_buffer_wrap(self.rt, @ptrFromInt(base), end_addr - base)) |h| {
                self.stats.wrapped_bytes += host.len;
                return .{ .handle = h, .host = host, .aliased = true, .offset = addr - base };
            }
        }
        var b = try self.alloc(host.len);
        b.host = host;
        if (copy_in) {
            @memcpy(b.ptr()[0..host.len], host);
            self.stats.copied_bytes += host.len;
        }
        return b;
    }

    /// Copies a non-aliased view back to host (first `n` bytes) and releases it.
    pub fn release(self: *Gpu, b: Buf, copy_out: ?usize) void {
        if (copy_out) |n| if (!b.aliased) {
            if (b.host) |h| {
                @memcpy(h[0..n], b.ptr()[0..n]);
                self.stats.copied_bytes += n;
            }
        };
        self.free(b);
    }

    pub fn end(cmd: *anyopaque) !f64 {
        var ms: f64 = 0;
        var err: [1024]u8 = undefined;
        @memset(&err, 0);
        if (tm_cmd_end(cmd, &ms, &err, err.len) != 0) {
            std.log.err("metal command: {s}", .{std.mem.sliceTo(&err, 0)});
            return Error.MetalCommand;
        }
        return ms;
    }

    // -----------------------------------------------------------------------
    // Commitment

    const ExpandParams = extern struct { log_c: u32, log_e: u32, rows: u32, row0: u32 };
    const TailParams = extern struct { log_e: u32, tile_log: u32, top_layer: u32, tw_len: u32, rows: u32 };
    const LeafParams = extern struct { log_e: u32, rows: u32, row0: u32, total_rows: u32, last_chunk: u32 };
    const TILE_LOG: u32 = 12;

    fn releaseEnc(ctx: *anyopaque, handle: *anyopaque) void {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const box: *Buf = @ptrCast(@alignCast(handle));
        g.free(box.*);
        std.heap.c_allocator.destroy(box);
    }

    fn commitI32(ctx: *anyopaque, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(i32), lb: u32) anyerror!?pcs.Committed {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        return g.commit(i32, a, tw, m, lb);
    }

    fn commitI8(ctx: *anyopaque, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(i8), lb: u32) anyerror!?pcs.Committed {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        return g.commit(i8, a, tw, m, lb);
    }

    pub fn commit(self: *Gpu, comptime T: type, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(T), lb: u32) !?pcs.Committed {
        const R = m.usedRows();
        const log_c = m.log_cols;
        const log_e = log_c + lb;
        const C = @as(usize, 1) << @intCast(log_c);
        const E = @as(usize, 1) << @intCast(log_e);
        // tiny encodings take the CPU's special-cased small transforms
        if (log_e < 3 or R == 0 or R * E >= (1 << 32) or tw.domain.logSize() != log_e) return null;
        const tw_len: u32 = @intCast(tw.tree.twiddles.len);

        // The codeword lives in a (pooled, already resident) device buffer
        // owned by the commitment; the opening reads its columns directly.
        const enc_box = try std.heap.c_allocator.create(Buf);
        errdefer std.heap.c_allocator.destroy(enc_box);
        const enc_buf = try self.alloc(R * E * 4);
        enc_box.* = enc_buf;
        var enc_owned = false;
        errdefer if (!enc_owned) self.free(enc_buf);
        const enc: []M31 = @as([*]M31, @ptrCast(@alignCast(enc_buf.ptr())))[0 .. R * E];
        const nodes = try a.alloc(Hash, 2 * E);
        errdefer a.free(nodes);

        const in_bytes = std.mem.sliceAsBytes(m.data[0 .. R * C]);
        const in_buf = try self.view(@constCast(in_bytes), true);
        defer self.release(in_buf, null);
        const tw_buf = try self.view(@constCast(std.mem.sliceAsBytes(tw.tree.twiddles)), true);
        defer self.release(tw_buf, null);
        const nodes_buf = try self.view(std.mem.sliceAsBytes(nodes), false);
        var nodes_released = false;
        defer if (!nodes_released) self.release(nodes_buf, null);
        const states = try self.alloc(E * 32);
        defer self.free(states);

        var ch = (self.chunk_bytes / (E * 4)) & ~@as(usize, 15);
        if (ch < 16) ch = 16;
        if (ch > R) ch = R;
        const scratch = try self.alloc(ch * E * 4);
        defer self.free(scratch);

        const tile_log = @min(TILE_LOG, log_e);
        const cmd = tm_cmd_begin(self.rt);
        var row0: usize = 0;
        while (row0 < R) : (row0 += ch) {
            const rows = @min(ch, R - row0);
            // expansion (implicit top lb layers)
            const ep = ExpandParams{ .log_c = log_c, .log_e = log_e, .rows = @intCast(rows), .row0 = @intCast(row0) };
            tm_cmd_pipeline(cmd, if (T == i8) self.p_expand_i8 else self.p_expand_i32);
            bind(cmd, 0, in_buf);
            bind(cmd, 1, scratch);
            tm_cmd_bytes(cmd, 2, &ep, @sizeOf(ExpandParams));
            const n_el = rows * E;
            tm_cmd_dispatch(cmd, @intCast((n_el + 255) / 256), 1, 1, 256, 1, 1);
            // global layers log_c-1 .. tile_log
            var layer: u32 = log_c;
            while (layer > tile_log) {
                layer -= 1;
                const ls: u32 = log_e;
                const off: u32 = tw_len - (@as(u32, 1) << @intCast(log_e - layer));
                const cols: u32 = @intCast(rows);
                tm_cmd_pipeline(cmd, self.p_layer);
                bind(cmd, 0, scratch);
                bind(cmd, 1, tw_buf);
                tm_cmd_bytes(cmd, 2, &ls, 4);
                tm_cmd_bytes(cmd, 3, &layer, 4);
                tm_cmd_bytes(cmd, 4, &off, 4);
                tm_cmd_bytes(cmd, 5, &cols, 4);
                const pairs: u32 = @intCast(E / 2);
                tm_cmd_dispatch(cmd, (pairs + 255) / 256, cols, 1, 256, 1, 1);
            }
            // fused low layers + circle layer
            const tp = TailParams{ .log_e = log_e, .tile_log = tile_log, .top_layer = @min(log_c, tile_log) - 1, .tw_len = tw_len, .rows = @intCast(rows) };
            const tile = @as(u32, 1) << @intCast(tile_log);
            const threads: u32 = @min(512, tile / 2);
            tm_cmd_pipeline(cmd, self.p_tail);
            bind(cmd, 0, scratch);
            bind(cmd, 1, tw_buf);
            tm_cmd_bytes(cmd, 2, &tp, @sizeOf(TailParams));
            tm_cmd_threadgroup_memory(cmd, 0, tile * 4);
            tm_cmd_dispatch(cmd, @intCast(rows * (E >> @intCast(tile_log))), 1, 1, threads, 1, 1);
            // column leaves (streamed Blake2s) + column-major codeword
            const lp = LeafParams{ .log_e = log_e, .rows = @intCast(rows), .row0 = @intCast(row0), .total_rows = @intCast(R), .last_chunk = @intFromBool(row0 + rows == R) };
            tm_cmd_pipeline(cmd, self.p_leaf);
            bind(cmd, 0, scratch);
            bind(cmd, 1, states);
            bind(cmd, 2, enc_buf);
            bind(cmd, 3, nodes_buf);
            tm_cmd_bytes(cmd, 4, &lp, @sizeOf(LeafParams));
            tm_cmd_dispatch(cmd, @intCast((E + 63) / 64), 1, 1, 64, 1, 1);
        }
        // Merkle parents, level by level
        var level: usize = E / 2;
        while (level >= 1) : (level /= 2) {
            const child_off: u32 = @intCast(2 * level * 8);
            const dst_off: u32 = @intCast(level * 8);
            const cnt: u32 = @intCast(level);
            tm_cmd_pipeline(cmd, self.p_parents);
            bind(cmd, 0, nodes_buf);
            tm_cmd_bytes(cmd, 1, &child_off, 4);
            tm_cmd_bytes(cmd, 2, &dst_off, 4);
            tm_cmd_bytes(cmd, 3, &cnt, 4);
            const th: u32 = @min(256, cnt);
            tm_cmd_dispatch(cmd, (cnt + th - 1) / th, 1, 1, th, 1, 1);
            if (level == 1) break;
        }
        self.stats.commit_gpu_ms += try end(cmd);
        self.stats.commit_calls += 1;
        enc_owned = true;
        nodes_released = true;
        self.release(nodes_buf, nodes.len * 32);
        return .{
            .combine = .{ .ctx = self, .i8 = combineI8, .i32 = combineI32 },
            .enc_owner = .{ .ctx = self, .handle = enc_box, .release = releaseEnc },
            .log_rows = m.log_rows,
            .log_cols = m.log_cols,
            .log_blowup = lb,
            .rows_used = R,
            .enc = enc,
            .tree = .{ .nodes = nodes, .n_leaves = E },
        };
    }

    // -----------------------------------------------------------------------
    // Matmul accumulators

    const MatmulParams = extern struct { T: u32, K: u32, N: u32 };

    fn matmulAcc(ctx: *anyopaque, a: std.mem.Allocator, x: []const i32, T: usize, wm: pcs.Matrix(i8)) anyerror!?[]i64 {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const K = wm.nRows();
        const N = wm.nCols();
        if (x.len != T * K or T * N >= (1 << 32) or T * K >= (1 << 32) or K * N >= (1 << 32)) return null;
        // exactness bounds: fp32 matrix units for x in [-128, 127] (the
        // activations are packed to int8 by tm_pack_i8, so +128 would wrap to
        // -128: KERN-2), int32 chunk sums for |x| < 2^15, CPU otherwise
        var max_abs: u32 = 0;
        var lo: i32 = 0;
        var hi: i32 = 0;
        for (x) |v| {
            max_abs = @max(max_abs, @abs(v));
            lo = @min(lo, v);
            hi = @max(hi, v);
        }
        if (max_abs >= (1 << 15)) return null;
        const simd = lo >= -128 and hi <= 127 and !g.matmul_int_only;
        const out = try a.alloc(i64, T * N);
        errdefer a.free(out);
        const xb = try g.view(@constCast(std.mem.sliceAsBytes(x)), true);
        defer g.release(xb, null);
        const wb = try g.view(@constCast(std.mem.sliceAsBytes(wm.data[0 .. K * N])), true);
        defer g.release(wb, null);
        const ob = try g.view(std.mem.sliceAsBytes(out), false);
        var ob_released = false;
        defer if (!ob_released) g.release(ob, null);
        const mp = MatmulParams{ .T = @intCast(T), .K = @intCast(K), .N = @intCast(N) };
        const cmd = tm_cmd_begin(g.rt);
        // int8 activations are packed once (X is re-read N/64 times)
        const x8: ?Buf = if (simd) try g.alloc(T * K) else null;
        defer if (x8) |b| g.free(b);
        if (x8) |b| {
            const n32: u32 = @intCast(T * K);
            tm_cmd_pipeline(cmd, g.p_pack_i8);
            bind(cmd, 0, xb);
            bind(cmd, 1, b);
            tm_cmd_bytes(cmd, 2, &n32, 4);
            tm_cmd_dispatch(cmd, (n32 + 255) / 256, 1, 1, 256, 1, 1);
        }
        tm_cmd_pipeline(cmd, if (simd) g.p_matmul_simd else g.p_matmul);
        bind(cmd, 0, x8 orelse xb);
        bind(cmd, 1, wb);
        bind(cmd, 2, ob);
        tm_cmd_bytes(cmd, 3, &mp, @sizeOf(MatmulParams));
        tm_cmd_dispatch(cmd, @intCast((N + 63) / 64), @intCast((T + 63) / 64), 1, 256, 1, 1);
        g.stats.matmul_gpu_ms += try end(cmd);
        g.stats.matmul_calls += 1;
        ob_released = true;
        g.release(ob, out.len * 8);
        return out;
    }

    // -----------------------------------------------------------------------
    // Weight passes

    const CombineParams = extern struct { rows: u32, cols: u32, groups: u32, is_i8: u32 };

    fn combineI8(ctx: *anyopaque, a: std.mem.Allocator, m: pcs.Matrix(i8), coeffs: []const []const QM31) anyerror!?[][]QM31 {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        return g.combine(i8, a, m, coeffs);
    }
    fn combineI32(ctx: *anyopaque, a: std.mem.Allocator, m: pcs.Matrix(i32), coeffs: []const []const QM31) anyerror!?[][]QM31 {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        return g.combine(i32, a, m, coeffs);
    }

    /// out[g][c] = sum_i coeffs[g][i] m[i][c] over the used rows.
    pub fn combine(self: *Gpu, comptime T: type, a: std.mem.Allocator, m: pcs.Matrix(T), coeffs: []const []const QM31) !?[][]QM31 {
        const R = m.usedRows();
        const C = m.nCols();
        const G = coeffs.len;
        if (G == 0 or G > 4 or R * C >= (1 << 32) or R * C < (1 << 16)) return null;
        const cb = try self.alloc(G * R * 16);
        defer self.free(cb);
        const cq: [*]QM31 = @ptrCast(@alignCast(cb.ptr()));
        for (coeffs, 0..) |cg, gi| @memcpy(cq[gi * R ..][0..R], cg[0..R]);
        // enough row chunks to fill the device when there are few columns
        const chunk_rows: u32 = @intCast(@max(256, (R * C) / (1 << 21)));
        const n_chunks: usize = (R + chunk_rows - 1) / chunk_rows;
        const ob = try self.alloc(n_chunks * G * C * 16);
        defer self.free(ob);
        const mb = try self.view(@constCast(std.mem.sliceAsBytes(m.data[0 .. R * C])), true);
        defer self.release(mb, null);
        const cp = CombineParams{ .rows = @intCast(R), .cols = @intCast(C), .groups = @intCast(G), .is_i8 = @intFromBool(T == i8) };
        const cmd = tm_cmd_begin(self.rt);
        tm_cmd_pipeline(cmd, self.p_combine);
        bind(cmd, 0, mb);
        bind(cmd, 1, mb);
        bind(cmd, 2, cb);
        bind(cmd, 3, ob);
        tm_cmd_bytes(cmd, 4, &cp, @sizeOf(CombineParams));
        tm_cmd_bytes(cmd, 5, &chunk_rows, 4);
        const c32: u32 = @intCast(C);
        tm_cmd_dispatch(cmd, (c32 + 63) / 64, @intCast(n_chunks), 1, 64, 1, 1);
        self.stats.weight_pass_gpu_ms += try end(cmd);
        self.stats.weight_pass_calls += 1;
        const pq: [*]QM31 = @ptrCast(@alignCast(ob.ptr()));
        for (1..n_chunks) |ch| for (0..G * C) |j| {
            pq[j] = pq[j].add(pq[ch * G * C + j]);
        };
        const oq: [*]const QM31 = pq;
        const out = try a.alloc([]QM31, G);
        var made: usize = 0;
        errdefer {
            for (out[0..made]) |o| a.free(o);
            a.free(out);
        }
        for (0..G) |gi| {
            out[gi] = try a.dupe(QM31, oq[gi * C ..][0..C]);
            made += 1;
        }
        return out;
    }

    fn rowDotsI8(ctx: *anyopaque, a: std.mem.Allocator, m: pcs.Matrix(i8), vec: []const QM31) anyerror!?[]QM31 {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const R = m.nRows();
        const C = m.nCols();
        if (vec.len != C or R * C >= (1 << 32) or R * C < (1 << 16)) return null;
        const vb = try g.alloc(C * 16);
        defer g.free(vb);
        const vq: [*]QM31 = @ptrCast(@alignCast(vb.ptr()));
        @memcpy(vq[0..C], vec);
        const out = try a.alloc(QM31, R);
        errdefer a.free(out);
        const ob = try g.view(std.mem.sliceAsBytes(out), false);
        var ob_released = false;
        defer if (!ob_released) g.release(ob, null);
        const mb = try g.view(@constCast(std.mem.sliceAsBytes(m.data[0 .. R * C])), true);
        defer g.release(mb, null);
        const cp = CombineParams{ .rows = @intCast(R), .cols = @intCast(C), .groups = 1, .is_i8 = 1 };
        const cmd = tm_cmd_begin(g.rt);
        tm_cmd_pipeline(cmd, g.p_row_dots);
        bind(cmd, 0, mb);
        bind(cmd, 1, mb);
        bind(cmd, 2, vb);
        bind(cmd, 3, ob);
        tm_cmd_bytes(cmd, 4, &cp, @sizeOf(CombineParams));
        tm_cmd_threadgroup_memory(cmd, 0, 256 * 16);
        tm_cmd_dispatch(cmd, @intCast(R), 1, 1, 256, 1, 1);
        g.stats.weight_pass_gpu_ms += try end(cmd);
        g.stats.weight_pass_calls += 1;
        ob_released = true;
        g.release(ob, out.len * 16);
        return out;
    }

    // -----------------------------------------------------------------------
    // MLE evaluation of integer vectors

    const MleParams = extern struct { count: u32, lo_bits: u32 };

    fn mleEvalI32(ctx: *anyopaque, values: []const i32, point: []const QM31) anyerror!?QM31 {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const n = point.len;
        if (values.len != (@as(usize, 1) << @intCast(n)) or values.len >= (1 << 32)) return null;
        const ca = std.heap.c_allocator;
        const lo = n / 2;
        const pre = try f.eqTable(ca, point[0 .. n - lo], QM31.one());
        defer ca.free(pre);
        const suf = try f.eqTable(ca, point[n - lo ..], QM31.one());
        defer ca.free(suf);
        const tabs = try g.alloc((pre.len + suf.len) * 16);
        defer g.free(tabs);
        const tq: [*]QM31 = @ptrCast(@alignCast(tabs.ptr()));
        @memcpy(tq[0..pre.len], pre);
        @memcpy(tq[pre.len..][0..suf.len], suf);
        const groups: u32 = @intCast(@max(1, @min(SC_MAX_GROUPS, (values.len + SC_TG * 8 - 1) / (SC_TG * 8))));
        const parts = try g.alloc(groups * 16);
        defer g.free(parts);
        const vb = try g.view(@constCast(std.mem.sliceAsBytes(values)), true);
        defer g.release(vb, null);
        const mp = MleParams{ .count = @intCast(values.len), .lo_bits = @intCast(lo) };
        const cmd = tm_cmd_begin(g.rt);
        tm_cmd_pipeline(cmd, g.p_mle);
        bind(cmd, 0, vb);
        tm_cmd_buffer(cmd, 1, tabs.handle, 0);
        tm_cmd_buffer(cmd, 2, tabs.handle, pre.len * 16);
        bind(cmd, 3, parts);
        tm_cmd_bytes(cmd, 4, &mp, @sizeOf(MleParams));
        tm_cmd_threadgroup_memory(cmd, 0, SC_TG * 16);
        tm_cmd_dispatch(cmd, groups, 1, 1, SC_TG, 1, 1);
        g.stats.mle_gpu_ms += try end(cmd);
        g.stats.mle_calls += 1;
        const pq: [*]const Q = @ptrCast(@alignCast(parts.ptr()));
        var out = QM31.zero();
        for (0..groups) |i| out = out.add(fromQ(pq[i]));
        return out;
    }

    // -----------------------------------------------------------------------
    // Sumcheck

    pub const Q = extern struct { a: u32, b: u32, c: u32, d: u32 };
    const ScParams = extern struct {
        half_len: u32,
        active: u32,
        work: u32,
        prev_half: u32,
        prev_active: u32,
        n_factors: u32,
        n_terms: u32,
        deg: u32,
        term_len: [4]u32,
        term_fac: [4][3]u32,
        coeff: [4]Q,
        r: Q,
    };
    const SC_TG: u32 = 256;
    const SC_MAX_GROUPS: usize = 1024;

    pub fn toQ(x: QM31) Q {
        const l = f.limbs(x);
        return .{ .a = l[0], .b = l[1], .c = l[2], .d = l[3] };
    }
    pub fn fromQ(q: Q) QM31 {
        return f.fromLimbs(.{ q.a, q.b, q.c, q.d });
    }

    const Session = struct {
        bufs: [4]Buf,
        nf: usize,
        partials: Buf,
        base: ScParams,
        len: usize,
        active: usize,
        prev_half: usize = 0,
        prev_active: usize = 0,
        a: std.mem.Allocator,
        /// batch sumcheck before its first fold: factors are implicit
        lazy: ?Lazy = null,
    };

    const Lazy = struct {
        srcs: [4]?Buf,
        tabs: Buf,
        claims: Buf,
        segs: Buf,
        params: LazyParams,
        /// challenges of the lazy rounds run so far (folded on the fly)
        rs: [3]QM31 = undefined,
        n_rs: u32 = 0,
        active0: usize = 0,
    };

    /// wts[c] = eq(rs, c) over n = rs.len bits, c MSB-first (rs[0] <-> MSB):
    /// the weight of f(c * fold_len + y) in the n-times folded factor at y.
    fn cornerWeights(rs: []const QM31) [8]Q {
        var out: [8]Q = undefined;
        const n = rs.len;
        for (0..@as(usize, 1) << @intCast(n)) |c| {
            var w = QM31.one();
            for (0..n) |i| {
                const bit = (c >> @intCast(n - 1 - i)) & 1;
                w = w.mul(if (bit == 1) rs[i] else QM31.one().sub(rs[i]));
            }
            out[c] = toQ(w);
        }
        for ((@as(usize, 1) << @intCast(n))..8) |c| out[c] = toQ(QM31.zero());
        return out;
    }
    const BatchClaimGpu = extern struct { offset: u32, count: u32, lo_bits: u32, pre_off: u32, suf_off: u32 };
    const LazyFactor = extern struct { kind: u32, claim0: u32, n_claims: u32, _pad: u32 = 0 };
    const LazyParams = extern struct {
        half_len: u32,
        active: u32,
        work: u32,
        n_factors: u32,
        n_terms: u32,
        deg: u32,
        _pad0: u32 = 0,
        _pad1: u32 = 0,
        term_len: [4]u32,
        term_fac: [4][3]u32,
        coeff: [4]Q,
        r: Q,
        fac: [4]LazyFactor,
        n_fold: u32 = 0,
        fold_len: u32 = 0,
        active0: u32 = 0,
        _pad2: u32 = 0,
        wts: [8]Q = undefined,
    };

    fn bindLazy(s: *Session, cmd: *anyopaque) void {
        const lz = s.lazy.?;
        var first: ?Buf = null;
        for (lz.srcs) |b| if (b != null and first == null) {
            first = b;
        };
        for (0..4) |j| bind(cmd, @intCast(j), lz.srcs[j] orelse first orelse lz.tabs);
        bind(cmd, 4, lz.tabs);
        bind(cmd, 5, lz.claims);
        bind(cmd, 11, lz.segs);
    }

    /// Encodes the round-0 fold of a lazy session into fresh half-size
    /// QM31 factor buffers.
    fn lazyFold(g: *Gpu, s: *Session, cmd: *anyopaque, r: QM31) !void {
        const lz = s.lazy.?;
        const half = s.prev_half;
        const work = s.active;
        const nf = lz.params.n_factors;
        // full half length: the tail copy reads [0, len); entries >= work are
        // never read by the prover
        for (0..nf) |j| s.bufs[j] = try g.alloc(half * 16);
        var lp = lz.params;
        lp.half_len = @intCast(half);
        lp.active = @intCast(s.prev_active);
        lp.work = @intCast(work);
        lp.r = toQ(r);
        lp.n_fold = 0;
        if (lz.n_rs > 0) {
            // fold at all lazy challenges and r: out(y) = sum_c eq(rs ++ r, c) f(c * half + y)
            var all: [4]QM31 = undefined;
            @memcpy(all[0..lz.n_rs], lz.rs[0..lz.n_rs]);
            all[lz.n_rs] = r;
            lp.n_fold = lz.n_rs + 1;
            lp.fold_len = @intCast(half);
            lp.active0 = @intCast(lz.active0);
            lp.wts = cornerWeights(all[0 .. lz.n_rs + 1]);
        }
        tm_cmd_pipeline(cmd, g.p_lazy_fold0);
        bindLazy(s, cmd);
        for (0..4) |j| bind(cmd, @intCast(6 + j), s.bufs[if (j < nf) j else 0]);
        tm_cmd_bytes(cmd, 10, &lp, @sizeOf(LazyParams));
        const w: u32 = @intCast(work);
        if (w > 0) tm_cmd_dispatch(cmd, (w + 255) / 256, 1, 1, 256, 1, 1);
        s.nf = nf;
        // the lazy inputs are referenced by this command: retire them
        for (lz.srcs) |b| if (b) |x| try g.retire(x);
        try g.retire(lz.tabs);
        try g.retire(lz.claims);
        try g.retire(lz.segs);
        s.lazy = null;
    }

    fn scBegin(ctx: *anyopaque, factors: []const []QM31, terms: []const sc.Term, active: usize) anyerror!?*anyopaque {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const len = factors[0].len;
        if (len >= (1 << 32)) return null;
        var p = std.mem.zeroes(ScParams);
        p.n_factors = @intCast(factors.len);
        p.n_terms = @intCast(terms.len);
        var deg: u32 = 2;
        for (terms, 0..) |term, i| {
            p.term_len[i] = @intCast(term.factors.len);
            for (term.factors, 0..) |fi, k| p.term_fac[i][k] = fi;
            p.coeff[i] = toQ(term.coeff);
            deg = @max(deg, @as(u32, @intCast(term.factors.len)));
        }
        p.deg = deg;
        const s = try std.heap.c_allocator.create(Session);
        s.* = .{ .bufs = undefined, .nf = factors.len, .partials = undefined, .base = p, .len = len, .active = active, .a = std.heap.c_allocator };
        var made: usize = 0;
        errdefer {
            for (s.bufs[0..made]) |b| g.release(b, null);
            std.heap.c_allocator.destroy(s);
        }
        for (factors, 0..) |fac, j| {
            s.bufs[j] = try g.view(std.mem.sliceAsBytes(fac), true);
            made += 1;
        }
        s.partials = try g.alloc(SC_MAX_GROUPS * 3 * 16);
        g.stats.sc_calls += 1;
        return s;
    }

    fn bindFactors(s: *Session, cmd: *anyopaque) void {
        for (0..4) |j| bind(cmd, @intCast(j), s.bufs[if (j < s.nf) j else 0]);
    }

    fn scRound(ctx: *anyopaque, sp: *anyopaque, r_prev: ?QM31) anyerror![3]QM31 {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const s: *Session = @ptrCast(@alignCast(sp));
        var p = s.base;
        if (r_prev) |r| {
            p.prev_half = @intCast(s.prev_half);
            p.prev_active = @intCast(s.prev_active);
            p.r = toQ(r);
        }
        const half = s.len / 2;
        const work = @min(half, s.active);
        p.half_len = @intCast(half);
        p.active = @intCast(s.active);
        p.work = @intCast(work);
        const groups: u32 = @intCast(@max(1, @min(SC_MAX_GROUPS, (work + SC_TG * 4 - 1) / (SC_TG * 4))));
        const cmd = tm_cmd_begin(g.rt);
        if (s.lazy) |*lz| {
            var lazy_round = r_prev == null;
            if (r_prev) |r| {
                if (lz.n_rs + 1 < @min(g.lazy_rounds, 3)) {
                    // another lazy round: fold at r on the fly
                    lz.rs[lz.n_rs] = r;
                    lz.n_rs += 1;
                    lazy_round = true;
                } else {
                    // first fold materialises the folded factors, then a plain round
                    try lazyFold(g, s, cmd, r);
                    p.prev_half = 0;
                    p.prev_active = 0;
                }
            }
            if (lazy_round) {
                var lp = lz.params;
                lp.half_len = @intCast(half);
                lp.active = @intCast(s.active);
                lp.work = @intCast(work);
                lp.n_fold = lz.n_rs;
                if (lz.n_rs > 0) {
                    lp.fold_len = @intCast(s.len);
                    lp.active0 = @intCast(lz.active0);
                    lp.wts = cornerWeights(lz.rs[0..lz.n_rs]);
                }
                tm_cmd_pipeline(cmd, g.p_lazy_round0);
                bindLazy(s, cmd);
                bind(cmd, 6, s.partials);
                tm_cmd_bytes(cmd, 10, &lp, @sizeOf(LazyParams));
                tm_cmd_threadgroup_memory(cmd, 0, SC_TG * 3 * 16);
                tm_cmd_dispatch(cmd, groups, 1, 1, SC_TG, 1, 1);
            }
        }
        if (s.lazy == null) {
            tm_cmd_pipeline(cmd, g.p_sc_round);
            bindFactors(s, cmd);
            bind(cmd, 4, s.partials);
            tm_cmd_bytes(cmd, 5, &p, @sizeOf(ScParams));
            tm_cmd_threadgroup_memory(cmd, 0, SC_TG * 3 * 16);
            tm_cmd_dispatch(cmd, groups, 1, 1, SC_TG, 1, 1);
        }
        g.stats.sc_gpu_ms += try end(cmd);
        g.releaseRetired();
        g.stats.sc_rounds += 1;
        const parts: [*]const Q = @ptrCast(@alignCast(s.partials.ptr()));
        var out = [3]QM31{ QM31.zero(), QM31.zero(), QM31.zero() };
        for (0..groups) |gi| for (0..3) |k| {
            out[k] = out[k].add(fromQ(parts[gi * 3 + k]));
        };
        // advance: the next round folds this one
        s.prev_half = half;
        s.prev_active = s.active;
        s.len = half;
        s.active = work;
        return out;
    }

    fn scFinish(ctx: *anyopaque, sp: *anyopaque, r_last: QM31, out: []const []QM31) anyerror!void {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const s: *Session = @ptrCast(@alignCast(sp));
        defer scAbort(ctx, sp);
        // fold of the last device round: state before it had length 2*len
        var p = s.base;
        p.half_len = @intCast(s.prev_half);
        p.active = @intCast(s.prev_active);
        p.work = @intCast(s.active);
        p.r = toQ(r_last);
        const cmd = tm_cmd_begin(g.rt);
        if (s.lazy != null) {
            try lazyFold(g, s, cmd, r_last);
        } else {
            tm_cmd_pipeline(cmd, g.p_sc_fold);
            bindFactors(s, cmd);
            tm_cmd_bytes(cmd, 5, &p, @sizeOf(ScParams));
            const w: u32 = @intCast(s.active);
            if (w > 0) tm_cmd_dispatch(cmd, (w + 255) / 256, 1, 1, 256, 1, 1);
        }
        g.stats.sc_gpu_ms += try end(cmd);
        g.releaseRetired();
        for (s.bufs[0..s.nf], out) |*b, o| {
            const dst = std.mem.sliceAsBytes(o[0..s.len]);
            const src = b.ptr();
            if (@intFromPtr(dst.ptr) != @intFromPtr(src)) {
                @memcpy(dst, src[0..dst.len]);
                g.stats.copied_bytes += dst.len;
            }
        }
    }

    /// Lazy session: every factor is an int32 vector or a sum of eq tables
    /// (each claim's gamma*eq factored as a CPU prefix (x) suffix). Round 0
    /// and its fold evaluate the factors on the fly (tm_lazy_round0/fold0), so
    /// no full-length factor is materialised; the fold writes the half-size
    /// QM31 factors the generic rounds continue on.
    fn scBeginLazy(ctx: *anyopaque, specs: []const t.accel.FactorSpec, terms: []const sc.Term, len: usize, active: usize) anyerror!?*anyopaque {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        if (len >= (1 << 31) or specs.len == 0 or specs.len > 4 or terms.len > 4) return null;
        var lp = std.mem.zeroes(LazyParams);
        lp.n_factors = @intCast(specs.len);
        lp.n_terms = @intCast(terms.len);
        var deg: u32 = 2;
        for (terms, 0..) |term, i| {
            lp.term_len[i] = @intCast(term.factors.len);
            for (term.factors, 0..) |fi, k| lp.term_fac[i][k] = fi;
            lp.coeff[i] = toQ(term.coeff);
            deg = @max(deg, @as(u32, @intCast(term.factors.len)));
        }
        lp.deg = deg;
        var p = std.mem.zeroes(ScParams);
        p.n_factors = lp.n_factors;
        p.n_terms = lp.n_terms;
        p.deg = deg;
        p.term_len = lp.term_len;
        p.term_fac = lp.term_fac;
        p.coeff = lp.coeff;
        var total_tab: usize = 0;
        var n_claims: usize = 0;
        for (specs) |sp| switch (sp) {
            .int => |v| if (v.len != len) return null,
            .eq_prefix => |ep| {
                const sp_ = prefixSplit(ep) orelse return null;
                if ((@as(usize, 1) << @intCast(ep.point.len + ep.free_bits)) != len) return null;
                total_tab += (@as(usize, 1) << @intCast(sp_.n_pre)) + (@as(usize, 1) << @intCast(sp_.lo_bits));
                n_claims += 1;
            },
            .eq => |cs| for (cs) |c| {
                if (c.offset + (@as(usize, 1) << @intCast(c.point.len)) > len) return error.BatchClaimRange;
                const lo = c.point.len / 2;
                total_tab += (@as(usize, 1) << @intCast(c.point.len - lo)) + (@as(usize, 1) << @intCast(lo));
                n_claims += 1;
            },
        };
        const tabs = try g.alloc(@max(1, total_tab) * 16);
        errdefer g.free(tabs);
        const cbuf = try g.alloc(@max(1, n_claims) * @sizeOf(BatchClaimGpu));
        errdefer g.free(cbuf);
        const tq: [*]QM31 = @ptrCast(@alignCast(tabs.ptr()));
        const cq: [*]BatchClaimGpu = @ptrCast(@alignCast(cbuf.ptr()));
        var at: usize = 0;
        var ci: usize = 0;
        var srcs: [4]?Buf = .{ null, null, null, null };
        errdefer for (srcs) |b| if (b) |x| g.release(x, null);
        for (specs, 0..) |sp, j| switch (sp) {
            .int => |v| {
                lp.fac[j] = .{ .kind = 0, .claim0 = 0, .n_claims = 0 };
                srcs[j] = try g.view(@constCast(std.mem.sliceAsBytes(v)), true);
            },
            .eq_prefix => |ep| {
                // one claim at offset 0: pre = eq(point[..n_pre]) over the high
                // eq bits, suf[j] = eq(point[n_pre..], j >> free_bits) over the
                // low eq bits and the free bits, so pre[i >> lo] * suf[i & mask]
                // = eq(point, i >> free_bits)
                const sp_ = prefixSplit(ep).?;
                lp.fac[j] = .{ .kind = 1, .claim0 = @intCast(ci), .n_claims = 1 };
                const ca = std.heap.c_allocator;
                const pre = try f.eqTable(ca, ep.point[0..sp_.n_pre], QM31.one());
                defer ca.free(pre);
                const eql = try f.eqTable(ca, ep.point[sp_.n_pre..], QM31.one());
                defer ca.free(eql);
                @memcpy(tq[at..][0..pre.len], pre);
                const suf_len = @as(usize, 1) << @intCast(sp_.lo_bits);
                for (0..suf_len) |q| tq[at + pre.len + q] = eql[q >> @intCast(ep.free_bits)];
                cq[ci] = .{ .offset = 0, .count = @intCast(len), .lo_bits = sp_.lo_bits, .pre_off = @intCast(at), .suf_off = @intCast(at + pre.len) };
                at += pre.len + suf_len;
                ci += 1;
            },
            .eq => |cs| {
                lp.fac[j] = .{ .kind = 1, .claim0 = @intCast(ci), .n_claims = @intCast(cs.len) };
                for (cs) |c| {
                    const n = c.point.len;
                    const lo = n / 2;
                    const pre = try f.eqTable(std.heap.c_allocator, c.point[0 .. n - lo], c.gamma);
                    defer std.heap.c_allocator.free(pre);
                    const suf = try f.eqTable(std.heap.c_allocator, c.point[n - lo ..], QM31.one());
                    defer std.heap.c_allocator.free(suf);
                    @memcpy(tq[at..][0..pre.len], pre);
                    @memcpy(tq[at + pre.len ..][0..suf.len], suf);
                    cq[ci] = .{ .offset = @intCast(c.offset), .count = @intCast(@as(usize, 1) << @intCast(n)), .lo_bits = @intCast(lo), .pre_off = @intCast(at), .suf_off = @intCast(at + pre.len) };
                    at += pre.len + suf.len;
                    ci += 1;
                }
            },
        };
        // segment index per eq factor (claim0 / n_claims become seg0 / n_segs)
        const sxl = try buildSegments(std.heap.c_allocator, specs, &lp);
        defer std.heap.c_allocator.free(sxl);
        const sbuf = try g.alloc(@max(1, sxl.len) * 4);
        errdefer g.free(sbuf);
        const sq: [*]u32 = @ptrCast(@alignCast(sbuf.ptr()));
        @memcpy(sq[0..sxl.len], sxl);
        const s = try std.heap.c_allocator.create(Session);
        errdefer std.heap.c_allocator.destroy(s);
        s.* = .{ .bufs = undefined, .nf = 0, .partials = try g.alloc(SC_MAX_GROUPS * 3 * 16), .base = p, .len = len, .active = active, .a = std.heap.c_allocator, .lazy = .{ .srcs = srcs, .tabs = tabs, .claims = cbuf, .segs = sbuf, .params = lp, .active0 = active } };
        g.stats.sc_calls += 1;
        return s;
    }

    /// pre/suf split of an eq_prefix factor: the suffix table covers the low
    /// eq bits plus the free bits (both tables at most 2^20 entries).
    fn prefixSplit(ep: t.accel.EqPrefix) ?struct { n_pre: usize, lo_bits: u32 } {
        const nb = ep.point.len;
        const l2 = nb / 2;
        const lo = l2 + ep.free_bits;
        if (lo > 20 or nb - l2 > 20 or nb + ep.free_bits >= 31) return null;
        return .{ .n_pre = nb - l2, .lo_bits = @intCast(lo) };
    }

    /// Segment index of the eq factors' claims: per factor j, the breakpoints
    /// {offset, offset + count} of its claims cut the table into disjoint
    /// intervals; each interval covered by at least one claim becomes a
    /// segment (start, end, list0, nlist) listing exactly the (global) claim
    /// indices that cover it. Segments of all factors come first, then the
    /// lists. lp.fac[j].claim0 / n_claims are rewritten to (seg0, n_segs).
    fn buildSegments(a: std.mem.Allocator, specs: []const t.accel.FactorSpec, lp: *LazyParams) ![]u32 {
        var segs: std.ArrayList([4]u32) = .empty;
        defer segs.deinit(a);
        var lists: std.ArrayList(u32) = .empty;
        defer lists.deinit(a);
        var bps: std.ArrayList(usize) = .empty;
        defer bps.deinit(a);
        var ci: u32 = 0;
        for (specs, 0..) |sp, j| switch (sp) {
            .int => {},
            .eq_prefix => |ep| {
                const n = @as(usize, 1) << @intCast(ep.point.len + ep.free_bits);
                lp.fac[j].claim0 = @intCast(segs.items.len);
                lp.fac[j].n_claims = 1;
                try lists.append(a, ci);
                try segs.append(a, .{ 0, @intCast(n), @intCast(lists.items.len - 1), 1 });
                ci += 1;
            },
            .eq => |cs| {
                bps.clearRetainingCapacity();
                for (cs) |c| {
                    try bps.append(a, c.offset);
                    try bps.append(a, c.offset + (@as(usize, 1) << @intCast(c.point.len)));
                }
                std.mem.sort(usize, bps.items, {}, std.sort.asc(usize));
                const seg0: u32 = @intCast(segs.items.len);
                var k: usize = 0;
                while (k + 1 < bps.items.len) : (k += 1) {
                    const lo = bps.items[k];
                    const hi = bps.items[k + 1];
                    if (lo == hi) continue;
                    const l0 = lists.items.len;
                    for (cs, 0..) |c, q| {
                        const c_end = c.offset + (@as(usize, 1) << @intCast(c.point.len));
                        if (c.offset <= lo and hi <= c_end) try lists.append(a, ci + @as(u32, @intCast(q)));
                    }
                    const nl = lists.items.len - l0;
                    if (nl == 0) continue;
                    try segs.append(a, .{ @intCast(lo), @intCast(hi), @intCast(l0), @intCast(nl) });
                }
                lp.fac[j].claim0 = seg0;
                lp.fac[j].n_claims = @intCast(segs.items.len - seg0);
                ci += @intCast(cs.len);
            },
        };
        const base: u32 = @intCast(4 * segs.items.len);
        const out = try a.alloc(u32, 4 * segs.items.len + lists.items.len);
        for (segs.items, 0..) |sg, i| out[4 * i ..][0..4].* = .{ sg[0], sg[1], sg[2] + base, sg[3] };
        @memcpy(out[4 * segs.items.len ..], lists.items);
        return out;
    }

    fn scAbort(ctx: *anyopaque, sp: *anyopaque) void {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const s: *Session = @ptrCast(@alignCast(sp));
        if (s.lazy) |lz| {
            for (lz.srcs) |b| if (b) |x| g.release(x, null);
            g.free(lz.tabs);
            g.free(lz.claims);
            g.free(lz.segs);
        } else for (s.bufs[0..s.nf]) |b| g.release(b, null);
        g.free(s.partials);
        s.a.destroy(s);
    }
};
