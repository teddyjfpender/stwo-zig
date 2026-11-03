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

extern fn tm_create(source: [*:0]const u8, err: [*]u8, err_len: usize) ?*anyopaque;
extern fn tm_destroy(rt: *anyopaque) void;
extern fn tm_pipeline(rt: *anyopaque, name: [*:0]const u8, err: [*]u8, err_len: usize) ?*anyopaque;
extern fn tm_pipeline_max_threads(p: *anyopaque) u32;
extern fn tm_release(obj: *anyopaque) void;
extern fn tm_buffer_alloc(rt: *anyopaque, len: usize) ?*anyopaque;
extern fn tm_buffer_wrap(rt: *anyopaque, ptr: *anyopaque, len: usize) ?*anyopaque;
extern fn tm_buffer_contents(buf: *anyopaque) *anyopaque;
extern fn tm_cmd_begin(rt: *anyopaque) *anyopaque;
extern fn tm_cmd_pipeline(cmd: *anyopaque, p: *anyopaque) void;
extern fn tm_cmd_buffer(cmd: *anyopaque, index: u32, buf: *anyopaque, offset: usize) void;
extern fn tm_cmd_bytes(cmd: *anyopaque, index: u32, bytes: *const anyopaque, len: usize) void;
extern fn tm_cmd_threadgroup_memory(cmd: *anyopaque, index: u32, len: usize) void;
extern fn tm_cmd_dispatch(cmd: *anyopaque, gx: u32, gy: u32, gz: u32, tx: u32, ty: u32, tz: u32) void;
extern fn tm_cmd_end(cmd: *anyopaque, gpu_ms: *f64, err: [*]u8, err_len: usize) c_int;

pub const source: [:0]const u8 = @import("tensor_metal_shaders").source;

pub const Error = error{ MetalInit, MetalPipeline, MetalAlloc, MetalCommand };

// ---------------------------------------------------------------------------
// Device buffers over host memory.

const Buf = struct {
    handle: *anyopaque,
    /// host slice the buffer mirrors (null for device-only scratch)
    host: ?[]u8 = null,
    /// true when `handle` aliases `host` (no copies needed)
    aliased: bool = false,

    fn ptr(self: Buf) [*]u8 {
        return @ptrCast(tm_buffer_contents(self.handle));
    }
};

pub const Stats = struct {
    commit_gpu_ms: f64 = 0,
    commit_calls: usize = 0,
    sc_gpu_ms: f64 = 0,
    sc_rounds: usize = 0,
    sc_calls: usize = 0,
    wrapped_bytes: usize = 0,
    copied_bytes: usize = 0,
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
            .page = std.heap.pageSize(),
        };
        g.vt = .{
            .ctx = g,
            .commit_i32 = commitI32,
            .commit_i8 = commitI8,
            .sc_begin = scBegin,
            .sc_round = scRound,
            .sc_finish = scFinish,
            .sc_abort = scAbort,
        };
        return g;
    }

    pub fn deinit(self: *Gpu, a: std.mem.Allocator) void {
        inline for (.{ "p_expand_i32", "p_expand_i8", "p_layer", "p_tail", "p_leaf", "p_parents", "p_sc_round", "p_sc_fold" }) |name|
            tm_release(@field(self, name));
        tm_destroy(self.rt);
        a.destroy(self);
    }

    pub fn accel(self: *Gpu) *const Accel {
        return &self.vt;
    }

    fn pipeline(rt: *anyopaque, name: [:0]const u8) !*anyopaque {
        var err: [1024]u8 = undefined;
        @memset(&err, 0);
        return tm_pipeline(rt, name.ptr, &err, err.len) orelse {
            std.log.err("metal pipeline {s}: {s}", .{ name, std.mem.sliceTo(&err, 0) });
            return Error.MetalPipeline;
        };
    }

    fn alloc(self: *Gpu, len: usize) !Buf {
        return .{ .handle = tm_buffer_alloc(self.rt, len) orelse return Error.MetalAlloc };
    }

    /// Device view of host memory: aliased (zero-copy) when page aligned,
    /// otherwise a shared buffer, filled from host when `copy_in`.
    fn view(self: *Gpu, host: []u8, copy_in: bool) !Buf {
        const addr = @intFromPtr(host.ptr);
        if (host.len > 0 and addr % self.page == 0) {
            const len = std.mem.alignForward(usize, host.len, self.page);
            if (tm_buffer_wrap(self.rt, host.ptr, len)) |h| {
                self.stats.wrapped_bytes += host.len;
                return .{ .handle = h, .host = host, .aliased = true };
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
    fn release(self: *Gpu, b: Buf, copy_out: ?usize) void {
        if (copy_out) |n| if (!b.aliased) {
            if (b.host) |h| {
                @memcpy(h[0..n], b.ptr()[0..n]);
                self.stats.copied_bytes += n;
            }
        };
        tm_release(b.handle);
    }

    fn end(cmd: *anyopaque) !f64 {
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

        const enc = try a.alloc(M31, R * E);
        errdefer a.free(enc);
        const nodes = try a.alloc(Hash, 2 * E);
        errdefer a.free(nodes);

        const in_bytes = std.mem.sliceAsBytes(m.data[0 .. R * C]);
        const in_buf = try self.view(@constCast(in_bytes), true);
        defer self.release(in_buf, null);
        const enc_buf = try self.view(std.mem.sliceAsBytes(enc), false);
        var enc_released = false;
        defer if (!enc_released) self.release(enc_buf, null);
        const tw_buf = try self.view(@constCast(std.mem.sliceAsBytes(tw.tree.twiddles)), true);
        defer self.release(tw_buf, null);
        const nodes_buf = try self.view(std.mem.sliceAsBytes(nodes), false);
        var nodes_released = false;
        defer if (!nodes_released) self.release(nodes_buf, null);
        const states = try self.alloc(E * 32);
        defer tm_release(states.handle);

        var ch = (self.chunk_bytes / (E * 4)) & ~@as(usize, 15);
        if (ch < 16) ch = 16;
        if (ch > R) ch = R;
        const scratch = try self.alloc(ch * E * 4);
        defer tm_release(scratch.handle);

        const tile_log = @min(TILE_LOG, log_e);
        const cmd = tm_cmd_begin(self.rt);
        var row0: usize = 0;
        while (row0 < R) : (row0 += ch) {
            const rows = @min(ch, R - row0);
            // expansion (implicit top lb layers)
            const ep = ExpandParams{ .log_c = log_c, .log_e = log_e, .rows = @intCast(rows), .row0 = @intCast(row0) };
            tm_cmd_pipeline(cmd, if (T == i8) self.p_expand_i8 else self.p_expand_i32);
            tm_cmd_buffer(cmd, 0, in_buf.handle, 0);
            tm_cmd_buffer(cmd, 1, scratch.handle, 0);
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
                tm_cmd_buffer(cmd, 0, scratch.handle, 0);
                tm_cmd_buffer(cmd, 1, tw_buf.handle, 0);
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
            tm_cmd_buffer(cmd, 0, scratch.handle, 0);
            tm_cmd_buffer(cmd, 1, tw_buf.handle, 0);
            tm_cmd_bytes(cmd, 2, &tp, @sizeOf(TailParams));
            tm_cmd_threadgroup_memory(cmd, 0, tile * 4);
            tm_cmd_dispatch(cmd, @intCast(rows * (E >> @intCast(tile_log))), 1, 1, threads, 1, 1);
            // column leaves (streamed Blake2s) + column-major codeword
            const lp = LeafParams{ .log_e = log_e, .rows = @intCast(rows), .row0 = @intCast(row0), .total_rows = @intCast(R), .last_chunk = @intFromBool(row0 + rows == R) };
            tm_cmd_pipeline(cmd, self.p_leaf);
            tm_cmd_buffer(cmd, 0, scratch.handle, 0);
            tm_cmd_buffer(cmd, 1, states.handle, 0);
            tm_cmd_buffer(cmd, 2, enc_buf.handle, 0);
            tm_cmd_buffer(cmd, 3, nodes_buf.handle, 0);
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
            tm_cmd_buffer(cmd, 0, nodes_buf.handle, 0);
            tm_cmd_bytes(cmd, 1, &child_off, 4);
            tm_cmd_bytes(cmd, 2, &dst_off, 4);
            tm_cmd_bytes(cmd, 3, &cnt, 4);
            const th: u32 = @min(256, cnt);
            tm_cmd_dispatch(cmd, (cnt + th - 1) / th, 1, 1, th, 1, 1);
            if (level == 1) break;
        }
        self.stats.commit_gpu_ms += try end(cmd);
        self.stats.commit_calls += 1;
        enc_released = true;
        self.release(enc_buf, enc.len * 4);
        nodes_released = true;
        self.release(nodes_buf, nodes.len * 32);
        return .{
            .log_rows = m.log_rows,
            .log_cols = m.log_cols,
            .log_blowup = lb,
            .rows_used = R,
            .enc = enc,
            .tree = .{ .nodes = nodes, .n_leaves = E },
        };
    }

    // -----------------------------------------------------------------------
    // Sumcheck

    const Q = extern struct { a: u32, b: u32, c: u32, d: u32 };
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

    fn toQ(x: QM31) Q {
        const l = f.limbs(x);
        return .{ .a = l[0], .b = l[1], .c = l[2], .d = l[3] };
    }
    fn fromQ(q: Q) QM31 {
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
    };

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
        for (0..4) |j| tm_cmd_buffer(cmd, @intCast(j), s.bufs[if (j < s.nf) j else 0].handle, 0);
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
        tm_cmd_pipeline(cmd, g.p_sc_round);
        bindFactors(s, cmd);
        tm_cmd_buffer(cmd, 4, s.partials.handle, 0);
        tm_cmd_bytes(cmd, 5, &p, @sizeOf(ScParams));
        tm_cmd_threadgroup_memory(cmd, 0, SC_TG * 3 * 16);
        tm_cmd_dispatch(cmd, groups, 1, 1, SC_TG, 1, 1);
        g.stats.sc_gpu_ms += try end(cmd);
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

    fn scFinish(ctx: *anyopaque, sp: *anyopaque, r_last: QM31) anyerror!void {
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
        tm_cmd_pipeline(cmd, g.p_sc_fold);
        bindFactors(s, cmd);
        tm_cmd_bytes(cmd, 5, &p, @sizeOf(ScParams));
        const w: u32 = @intCast(s.active);
        if (w > 0) tm_cmd_dispatch(cmd, (w + 255) / 256, 1, 1, 256, 1, 1);
        g.stats.sc_gpu_ms += try end(cmd);
        for (s.bufs[0..s.nf]) |*b| {
            if (!b.aliased) {
                const n = @min(s.len * 16, b.host.?.len);
                @memcpy(b.host.?[0..n], b.ptr()[0..n]);
                g.stats.copied_bytes += n;
            }
        }
    }

    fn scAbort(ctx: *anyopaque, sp: *anyopaque) void {
        const g: *Gpu = @ptrCast(@alignCast(ctx));
        const s: *Session = @ptrCast(@alignCast(sp));
        for (s.bufs[0..s.nf]) |b| g.release(b, null);
        tm_release(s.partials.handle);
        s.a.destroy(s);
    }
};
