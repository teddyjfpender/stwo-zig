//! CUDA accelerator for the tensor prover: fills `accel.Accel` with the C ABI
//! of tc_api.h (libtensor_cuda). The same Zig code links either the nvcc
//! build (zig build -Dcuda=true, a real NVIDIA device) or the CPU emulation
//! of the identical kernel sources (zig build test-cuda-emu), so every hook
//! below is exercised, bit for bit, on machines without a GPU.
//!
//! Contract (as metal/gpu.zig): every result is bit-identical to the CPU
//! path; the transcript and all challenge derivation stay on the CPU; a hook
//! may decline (null) and the CPU runs instead.
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const pcs = t.pcs;
const sc = t.sumcheck;
const Accel = t.accel.Accel;
const QM31 = f.QM31;
const M31 = f.M31;
const Hash = [32]u8;

pub const TcCtx = opaque {};
pub const TcSc = opaque {};

pub const Stats = extern struct {
    launches: u64,
    h2d_bytes: u64,
    d2h_bytes: u64,
    syncs: u64,
    device_allocs: u64,
    resident_hits: u64,
    sc_sessions: u64,
    sc_rounds: u64,
    commits: u64,
    weight_passes: u64,
    matmuls: u64,
    mles: u64,
    gkr_layers: u64,
};

pub const Terms = extern struct {
    n_factors: u32,
    n_terms: u32,
    deg: u32,
    pad: u32 = 0,
    term_len: [4]u32,
    term_fac: [4][3]u32,
    coeff: [4][4]u32,
};

pub const Claim = extern struct { offset: u64, point: [*]const u32, point_len: u32, gamma: [4]u32 };
pub const Spec = extern struct {
    kind: u32,
    free_bits: u32 = 0,
    ints: ?[*]const i32 = null,
    n_ints: u64 = 0,
    claims: ?[*]const Claim = null,
    n_claims: u32 = 0,
    pad: u32 = 0,
};
pub const SPEC_INT: u32 = 0;
pub const SPEC_EQ: u32 = 1;
pub const SPEC_EQ_PREFIX: u32 = 2;

pub extern fn tc_backend_kind() c_int;
pub extern fn tc_create(device: c_int) ?*TcCtx;
pub extern fn tc_destroy(ctx: *TcCtx) void;
pub extern fn tc_last_error(ctx: *TcCtx) [*:0]const u8;
pub extern fn tc_get_stats(ctx: *TcCtx, out: *Stats) void;
pub extern fn tc_device_name(ctx: *TcCtx) [*:0]const u8;
pub extern fn tc_pin(ctx: *TcCtx, host: *const anyopaque, bytes: u64) c_int;
pub extern fn tc_unpin_all(ctx: *TcCtx) void;
pub extern fn tc_qm_mul_batch(ctx: *TcCtx, x: [*]const u32, y: [*]const u32, n: u64, out: [*]u32) c_int;
pub extern fn tc_eq_table(ctx: *TcCtx, point: [*]const u32, n: u32, gamma: *const [4]u32, out: [*]u32) c_int;
pub extern fn tc_combine_rows(ctx: *TcCtx, m: *const anyopaque, is_i8: c_int, R: u64, C: u64, coeffs: [*]const u32, G: u32, out: [*]u32) c_int;
pub extern fn tc_row_dots_i8(ctx: *TcCtx, m: [*]const i8, R: u64, C: u64, vec: [*]const u32, out: [*]u32) c_int;
pub extern fn tc_matmul_i32_i8(ctx: *TcCtx, x: [*]const i32, w: [*]const i8, T: u32, K: u32, N: u32, out: [*]i64) c_int;
pub extern fn tc_mle_i32(ctx: *TcCtx, v: [*]const i32, log_n: u32, point: [*]const u32, out: *[4]u32) c_int;
pub extern fn tc_sc_begin(ctx: *TcCtx, factors: [*]const [*]const u32, nf: u32, len: u64, active: u64, terms: *const Terms) ?*TcSc;
pub extern fn tc_sc_begin_specs(ctx: *TcCtx, specs: [*]const Spec, nf: u32, len: u64, active: u64, terms: *const Terms) ?*TcSc;
pub extern fn tc_sc_round(ctx: *TcCtx, s: *TcSc, r_prev: ?*const [4]u32, out: *[12]u32) c_int;
pub extern fn tc_sc_finish(ctx: *TcCtx, s: *TcSc, r_last: *const [4]u32, out: [*]const [*]u32) c_int;
pub extern fn tc_sc_len(s: *TcSc) u64;
pub extern fn tc_sc_abort(ctx: *TcCtx, s: *TcSc) void;
pub extern fn tc_commit(ctx: *TcCtx, m: *const anyopaque, is_i8: c_int, R: u64, log_c: u32, log_b: u32, twiddles: [*]const u32, tw_len: u32, enc_out: *?[*]u32, nodes_out: [*]u8) c_int;
pub extern fn tc_free_visible(ctx: *TcCtx, p: *anyopaque) void;
pub extern fn tc_set_commit_chunk_rows(ctx: *TcCtx, rows: u64) void;
pub extern fn tc_gkr_layer(ctx: *TcCtx, in_off: [*]const u64, out_off: [*]const u64, n_inst: u32, num: [*]const u32, den: [*]const u32, n_in: u64, num_out: [*]u32, den_out: [*]u32) c_int;

pub fn limbsPtr(x: []const QM31) [*]const u32 {
    return @ptrCast(x.ptr);
}

pub const Cuda = struct {
    ctx: *TcCtx,
    acc: Accel,
    /// weight passes below this many matrix entries stay on the CPU
    min_pass_elems: usize = 1 << 16,
    /// declined calls (shape outside the device kernels' bounds)
    declined: u64 = 0,

    pub fn init(a: std.mem.Allocator, device: c_int) !*Cuda {
        const ctx = tc_create(device) orelse return error.CudaInit;
        const self = try a.create(Cuda);
        self.* = .{ .ctx = ctx, .acc = undefined };
        self.acc = .{
            .ctx = self,
            .commit_i32 = commitI32,
            .commit_i8 = commitI8,
            .sc_begin = scBegin,
            .sc_round = scRound,
            .sc_finish = scFinish,
            .sc_abort = scAbort,
            .sc_begin_lazy = scBeginLazy,
            .matmul_acc = matmulAcc,
            .combine_i8 = combineI8,
            .combine_i32 = combineI32,
            .row_dots_i8 = rowDotsI8,
            .mle_eval_i32 = mleEvalI32,
            // LogUp-GKR stays on the CPU until the batched device prover
            // (tc_gkr_layer + device sumcheck rounds) is wired; cuda.md.
            .gkr_prove = null,
        };
        return self;
    }

    pub fn deinit(self: *Cuda, a: std.mem.Allocator) void {
        tc_destroy(self.ctx);
        a.destroy(self);
    }

    pub fn accel(self: *Cuda) *const Accel {
        return &self.acc;
    }

    pub fn stats(self: *Cuda) Stats {
        var s: Stats = undefined;
        tc_get_stats(self.ctx, &s);
        return s;
    }

    pub fn isEmulation(_: *Cuda) bool {
        return tc_backend_kind() == 2;
    }

    pub fn deviceName(self: *Cuda) []const u8 {
        return std.mem.span(tc_device_name(self.ctx));
    }

    /// Keep a host range (e.g. the committed weight table) on the device for
    /// the context's life; later passes over it skip the upload. The caller
    /// must call unpinAll before freeing or changing the range.
    pub fn pin(self: *Cuda, bytes: []const u8) !void {
        if (tc_pin(self.ctx, bytes.ptr, bytes.len) != 0) return self.err();
    }
    pub fn unpinAll(self: *Cuda) void {
        tc_unpin_all(self.ctx);
    }

    fn err(self: *Cuda) error{CudaFailed} {
        std.log.err("tensor cuda: {s}", .{tc_last_error(self.ctx)});
        return error.CudaFailed;
    }

    fn from(ctx: *anyopaque) *Cuda {
        return @ptrCast(@alignCast(ctx));
    }

    // -----------------------------------------------------------------------
    // Commitment

    fn commitI32(ctx: *anyopaque, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(i32), lb: u32) anyerror!?pcs.Committed {
        return from(ctx).commit(i32, a, tw, m, lb);
    }
    fn commitI8(ctx: *anyopaque, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(i8), lb: u32) anyerror!?pcs.Committed {
        return from(ctx).commit(i8, a, tw, m, lb);
    }

    fn releaseEnc(ctx: *anyopaque, handle: *anyopaque) void {
        tc_free_visible(from(ctx).ctx, handle);
    }

    pub fn commit(self: *Cuda, comptime T: type, a: std.mem.Allocator, tw: *const pcs.Twiddles, m: pcs.Matrix(T), lb: u32) !?pcs.Committed {
        const R = m.usedRows();
        const log_e = m.log_cols + lb;
        const E = @as(usize, 1) << @intCast(log_e);
        if (log_e < 3 or log_e > 30 or R == 0 or tw.domain.logSize() != log_e or tw.tree.twiddles.len != E / 2) {
            self.declined += 1;
            return null;
        }
        const nodes = try a.alloc(Hash, 2 * E);
        errdefer a.free(nodes);
        var enc: ?[*]u32 = null;
        if (tc_commit(self.ctx, m.data.ptr, @intFromBool(T == i8), R, m.log_cols, lb, @ptrCast(tw.tree.twiddles.ptr), @intCast(tw.tree.twiddles.len), &enc, @ptrCast(nodes.ptr)) != 0) return self.err();
        const enc_m: [*]M31 = @ptrCast(enc.?);
        return .{
            .combine = .{ .ctx = self, .i8 = combineI8, .i32 = combineI32 },
            .enc_owner = .{ .ctx = self, .handle = @ptrCast(enc.?), .release = releaseEnc },
            .log_rows = m.log_rows,
            .log_cols = m.log_cols,
            .log_blowup = lb,
            .rows_used = R,
            .enc = enc_m[0 .. R * E],
            .tree = .{ .nodes = nodes, .n_leaves = E },
        };
    }

    // -----------------------------------------------------------------------
    // Weight passes, matmul, MLE

    fn combineI8(ctx: *anyopaque, a: std.mem.Allocator, m: pcs.Matrix(i8), coeffs: []const []const QM31) anyerror!?[][]QM31 {
        return from(ctx).combine(i8, a, m, coeffs);
    }
    fn combineI32(ctx: *anyopaque, a: std.mem.Allocator, m: pcs.Matrix(i32), coeffs: []const []const QM31) anyerror!?[][]QM31 {
        return from(ctx).combine(i32, a, m, coeffs);
    }

    pub fn combine(self: *Cuda, comptime T: type, a: std.mem.Allocator, m: pcs.Matrix(T), coeffs: []const []const QM31) !?[][]QM31 {
        const R = m.usedRows();
        const C = m.nCols();
        const G = coeffs.len;
        if (G == 0 or G > 4 or R == 0 or R * C < self.min_pass_elems) {
            self.declined += 1;
            return null;
        }
        const cbuf = try a.alloc(QM31, G * R);
        defer a.free(cbuf);
        for (coeffs, 0..) |cg, g| @memcpy(cbuf[g * R ..][0..R], cg[0..R]);
        const flat = try a.alloc(QM31, G * C);
        defer a.free(flat);
        if (tc_combine_rows(self.ctx, m.data.ptr, @intFromBool(T == i8), R, C, limbsPtr(cbuf), @intCast(G), @ptrCast(flat.ptr)) != 0) return self.err();
        const out = try a.alloc([]QM31, G);
        var made: usize = 0;
        errdefer {
            for (out[0..made]) |o| a.free(o);
            a.free(out);
        }
        for (0..G) |g| {
            out[g] = try a.dupe(QM31, flat[g * C ..][0..C]);
            made += 1;
        }
        return out;
    }

    fn rowDotsI8(ctx: *anyopaque, a: std.mem.Allocator, m: pcs.Matrix(i8), vec: []const QM31) anyerror!?[]QM31 {
        const self = from(ctx);
        const R = m.nRows();
        const C = m.nCols();
        if (vec.len != C or R * C < self.min_pass_elems or R >= (1 << 31) or C > (1 << 24)) {
            self.declined += 1;
            return null;
        }
        const out = try a.alloc(QM31, R);
        errdefer a.free(out);
        if (tc_row_dots_i8(self.ctx, m.data.ptr, R, C, limbsPtr(vec), @ptrCast(out.ptr)) != 0) return self.err();
        return out;
    }

    fn matmulAcc(ctx: *anyopaque, a: std.mem.Allocator, x: []const i32, T: usize, wm: pcs.Matrix(i8)) anyerror!?[]i64 {
        const self = from(ctx);
        const K = wm.nRows();
        const N = wm.nCols();
        if (x.len != T * K or T >= (1 << 32) or N >= (1 << 32) or K >= (1 << 24)) {
            self.declined += 1;
            return null;
        }
        const out = try a.alloc(i64, T * N);
        errdefer a.free(out);
        if (tc_matmul_i32_i8(self.ctx, x.ptr, wm.data.ptr, @intCast(T), @intCast(K), @intCast(N), out.ptr) != 0) return self.err();
        return out;
    }

    fn mleEvalI32(ctx: *anyopaque, values: []const i32, point: []const QM31) anyerror!?QM31 {
        const self = from(ctx);
        if (values.len != (@as(usize, 1) << @intCast(point.len)) or point.len > 34) {
            self.declined += 1;
            return null;
        }
        var out: [4]u32 = undefined;
        if (tc_mle_i32(self.ctx, values.ptr, @intCast(point.len), limbsPtr(point), &out) != 0) return self.err();
        return f.fromLimbs(out);
    }

    // -----------------------------------------------------------------------
    // Sumcheck

    fn termsOf(terms: []const sc.Term, nf: usize) Terms {
        var tt = std.mem.zeroes(Terms);
        tt.n_factors = @intCast(nf);
        tt.n_terms = @intCast(terms.len);
        var deg: u32 = 2;
        for (terms, 0..) |term, i| {
            tt.term_len[i] = @intCast(term.factors.len);
            for (term.factors, 0..) |fi, k| tt.term_fac[i][k] = fi;
            tt.coeff[i] = f.limbs(term.coeff);
            deg = @max(deg, @as(u32, @intCast(term.factors.len)));
        }
        tt.deg = deg;
        return tt;
    }

    fn scBegin(ctx: *anyopaque, factors: []const []QM31, terms: []const sc.Term, active: usize) anyerror!?*anyopaque {
        const self = from(ctx);
        if (factors.len == 0 or factors.len > 4 or terms.len > 4) return null;
        var ptrs: [4][*]const u32 = undefined;
        for (factors, 0..) |fac, j| ptrs[j] = limbsPtr(fac);
        const tt = termsOf(terms, factors.len);
        const s = tc_sc_begin(self.ctx, &ptrs, @intCast(factors.len), factors[0].len, active, &tt) orelse return self.err();
        return @ptrCast(s);
    }

    fn scBeginLazy(ctx: *anyopaque, specs: []const t.accel.FactorSpec, terms: []const sc.Term, len: usize, active: usize) anyerror!?*anyopaque {
        const self = from(ctx);
        if (specs.len == 0 or specs.len > 4 or terms.len > 4) return null;
        var claim_bufs: [4][]Claim = .{ &.{}, &.{}, &.{}, &.{} };
        defer for (claim_bufs) |cb| if (cb.len > 0) std.heap.c_allocator.free(cb);
        var cs: [4]Spec = undefined;
        for (specs, 0..) |spec, j| {
            switch (spec) {
                .int => |v| cs[j] = .{ .kind = SPEC_INT, .ints = v.ptr, .n_ints = v.len },
                .eq => |claims| {
                    const cb = try std.heap.c_allocator.alloc(Claim, @max(1, claims.len));
                    claim_bufs[j] = cb;
                    for (claims, 0..) |c, k| cb[k] = .{ .offset = c.offset, .point = limbsPtr(c.point), .point_len = @intCast(c.point.len), .gamma = f.limbs(c.gamma) };
                    cs[j] = .{ .kind = SPEC_EQ, .claims = cb.ptr, .n_claims = @intCast(claims.len) };
                },
                .eq_prefix => |ep| {
                    const cb = try std.heap.c_allocator.alloc(Claim, 1);
                    claim_bufs[j] = cb;
                    cb[0] = .{ .offset = 0, .point = limbsPtr(ep.point), .point_len = @intCast(ep.point.len), .gamma = f.limbs(QM31.one()) };
                    cs[j] = .{ .kind = SPEC_EQ_PREFIX, .free_bits = ep.free_bits, .claims = cb.ptr, .n_claims = 1 };
                },
            }
        }
        const tt = termsOf(terms, specs.len);
        const s = tc_sc_begin_specs(self.ctx, &cs, @intCast(specs.len), len, active, &tt) orelse return self.err();
        return @ptrCast(s);
    }

    fn scRound(ctx: *anyopaque, sp: *anyopaque, r_prev: ?QM31) anyerror![3]QM31 {
        const self = from(ctx);
        var out: [12]u32 = undefined;
        const rl: ?[4]u32 = if (r_prev) |r| f.limbs(r) else null;
        if (tc_sc_round(self.ctx, @ptrCast(sp), if (rl) |*x| x else null, &out) != 0) return self.err();
        return .{ f.fromLimbs(out[0..4].*), f.fromLimbs(out[4..8].*), f.fromLimbs(out[8..12].*) };
    }

    fn scFinish(ctx: *anyopaque, sp: *anyopaque, r_last: QM31, out: []const []QM31) anyerror!void {
        const self = from(ctx);
        const s: *TcSc = @ptrCast(sp);
        var ptrs: [4][*]u32 = undefined;
        for (out, 0..) |o, j| {
            std.debug.assert(o.len == tc_sc_len(s));
            ptrs[j] = @ptrCast(o.ptr);
        }
        const rl = f.limbs(r_last);
        if (tc_sc_finish(self.ctx, s, &rl, &ptrs) != 0) return self.err();
    }

    fn scAbort(ctx: *anyopaque, sp: *anyopaque) void {
        tc_sc_abort(from(ctx).ctx, @ptrCast(sp));
    }
};
