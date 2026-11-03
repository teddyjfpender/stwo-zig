//! Metal LogUp-GKR batch prover: the control flow, transcript and proof
//! assembly of `gkr_prover_fast.proveBatch` (same channel calls in the same
//! order), with the layer storage in device memory and the layer build, round
//! sums and folds as device kernels. Field arithmetic is exact and the eq
//! table is the same product expansion, so the proof is bit-identical.
const std = @import("std");
const t = @import("stwo_tensor");
const engine = @import("stwo_prover_engine");
const gpu_mod = @import("gpu.zig");
const Gpu = gpu_mod.Gpu;
const Buf = gpu_mod.Buf;
const bind = gpu_mod.bind;
const f = t.field;

const M31 = f.M31;
const QM31 = f.QM31;
const S = QM31;
const lookups = engine.lookups;
const Fast = lookups.gkr_prover_fast.ForField(QM31);
const PF = lookups.gkr_prover.ForField(QM31);
const GV = lookups.gkr_verifier.ForField(QM31);
const SC = lookups.sumcheck.ForField(QM31);
const utils = lookups.utils;
const Poly = utils.UnivariatePoly(S);

const ONES: u32 = 0;
const BASE: u32 = 1;
const SECURE: u32 = 2;

const NextParams = extern struct { size: u32, num_kind: u32 };
const SumParams = extern struct { n_terms: u32, num_kind: u32, eq_lo: u32, _pad: u32 = 0, lambda: Gpu.Q };
const FoldParams = extern struct { half_len: u32, num_kind: u32, _pad0: u32 = 0, _pad1: u32 = 0, r: Gpu.Q };

const TG: u32 = 256;

const Pending = union(enum) { gpu: u32, cpu: [2]S };

fn qs(b: Buf) [*]S {
    return @ptrCast(@alignCast(b.ptr()));
}

/// CPU twin of tm_gkr_sum (same per-term arithmetic).
fn cpuSum(layer: *const Layer, n_terms: usize, eq: EqTabs, lambda: S) [2]S {
    const den = qs(layer.den.?);
    const eqb: [*]const u8 = eq.buf.ptr();
    const pre: [*]const S = @ptrCast(@alignCast(eqb + eq.pre_off));
    const suf: [*]const S = @ptrCast(@alignCast(eqb + eq.suf_off));
    const mask = (@as(usize, 1) << @intCast(eq.lo)) - 1;
    var e0 = S.zero();
    var e2 = S.zero();
    for (0..n_terms) |i| {
        const lo = 2 * i;
        const hi = 2 * (n_terms + i);
        const d00 = den[lo];
        const d01 = den[lo + 1];
        const d10 = den[hi];
        const d11 = den[hi + 1];
        const d20 = d10.add(d10).sub(d00);
        const d21 = d11.add(d11).sub(d01);
        var n0: S = undefined;
        var n2: S = undefined;
        switch (layer.kind) {
            ONES => {
                n0 = d00.add(d01);
                n2 = d20.add(d21);
            },
            BASE => {
                const b: [*]const M31 = @ptrCast(@alignCast(layer.num.?.ptr()));
                const n00 = b[lo];
                const n01 = b[lo + 1];
                const n10 = b[hi];
                const n11 = b[hi + 1];
                const n20 = n10.add(n10).sub(n00);
                const n21 = n11.add(n11).sub(n01);
                n0 = d01.mulM31(n00).add(d00.mulM31(n01));
                n2 = d21.mulM31(n20).add(d20.mulM31(n21));
            },
            else => {
                const nm = qs(layer.num.?);
                const n00 = nm[lo];
                const n01 = nm[lo + 1];
                const n10 = nm[hi];
                const n11 = nm[hi + 1];
                const n20 = n10.add(n10).sub(n00);
                const n21 = n11.add(n11).sub(n01);
                n0 = n00.mul(d01).add(d00.mul(n01));
                n2 = n20.mul(d21).add(d20.mul(n21));
            },
        }
        const w = pre[i >> @intCast(eq.lo)].mul(suf[i & mask]);
        e0 = e0.add(w.mul(n0.add(lambda.mul(d00.mul(d01)))));
        e2 = e2.add(w.mul(n2.add(lambda.mul(d20.mul(d21)))));
    }
    return .{ e0, e2 };
}

fn sumAny(g: *Gpu, cmd: ?*anyopaque, layer: *const Layer, n_terms: usize, eq: EqTabs, lambda: S, partials: Buf, slot: usize) Pending {
    if (n_terms <= g.gkr_cpu_sum_max or cmd == null) return .{ .cpu = cpuSum(layer, n_terms, eq, lambda) };
    return .{ .gpu = encodeSum(g, cmd.?, layer, n_terms, eq, lambda, partials, slot) };
}
const MAX_GROUPS: usize = 512;

/// One layer in device memory: `len` live entries of den (and num unless ones).
const Layer = struct {
    den: ?Buf = null,
    num: ?Buf = null,
    kind: u32 = ONES,
    len: usize = 0,
    /// den/num may be folded in place (device-owned, not the caller's input)
    writable: bool = false,

    fn free(self: *Layer, g: *Gpu) void {
        if (self.den) |b| g.release(b, null);
        if (self.num) |b| g.release(b, null);
        self.* = .{};
    }
    fn denAt(self: Layer, i: usize) S {
        const q: [*]const Gpu.Q = @ptrCast(@alignCast(self.den.?.ptr()));
        return Gpu.fromQ(q[i]);
    }
    fn numAt(self: Layer, i: usize) S {
        return switch (self.kind) {
            ONES => S.one(),
            BASE => blk: {
                const b: [*]const u32 = @ptrCast(@alignCast(self.num.?.ptr()));
                break :blk S.fromBase(M31.fromCanonical(b[i]));
            },
            else => blk: {
                const q: [*]const Gpu.Q = @ptrCast(@alignCast(self.num.?.ptr()));
                break :blk Gpu.fromQ(q[i]);
            },
        };
    }
};

fn pow2(n: usize) M31 {
    return M31.fromU64(@as(u64, 1) << @intCast(n));
}

fn eqOne(x: S, y: S) S {
    return x.mul(y).add(S.one().sub(x).mul(S.one().sub(y)));
}

const EqTabs = struct {
    buf: Buf,
    pre_off: usize,
    suf_off: usize,
    lo: u32,
};

/// eq table of `gkr_prover_fast.eqTable(y)` (scale 1 - y[0] over y[1..],
/// MSB first) factored as prefix (x) suffix.
fn eqTabs(g: *Gpu, y: []const S) !EqTabs {
    const ca = std.heap.c_allocator;
    var pre: []S = undefined;
    var suf: []S = undefined;
    var lo: u32 = 0;
    if (y.len == 0) {
        pre = try ca.dupe(S, &.{S.one()});
        suf = try ca.dupe(S, &.{S.one()});
    } else {
        const r = y[1..];
        lo = @intCast(r.len / 2);
        pre = try f.eqTable(ca, r[0 .. r.len - lo], S.one().sub(y[0]));
        suf = try f.eqTable(ca, r[r.len - lo ..], S.one());
    }
    defer ca.free(pre);
    defer ca.free(suf);
    const buf = try g.alloc((pre.len + suf.len) * 16);
    const q: [*]S = @ptrCast(@alignCast(buf.ptr()));
    @memcpy(q[0..pre.len], pre);
    @memcpy(q[pre.len..][0..suf.len], suf);
    return .{ .buf = buf, .pre_off = 0, .suf_off = pre.len * 16, .lo = lo };
}

fn encodeSum(g: *Gpu, cmd: *anyopaque, layer: *const Layer, n_terms: usize, eq: EqTabs, lambda: S, partials: Buf, slot: usize) u32 {
    const groups: u32 = @intCast(@max(1, @min(MAX_GROUPS, (n_terms + TG * 4 - 1) / (TG * 4))));
    const p = SumParams{ .n_terms = @intCast(n_terms), .num_kind = layer.kind, .eq_lo = eq.lo, .lambda = Gpu.toQ(lambda) };
    gpu_mod.tm_cmd_pipeline(cmd, g.p_gkr_sum);
    bind(cmd, 0, layer.den.?);
    bind(cmd, 1, layer.num orelse layer.den.?);
    gpu_mod.tm_cmd_buffer(cmd, 2, eq.buf.handle, eq.pre_off);
    gpu_mod.tm_cmd_buffer(cmd, 3, eq.buf.handle, eq.suf_off);
    gpu_mod.tm_cmd_buffer(cmd, 4, partials.handle, slot * MAX_GROUPS * 32);
    gpu_mod.tm_cmd_bytes(cmd, 5, &p, @sizeOf(SumParams));
    gpu_mod.tm_cmd_threadgroup_memory(cmd, 0, TG * 32);
    gpu_mod.tm_cmd_dispatch(cmd, groups, 1, 1, TG, 1, 1);
    return groups;
}

fn readSum(partials: Buf, slot: usize, groups: u32) [2]S {
    const q: [*]const Gpu.Q = @ptrCast(@alignCast(partials.ptr()));
    var e0 = S.zero();
    var e2 = S.zero();
    for (0..groups) |i| {
        e0 = e0.add(Gpu.fromQ(q[(slot * MAX_GROUPS + i) * 2]));
        e2 = e2.add(Gpu.fromQ(q[(slot * MAX_GROUPS + i) * 2 + 1]));
    }
    return .{ e0, e2 };
}

/// Folds `layer` by r (first fold of a read-only layer goes to fresh
/// device buffers; base numerators become secure).
fn encodeFold(g: *Gpu, cmd_opt: ?*anyopaque, layer: *Layer, r: S) !void {
    const half = layer.len / 2;
    var den_dst = layer.den.?;
    var num_dst: ?Buf = layer.num;
    var fresh_den = false;
    var fresh_num = false;
    if (!layer.writable) {
        den_dst = try g.alloc(half * 16);
        fresh_den = true;
    }
    if (layer.kind == BASE or (layer.kind == SECURE and !layer.writable)) {
        num_dst = try g.alloc(half * 16);
        fresh_num = true;
    }
    if (half <= g.gkr_cpu_fold_max) {
        const sd = qs(layer.den.?);
        const dd = qs(den_dst);
        for (0..half) |j| dd[j] = r.mul(sd[j + half].sub(sd[j])).add(sd[j]);
        switch (layer.kind) {
            ONES => {},
            BASE => {
                const b: [*]const M31 = @ptrCast(@alignCast(layer.num.?.ptr()));
                const nd = qs(num_dst.?);
                for (0..half) |j| nd[j] = utils.foldMleEvalsFor(S, M31, r, b[j], b[j + half]);
            },
            else => {
                const sn = qs(layer.num.?);
                const nd = qs(num_dst.?);
                for (0..half) |j| nd[j] = r.mul(sn[j + half].sub(sn[j])).add(sn[j]);
            },
        }
    } else {
        const cmd = cmd_opt.?;
        const p = FoldParams{ .half_len = @intCast(half), .num_kind = layer.kind, .r = Gpu.toQ(r) };
        gpu_mod.tm_cmd_pipeline(cmd, g.p_gkr_fold);
        bind(cmd, 0, layer.den.?);
        bind(cmd, 1, layer.num orelse layer.den.?);
        bind(cmd, 2, den_dst);
        bind(cmd, 3, num_dst orelse den_dst);
        gpu_mod.tm_cmd_bytes(cmd, 4, &p, @sizeOf(FoldParams));
        const h: u32 = @intCast(half);
        gpu_mod.tm_cmd_dispatch(cmd, (h + 255) / 256, 1, 1, 256, 1, 1);
    }
    // Old buffers stay referenced by this command until it completes; they
    // are released by the caller after `end` via `retired`.
    if (fresh_den) {
        try g.retire(layer.den.?);
        layer.den = den_dst;
    }
    if (fresh_num) {
        if (layer.num) |b| try g.retire(b);
        layer.num = num_dst;
        layer.kind = SECURE;
    }
    layer.writable = true;
    layer.len = half;
}

pub fn proveBatch(g: *Gpu, a: std.mem.Allocator, channel: anytype, inputs: []const Fast.Input) !Fast.ProveBatchResult {
    defer for (inputs) |input| freeInput(a, input);
    const n_inst = inputs.len;
    if (n_inst == 0) return error.InvalidBatch;
    for (inputs) |input| {
        if (input.den.len < 2 or !std.math.isPowerOfTwo(input.den.len) or input.den.len >= (1 << 31)) return error.InvalidInputShape;
        switch (input.num) {
            .ones => {},
            .base => |n| if (n.len != input.den.len) return error.InvalidInputShape,
            .secure => |n| if (n.len != input.den.len) return error.InvalidInputShape,
        }
    }
    const n_vars = try a.alloc(usize, n_inst);
    defer a.free(n_vars);
    const layers = try a.alloc([]Layer, n_inst);
    defer a.free(layers);
    var built: usize = 0;
    defer for (layers[0..built]) |ls| {
        for (ls) |*l| l.free(g);
        a.free(ls);
    };
    defer g.releaseRetired();

    // ---- build all layers in one command buffer
    var n_layers: usize = 0;
    {
        const cmd = gpu_mod.tm_cmd_begin(g.rt);
        var cmd_open = true;
        errdefer if (cmd_open) {
            _ = Gpu.end(cmd) catch {};
        };
        for (inputs, 0..) |input, i| {
            n_vars[i] = std.math.log2_int(usize, input.den.len);
            n_layers = @max(n_layers, n_vars[i]);
            layers[i] = try a.alloc(Layer, n_vars[i] + 1);
            for (layers[i]) |*l| l.* = .{};
            built += 1;
            const top = &layers[i][n_vars[i]];
            top.len = input.den.len;
            top.den = try g.view(std.mem.sliceAsBytes(input.den), true);
            switch (input.num) {
                .ones => top.kind = ONES,
                .base => |n| {
                    top.kind = BASE;
                    top.num = try g.view(@constCast(std.mem.sliceAsBytes(n)), true);
                },
                .secure => |n| {
                    top.kind = SECURE;
                    top.num = try g.view(std.mem.sliceAsBytes(n), true);
                },
            }
            // Owned inputs are consumed by this call, so they may be folded in
            // place (as the CPU prover does); borrowed ones are never written.
            top.writable = input.owned and input.num != .base;
            var k = n_vars[i];
            while (k > 0) : (k -= 1) {
                const size = @as(usize, 1) << @intCast(k - 1);
                const src = &layers[i][k];
                const dst = &layers[i][k - 1];
                dst.* = .{ .den = try g.alloc(size * 16), .num = try g.alloc(size * 16), .kind = SECURE, .len = size, .writable = true };
                const p = NextParams{ .size = @intCast(size), .num_kind = src.kind };
                gpu_mod.tm_cmd_pipeline(cmd, g.p_gkr_next);
                bind(cmd, 0, src.den.?);
                bind(cmd, 1, src.num orelse src.den.?);
                bind(cmd, 2, dst.den.?);
                bind(cmd, 3, dst.num.?);
                gpu_mod.tm_cmd_bytes(cmd, 4, &p, @sizeOf(NextParams));
                const sz: u32 = @intCast(size);
                gpu_mod.tm_cmd_dispatch(cmd, (sz + 255) / 256, 1, 1, 256, 1, 1);
            }
        }
        cmd_open = false;
        g.stats.gkr_gpu_ms += try Gpu.end(cmd);
    }

    const output_claims = try a.alloc([2]S, n_inst);
    defer a.free(output_claims);
    const claims = try a.alloc(?[2]S, n_inst);
    defer a.free(claims);
    @memset(claims, null);
    const masks = try a.alloc(std.ArrayList(GV.GkrMask), n_inst);
    defer a.free(masks);
    for (masks) |*m| m.* = .empty;
    defer for (masks) |*m| {
        for (m.items) |*x| x.deinit(a);
        m.deinit(a);
    };
    var sumcheck_proofs = std.ArrayList(SC.SumcheckProof).empty;
    defer {
        for (sumcheck_proofs.items) |*p| p.deinit(a);
        sumcheck_proofs.deinit(a);
    }
    var ood = std.ArrayList(S).empty;
    defer ood.deinit(a);
    const active = try a.alloc(usize, n_inst);
    defer a.free(active);
    const sc_claim = try a.alloc(S, n_inst);
    defer a.free(sc_claim);
    const nv = try a.alloc(usize, n_inst);
    defer a.free(nv);
    const correction = try a.alloc(S, n_inst);
    defer a.free(correction);
    const pending = try a.alloc(?Pending, n_inst); // computed-but-unread round sums
    defer a.free(pending);
    const polys = try a.alloc(Poly, n_inst);
    defer a.free(polys);
    const partials = try g.alloc(n_inst * MAX_GROUPS * 32);
    defer gpu_mod.tm_release(partials.handle);

    for (0..n_layers) |layer_idx| {
        const n_remaining = n_layers - layer_idx;
        for (0..n_inst) |i| if (n_vars[i] == n_remaining) {
            const top = &layers[i][0];
            const out = [2]S{ top.numAt(0), top.denAt(0) };
            output_claims[i] = out;
            claims[i] = out;
        };
        for (claims) |c| if (c) |v| channel.mixFelts(&v);
        const eq = try eqTabs(g, ood.items);
        defer gpu_mod.tm_release(eq.buf.handle);
        const alpha = channel.drawSecureFelt();
        const lambda = channel.drawSecureFelt();

        var n_active: usize = 0;
        for (0..n_inst) |i| if (claims[i]) |c| {
            active[n_active] = i;
            nv[n_active] = layer_idx - (n_layers - n_vars[i]);
            sc_claim[n_active] = utils.hornerEval(S, &c, lambda);
            correction[n_active] = S.one();
            pending[n_active] = null;
            n_active += 1;
        };
        const n_sc_vars = layer_idx;
        for (0..n_active) |s| sc_claim[s] = utils.mulBaseFor(S, sc_claim[s], pow2(n_sc_vars - nv[s]));
        var round_polys = std.ArrayList(Poly).empty;
        errdefer {
            for (round_polys.items) |*p| p.deinit(a);
            round_polys.deinit(a);
        }
        var assignment = std.ArrayList(S).empty;
        defer assignment.deinit(a);
        for (0..n_sc_vars) |round| {
            const n_remaining_rounds = n_sc_vars - round;
            // sums for instances due this round that were not precomputed
            {
                var need_gpu = false;
                for (0..n_active) |s| if (nv[s] == n_remaining_rounds and pending[s] == null and (@as(usize, 1) << @intCast(nv[s] - 1)) > g.gkr_cpu_sum_max) {
                    need_gpu = true;
                };
                const cmd: ?*anyopaque = if (need_gpu) gpu_mod.tm_cmd_begin(g.rt) else null;
                for (0..n_active) |s| if (nv[s] == n_remaining_rounds and pending[s] == null) {
                    const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                    pending[s] = sumAny(g, cmd, layer, @as(usize, 1) << @intCast(nv[s] - 1), eq, lambda, partials, s);
                };
                if (cmd) |c| g.stats.gkr_gpu_ms += try Gpu.end(c);
            }
            var made: usize = 0;
            defer for (polys[0..made]) |*p| p.deinit(a);
            for (0..n_active) |s| {
                if (nv[s] == n_remaining_rounds) {
                    const sums = switch (pending[s].?) {
                        .gpu => |groups| readSum(partials, s, groups),
                        .cpu => |v| v,
                    };
                    pending[s] = null;
                    polys[s] = try PF.correctSumAsPolyInFirstVariable(a, sums[0].mul(correction[s]), sums[1].mul(correction[s]), sc_claim[s], ood.items, nv[s]);
                } else {
                    polys[s] = Poly.initOwned(try a.dupe(S, &.{try utils.divBaseFor(S, sc_claim[s], M31.fromCanonical(2))}));
                }
                made += 1;
                if (!polys[s].evalAtPoint(S.zero()).add(polys[s].evalAtPoint(S.one())).eql(sc_claim[s])) return error.InvalidSumcheck;
                if (polys[s].degree() > lookups.sumcheck.MAX_DEGREE) return error.InvalidSumcheck;
            }
            var acc = Poly.initOwned(try a.alloc(S, 0));
            var s_idx = n_active;
            while (s_idx > 0) {
                s_idx -= 1;
                var scaled = acc.mulScalar(a, alpha) catch |err| {
                    acc.deinit(a);
                    return err;
                };
                acc.deinit(a);
                acc = scaled.add(a, polys[s_idx]) catch |err| {
                    scaled.deinit(a);
                    return err;
                };
                scaled.deinit(a);
            }
            round_polys.append(a, acc) catch |err| {
                acc.deinit(a);
                return err;
            };
            channel.mixFelts(acc.coeffsSlice());
            const r = channel.drawSecureFelt();
            try assignment.append(a, r);
            // folds of this round + next-round sums: one command buffer for
            // the large layers, the small ones directly on the CPU
            var big = false;
            for (0..n_active) |s| if (nv[s] == n_remaining_rounds) {
                const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                if (layer.len / 2 > g.gkr_cpu_fold_max) big = true;
            };
            const cmd: ?*anyopaque = if (big) gpu_mod.tm_cmd_begin(g.rt) else null;
            var cmd_open = cmd != null;
            errdefer if (cmd_open) {
                _ = Gpu.end(cmd.?) catch {};
            };
            for (0..n_active) |s| {
                sc_claim[s] = polys[s].evalAtPoint(r);
                if (nv[s] != n_remaining_rounds) continue;
                const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                const z0 = ood.items[ood.items.len - nv[s]];
                correction[s] = correction[s].mul(eqOne(r, z0));
                const gpu_fold = layer.len / 2 > g.gkr_cpu_fold_max;
                try encodeFold(g, cmd, layer, r);
                nv[s] -= 1;
                if (nv[s] >= 1) {
                    const nt = @as(usize, 1) << @intCast(nv[s] - 1);
                    // a device fold is still in flight: its sum must follow it on the device
                    pending[s] = if (gpu_fold) .{ .gpu = encodeSum(g, cmd.?, layer, nt, eq, lambda, partials, s) } else .{ .cpu = cpuSum(layer, nt, eq, lambda) };
                }
            }
            if (cmd) |c| {
                cmd_open = false;
                g.stats.gkr_gpu_ms += try Gpu.end(c);
            }
            g.stats.gkr_rounds += 1;
            g.releaseRetired();
        }
        try sumcheck_proofs.append(a, .{ .round_polys = try round_polys.toOwnedSlice(a) });

        for (0..n_active) |s| {
            const i = active[s];
            const layer = &layers[i][layer_idx - (n_layers - n_vars[i]) + 1];
            if (layer.len != 2) return error.InvalidLayerStructure;
            const nums = [2]S{ layer.numAt(0), layer.numAt(1) };
            const dens = [2]S{ layer.denAt(0), layer.denAt(1) };
            const flat = [4]S{ nums[0], nums[1], dens[0], dens[1] };
            try masks[i].ensureUnusedCapacity(a, 1);
            masks[i].appendAssumeCapacity(GV.GkrMask.initOwned(try a.dupe([2]S, &.{ nums, dens })));
            channel.mixFelts(&flat);
        }
        const challenge = channel.drawSecureFelt();
        ood.clearRetainingCapacity();
        try ood.appendSlice(a, assignment.items);
        try ood.append(a, challenge);
        for (0..n_active) |s| {
            const i = active[s];
            const layer = &layers[i][layer_idx - (n_layers - n_vars[i]) + 1];
            const nums = [2]S{ layer.numAt(0), layer.numAt(1) };
            claims[i] = .{ utils.foldMleEvalsFor(S, S, challenge, nums[0], nums[1]), utils.foldMleEvalsFor(S, S, challenge, layer.denAt(0), layer.denAt(1)) };
            layer.free(g);
        }
    }

    const proof_masks = try a.alloc([]GV.GkrMask, n_inst);
    var masks_moved: usize = 0;
    errdefer {
        for (proof_masks[0..masks_moved]) |row| {
            for (row) |*m| m.deinit(a);
            a.free(row);
        }
        a.free(proof_masks);
    }
    for (masks, 0..) |*m, i| {
        proof_masks[i] = try m.toOwnedSlice(a);
        masks_moved += 1;
    }
    const proof_outputs = try a.alloc([]S, n_inst);
    var outputs_made: usize = 0;
    errdefer {
        for (proof_outputs[0..outputs_made]) |o| a.free(o);
        a.free(proof_outputs);
    }
    for (output_claims, 0..) |c, i| {
        proof_outputs[i] = try a.dupe(S, &c);
        outputs_made += 1;
    }
    const artifact_claims = try a.alloc([]S, n_inst);
    var claims_made: usize = 0;
    errdefer {
        for (artifact_claims[0..claims_made]) |c| a.free(c);
        a.free(artifact_claims);
    }
    for (claims, 0..) |c, i| {
        artifact_claims[i] = try a.dupe(S, &(c orelse return error.InvalidLayerStructure));
        claims_made += 1;
    }
    const ood_point = try a.dupe(S, ood.items);
    errdefer a.free(ood_point);
    const n_variables = try a.dupe(usize, n_vars);
    const sumchecks = try sumcheck_proofs.toOwnedSlice(a);
    return .{
        .proof = .{ .sumcheck_proofs = sumchecks, .layer_masks_by_instance = proof_masks, .output_claims_by_instance = proof_outputs },
        .artifact = .{ .ood_point = ood_point, .claims_to_verify_by_instance = artifact_claims, .n_variables_by_instance = n_variables },
    };
}

fn freeInput(a: std.mem.Allocator, input: Fast.Input) void {
    if (!input.owned) return;
    switch (input.num) {
        .ones => {},
        .base => |n| a.free(n),
        .secure => |n| a.free(n),
    }
    a.free(input.den);
}
