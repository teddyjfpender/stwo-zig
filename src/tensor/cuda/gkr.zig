//! CUDA LogUp-GKR batch prover: the control flow, transcript and proof
//! assembly of `gkr_prover_fast.proveBatch` (the same channel calls in the
//! same order, as metal/gkr.zig), with every layer of every instance in
//! device memory (tc_gkr_*). Per GKR layer the device runs one eq launch and
//! one launch per sumcheck round covering all live instances (the fold of the
//! previous round fused with this round's sums), plus one launch for the
//! last fold and the layer masks. Field arithmetic is exact and the eq table
//! is the same prefix (x) suffix product, so the proof is bit-identical.
const std = @import("std");
const t = @import("stwo_tensor");
const engine = @import("stwo_prover_engine");
const be = @import("backend.zig");
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

fn pow2(n: usize) M31 {
    return M31.fromU64(@as(u64, 1) << @intCast(n));
}

fn eqOne(x: S, y: S) S {
    return x.mul(y).add(S.one().sub(x).mul(S.one().sub(y)));
}

fn q(w: []const u32) S {
    return f.fromLimbs(w[0..4].*);
}

/// True when the batch fits the device session's bounds (otherwise the
/// caller runs the CPU prover; nothing has touched the device).
pub fn fits(inputs: []const Fast.Input) bool {
    if (inputs.len == 0 or inputs.len > be.GKR_MAX_JOBS) return false;
    for (inputs) |input| {
        if (input.den.len < 2 or !std.math.isPowerOfTwo(input.den.len) or input.den.len > (1 << 30)) return false;
        switch (input.num) {
            .ones => {},
            .base => |n| if (n.len != input.den.len) return false,
            .secure => |n| if (n.len != input.den.len) return false,
        }
    }
    return true;
}

/// The CPU prover (a batch the device session declines).
pub fn cpuProveBatch(a: std.mem.Allocator, channel: anytype, inputs: []const Fast.Input) !Fast.ProveBatchResult {
    return Fast.proveBatch(a, channel, inputs, .{ .threads = 1 }, null);
}

pub fn proveBatch(cu: *be.Cuda, a: std.mem.Allocator, channel: anytype, inputs: []const Fast.Input) !Fast.ProveBatchResult {
    defer for (inputs) |input| freeInput(a, input);
    const n_inst = inputs.len;
    const ctx = cu.ctx;

    // ---- upload + build every layer (one launch per depth), output claims
    const n_vars = try a.alloc(usize, n_inst);
    defer a.free(n_vars);
    const tin = try a.alloc(be.GkrInputC, n_inst);
    defer a.free(tin);
    var n_layers: usize = 0;
    for (inputs, 0..) |input, i| {
        n_vars[i] = std.math.log2_int(usize, input.den.len);
        n_layers = @max(n_layers, n_vars[i]);
        tin[i] = .{
            .kind = switch (input.num) {
                .ones => be.GKR_ONES,
                .base => be.GKR_BASE,
                .secure => be.GKR_SECURE,
            },
            .log_n = @intCast(n_vars[i]),
            .den = be.limbsPtr(input.den),
            .num = switch (input.num) {
                .ones => null,
                .base => |n| @ptrCast(n.ptr),
                .secure => |n| be.limbsPtr(n),
            },
        };
    }
    const top = try a.alloc(u32, 8 * n_inst);
    defer a.free(top);
    const g = be.tc_gkr_begin(ctx, tin.ptr, @intCast(n_inst), top.ptr) orelse return cu.err();
    defer be.tc_gkr_end(ctx, g);

    const output_claims = try a.alloc([2]S, n_inst);
    defer a.free(output_claims);
    for (output_claims, 0..) |*c, i| c.* = .{ q(top[8 * i ..]), q(top[8 * i + 4 ..]) };
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
    const cur_log = try a.alloc(u32, n_inst);
    defer a.free(cur_log);
    const correction = try a.alloc(S, n_inst);
    defer a.free(correction);
    const folded_prev = try a.alloc(bool, n_inst); // due last round: fold by r_prev now
    defer a.free(folded_prev);
    const polys = try a.alloc(Poly, n_inst);
    defer a.free(polys);
    const jobs = try a.alloc(be.GkrJobC, n_inst);
    defer a.free(jobs);
    const job_of = try a.alloc(?usize, n_inst);
    defer a.free(job_of);
    const out = try a.alloc(u32, 16 * n_inst);
    defer a.free(out);

    for (0..n_layers) |layer_idx| {
        const n_remaining = n_layers - layer_idx;
        for (0..n_inst) |i| if (n_vars[i] == n_remaining) {
            claims[i] = output_claims[i];
        };
        for (claims) |c| if (c) |v| channel.mixFelts(&v);
        const alpha = channel.drawSecureFelt();
        const lambda = channel.drawSecureFelt();
        {
            const ll = f.limbs(lambda);
            const rc = be.tc_gkr_eq(ctx, g, @ptrCast(ood.items.ptr), @intCast(ood.items.len), &ll);
            if (rc != 0) return cu.err();
        }

        var n_active: usize = 0;
        for (0..n_inst) |i| if (claims[i]) |c| {
            active[n_active] = i;
            nv[n_active] = layer_idx - (n_layers - n_vars[i]);
            cur_log[n_active] = @intCast(nv[n_active] + 1);
            sc_claim[n_active] = utils.hornerEval(S, &c, lambda);
            correction[n_active] = S.one();
            folded_prev[n_active] = false;
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
        var r_prev: ?S = null;
        for (0..n_sc_vars) |round| {
            const n_remaining_rounds = n_sc_vars - round;
            // one launch: fold the instances due last round by r_prev and
            // take this round's sums of every instance due now
            var n_jobs: usize = 0;
            for (0..n_active) |s| {
                job_of[s] = null;
                if (nv[s] != n_remaining_rounds) continue;
                const layer: u32 = @intCast(layer_idx - (n_layers - n_vars[active[s]]) + 1);
                jobs[n_jobs] = .{ .inst = @intCast(active[s]), .layer = layer, .cur_log = cur_log[s], .flags = be.GKR_SUM | (if (folded_prev[s]) be.GKR_FOLD else 0) };
                if (folded_prev[s]) cur_log[s] -= 1;
                job_of[s] = n_jobs;
                n_jobs += 1;
            }
            if (n_jobs > 0) {
                const rl: ?[4]u32 = if (r_prev) |r| f.limbs(r) else null;
                if (be.tc_gkr_round(ctx, g, jobs.ptr, @intCast(n_jobs), if (rl) |*x| x else null, out.ptr) != 0) return cu.err();
            }
            var made: usize = 0;
            defer for (polys[0..made]) |*p| p.deinit(a);
            for (0..n_active) |s| {
                if (job_of[s]) |j| {
                    const e0 = q(out[16 * j ..]);
                    const e2 = q(out[16 * j + 4 ..]);
                    polys[s] = try PF.correctSumAsPolyInFirstVariable(a, e0.mul(correction[s]), e2.mul(correction[s]), sc_claim[s], ood.items, nv[s]);
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
                var scaled = acc.mulScalar(a, alpha) catch |e| {
                    acc.deinit(a);
                    return e;
                };
                acc.deinit(a);
                acc = scaled.add(a, polys[s_idx]) catch |e| {
                    scaled.deinit(a);
                    return e;
                };
                scaled.deinit(a);
            }
            round_polys.append(a, acc) catch |e| {
                acc.deinit(a);
                return e;
            };
            channel.mixFelts(acc.coeffsSlice());
            const r = channel.drawSecureFelt();
            try assignment.append(a, r);
            for (0..n_active) |s| {
                sc_claim[s] = polys[s].evalAtPoint(r);
                folded_prev[s] = false;
                if (nv[s] != n_remaining_rounds) continue;
                const z0 = ood.items[ood.items.len - nv[s]];
                correction[s] = correction[s].mul(eqOne(r, z0));
                nv[s] -= 1;
                folded_prev[s] = true;
            }
            r_prev = r;
        }
        try sumcheck_proofs.append(a, .{ .round_polys = try round_polys.toOwnedSlice(a) });

        // one launch: last fold of the instances due in the last round, and
        // the length-2 masks of every active instance
        for (0..n_active) |s| {
            const layer: u32 = @intCast(layer_idx - (n_layers - n_vars[active[s]]) + 1);
            jobs[s] = .{ .inst = @intCast(active[s]), .layer = layer, .cur_log = cur_log[s], .flags = be.GKR_MASK | (if (folded_prev[s]) be.GKR_FOLD else 0) };
            if ((if (folded_prev[s]) cur_log[s] - 1 else cur_log[s]) != 1) return error.InvalidLayerStructure;
        }
        {
            const rl: ?[4]u32 = if (r_prev) |r| f.limbs(r) else null;
            if (be.tc_gkr_round(ctx, g, jobs.ptr, @intCast(n_active), if (rl) |*x| x else null, out.ptr) != 0) return cu.err();
        }
        for (0..n_active) |s| {
            const i = active[s];
            const w = out[16 * s ..];
            const nums = [2]S{ q(w[0..]), q(w[4..]) };
            const dens = [2]S{ q(w[8..]), q(w[12..]) };
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
            const w = out[16 * s ..];
            claims[active[s]] = .{ utils.foldMleEvalsFor(S, S, challenge, q(w[0..]), q(w[4..])), utils.foldMleEvalsFor(S, S, challenge, q(w[8..]), q(w[12..])) };
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
