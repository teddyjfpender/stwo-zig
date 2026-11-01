//! Parallel, clone-free LogUp batch GKR prover for WGKR-LS-RANGE-v0.
//!
//! It emits exactly the transcript and proof of the reference
//! `lookups/gkr_prover.zig:proveBatch` for LogUp inputs (field arithmetic is
//! exact, so chunked summation order cannot change any transcript value); the
//! test below compares encoded proofs byte for byte. Differences from the
//! reference are engineering only:
//!   - layers are built once and folded IN PLACE during their own sumcheck
//!     (the reference clones each layer into the oracle and again in sumcheck);
//!   - singles keep an implicit all-ones numerator through every fold;
//!   - layer construction, round sums and folds are chunked over a thread pool;
//!   - each layer's storage is released right after its sumcheck.
//! Memory is still "materialise every layer" (design note section 8, v0):
//! sum_k 2^k * 32 B over generic layers plus the 16 B/leaf input layer.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const lookups = @import("stwo_prover_engine").lookups;
const gkr_prover = lookups.gkr_prover;
const gkr_verifier = lookups.gkr_verifier;
const gkr_circuit = @import("stwo_prover_engine").lookups.gkr_prover;
const sumcheck = lookups.sumcheck;
const lookup_utils = lookups.utils;
const MP = @import("mle_point.zig");

const Poly = lookup_utils.UnivariatePoly(QM31);

/// Owned input layer. `num == null` means LogUp singles (all numerators 1).
pub const Input = struct {
    num: ?[]QM31,
    den: []QM31,
    pub fn nVariables(self: Input) usize {
        return std.math.log2_int(usize, self.den.len);
    }
};

/// `num`/`den` are views that shrink as the layer is folded in place;
/// `num_buf`/`den_buf` keep the original allocations for `free`.
const Layer = struct {
    num: ?[]QM31,
    den: []QM31,
    num_buf: ?[]QM31,
    den_buf: []QM31,
    fn init(num: ?[]QM31, den: []QM31) Layer {
        return .{ .num = num, .den = den, .num_buf = num, .den_buf = den };
    }
    fn free(self: *Layer, a: std.mem.Allocator) void {
        if (self.num_buf) |n| a.free(n);
        a.free(self.den_buf);
        self.* = init(null, &.{});
    }
};

pub const Stats = struct {
    build_ns: u64 = 0,
    sumcheck_ns: u64 = 0,
    peak_layer_bytes: u64 = 0,
};

pub const Options = struct {
    /// Dedicated prototype pool, never borrowed from a production coordinator.
    /// The caller must include it in its own scheduling/resource admission.
    threads: usize = 1,
    /// Smallest loop that is split across the pool (tests lower it).
    min_parallel: usize = 1 << 13,
};

pub const MAX_THREADS: usize = 64;

const Ctx = struct {
    pool: *std.Thread.Pool,
    threads: usize,
    min_parallel: usize,

    fn chunks(self: Ctx, n: usize) usize {
        if (n < self.min_parallel or self.threads == 1) return 1;
        return @max(1, @min(self.threads * 4, n / @max(1, self.min_parallel / 4)));
    }

    fn run(self: Ctx, n: usize, comptime func: anytype, args: anytype) void {
        const k = self.chunks(n);
        if (k <= 1) {
            @call(.auto, func, args ++ .{ 0, n, 0 });
            return;
        }
        var wg = std.Thread.WaitGroup{};
        for (0..k) |c| {
            const start = n * c / k;
            const end = n * (c + 1) / k;
            self.pool.spawnWg(&wg, func, args ++ .{ start, end, c });
        }
        self.pool.waitAndWork(&wg);
    }
};

fn nextLayerChunk(src: *const Layer, dst: *Layer, start: usize, end: usize, _: usize) void {
    for (start..end) |i| {
        const d0 = src.den[2 * i];
        const d1 = src.den[2 * i + 1];
        if (src.num) |n| {
            dst.num.?[i] = n[2 * i].mul(d1).add(d0.mul(n[2 * i + 1]));
        } else {
            dst.num.?[i] = d0.add(d1);
        }
        dst.den[i] = d0.mul(d1);
    }
}

fn sumChunk(layer: *const Layer, eq: []const QM31, n_terms: usize, lambda: QM31, partial: [][2]QM31, start: usize, end: usize, chunk: usize) void {
    var e0 = QM31.zero();
    var e2 = QM31.zero();
    const den = layer.den;
    for (start..end) |i| {
        const d00 = den[2 * i];
        const d01 = den[2 * i + 1];
        const d10 = den[2 * (n_terms + i)];
        const d11 = den[2 * (n_terms + i) + 1];
        const d20 = d10.add(d10).sub(d00);
        const d21 = d11.add(d11).sub(d01);
        var n0: QM31 = undefined;
        var n2: QM31 = undefined;
        if (layer.num) |num| {
            const n00 = num[2 * i];
            const n01 = num[2 * i + 1];
            const n10 = num[2 * (n_terms + i)];
            const n11 = num[2 * (n_terms + i) + 1];
            const n20 = n10.add(n10).sub(n00);
            const n21 = n11.add(n11).sub(n01);
            n0 = n00.mul(d01).add(d00.mul(n01));
            n2 = n20.mul(d21).add(d20.mul(n21));
        } else {
            n0 = d00.add(d01);
            n2 = d20.add(d21);
        }
        const w = eq[i];
        e0 = e0.add(w.mul(n0.add(lambda.mul(d00.mul(d01)))));
        e2 = e2.add(w.mul(n2.add(lambda.mul(d20.mul(d21)))));
    }
    partial[chunk] = .{ e0, e2 };
}

fn foldChunk(values: []QM31, half: usize, r: QM31, start: usize, end: usize, _: usize) void {
    for (start..end) |i| values[i] = r.mul(values[i + half].sub(values[i])).add(values[i]);
}

fn eqTable(a: std.mem.Allocator, y: []const QM31) ![]QM31 {
    if (y.len == 0) return a.dupe(QM31, &.{QM31.one()});
    const t = try MP.genEqEvals(a, y[1..]);
    const s = QM31.one().sub(y[0]);
    for (t) |*v| v.* = v.mul(s);
    return t;
}

fn eqOne(x: QM31, y: QM31) QM31 {
    return x.mul(y).add(QM31.one().sub(x).mul(QM31.one().sub(y)));
}

fn pow2(n: usize) M31 {
    return M31.fromU64(@as(u64, 1) << @intCast(n));
}

/// Consumes `inputs` (frees their buffers). Returns the same result type as
/// the reference prover.
pub fn proveBatch(a: std.mem.Allocator, channel: anytype, inputs: []Input, options: Options, stats: ?*Stats) !gkr_prover.ProveBatchResult {
    // Inputs are consumed on every exit, including validation/pool-init OOM.
    var adopted: usize = 0;
    defer for (inputs[adopted..]) |input| {
        if (input.num) |num| a.free(num);
        a.free(input.den);
    };
    if (options.threads == 0 or options.threads > MAX_THREADS) return error.InvalidGkrThreads;
    const threads = options.threads;
    var timer = try std.time.Timer.start();
    const n_inst = inputs.len;
    if (n_inst == 0 or n_inst > 4) return error.InvalidBatch;
    for (inputs) |input| {
        if (input.den.len < 2 or !std.math.isPowerOfTwo(input.den.len)) return error.InvalidInputShape;
        if (input.num) |num| if (num.len != input.den.len) return error.InvalidInputShape;
    }
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = a, .n_jobs = threads });
    defer pool.deinit();
    const ctx = Ctx{ .pool = &pool, .threads = threads, .min_parallel = options.min_parallel };

    // layers[i][k] has k variables; layers[i][n_vars] is the input.
    var layers: [4][]Layer = undefined;
    var n_vars: [4]usize = undefined;
    var built: usize = 0;
    defer for (layers[0..built]) |ls| {
        for (ls) |*l| l.free(a);
        a.free(ls);
    };
    var n_layers: usize = 0;
    var layer_bytes: u64 = 0;
    for (inputs, 0..) |input, i| {
        n_vars[i] = input.nVariables();
        n_layers = @max(n_layers, n_vars[i]);
        layers[i] = try a.alloc(Layer, n_vars[i] + 1);
        for (layers[i]) |*l| l.* = Layer.init(null, &.{});
        built += 1;
        layers[i][n_vars[i]] = Layer.init(input.num, input.den);
        adopted = i + 1;
        layer_bytes += input.den.len * @sizeOf(QM31) * @as(u64, if (input.num != null) 2 else 1);
        var k = n_vars[i];
        while (k > 0) : (k -= 1) {
            const size = @as(usize, 1) << @intCast(k - 1);
            const num = try a.alloc(QM31, size);
            const den = a.alloc(QM31, size) catch |err| {
                a.free(num);
                return err;
            };
            layers[i][k - 1] = Layer.init(num, den);
            layer_bytes += 2 * size * @sizeOf(QM31);
            ctx.run(size, nextLayerChunk, .{ &layers[i][k], &layers[i][k - 1] });
        }
    }
    if (stats) |s| {
        s.build_ns = timer.read();
        s.peak_layer_bytes = layer_bytes;
    }

    var output_claims: [4][2]QM31 = undefined;
    var claims: [4]?[2]QM31 = .{ null, null, null, null };
    var masks: [4]std.ArrayList(gkr_verifier.GkrMask) = .{ .empty, .empty, .empty, .empty };
    defer for (&masks) |*m| {
        for (m.items) |*x| x.deinit(a);
        m.deinit(a);
    };
    var sumcheck_proofs = std.ArrayList(sumcheck.SumcheckProof).empty;
    defer {
        for (sumcheck_proofs.items) |*p| p.deinit(a);
        sumcheck_proofs.deinit(a);
    }
    var ood = std.ArrayList(QM31).empty;
    defer ood.deinit(a);
    const partial = try a.alloc([2]QM31, ctx.threads * 4 + 1);
    defer a.free(partial);

    for (0..n_layers) |layer_idx| {
        const n_remaining = n_layers - layer_idx;
        for (0..n_inst) |i| if (n_vars[i] == n_remaining) {
            const top = &layers[i][0];
            const out = [2]QM31{ if (top.num) |n| n[0] else QM31.one(), top.den[0] };
            output_claims[i] = out;
            claims[i] = out;
        };
        for (claims[0..n_inst]) |c| if (c) |v| channel.mixFelts(&v);
        const eq = try eqTable(a, ood.items);
        defer a.free(eq);
        const alpha = channel.drawSecureFelt();
        const lambda = channel.drawSecureFelt();

        // Active instances, their layer (local vars m), sumcheck claims.
        var active: [4]usize = undefined;
        var n_active: usize = 0;
        var sc_claim: [4]QM31 = undefined;
        var nv: [4]usize = undefined; // remaining sumcheck variables per active instance
        var correction: [4]QM31 = undefined;
        for (0..n_inst) |i| if (claims[i]) |c| {
            const local = layer_idx - (n_layers - n_vars[i]);
            active[n_active] = i;
            nv[n_active] = local; // oracle nVariables = (local + 1) - 1
            sc_claim[n_active] = lookup_utils.randomLinearCombination(&c, lambda);
            correction[n_active] = QM31.one();
            n_active += 1;
        };
        const n_sc_vars = layer_idx;
        for (0..n_active) |s| sc_claim[s] = sc_claim[s].mulM31(pow2(n_sc_vars - nv[s]));
        var round_polys = std.ArrayList(Poly).empty;
        errdefer {
            for (round_polys.items) |*p| p.deinit(a);
            round_polys.deinit(a);
        }
        var assignment = std.ArrayList(QM31).empty;
        defer assignment.deinit(a);
        for (0..n_sc_vars) |round| {
            const n_remaining_rounds = n_sc_vars - round;
            var polys: [4]Poly = undefined;
            var made: usize = 0;
            defer for (polys[0..made]) |*p| p.deinit(a);
            for (0..n_active) |s| {
                if (nv[s] == n_remaining_rounds) {
                    const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                    const n_terms = @as(usize, 1) << @intCast(nv[s] - 1);
                    const k = ctx.chunks(n_terms);
                    ctx.run(n_terms, sumChunk, .{ layer, @as([]const QM31, eq), n_terms, lambda, partial });
                    var f0 = QM31.zero();
                    var f2 = QM31.zero();
                    for (partial[0..k]) |p| {
                        f0 = f0.add(p[0]);
                        f2 = f2.add(p[1]);
                    }
                    polys[s] = try gkr_circuit.correctSumAsPolyInFirstVariable(a, f0.mul(correction[s]), f2.mul(correction[s]), sc_claim[s], ood.items, nv[s]);
                } else {
                    const half = try sc_claim[s].divM31(M31.fromCanonical(2));
                    polys[s] = Poly.initOwned(try a.dupe(QM31, &.{half}));
                }
                made += 1;
            }
            // Random linear combination with alpha (Horner from the last poly).
            var acc = Poly.initOwned(try a.alloc(QM31, 0));
            var s_idx = n_active;
            while (s_idx > 0) {
                s_idx -= 1;
                var scaled = try acc.mulScalar(a, alpha);
                acc.deinit(a);
                acc = try scaled.add(a, polys[s_idx]);
                scaled.deinit(a);
            }
            channel.mixFelts(acc.coeffsSlice());
            const r = channel.drawSecureFelt();
            try round_polys.append(a, acc);
            try assignment.append(a, r);
            for (0..n_active) |s| {
                sc_claim[s] = polys[s].evalAtPoint(r);
                if (nv[s] != n_remaining_rounds) continue;
                const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                const z0 = ood.items[ood.items.len - nv[s]];
                correction[s] = correction[s].mul(eqOne(r, z0));
                const half = layer.den.len / 2;
                ctx.run(half, foldChunk, .{ layer.den, half, r });
                layer.den = layer.den[0..half];
                if (layer.num) |n| {
                    ctx.run(half, foldChunk, .{ n, half, r });
                    layer.num = n[0..half];
                }
                nv[s] -= 1;
            }
        }
        try sumcheck_proofs.append(a, .{ .round_polys = try round_polys.toOwnedSlice(a) });

        var flat: [4][4]QM31 = undefined;
        for (0..n_active) |s| {
            const i = active[s];
            const layer = &layers[i][layer_idx - (n_layers - n_vars[i]) + 1];
            if (layer.den.len != 2) return error.InvalidLayerStructure;
            const nums = if (layer.num) |n| [2]QM31{ n[0], n[1] } else [2]QM31{ QM31.one(), QM31.one() };
            flat[s] = .{ nums[0], nums[1], layer.den[0], layer.den[1] };
            try masks[i].append(a, gkr_verifier.GkrMask.initOwned(try a.dupe([2]QM31, &.{ nums, .{ layer.den[0], layer.den[1] } })));
            channel.mixFelts(&flat[s]);
        }
        const challenge = channel.drawSecureFelt();
        ood.clearRetainingCapacity();
        try ood.appendSlice(a, assignment.items);
        try ood.append(a, challenge);
        for (0..n_active) |s| {
            const i = active[s];
            const f = flat[s];
            claims[i] = .{ lookup_utils.foldMleEvals(QM31, challenge, f[0], f[1]), lookup_utils.foldMleEvals(QM31, challenge, f[2], f[3]) };
            layers[i][layer_idx - (n_layers - n_vars[i]) + 1].free(a);
        }
    }
    if (stats) |s| s.sumcheck_ns = timer.read() - s.build_ns;

    // Assemble owned results.
    var proof = gkr_verifier.GkrBatchProof{
        .sumcheck_proofs = try sumcheck_proofs.toOwnedSlice(a),
        .layer_masks_by_instance = try a.alloc([]gkr_verifier.GkrMask, n_inst),
        .output_claims_by_instance = try a.alloc([]QM31, n_inst),
    };
    for (0..n_inst) |i| {
        proof.layer_masks_by_instance[i] = try masks[i].toOwnedSlice(a);
        proof.output_claims_by_instance[i] = try a.dupe(QM31, &output_claims[i]);
    }
    const artifact_claims = try a.alloc([]QM31, n_inst);
    for (0..n_inst) |i| artifact_claims[i] = try a.dupe(QM31, &(claims[i].?));
    const artifact = gkr_verifier.GkrArtifact{
        .ood_point = try a.dupe(QM31, ood.items),
        .claims_to_verify_by_instance = artifact_claims,
        .n_variables_by_instance = try a.dupe(usize, n_vars[0..n_inst]),
    };
    return .{ .proof = proof, .artifact = artifact };
}
