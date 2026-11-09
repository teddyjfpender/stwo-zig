//! Clone-free, packed and optionally parallel LogUp batch GKR prover.
//!
//! Emits exactly the proof, artifact and channel transcript of the reference
//! `gkr_prover_field.ForField(Secure).proveBatch` for LogUp inputs (singles,
//! generic and base-field multiplicities). Field arithmetic is exact, so the
//! chunked, lane-wise and fused evaluation orders below cannot change any
//! transcript value; the tests compare encoded transcripts byte for byte.
//! Engineering differences from the reference only:
//!   - layers are built once and folded in place (the reference clones every
//!     layer into the oracle, its eq table every round, and sumcheck clones
//!     every oracle again);
//!   - borrowed inputs are never written: their first fold writes a new
//!     half-size layer;
//!   - singles keep an implicit all-ones numerator through every fold and
//!     multiplicities keep base-field numerators until the first fold;
//!   - the build, the round sums, the folds (fused with the next round's sum)
//!     and the eq table run four terms per AdvSIMD operation and, with
//!     `threads > 1`, over a private pool;
//!   - each layer's storage is released right after its sumcheck.
//! Memory remains "materialise every layer": sum_k 2^k * 2|Secure| bytes over
//! the generic layers, plus owned or borrowed inputs.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const OM31 = core.fields.om31.OM31;
const m31 = core.fields.m31;
const PE = core.fields.packed_extensions;
const gkr_prover_field = @import("gkr_prover_field.zig");
const gkr_verifier_module = @import("gkr_verifier.zig");
const sumcheck_module = @import("sumcheck.zig");
const utils = @import("utils.zig");

pub const MAX_THREADS: usize = 64;
const LANES = 4;
const V = m31.Vec4u32;

/// Four-lane packed arithmetic for a secure field: QM31 directly, OM31 as a
/// Karatsuba quadratic over packed QM31 (`OM31 = QM31[v]/(v^2 - u)`).
pub fn Lanes(comptime S: type) type {
    if (S == QM31) return struct {
        pub const T = PE.PackedQM31x4;
        pub inline fn load(p: [*]const S) T {
            return PE.loadPackedQM31x4(p);
        }
        pub inline fn store(p: [*]S, x: T) void {
            PE.storePackedQM31x4(p, x);
        }
        pub const add = PE.addPackedQM31x4;
        pub const sub = PE.subPackedQM31x4;
        pub const mul = PE.mulPackedQM31x4;
        pub const splat = PE.splatPackedQM31x4;
        pub const zero = PE.zeroPackedQM31x4;
        pub const evenOdd = PE.evenOddPackedQM31x4;
        pub const interleave = PE.interleavePackedQM31x4;
        pub const sumLanes = PE.sumLanesPackedQM31x4;
        pub inline fn mulBase(x: T, b: V) T {
            return .{ .c0a = m31.mulVec4(x.c0a, b), .c0b = m31.mulVec4(x.c0b, b), .c1a = m31.mulVec4(x.c1a, b), .c1b = m31.mulVec4(x.c1b, b) };
        }
        pub inline fn fromBase(b: V) T {
            return .{ .c0a = b, .c0b = @splat(0), .c1a = @splat(0), .c1b = @splat(0) };
        }
    };
    if (S == OM31) return struct {
        const Q = Lanes(QM31);
        pub const T = struct { c0: Q.T, c1: Q.T };
        comptime {
            std.debug.assert(@sizeOf(OM31) == 2 * @sizeOf(QM31));
            std.debug.assert(@offsetOf(OM31, "c0") == 0 and @offsetOf(OM31, "c1") == @sizeOf(QM31));
        }
        pub inline fn load(p: [*]const S) T {
            const q: [*]const QM31 = @ptrCast(p);
            const x = Q.evenOdd(Q.load(q), Q.load(q + 4));
            return .{ .c0 = x[0], .c1 = x[1] };
        }
        pub inline fn store(p: [*]S, x: T) void {
            const q: [*]QM31 = @ptrCast(p);
            const y = Q.interleave(x.c0, x.c1);
            Q.store(q, y[0]);
            Q.store(q + 4, y[1]);
        }
        pub inline fn add(x: T, y: T) T {
            return .{ .c0 = Q.add(x.c0, y.c0), .c1 = Q.add(x.c1, y.c1) };
        }
        pub inline fn sub(x: T, y: T) T {
            return .{ .c0 = Q.sub(x.c0, y.c0), .c1 = Q.sub(x.c1, y.c1) };
        }
        /// (a + b v)(c + d v) = (ac + u bd) + ((a + b)(c + d) - ac - bd) v.
        pub inline fn mul(x: T, y: T) T {
            const ac = Q.mul(x.c0, y.c0);
            const bd = Q.mul(x.c1, y.c1);
            const cross = Q.sub(Q.sub(Q.mul(Q.add(x.c0, x.c1), Q.add(y.c0, y.c1)), ac), bd);
            return .{ .c0 = Q.add(ac, mulByU(bd)), .c1 = cross };
        }
        /// (a + b u) u = (2 + i) b + a u, coordinate-wise as in om31.NativeOps.
        inline fn mulByU(x: Q.T) Q.T {
            return .{
                .c0a = m31.subVec4(m31.addVec4(x.c1a, x.c1a), x.c1b),
                .c0b = m31.addVec4(x.c1a, m31.addVec4(x.c1b, x.c1b)),
                .c1a = x.c0a,
                .c1b = x.c0b,
            };
        }
        pub inline fn splat(x: S) T {
            return .{ .c0 = Q.splat(x.c0), .c1 = Q.splat(x.c1) };
        }
        pub inline fn zero() T {
            return .{ .c0 = Q.zero(), .c1 = Q.zero() };
        }
        pub inline fn evenOdd(lo: T, hi: T) [2]T {
            const a = Q.evenOdd(lo.c0, hi.c0);
            const b = Q.evenOdd(lo.c1, hi.c1);
            return .{ .{ .c0 = a[0], .c1 = b[0] }, .{ .c0 = a[1], .c1 = b[1] } };
        }
        pub inline fn interleave(even: T, odd: T) [2]T {
            const a = Q.interleave(even.c0, odd.c0);
            const b = Q.interleave(even.c1, odd.c1);
            return .{ .{ .c0 = a[0], .c1 = b[0] }, .{ .c0 = a[1], .c1 = b[1] } };
        }
        pub inline fn sumLanes(x: T) S {
            return .{ .c0 = Q.sumLanes(x.c0), .c1 = Q.sumLanes(x.c1) };
        }
        pub inline fn mulBase(x: T, b: V) T {
            return .{ .c0 = Q.mulBase(x.c0, b), .c1 = Q.mulBase(x.c1, b) };
        }
        pub inline fn fromBase(b: V) T {
            return .{ .c0 = Q.fromBase(b), .c1 = Q.zero() };
        }
    };
    @compileError("no packed lanes for this secure field");
}

inline fn loadBase(p: [*]const M31) V {
    const raw: *const [4]u32 = @ptrCast(p);
    return raw.*;
}

inline fn evenOddBase(p: [*]const M31) [2]V {
    const lo = loadBase(p);
    const hi = loadBase(p + 4);
    return .{
        @shuffle(u32, lo, hi, @Vector(4, i32){ 0, 2, -1, -3 }),
        @shuffle(u32, lo, hi, @Vector(4, i32){ 1, 3, -2, -4 }),
    };
}

pub fn ForField(comptime S: type) type {
    return struct {
        const L = Lanes(S);
        const PF = gkr_prover_field.ForField(S);
        const GV = gkr_verifier_module.ForField(S);
        const SC = sumcheck_module.ForField(S);
        const Poly = utils.UnivariatePoly(S);
        pub const ProveBatchResult = PF.ProveBatchResult;

        pub const Numerators = union(enum) {
            /// LogUp singles: every numerator is one.
            ones,
            /// LogUp multiplicities: base-field numerators (never written).
            base: []const M31,
            /// LogUp generic: secure numerators.
            secure: []S,
        };

        /// A LogUp singles input given by a function instead of a column:
        /// `fill(ctx, out, start)` writes den[start .. start + out.len] of the
        /// 2^log_len input column. The input column and the first two
        /// generic layers are never kept: layer n-2 is built straight from
        /// `fill`, the lower layers live in one block of 2^n entries, and that
        /// block is refilled with layer n-1 (for the step that reads it) and
        /// then with the input column (the last step). Peak layer memory:
        /// about 3 n|S| (column + every generic layer) -> n|S|, for any
        /// allocator. Every value is recomputed with the same operations, so
        /// the proof is unchanged. Such an input has `den = &.{}`,
        /// `num = .ones`, `owned = false`.
        pub const Regen = struct {
            ctx: *const anyopaque,
            fill: *const fn (ctx: *const anyopaque, out: []S, start: usize) void,
            log_len: u32,
        };

        /// `owned` inputs are folded in place and freed with `allocator`;
        /// borrowed inputs are only read.
        pub const Input = struct {
            num: Numerators,
            den: []S,
            owned: bool,
            /// See `Regen`.
            regen: ?Regen = null,

            fn nVariables(self: Input) usize {
                if (self.regen) |r| return r.log_len;
                return std.math.log2_int(usize, self.den.len);
            }
            fn free(self: Input, a: std.mem.Allocator) void {
                if (!self.owned) return;
                switch (self.num) {
                    .ones => {},
                    .base => |n| a.free(n),
                    .secure => |n| a.free(n),
                }
                a.free(self.den);
            }
        };

        pub const Options = struct {
            /// Private pool size; 1 runs on the calling thread with no pool.
            /// The caller must include it in its own scheduling/admission.
            threads: usize = 1,
            /// Smallest loop that is split across the pool (tests lower it).
            min_parallel: usize = 1 << 13,
        };

        pub const Stats = struct {
            build_ns: u64 = 0,
            sumcheck_ns: u64 = 0,
            peak_layer_bytes: u64 = 0,
        };

        /// One layer: views that shrink as it folds, and the allocations it
        /// owns (freed with their original lengths).
        const Layer = struct {
            num: Numerators,
            den: []S,
            num_buf: Buf = .none,
            den_buf: ?[]S = null,
            /// num and den are views into a regen instance's arena block (owned by
            /// the prover, not the layer): fold in place, never free.
            in_spare: bool = false,
            const Buf = union(enum) { none, base: []const M31, secure: []S };
            fn empty() Layer {
                return .{ .num = .ones, .den = &.{} };
            }
            fn free(self: *Layer, a: std.mem.Allocator) void {
                if (self.in_spare) {
                    self.* = empty();
                    return;
                }
                switch (self.num_buf) {
                    .none => {},
                    .base => |n| a.free(n),
                    .secure => |n| a.free(n),
                }
                if (self.den_buf) |d| a.free(d);
                self.* = empty();
            }
        };

        const Ctx = struct {
            pool: ?*std.Thread.Pool,
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
                for (0..k) |c| self.pool.?.spawnWg(&wg, func, args ++ .{ n * c / k, n * (c + 1) / k, c });
                self.pool.?.waitAndWork(&wg);
            }

            /// Exactly `n` coarse units, one task each (no grain threshold).
            fn runExact(self: Ctx, n: usize, comptime func: anytype, args: anytype) void {
                if (n <= 1 or self.threads == 1) {
                    @call(.auto, func, args ++ .{ 0, n, 0 });
                    return;
                }
                var wg = std.Thread.WaitGroup{};
                for (0..n) |c| self.pool.?.spawnWg(&wg, func, args ++ .{ c, c + 1, c });
                self.pool.?.waitAndWork(&wg);
            }
        };

        // ------------------------------------------------------------ build

        fn nextScalar(src: *const Layer, num: []S, den: []S, i: usize) void {
            const d0 = src.den[2 * i];
            const d1 = src.den[2 * i + 1];
            num[i] = switch (src.num) {
                .ones => d0.add(d1),
                .base => |n| utils.mulBaseFor(S, d1, n[2 * i]).add(utils.mulBaseFor(S, d0, n[2 * i + 1])),
                .secure => |n| n[2 * i].mul(d1).add(d0.mul(n[2 * i + 1])),
            };
            den[i] = d0.mul(d1);
        }

        fn regenChunk(rg: Regen, d: []S, start: usize, end: usize, _: usize) void {
            rg.fill(rg.ctx, d[start..end], start);
        }

        /// Entries [start, end) of generic layer n - `up` (up = 1 or 2) of a
        /// regen input, built from the source through a small stack window
        /// with the same `nextChunk` arithmetic as a materialised build.
        fn regenLayerChunk(rg: Regen, up: u32, num: []S, den: []S, start: usize, end: usize, _: usize) void {
            const W = 512; // outputs per window
            var src: [4 * W]S = undefined;
            var mid_num: [2 * W]S = undefined;
            var mid_den: [2 * W]S = undefined;
            var o = start;
            while (o < end) {
                const m: usize = @min(W, end - o);
                const w_in = m << @intCast(up);
                rg.fill(rg.ctx, src[0..w_in], o << @intCast(up));
                const l0 = Layer{ .num = .ones, .den = src[0..w_in] };
                if (up == 1) {
                    nextChunk(&l0, num[o..], den[o..], 0, m, 0);
                } else {
                    nextChunk(&l0, &mid_num, &mid_den, 0, 2 * m, 0);
                    const l1 = Layer{ .num = .{ .secure = mid_num[0 .. 2 * m] }, .den = mid_den[0 .. 2 * m] };
                    nextChunk(&l1, num[o..], den[o..], 0, m, 0);
                }
                o += m;
            }
        }

        fn nextChunk(src: *const Layer, num: []S, den: []S, start: usize, end: usize, _: usize) void {
            @setEvalBranchQuota(40_000);
            var i = start;
            while (i < end and i % LANES != 0) : (i += 1) nextScalar(src, num, den, i);
            while (i + LANES <= end) : (i += LANES) {
                const d = L.evenOdd(L.load(src.den.ptr + 2 * i), L.load(src.den.ptr + 2 * i + LANES));
                const n = switch (src.num) {
                    .ones => L.add(d[0], d[1]),
                    .base => |b| blk: {
                        const x = evenOddBase(b.ptr + 2 * i);
                        break :blk L.add(L.mulBase(d[1], x[0]), L.mulBase(d[0], x[1]));
                    },
                    .secure => |s| blk: {
                        const x = L.evenOdd(L.load(s.ptr + 2 * i), L.load(s.ptr + 2 * i + LANES));
                        break :blk L.add(L.mul(x[0], d[1]), L.mul(d[0], x[1]));
                    },
                };
                L.store(num.ptr + i, n);
                L.store(den.ptr + i, L.mul(d[0], d[1]));
            }
            while (i < end) : (i += 1) nextScalar(src, num, den, i);
        }

        // ------------------------------------------------------- round sums

        fn sumScalar(layer: *const Layer, eq: []const S, n_terms: usize, lambda: S, i: usize, e0: *S, e2: *S) void {
            const den = layer.den;
            const d00 = den[2 * i];
            const d01 = den[2 * i + 1];
            const d10 = den[2 * (n_terms + i)];
            const d11 = den[2 * (n_terms + i) + 1];
            const d20 = d10.add(d10).sub(d00);
            const d21 = d11.add(d11).sub(d01);
            var n0: S = undefined;
            var n2: S = undefined;
            switch (layer.num) {
                .ones => {
                    n0 = d00.add(d01);
                    n2 = d20.add(d21);
                },
                .base => |num| {
                    const n00 = num[2 * i];
                    const n01 = num[2 * i + 1];
                    const n10 = num[2 * (n_terms + i)];
                    const n11 = num[2 * (n_terms + i) + 1];
                    const n20 = n10.add(n10).sub(n00);
                    const n21 = n11.add(n11).sub(n01);
                    n0 = utils.mulBaseFor(S, d01, n00).add(utils.mulBaseFor(S, d00, n01));
                    n2 = utils.mulBaseFor(S, d21, n20).add(utils.mulBaseFor(S, d20, n21));
                },
                .secure => |num| {
                    const n00 = num[2 * i];
                    const n01 = num[2 * i + 1];
                    const n10 = num[2 * (n_terms + i)];
                    const n11 = num[2 * (n_terms + i) + 1];
                    const n20 = n10.add(n10).sub(n00);
                    const n21 = n11.add(n11).sub(n01);
                    n0 = n00.mul(d01).add(d00.mul(n01));
                    n2 = n20.mul(d21).add(d20.mul(n21));
                },
            }
            const w = eq[i];
            e0.* = e0.add(w.mul(n0.add(lambda.mul(d00.mul(d01)))));
            e2.* = e2.add(w.mul(n2.add(lambda.mul(d20.mul(d21)))));
        }

        /// Packed term body shared by the plain and the fused sums.
        inline fn sumPacked(lo: [2]L.T, hi: [2]L.T, n0: L.T, n2: L.T, w: L.T, plambda: L.T, p0: *L.T, p2: *L.T) void {
            const d20 = L.sub(L.add(hi[0], hi[0]), lo[0]);
            const d21 = L.sub(L.add(hi[1], hi[1]), lo[1]);
            p0.* = L.add(p0.*, L.mul(w, L.add(n0, L.mul(plambda, L.mul(lo[0], lo[1])))));
            p2.* = L.add(p2.*, L.mul(w, L.add(n2, L.mul(plambda, L.mul(d20, d21)))));
        }

        inline fn numPacked(num_lo: [2]L.T, num_hi: [2]L.T, lo: [2]L.T, hi: [2]L.T) [2]L.T {
            const d20 = L.sub(L.add(hi[0], hi[0]), lo[0]);
            const d21 = L.sub(L.add(hi[1], hi[1]), lo[1]);
            const n20 = L.sub(L.add(num_hi[0], num_hi[0]), num_lo[0]);
            const n21 = L.sub(L.add(num_hi[1], num_hi[1]), num_lo[1]);
            return .{ L.add(L.mul(num_lo[0], lo[1]), L.mul(lo[0], num_lo[1])), L.add(L.mul(n20, d21), L.mul(d20, n21)) };
        }

        inline fn numOnes(lo: [2]L.T, hi: [2]L.T) [2]L.T {
            const d20 = L.sub(L.add(hi[0], hi[0]), lo[0]);
            const d21 = L.sub(L.add(hi[1], hi[1]), lo[1]);
            return .{ L.add(lo[0], lo[1]), L.add(d20, d21) };
        }

        inline fn loadEvenOdd(p: [*]const S) [2]L.T {
            return L.evenOdd(L.load(p), L.load(p + LANES));
        }

        fn sumChunk(layer: *const Layer, eq: []const S, n_terms: usize, lambda: S, partial: [][2]S, start: usize, end: usize, chunk: usize) void {
            @setEvalBranchQuota(40_000);
            var e0 = S.zero();
            var e2 = S.zero();
            var i = start;
            while (i < end and i % LANES != 0) : (i += 1) sumScalar(layer, eq, n_terms, lambda, i, &e0, &e2);
            if (i + LANES <= end) {
                const den = layer.den.ptr;
                const plambda = L.splat(lambda);
                var p0 = L.zero();
                var p2 = L.zero();
                while (i + LANES <= end) : (i += LANES) {
                    const lo = loadEvenOdd(den + 2 * i);
                    const hi = loadEvenOdd(den + 2 * (n_terms + i));
                    const n = switch (layer.num) {
                        .ones => numOnes(lo, hi),
                        .secure => |s| numPacked(loadEvenOdd(s.ptr + 2 * i), loadEvenOdd(s.ptr + 2 * (n_terms + i)), lo, hi),
                        .base => |b| blk: {
                            const nlo = evenOddBase(b.ptr + 2 * i);
                            const nhi = evenOddBase(b.ptr + 2 * (n_terms + i));
                            const n20 = m31.subVec4(m31.addVec4(nhi[0], nhi[0]), nlo[0]);
                            const n21 = m31.subVec4(m31.addVec4(nhi[1], nhi[1]), nlo[1]);
                            const d20 = L.sub(L.add(hi[0], hi[0]), lo[0]);
                            const d21 = L.sub(L.add(hi[1], hi[1]), lo[1]);
                            break :blk [2]L.T{ L.add(L.mulBase(lo[1], nlo[0]), L.mulBase(lo[0], nlo[1])), L.add(L.mulBase(d21, n20), L.mulBase(d20, n21)) };
                        },
                    };
                    sumPacked(lo, hi, n[0], n[1], L.load(eq.ptr + i), plambda, &p0, &p2);
                }
                e0 = e0.add(L.sumLanes(p0));
                e2 = e2.add(L.sumLanes(p2));
            }
            while (i < end) : (i += 1) sumScalar(layer, eq, n_terms, lambda, i, &e0, &e2);
            partial[chunk] = .{ e0, e2 };
        }

        // ------------------------------------------------------------ folds

        inline fn foldOne(dst: []S, src: []const S, half: usize, r: S, j: usize) void {
            dst[j] = r.mul(src[j + half].sub(src[j])).add(src[j]);
        }

        inline fn foldBaseOne(dst: []S, src: []const M31, half: usize, r: S, j: usize) void {
            dst[j] = utils.foldMleEvalsFor(S, M31, r, src[j], src[j + half]);
        }

        /// `dst[j] = r * (src[j + half] - src[j]) + src[j]`; `dst` may alias `src`.
        fn foldChunk(dst: []S, src: []const S, half: usize, r: S, start: usize, end: usize, _: usize) void {
            @setEvalBranchQuota(40_000);
            var i = start;
            while (i < end and i % LANES != 0) : (i += 1) foldOne(dst, src, half, r, i);
            const pr = L.splat(r);
            while (i + LANES <= end) : (i += LANES) {
                const x = L.load(src.ptr + i);
                L.store(dst.ptr + i, L.add(L.mul(pr, L.sub(L.load(src.ptr + i + half), x)), x));
            }
            while (i < end) : (i += 1) foldOne(dst, src, half, r, i);
        }

        fn foldBaseChunk(dst: []S, src: []const M31, half: usize, r: S, start: usize, end: usize, _: usize) void {
            @setEvalBranchQuota(40_000);
            var i = start;
            while (i < end and i % LANES != 0) : (i += 1) foldBaseOne(dst, src, half, r, i);
            const pr = L.splat(r);
            while (i + LANES <= end) : (i += LANES) {
                const x = loadBase(src.ptr + i);
                L.store(dst.ptr + i, L.add(L.mulBase(pr, m31.subVec4(loadBase(src.ptr + i + half), x)), L.fromBase(x)));
            }
            while (i < end) : (i += 1) foldBaseOne(dst, src, half, r, i);
        }

        inline fn foldEight(dst: [*]S, src: [*]const S, half: usize, pr: L.T, j: usize) [2]L.T {
            const x0 = L.load(src + j);
            const x1 = L.load(src + j + LANES);
            const f0 = L.add(L.mul(pr, L.sub(L.load(src + j + half), x0)), x0);
            const f1 = L.add(L.mul(pr, L.sub(L.load(src + j + LANES + half), x1)), x1);
            L.store(dst + j, f0);
            L.store(dst + j + LANES, f1);
            return L.evenOdd(f0, f1);
        }

        inline fn foldEightBase(dst: [*]S, src: [*]const M31, half: usize, pr: L.T, j: usize) [2]L.T {
            const x0 = loadBase(src + j);
            const x1 = loadBase(src + j + LANES);
            const f0 = L.add(L.mulBase(pr, m31.subVec4(loadBase(src + j + half), x0)), L.fromBase(x0));
            const f1 = L.add(L.mulBase(pr, m31.subVec4(loadBase(src + j + LANES + half), x1)), L.fromBase(x1));
            L.store(dst + j, f0);
            L.store(dst + j + LANES, f1);
            return L.evenOdd(f0, f1);
        }

        /// Folded destination of one layer: secure numerators unless singles.
        const Folded = struct { num: ?[]S, den: []S };

        /// Folds `src` by `r` into `dst` (which may alias it) and accumulates
        /// the NEXT round's sums over the folded layer (`n_terms = half/4`).
        /// Term `i` owns folded positions `2i, 2i+1, 2(n+i), 2(n+i)+1`, so the
        /// term ranges partition `[0, half)` and each position is folded once,
        /// before it is read, by its owner.
        fn foldSumChunk(src: *const Layer, dst: Folded, half: usize, r: S, eq: []const S, lambda: S, partial: [][2]S, start: usize, end: usize, chunk: usize) void {
            @setEvalBranchQuota(80_000);
            const n_terms = half / 4;
            const view = Layer{ .num = if (dst.num) |n| .{ .secure = n } else .ones, .den = dst.den };
            var e0 = S.zero();
            var e2 = S.zero();
            var i = start;
            while (i < end and i % LANES != 0) : (i += 1) foldSumScalar(src, dst, &view, half, r, eq, n_terms, lambda, i, &e0, &e2);
            if (i + LANES <= end) {
                const pr = L.splat(r);
                const plambda = L.splat(lambda);
                var p0 = L.zero();
                var p2 = L.zero();
                while (i + LANES <= end) : (i += LANES) {
                    const lo = foldEight(dst.den.ptr, src.den.ptr, half, pr, 2 * i);
                    const hi = foldEight(dst.den.ptr, src.den.ptr, half, pr, 2 * (n_terms + i));
                    const n = switch (src.num) {
                        .ones => numOnes(lo, hi),
                        .secure => |s| numPacked(foldEight(dst.num.?.ptr, s.ptr, half, pr, 2 * i), foldEight(dst.num.?.ptr, s.ptr, half, pr, 2 * (n_terms + i)), lo, hi),
                        .base => |b| numPacked(foldEightBase(dst.num.?.ptr, b.ptr, half, pr, 2 * i), foldEightBase(dst.num.?.ptr, b.ptr, half, pr, 2 * (n_terms + i)), lo, hi),
                    };
                    sumPacked(lo, hi, n[0], n[1], L.load(eq.ptr + i), plambda, &p0, &p2);
                }
                e0 = e0.add(L.sumLanes(p0));
                e2 = e2.add(L.sumLanes(p2));
            }
            while (i < end) : (i += 1) foldSumScalar(src, dst, &view, half, r, eq, n_terms, lambda, i, &e0, &e2);
            partial[chunk] = .{ e0, e2 };
        }

        fn foldSumScalar(src: *const Layer, dst: Folded, view: *const Layer, half: usize, r: S, eq: []const S, n_terms: usize, lambda: S, t: usize, e0: *S, e2: *S) void {
            for ([_]usize{ 2 * t, 2 * t + 1, 2 * (n_terms + t), 2 * (n_terms + t) + 1 }) |j| {
                foldOne(dst.den, src.den, half, r, j);
                switch (src.num) {
                    .ones => {},
                    .secure => |s| foldOne(dst.num.?, s, half, r, j),
                    .base => |b| foldBaseOne(dst.num.?, b, half, r, j),
                }
            }
            sumScalar(view, eq, n_terms, lambda, t, e0, e2);
        }

        // --------------------------------------------------------- eq table

        /// `eq((y0, x), y)` table, scaled by `1 - y[0]`, in the bit order of
        /// the reference `EqEvals.generate` (y[1] is the most significant
        /// index bit). Chunks expand independently from prefix products.
        fn eqTable(a: std.mem.Allocator, ctx: Ctx, y: []const S) ![]S {
            if (y.len == 0) return a.dupe(S, &.{S.one()});
            const r = y[1..];
            const n = @as(usize, 1) << @intCast(r.len);
            const out = try a.alloc(S, n);
            const k = ctx.chunks(n);
            const top: usize = if (k <= 1) 0 else @min(r.len, std.math.log2_int_ceil(usize, k));
            ctx.runExact(@as(usize, 1) << @intCast(top), eqChunk, .{ out, r, top, S.one().sub(y[0]) });
            return out;
        }

        fn eqChunk(out: []S, r: []const S, top: usize, scale: S, start: usize, end: usize, _: usize) void {
            @setEvalBranchQuota(40_000);
            const block = @as(usize, 1) << @intCast(r.len - top);
            for (start..end) |c| {
                var prefix = scale;
                for (0..top) |j| {
                    const bit = (c >> @intCast(top - 1 - j)) & 1;
                    prefix = prefix.mul(if (bit == 1) r[j] else S.one().sub(r[j]));
                }
                const dst = out[c * block ..][0..block];
                dst[0] = prefix;
                var len: usize = 1;
                for (r[top..]) |ri| {
                    const one_minus = S.one().sub(ri);
                    var i = len;
                    if (len >= LANES) {
                        // In-place doubling from the top: block `i` writes
                        // `[2i, 2i + 8)`, above every unread entry.
                        const pri = L.splat(ri);
                        const pom = L.splat(one_minus);
                        while (i > 0) {
                            i -= LANES;
                            const x = L.load(dst.ptr + i);
                            const y = L.interleave(L.mul(x, pom), L.mul(x, pri));
                            L.store(dst.ptr + 2 * i, y[0]);
                            L.store(dst.ptr + 2 * i + LANES, y[1]);
                        }
                    } else while (i > 0) {
                        i -= 1;
                        const v = dst[i];
                        dst[2 * i + 1] = v.mul(ri);
                        dst[2 * i] = v.mul(one_minus);
                    }
                    len *= 2;
                }
            }
        }

        fn reduce(partial: []const [2]S) [2]S {
            var f0 = S.zero();
            var f2 = S.zero();
            for (partial) |p| {
                f0 = f0.add(p[0]);
                f2 = f2.add(p[1]);
            }
            return .{ f0, f2 };
        }

        fn eqOne(x: S, y: S) S {
            return x.mul(y).add(S.one().sub(x).mul(S.one().sub(y)));
        }

        fn pow2(n: usize) M31 {
            return M31.fromU64(@as(u64, 1) << @intCast(n));
        }

        fn firstNum(num: Numerators) S {
            return switch (num) {
                .ones => S.one(),
                .base => |n| S.fromBase(n[0]),
                .secure => |n| n[0],
            };
        }

        fn maskNums(num: Numerators) [2]S {
            return switch (num) {
                .ones => .{ S.one(), S.one() },
                .base => |n| .{ S.fromBase(n[0]), S.fromBase(n[1]) },
                .secure => |n| .{ n[0], n[1] },
            };
        }

        /// Consumes owned inputs (frees them on every exit) and only reads
        /// borrowed ones.
        pub fn proveBatch(a: std.mem.Allocator, channel: anytype, inputs: []const Input, options: Options, stats: ?*Stats) !ProveBatchResult {
            var adopted: usize = 0;
            defer for (inputs[adopted..]) |input| input.free(a);
            if (options.threads == 0 or options.threads > MAX_THREADS) return error.InvalidGkrThreads;
            const n_inst = inputs.len;
            if (n_inst == 0) return error.InvalidBatch;
            for (inputs) |input| {
                if (input.regen) |r| {
                    if (r.log_len < 1 or r.log_len > 40 or input.owned or input.num != .ones or input.den.len != 0) return error.InvalidInputShape;
                    continue;
                }
                if (input.den.len < 2 or !std.math.isPowerOfTwo(input.den.len)) return error.InvalidInputShape;
                switch (input.num) {
                    .ones => {},
                    .base => |n| if (n.len != input.den.len) return error.InvalidInputShape,
                    .secure => |n| if (n.len != input.den.len) return error.InvalidInputShape,
                }
            }
            var timer = try std.time.Timer.start();
            var pool_storage: std.Thread.Pool = undefined;
            const pool: ?*std.Thread.Pool = if (options.threads > 1) blk: {
                try pool_storage.init(.{ .allocator = a, .n_jobs = options.threads });
                break :blk &pool_storage;
            } else null;
            defer if (pool) |p| p.deinit();
            const ctx = Ctx{ .pool = pool, .threads = options.threads, .min_parallel = options.min_parallel };

            const n_vars = try a.alloc(usize, n_inst);
            defer a.free(n_vars);
            // layers[i][k] has k variables; layers[i][n_vars[i]] is the input.
            const layers = try a.alloc([]Layer, n_inst);
            defer a.free(layers);
            var built: usize = 0;
            defer for (layers[0..built]) |ls| {
                for (ls) |*l| l.free(a);
                a.free(ls);
            };
            // Regen instances: the input column's block, which holds the layers
            // below the first generic one and then the refilled input column.
            const spare = try a.alloc(?[]S, n_inst);
            defer a.free(spare);
            @memset(spare, null);
            defer for (spare) |b| if (b) |x| a.free(x);
            var arena_used: usize = 0;
            var n_layers: usize = 0;
            var layer_bytes: u64 = 0;
            for (inputs, 0..) |input, i| {
                n_vars[i] = input.nVariables();
                n_layers = @max(n_layers, n_vars[i]);
                layers[i] = try a.alloc(Layer, n_vars[i] + 1);
                for (layers[i]) |*l| l.* = Layer.empty();
                built += 1;
                layers[i][n_vars[i]] = .{
                    .num = input.num,
                    .den = input.den,
                    .num_buf = if (!input.owned) .none else switch (input.num) {
                        .ones => .none,
                        .base => |n| .{ .base = n },
                        .secure => |n| .{ .secure = n },
                    },
                    .den_buf = if (input.owned) input.den else null,
                };
                adopted = i + 1;
                var k = n_vars[i];
                if (input.regen) |rg| {
                    if (k < 3) {
                        // small: materialise the column, then the usual build
                        const d = try a.alloc(S, @as(usize, 1) << @intCast(k));
                        layers[i][k].den = d;
                        layers[i][k].den_buf = d;
                        rg.fill(rg.ctx, d, 0);
                    } else {
                        // layer n-2 from the source, into the block's front half
                        const blk = try a.alloc(S, @as(usize, 1) << @intCast(k));
                        spare[i] = blk;
                        const size = @as(usize, 1) << @intCast(k - 2);
                        const num = blk[0..size];
                        const den = blk[size .. 2 * size];
                        ctx.run(size, regenLayerChunk, .{ rg, 2, num, den });
                        layers[i][k - 2] = .{ .num = .{ .secure = num }, .den = den, .in_spare = true };
                        layer_bytes += 2 * size * @sizeOf(S);
                        arena_used = 2 * size;
                        k -= 2;
                    }
                }
                while (k > 0) : (k -= 1) {
                    const size = @as(usize, 1) << @intCast(k - 1);
                    if (spare[i]) |arena| {
                        // layers below n-2: carved from the same block
                        // (2^(n-1) + 2^(n-1) - 2 < 2^n entries in all)
                        const num = arena[arena_used .. arena_used + size];
                        const den = arena[arena_used + size .. arena_used + 2 * size];
                        arena_used += 2 * size;
                        layers[i][k - 1] = .{ .num = .{ .secure = num }, .den = den, .in_spare = true };
                        layer_bytes += 2 * size * @sizeOf(S);
                        ctx.run(size, nextChunk, .{ &layers[i][k], num, den });
                        continue;
                    }
                    const num = try a.alloc(S, size);
                    const den = a.alloc(S, size) catch |err| {
                        a.free(num);
                        return err;
                    };
                    layers[i][k - 1] = .{ .num = .{ .secure = num }, .den = den, .num_buf = .{ .secure = num }, .den_buf = den };
                    layer_bytes += 2 * size * @sizeOf(S);
                    ctx.run(size, nextChunk, .{ &layers[i][k], num, den });
                }
            }
            if (stats) |s| {
                s.build_ns = timer.read();
                s.peak_layer_bytes = layer_bytes;
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
            const partial = try a.alloc([2]S, options.threads * 4 + 1);
            defer a.free(partial);
            // Per-instance partial sums, so the round work of all instances can
            // be dispatched to the pool at once (one barrier per round instead
            // of one per instance and round).
            const p_stride = options.threads * 4 + 1;
            const partials = try a.alloc([2]S, n_inst * p_stride);
            defer a.free(partials);
            const jobs = try a.alloc(FoldJob, n_inst);
            defer a.free(jobs);
            const sum_jobs = try a.alloc(SumJob, n_inst);
            defer a.free(sum_jobs);
            // Per active instance state (indexed by active slot).
            const active = try a.alloc(usize, n_inst);
            defer a.free(active);
            const sc_claim = try a.alloc(S, n_inst);
            defer a.free(sc_claim);
            const nv = try a.alloc(usize, n_inst);
            defer a.free(nv);
            const correction = try a.alloc(S, n_inst);
            defer a.free(correction);
            const pending = try a.alloc(?[2]S, n_inst);
            defer a.free(pending);
            const polys = try a.alloc(Poly, n_inst);
            defer a.free(polys);

            for (0..n_layers) |layer_idx| {
                const n_remaining = n_layers - layer_idx;
                for (0..n_inst) |i| if (n_vars[i] == n_remaining) {
                    const top = &layers[i][0];
                    const out = [2]S{ firstNum(top.num), top.den[0] };
                    output_claims[i] = out;
                    claims[i] = out;
                };
                for (claims) |c| if (c) |v| channel.mixFelts(&v);
                const eq = try eqTable(a, ctx, ood.items);
                defer a.free(eq);
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
                for (0..n_active) |s| {
                    // regen instances: refill the block with the layer this step reads
                    const i = active[s];
                    const rg = inputs[i].regen orelse continue;
                    const lvl = nv[s] + 1;
                    if (n_vars[i] < 3 or lvl + 1 < n_vars[i]) continue;
                    const blk = spare[i] orelse return error.InvalidLayerStructure;
                    // every block layer was consumed (and emptied) by an earlier
                    // step; the output layer 0 was read at the first step only
                    for (layers[i][1..]) |l| if (l.in_spare) return error.InvalidLayerStructure;
                    layers[i][0] = Layer.empty();
                    if (lvl + 1 == n_vars[i]) {
                        const h = blk.len / 2;
                        ctx.run(h, regenLayerChunk, .{ rg, 1, blk[0..h], blk[h..] });
                        layers[i][lvl] = .{ .num = .{ .secure = blk[0..h] }, .den = blk[h..], .in_spare = true };
                    } else {
                        ctx.run(blk.len, regenChunk, .{ rg, blk });
                        spare[i] = null;
                        layers[i][lvl] = .{ .num = .ones, .den = blk, .den_buf = blk };
                    }
                }
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
                    var made: usize = 0;
                    defer for (polys[0..made]) |*p| p.deinit(a);
                    {
                        // Round sums not already produced by a fused fold: all instances in one dispatch.
                        var n_sj: usize = 0;
                        for (0..n_active) |s| {
                            if (nv[s] != n_remaining_rounds or pending[s] != null) continue;
                            const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                            sum_jobs[n_sj] = .{ .layer = layer, .n_terms = @as(usize, 1) << @intCast(nv[s] - 1), .partial = partials[s * p_stride ..][0..p_stride], .s = s };
                            n_sj += 1;
                        }
                        runSumJobs(ctx, sum_jobs[0..n_sj], eq, lambda);
                        for (sum_jobs[0..n_sj]) |j| pending[j.s] = reduce(j.partial[0..ctx.chunks(j.n_terms)]);
                    }
                    for (0..n_active) |s| {
                        if (nv[s] == n_remaining_rounds) {
                            const sums = pending[s].?;
                            pending[s] = null;
                            polys[s] = try PF.correctSumAsPolyInFirstVariable(a, sums[0].mul(correction[s]), sums[1].mul(correction[s]), sc_claim[s], ood.items, nv[s]);
                        } else {
                            polys[s] = Poly.initOwned(try a.dupe(S, &.{try utils.divBaseFor(S, sc_claim[s], M31.fromCanonical(2))}));
                        }
                        made += 1;
                        // The reference sumcheck's self-checks.
                        if (!polys[s].evalAtPoint(S.zero()).add(polys[s].evalAtPoint(S.one())).eql(sc_claim[s])) return error.InvalidSumcheck;
                        if (polys[s].degree() > sumcheck_module.MAX_DEGREE) return error.InvalidSumcheck;
                    }
                    // Random linear combination with alpha (Horner from the last poly).
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
                    var n_jobs: usize = 0;
                    errdefer for (jobs[0..n_jobs]) |j| foldAbort(a, j);
                    for (0..n_active) |s| {
                        sc_claim[s] = polys[s].evalAtPoint(r);
                        if (nv[s] != n_remaining_rounds) continue;
                        const layer = &layers[active[s]][layer_idx - (n_layers - n_vars[active[s]]) + 1];
                        const z0 = ood.items[ood.items.len - nv[s]];
                        correction[s] = correction[s].mul(eqOne(r, z0));
                        if (nv[s] >= 2) {
                            // fused fold + next sums: deferred to one dispatch below
                            jobs[n_jobs] = try foldPrepare(a, layer, partials[s * p_stride ..][0..p_stride], s);
                            n_jobs += 1;
                        } else {
                            try foldLayer(a, ctx, layer, r, null, &pending[s]);
                        }
                        nv[s] -= 1;
                    }
                    runFoldJobs(ctx, jobs[0..n_jobs], r, eq, lambda);
                    for (jobs[0..n_jobs]) |j| {
                        pending[j.s] = reduce(j.partial[0..ctx.chunks(j.half / 4)]);
                        foldFinish(a, j);
                    }
                    n_jobs = 0;
                }
                try sumcheck_proofs.append(a, .{ .round_polys = try round_polys.toOwnedSlice(a) });

                for (0..n_active) |s| {
                    const i = active[s];
                    const layer = &layers[i][layer_idx - (n_layers - n_vars[i]) + 1];
                    if (layer.den.len != 2) return error.InvalidLayerStructure;
                    const nums = maskNums(layer.num);
                    const flat = [4]S{ nums[0], nums[1], layer.den[0], layer.den[1] };
                    try masks[i].ensureUnusedCapacity(a, 1);
                    masks[i].appendAssumeCapacity(GV.GkrMask.initOwned(try a.dupe([2]S, &.{ nums, .{ layer.den[0], layer.den[1] } })));
                    channel.mixFelts(&flat);
                }
                const challenge = channel.drawSecureFelt();
                ood.clearRetainingCapacity();
                try ood.appendSlice(a, assignment.items);
                try ood.append(a, challenge);
                for (0..n_active) |s| {
                    const i = active[s];
                    const layer = &layers[i][layer_idx - (n_layers - n_vars[i]) + 1];
                    const nums = maskNums(layer.num);
                    claims[i] = .{ utils.foldMleEvalsFor(S, S, challenge, nums[0], nums[1]), utils.foldMleEvalsFor(S, S, challenge, layer.den[0], layer.den[1]) };
                    layer.free(a);
                }
            }
            if (stats) |s| s.sumcheck_ns = timer.read() - s.build_ns;

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

        /// Test-only access to the parallel eq table.
        pub const testing = if (@import("builtin").is_test) struct {
            pub fn eqTableWith(a: std.mem.Allocator, threads: usize, min_parallel: usize, y: []const S) ![]S {
                var pool: std.Thread.Pool = undefined;
                try pool.init(.{ .allocator = a, .n_jobs = threads });
                defer pool.deinit();
                return eqTable(a, .{ .pool = &pool, .threads = threads, .min_parallel = min_parallel }, y);
            }
        } else struct {};

        const NextSum = struct { eq: []const S, lambda: S, partial: [][2]S };

        /// A layer fold whose fused next-round sums run in a batched dispatch.
        const FoldJob = struct {
            layer: *Layer,
            dst: Folded,
            half: usize,
            den_in_place: bool,
            num_in_place: bool,
            partial: [][2]S,
            s: usize,
        };

        const SumJob = struct { layer: *const Layer, n_terms: usize, partial: [][2]S, s: usize };

        fn foldPrepare(a: std.mem.Allocator, layer: *Layer, partial: [][2]S, s: usize) !FoldJob {
            const half = layer.den.len / 2;
            const den_in_place = layer.den_buf != null or layer.in_spare;
            const den_dst: []S = if (den_in_place) layer.den[0..half] else try a.alloc(S, half);
            errdefer if (!den_in_place) a.free(den_dst);
            const num_in_place = layer.num == .secure and (layer.num_buf == .secure or layer.in_spare);
            const num_dst: ?[]S = switch (layer.num) {
                .ones => null,
                .secure => |n| if (num_in_place) n[0..half] else try a.alloc(S, half),
                .base => try a.alloc(S, half),
            };
            return .{ .layer = layer, .dst = .{ .num = num_dst, .den = den_dst }, .half = half, .den_in_place = den_in_place, .num_in_place = num_in_place, .partial = partial, .s = s };
        }

        /// Releases a prepared job's fresh buffers (error path; the layer is untouched).
        fn foldAbort(a: std.mem.Allocator, j: FoldJob) void {
            if (!j.den_in_place) a.free(j.dst.den);
            if (j.dst.num) |n| if (!j.num_in_place) a.free(n);
        }

        /// Layer bookkeeping after the job's fold ran (same as foldLayer's tail).
        fn foldFinish(a: std.mem.Allocator, j: FoldJob) void {
            const layer = j.layer;
            if (!j.den_in_place) layer.den_buf = j.dst.den;
            layer.den = j.dst.den;
            if (j.dst.num) |n| {
                if (!j.num_in_place) {
                    switch (layer.num_buf) {
                        .none => {},
                        .base => |b| a.free(b),
                        .secure => |x| a.free(x),
                    }
                    layer.num_buf = .{ .secure = n };
                }
                layer.num = .{ .secure = n };
            }
        }

        /// Runs every job's chunks (same chunking as `Ctx.run`) behind one barrier.
        fn runFoldJobs(ctx: Ctx, js: []const FoldJob, r: S, eq: []const S, lambda: S) void {
            var wg = std.Thread.WaitGroup{};
            var spawned = false;
            for (js) |*j| {
                const n = j.half / 4;
                const k = ctx.chunks(n);
                if (k <= 1) continue;
                spawned = true;
                for (0..k) |c| ctx.pool.?.spawnWg(&wg, foldSumChunk, .{ @as(*const Layer, j.layer), j.dst, j.half, r, eq, lambda, j.partial, n * c / k, n * (c + 1) / k, c });
            }
            for (js) |*j| {
                const n = j.half / 4;
                if (ctx.chunks(n) <= 1) foldSumChunk(j.layer, j.dst, j.half, r, eq, lambda, j.partial, 0, n, 0);
            }
            if (spawned) ctx.pool.?.waitAndWork(&wg);
        }

        fn runSumJobs(ctx: Ctx, js: []const SumJob, eq: []const S, lambda: S) void {
            var wg = std.Thread.WaitGroup{};
            var spawned = false;
            for (js) |*j| {
                const k = ctx.chunks(j.n_terms);
                if (k <= 1) continue;
                spawned = true;
                for (0..k) |c| ctx.pool.?.spawnWg(&wg, sumChunk, .{ j.layer, eq, j.n_terms, lambda, j.partial, j.n_terms * c / k, j.n_terms * (c + 1) / k, c });
            }
            for (js) |*j| {
                if (ctx.chunks(j.n_terms) <= 1) sumChunk(j.layer, eq, j.n_terms, lambda, j.partial, 0, j.n_terms, 0);
            }
            if (spawned) ctx.pool.?.waitAndWork(&wg);
        }

        /// Folds one layer by `r`. Borrowed storage is never written: the
        /// first fold of a borrowed (or base-numerator) layer writes a new
        /// half-size layer. With `next`, the next round's sums are computed
        /// in the same pass into `pending`.
        fn foldLayer(a: std.mem.Allocator, ctx: Ctx, layer: *Layer, r: S, next: ?NextSum, pending: *?[2]S) !void {
            const half = layer.den.len / 2;
            const den_in_place = layer.den_buf != null or layer.in_spare;
            const den_dst: []S = if (den_in_place) layer.den[0..half] else try a.alloc(S, half);
            errdefer if (!den_in_place) a.free(den_dst);
            // Secure owned numerators fold in place; borrowed or base ones
            // fold into a fresh secure buffer.
            const num_in_place = layer.num == .secure and (layer.num_buf == .secure or layer.in_spare);
            const num_dst: ?[]S = switch (layer.num) {
                .ones => null,
                .secure => |n| if (num_in_place) n[0..half] else try a.alloc(S, half),
                .base => try a.alloc(S, half),
            };
            errdefer if (num_dst != null and !num_in_place) a.free(num_dst.?);
            const dst = Folded{ .num = num_dst, .den = den_dst };
            if (next) |n| {
                const next_terms = half / 4;
                ctx.run(next_terms, foldSumChunk, .{ @as(*const Layer, layer), dst, half, r, n.eq, n.lambda, n.partial });
                pending.* = reduce(n.partial[0..ctx.chunks(next_terms)]);
            } else {
                ctx.run(half, foldChunk, .{ dst.den, @as([]const S, layer.den), half, r });
                switch (layer.num) {
                    .ones => {},
                    .secure => |x| ctx.run(half, foldChunk, .{ dst.num.?, @as([]const S, x), half, r }),
                    .base => |b| ctx.run(half, foldBaseChunk, .{ dst.num.?, @as([]const M31, b), half, r }),
                }
            }
            if (!den_in_place) layer.den_buf = den_dst;
            layer.den = den_dst;
            if (num_dst) |n| {
                if (!num_in_place) {
                    // Release a replaced owned base buffer; borrowed stays.
                    switch (layer.num_buf) {
                        .none => {},
                        .base => |b| a.free(b),
                        .secure => |x| a.free(x),
                    }
                    layer.num_buf = .{ .secure = n };
                }
                layer.num = .{ .secure = n };
            }
        }
    };
}
