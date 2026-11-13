//! Bounded-source checkpoint reduction and parallel GKR round evaluation.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const mle_mod = @import("mle.zig");
const rows = @import("row_work.zig");
const utils = @import("utils.zig");
const fraction = @import("stwo_core").fraction;
pub fn ForField(comptime Secure: type, comptime GkrProverError: type, comptime Circuit: type) type {
    const Packed = @import("packed_rows.zig").ForField(Secure);
    const MleBase = mle_mod.MleFor(Secure, M31);
    const MleSecure = mle_mod.MleFor(Secure, Secure);
    const Layer = Circuit.Layer;
    const EqEvals = Circuit.EqEvals;
    const MultiplicitiesSource = Circuit.MultiplicitiesSource;
    const baseFraction = @import("gkr_base_fraction.zig").ForField(Secure).baseFraction;
    return struct {
        pub fn materializeSource(a: std.mem.Allocator, source: MultiplicitiesSource) !Layer {
            try source.validate();
            const n = try a.alloc(M31, source.len());
            errdefer a.free(n);
            const d = try a.alloc(Secure, source.len());
            errdefer a.free(d);
            var first: usize = 0;
            while (first < n.len) {
                const end = @min(first + 4 * REDUCED_TILE, n.len);
                try source.read(first, n[first..end], d[first..end]);
                first = end;
            }
            return .{ .LogUpMultiplicities = .{ .numerators = try MleBase.initOwned(n), .denominators = try MleSecure.initOwned(d) } };
        }
        /// Bounded source read plus exactly the original adjacent fraction add.
        pub fn readSourceReduced(source: MultiplicitiesSource, first: usize, n: []Secure, d: []Secure) !void {
            if (n.len != d.len or n.len > 2 * REDUCED_TILE) return error.ShapeMismatch;
            var ms: [4 * REDUCED_TILE]M31 = undefined;
            var ds: [4 * REDUCED_TILE]Secure = undefined;
            try source.read(2 * first, ms[0 .. 2 * n.len], ds[0 .. 2 * n.len]);
            const tail = Packed.nextLogup(M31, ms[0 .. 2 * n.len], ds[0 .. 2 * n.len], n, d, 0, n.len);
            for (tail..n.len) |i| {
                const value = baseFraction(ms[2 * i], ds[2 * i]).add(baseFraction(ms[2 * i + 1], ds[2 * i + 1]));
                n[i] = value.numerator;
                d[i] = value.denominator;
            }
        }
        pub fn firstSourceCheckpoint(a: std.mem.Allocator, source: MultiplicitiesSource, levels: usize) !Layer {
            try source.validate();
            if (levels < 1 or levels > 2 or levels > source.variables) return error.InvalidLayerStructure;
            const len = source.len() >> @intCast(levels);
            const n = try a.alloc(Secure, len);
            errdefer a.free(n);
            const d = try a.alloc(Secure, len);
            errdefer a.free(d);
            const Context = struct {
                source: MultiplicitiesSource,
                levels: usize,
                n: []Secure,
                d: []Secure,
                errors: [rows.MAX_SHARDS]?GkrProverError = @splat(null),
                pub fn runRange(ctx: *@This(), ordinal: usize, first: usize, end: usize) void {
                    ctx.process(first, end) catch |err| {
                        ctx.errors[ordinal] = err;
                    };
                }
                fn process(ctx: *@This(), first: usize, end: usize) GkrProverError!void {
                    var ns: [2 * REDUCED_TILE]Secure = undefined;
                    var ds: [2 * REDUCED_TILE]Secure = undefined;
                    var start = first;
                    while (start < end) {
                        const count: usize = @min(REDUCED_TILE, end - start);
                        const on = ctx.n[start..][0..count];
                        const od = ctx.d[start..][0..count];
                        if (ctx.levels == 1) try readSourceReduced(ctx.source, start, on, od) else {
                            try readSourceReduced(ctx.source, 2 * start, ns[0 .. 2 * count], ds[0 .. 2 * count]);
                            const tail = Packed.nextLogup(Secure, ns[0 .. 2 * count], ds[0 .. 2 * count], on, od, 0, count);
                            for (tail..count) |i| {
                                const value = fraction.Fraction(Secure, Secure).new(ns[2 * i], ds[2 * i]).add(fraction.Fraction(Secure, Secure).new(ns[2 * i + 1], ds[2 * i + 1]));
                                on[i] = value.numerator;
                                od[i] = value.denominator;
                            }
                        }
                        start += count;
                    }
                }
            };
            var context = Context{ .source = source, .levels = levels, .n = n, .d = d };
            const jobs = rows.forEachRange(len, &context, .{});
            for (context.errors[0..jobs]) |err| if (err) |failure| return failure;
            return .{ .LogUpGeneric = .{ .numerators = try MleSecure.initOwned(n), .denominators = try MleSecure.initOwned(d) } };
        }
        pub fn evalSourceSum(comptime reduced: bool, eq: *const EqEvals, source: MultiplicitiesSource, terms: usize, lambda: Secure) GkrProverError![2]Secure {
            const F = if (reduced) Secure else M31;
            const Context = struct {
                eq: *const EqEvals,
                source: MultiplicitiesSource,
                terms: usize,
                lambda: Secure,
                partial: [rows.MAX_SHARDS][2]Secure = undefined,
                errors: [rows.MAX_SHARDS]?GkrProverError = @splat(null),
                pub fn runRange(ctx: *@This(), ordinal: usize, first: usize, end: usize) void {
                    ctx.partial[ordinal] = ctx.process(first, end) catch |err| {
                        ctx.errors[ordinal] = err;
                        return;
                    };
                }
                fn process(ctx: *@This(), first: usize, end: usize) GkrProverError![2]Secure {
                    var ns: [4 * REDUCED_TILE]F = undefined;
                    var ds: [4 * REDUCED_TILE]Secure = undefined;
                    var es: [REDUCED_TILE]Secure = undefined;
                    var sum = [2]Secure{ Secure.zero(), Secure.zero() };
                    var start = first;
                    while (start < end) {
                        const count: usize = @min(REDUCED_TILE, end - start);
                        if (reduced) {
                            try readSourceReduced(ctx.source, 2 * start, ns[0 .. 2 * count], ds[0 .. 2 * count]);
                            try readSourceReduced(ctx.source, 2 * (ctx.terms + start), ns[2 * REDUCED_TILE ..][0 .. 2 * count], ds[2 * REDUCED_TILE ..][0 .. 2 * count]);
                        } else {
                            try ctx.source.read(2 * start, ns[0 .. 2 * count], ds[0 .. 2 * count]);
                            try ctx.source.read(2 * (ctx.terms + start), ns[2 * REDUCED_TILE ..][0 .. 2 * count], ds[2 * REDUCED_TILE ..][0 .. 2 * count]);
                        }
                        @memcpy(es[0..count], ctx.eq.evals.evals[start..][0..count]);
                        const le = EqEvals{ .y = &.{}, .owns_y = false, .evals = .{ .evals = &es, .owns_evals = false } };
                        const ln = mle_mod.MleFor(Secure, F){ .evals = &ns, .owns_evals = false };
                        const ld = MleSecure{ .evals = &ds, .owns_evals = false };
                        const value = evalLogupSumRange(F, &le, &ln, &ld, REDUCED_TILE, ctx.lambda, 0, count);
                        sum[0] = sum[0].add(value[0]);
                        sum[1] = sum[1].add(value[1]);
                        start += count;
                    }
                    return sum;
                }
            };
            var context = Context{ .eq = eq, .source = source, .terms = terms, .lambda = lambda };
            const jobs = rows.forEachRange(terms, &context, .{});
            var sum = [2]Secure{ Secure.zero(), Secure.zero() };
            for (0..jobs) |i| {
                if (context.errors[i]) |err| return err;
                sum[0] = sum[0].add(context.partial[i][0]);
                sum[1] = sum[1].add(context.partial[i][1]);
            }
            return sum;
        }
        pub fn foldSourceLayer(comptime reduced: bool, a: std.mem.Allocator, source: MultiplicitiesSource, challenge: Secure) !Layer {
            const F = if (reduced) Secure else M31;
            const len = source.len() >> @as(u6, if (reduced) 2 else 1);
            const n = try a.alloc(Secure, len);
            errdefer a.free(n);
            const d = try a.alloc(Secure, len);
            errdefer a.free(d);
            const Context = struct {
                source: MultiplicitiesSource,
                n: []Secure,
                d: []Secure,
                challenge: Secure,
                errors: [rows.MAX_SHARDS]?GkrProverError = @splat(null),
                pub fn runRange(ctx: *@This(), ordinal: usize, first: usize, end: usize) void {
                    ctx.process(first, end) catch |err| {
                        ctx.errors[ordinal] = err;
                    };
                }
                fn process(ctx: *@This(), first: usize, end: usize) GkrProverError!void {
                    var ns: [2 * REDUCED_TILE]F = undefined;
                    var ds: [2 * REDUCED_TILE]Secure = undefined;
                    var start = first;
                    while (start < end) {
                        const count: usize = @min(REDUCED_TILE, end - start);
                        if (reduced) {
                            try readSourceReduced(ctx.source, start, ns[0..count], ds[0..count]);
                            try readSourceReduced(ctx.source, ctx.n.len + start, ns[count..][0..count], ds[count..][0..count]);
                        } else {
                            try ctx.source.read(start, ns[0..count], ds[0..count]);
                            try ctx.source.read(ctx.n.len + start, ns[count..][0..count], ds[count..][0..count]);
                        }
                        const on = ctx.n[start..][0..count];
                        const od = ctx.d[start..][0..count];
                        const nt = Packed.fold(F, ns[0 .. 2 * count], on, ctx.challenge, 0, count);
                        for (nt..count) |i| on[i] = utils.foldMleEvalsFor(Secure, F, ctx.challenge, ns[i], ns[count + i]);
                        const dt = Packed.fold(Secure, ds[0 .. 2 * count], od, ctx.challenge, 0, count);
                        for (dt..count) |i| od[i] = utils.foldMleEvalsFor(Secure, Secure, ctx.challenge, ds[i], ds[count + i]);
                        start += count;
                    }
                }
            };
            var context = Context{ .source = source, .n = n, .d = d, .challenge = challenge };
            const jobs = rows.forEachRange(len, &context, .{});
            for (context.errors[0..jobs]) |err| if (err) |failure| return failure;
            return .{ .LogUpGeneric = .{ .numerators = try MleSecure.initOwned(n), .denominators = try MleSecure.initOwned(d) } };
        }

        const REDUCED_TILE = 16;
        /// Compute only a bounded span of the missing layer. Packed reductions
        /// are the original nextLayer kernels; scalar tails retain fraction.add.
        pub fn reduceCheckpointRows(input: Layer, first: usize, n: []Secure, d: []Secure) void {
            const count = n.len;
            const source = 2 * first;
            switch (input) {
                .GrandProduct => |x| {
                    const tail = Packed.nextProduct(x.evals[source..], n, 0, count);
                    for (tail..count) |i| n[i] = x.evals[source + 2 * i].mul(x.evals[source + 2 * i + 1]);
                },
                inline .LogUpGeneric, .LogUpMultiplicities => |x| {
                    const F = @TypeOf(x.numerators.evals[0]);
                    const tail = Packed.nextLogup(F, x.numerators.evals[source..], x.denominators.evals[source..], n, d, 0, count);
                    for (tail..count) |i| {
                        const j = source + 2 * i;
                        const value = if (F == M31)
                            baseFraction(x.numerators.evals[j], x.denominators.evals[j]).add(baseFraction(x.numerators.evals[j + 1], x.denominators.evals[j + 1]))
                        else
                            fraction.Fraction(Secure, Secure).new(x.numerators.evals[j], x.denominators.evals[j]).add(fraction.Fraction(Secure, Secure).new(x.numerators.evals[j + 1], x.denominators.evals[j + 1]));
                        n[i] = value.numerator;
                        d[i] = value.denominator;
                    }
                },
                .LogUpSingles => |x| {
                    const tail = Packed.nextLogup(void, &.{}, x.denominators.evals[source..], n, d, 0, count);
                    for (tail..count) |i| {
                        const j = source + 2 * i;
                        const value = utils.Reciprocal(Secure).new(x.denominators.evals[j]).add(utils.Reciprocal(Secure).new(x.denominators.evals[j + 1]));
                        n[i] = value.numerator;
                        d[i] = value.denominator;
                    }
                },
            }
        }
        pub fn evalReducedSum(eq: *const EqEvals, input: Layer, terms: usize, lambda: Secure) [2]Secure {
            const Context = struct {
                eq: *const EqEvals,
                input: Layer,
                terms: usize,
                lambda: Secure,
                pub fn sumRange(ctx: @This(), first: usize, end: usize) [2]Secure {
                    var ns: [4 * REDUCED_TILE]Secure = undefined;
                    var ds: [4 * REDUCED_TILE]Secure = undefined;
                    var es: [REDUCED_TILE]Secure = undefined;
                    var sum = [2]Secure{ Secure.zero(), Secure.zero() };
                    var start = first;
                    while (start < end) {
                        const count: usize = @min(REDUCED_TILE, end - start);
                        reduceCheckpointRows(ctx.input, 2 * start, ns[0 .. 2 * count], ds[0 .. 2 * count]);
                        reduceCheckpointRows(ctx.input, 2 * (ctx.terms + start), ns[2 * REDUCED_TILE ..][0 .. 2 * count], ds[2 * REDUCED_TILE ..][0 .. 2 * count]);
                        @memcpy(es[0..count], ctx.eq.evals.evals[start..][0..count]);
                        const local_eq = EqEvals{ .y = &.{}, .owns_y = false, .evals = .{ .evals = &es, .owns_evals = false } };
                        const local_n = MleSecure{ .evals = &ns, .owns_evals = false };
                        const local_d = MleSecure{ .evals = &ds, .owns_evals = false };
                        const value = if (ctx.input == .GrandProduct)
                            evalGrandProductSumRange(&local_eq, &local_n, REDUCED_TILE, 0, count)
                        else
                            evalLogupSumRange(Secure, &local_eq, &local_n, &local_d, REDUCED_TILE, ctx.lambda, 0, count);
                        sum[0] = sum[0].add(value[0]);
                        sum[1] = sum[1].add(value[1]);
                        start += count;
                    }
                    return sum;
                }
            };
            return rows.reduce(Secure, terms, Context{ .eq = eq, .input = input, .terms = terms, .lambda = lambda });
        }
        pub fn foldReducedLayer(a: std.mem.Allocator, input: Layer, challenge: Secure) !Layer {
            const len = @as(usize, 1) << @intCast(input.nVariables() - 2);
            const n = try a.alloc(Secure, len);
            errdefer a.free(n);
            const product = input == .GrandProduct;
            const d: []Secure = if (product) &.{} else try a.alloc(Secure, len);
            errdefer if (!product) a.free(d);
            const Context = struct {
                input: Layer,
                n: []Secure,
                d: []Secure,
                challenge: Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    var ns: [2 * REDUCED_TILE]Secure = undefined;
                    var ds: [2 * REDUCED_TILE]Secure = undefined;
                    var start = first;
                    while (start < end) {
                        const count: usize = @min(REDUCED_TILE, end - start);
                        reduceCheckpointRows(ctx.input, start, ns[0..count], ds[0..count]);
                        reduceCheckpointRows(ctx.input, ctx.n.len + start, ns[count..][0..count], ds[count..][0..count]);
                        const out_n = ctx.n[start..][0..count];
                        const tail_n = Packed.fold(Secure, ns[0 .. 2 * count], out_n, ctx.challenge, 0, count);
                        for (tail_n..count) |i| out_n[i] = utils.foldMleEvalsFor(Secure, Secure, ctx.challenge, ns[i], ns[count + i]);
                        if (ctx.input != .GrandProduct) {
                            const out_d = ctx.d[start..][0..count];
                            const tail_d = Packed.fold(Secure, ds[0 .. 2 * count], out_d, ctx.challenge, 0, count);
                            for (tail_d..count) |i| out_d[i] = utils.foldMleEvalsFor(Secure, Secure, ctx.challenge, ds[i], ds[count + i]);
                        }
                        start += count;
                    }
                }
            };
            rows.fill(len, Context{ .input = input, .n = n, .d = d, .challenge = challenge });
            if (product) return .{ .GrandProduct = try MleSecure.initOwned(n) };
            return .{ .LogUpGeneric = .{ .numerators = try MleSecure.initOwned(n), .denominators = try MleSecure.initOwned(d) } };
        }

        /// Computes `r(t) = sum_x eq((t, x), y[-k:]) * p(t, x)` from evaluations of
        /// `f(t) = sum_x eq(({0}^(n-k), 0, x), y) * p(t, x)`.
        pub fn evalGrandProductSum(
            eq_evals: *const EqEvals,
            input_layer: *const MleSecure,
            n_terms: usize,
        ) [2]Secure {
            const Context = struct {
                eq: *const EqEvals,
                input: *const MleSecure,
                terms: usize,
                pub fn sumRange(self: @This(), first: usize, end: usize) [2]Secure {
                    return evalGrandProductSumRange(self.eq, self.input, self.terms, first, end);
                }
            };
            return rows.reduce(Secure, n_terms, Context{ .eq = eq_evals, .input = input_layer, .terms = n_terms });
        }

        fn evalGrandProductSumRange(
            eq_evals: *const EqEvals,
            input_layer: *const MleSecure,
            n_terms: usize,
            first: usize,
            end: usize,
        ) [2]Secure {
            const batch = Packed.sumProduct(eq_evals.evals.evalsSlice(), input_layer.evalsSlice(), n_terms, first, end);
            var eval_at_0 = batch.values[0];
            var eval_at_2 = batch.values[1];

            const input = input_layer.evalsSlice();
            for (batch.end..end) |i| {
                const inp_at_r0i0 = input[i * 2];
                const inp_at_r0i1 = input[i * 2 + 1];
                const inp_at_r1i0 = input[(n_terms + i) * 2];
                const inp_at_r1i1 = input[(n_terms + i) * 2 + 1];

                const inp_at_r2i0 = inp_at_r1i0.add(inp_at_r1i0).sub(inp_at_r0i0);
                const inp_at_r2i1 = inp_at_r1i1.add(inp_at_r1i1).sub(inp_at_r0i1);

                const prod_at_r0i = inp_at_r0i0.mul(inp_at_r0i1);
                const prod_at_r2i = inp_at_r2i0.mul(inp_at_r2i1);

                const eq_eval = eq_evals.at(i);
                eval_at_0 = eval_at_0.add(eq_eval.mul(prod_at_r0i));
                eval_at_2 = eval_at_2.add(eq_eval.mul(prod_at_r2i));
            }

            return .{ eval_at_0, eval_at_2 };
        }

        pub fn evalLogupSum(
            comptime F: type,
            eq_evals: *const EqEvals,
            input_numerators: *const mle_mod.MleFor(Secure, F),
            input_denominators: *const MleSecure,
            n_terms: usize,
            lambda: Secure,
        ) [2]Secure {
            const Context = struct {
                eq: *const EqEvals,
                num: *const mle_mod.MleFor(Secure, F),
                den: *const MleSecure,
                terms: usize,
                lambda: Secure,
                pub fn sumRange(self: @This(), first: usize, end: usize) [2]Secure {
                    return evalLogupSumRange(F, self.eq, self.num, self.den, self.terms, self.lambda, first, end);
                }
            };
            return rows.reduce(Secure, n_terms, Context{ .eq = eq_evals, .num = input_numerators, .den = input_denominators, .terms = n_terms, .lambda = lambda });
        }

        fn evalLogupSumRange(
            comptime F: type,
            eq_evals: *const EqEvals,
            input_numerators: *const mle_mod.MleFor(Secure, F),
            input_denominators: *const MleSecure,
            n_terms: usize,
            lambda: Secure,
            first: usize,
            end: usize,
        ) [2]Secure {
            const batch = Packed.sumLogup(F, eq_evals.evals.evalsSlice(), input_numerators.evalsSlice(), input_denominators.evalsSlice(), n_terms, lambda, first, end);
            var eval_at_0 = batch.values[0];
            var eval_at_2 = batch.values[1];

            const numerators = input_numerators.evalsSlice();
            const denominators = input_denominators.evalsSlice();

            for (batch.end..end) |i| {
                const den_r0i0 = denominators[i * 2];
                const den_r0i1 = denominators[i * 2 + 1];
                const den_r1i0 = denominators[(n_terms + i) * 2];
                const den_r1i1 = denominators[(n_terms + i) * 2 + 1];

                const den_r2i0 = den_r1i0.add(den_r1i0).sub(den_r0i0);
                const den_r2i1 = den_r1i1.add(den_r1i1).sub(den_r0i1);

                const eq_eval = eq_evals.at(i);

                if (F == M31) {
                    // Small-big specialization: keep numerators as M31 through
                    // interpolation and use Fraction(M31, Secure) so cross-products
                    // use Secure.mulM31 (4 base-field muls) instead of Secure.mul
                    // (9 base-field muls via Karatsuba).
                    const num_r0i0 = numerators[i * 2];
                    const num_r0i1 = numerators[i * 2 + 1];
                    const num_r1i0 = numerators[(n_terms + i) * 2];
                    const num_r1i1 = numerators[(n_terms + i) * 2 + 1];

                    const num_r2i0 = num_r1i0.add(num_r1i0).sub(num_r0i0);
                    const num_r2i1 = num_r1i1.add(num_r1i1).sub(num_r0i1);

                    const frac_r0 = baseFraction(num_r0i0, den_r0i0)
                        .add(baseFraction(num_r0i1, den_r0i1));
                    const frac_r2 = baseFraction(num_r2i0, den_r2i0)
                        .add(baseFraction(num_r2i1, den_r2i1));

                    eval_at_0 = eval_at_0.add(
                        eq_eval.mul(frac_r0.numerator.add(lambda.mul(frac_r0.denominator))),
                    );
                    eval_at_2 = eval_at_2.add(
                        eq_eval.mul(frac_r2.numerator.add(lambda.mul(frac_r2.denominator))),
                    );
                } else {
                    const num_r0i0 = asSecure(F, numerators[i * 2]);
                    const num_r0i1 = asSecure(F, numerators[i * 2 + 1]);
                    const num_r1i0 = asSecure(F, numerators[(n_terms + i) * 2]);
                    const num_r1i1 = asSecure(F, numerators[(n_terms + i) * 2 + 1]);

                    const num_r2i0 = num_r1i0.add(num_r1i0).sub(num_r0i0);
                    const num_r2i1 = num_r1i1.add(num_r1i1).sub(num_r0i1);

                    const frac_r0 = fraction.Fraction(Secure, Secure).new(num_r0i0, den_r0i0)
                        .add(fraction.Fraction(Secure, Secure).new(num_r0i1, den_r0i1));
                    const frac_r2 = fraction.Fraction(Secure, Secure).new(num_r2i0, den_r2i0)
                        .add(fraction.Fraction(Secure, Secure).new(num_r2i1, den_r2i1));

                    eval_at_0 = eval_at_0.add(
                        eq_eval.mul(frac_r0.numerator.add(lambda.mul(frac_r0.denominator))),
                    );
                    eval_at_2 = eval_at_2.add(
                        eq_eval.mul(frac_r2.numerator.add(lambda.mul(frac_r2.denominator))),
                    );
                }
            }

            return .{ eval_at_0, eval_at_2 };
        }

        pub fn evalLogupSinglesSum(
            eq_evals: *const EqEvals,
            input_denominators: *const MleSecure,
            n_terms: usize,
            lambda: Secure,
        ) [2]Secure {
            const Context = struct {
                eq: *const EqEvals,
                den: *const MleSecure,
                terms: usize,
                lambda: Secure,
                pub fn sumRange(self: @This(), first: usize, end: usize) [2]Secure {
                    return evalLogupSinglesSumRange(self.eq, self.den, self.terms, self.lambda, first, end);
                }
            };
            return rows.reduce(Secure, n_terms, Context{ .eq = eq_evals, .den = input_denominators, .terms = n_terms, .lambda = lambda });
        }

        fn evalLogupSinglesSumRange(
            eq_evals: *const EqEvals,
            input_denominators: *const MleSecure,
            n_terms: usize,
            lambda: Secure,
            first: usize,
            end: usize,
        ) [2]Secure {
            const batch = Packed.sumLogup(void, eq_evals.evals.evalsSlice(), &.{}, input_denominators.evalsSlice(), n_terms, lambda, first, end);
            var eval_at_0 = batch.values[0];
            var eval_at_2 = batch.values[1];

            const denominators = input_denominators.evalsSlice();
            const R = utils.Reciprocal(Secure);

            for (batch.end..end) |i| {
                const den_r0i0 = denominators[i * 2];
                const den_r0i1 = denominators[i * 2 + 1];
                const den_r1i0 = denominators[(n_terms + i) * 2];
                const den_r1i1 = denominators[(n_terms + i) * 2 + 1];

                const den_r2i0 = den_r1i0.add(den_r1i0).sub(den_r0i0);
                const den_r2i1 = den_r1i1.add(den_r1i1).sub(den_r0i1);

                const frac_r0 = R.new(den_r0i0).add(R.new(den_r0i1));
                const frac_r2 = R.new(den_r2i0).add(R.new(den_r2i1));

                const eq_eval = eq_evals.at(i);
                eval_at_0 = eval_at_0.add(
                    eq_eval.mul(frac_r0.numerator.add(lambda.mul(frac_r0.denominator))),
                );
                eval_at_2 = eval_at_2.add(
                    eq_eval.mul(frac_r2.numerator.add(lambda.mul(frac_r2.denominator))),
                );
            }

            return .{ eval_at_0, eval_at_2 };
        }

        fn asSecure(comptime F: type, value: F) Secure {
            if (F == Secure) return value;
            if (F == M31) return Secure.fromBase(value);
            @compileError("unsupported field in gkr prover helper");
        }
    };
}
