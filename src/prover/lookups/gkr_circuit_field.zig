//! GKR circuit layers and the polynomial oracle consumed by batch sum-check.

const std = @import("std");
const fraction = @import("stwo_core").fraction;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const gkr_verifier_module = @import("gkr_verifier.zig");
const mle_mod = @import("mle.zig");
const utils = @import("utils.zig");
const rows = @import("row_work.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const GkrProverError = error{
    EmptyBatch,
    InvalidK,
    DivisionByZero,
    ShapeMismatch,
    NotPowerOfTwo,
    PointDimensionMismatch,
    NotOutputLayer,
    NotConstantPoly,
    InvalidLayerStructure,
    InvalidSumcheck,
    OutOfMemory,
};

/// Evaluations of `eq((0, x), y)` over the boolean hypercube.
/// One algorithm authority for the selected secure extension; Q entrypoints below remain compatible.
pub fn ForField(comptime Secure: type) type {
    return struct {
        const gkr_verifier_field = gkr_verifier_module.ForField(Secure);
        const Packed = @import("packed_rows.zig").ForField(Secure);
        const MleBase = mle_mod.MleFor(Secure, M31);
        const MleSecure = mle_mod.MleFor(Secure, Secure);
        pub const EqEvals = struct {
            y: []Secure,
            owns_y: bool = true,
            evals: MleSecure,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                if (self.owns_y) allocator.free(self.y);
                self.evals.deinit(allocator);
                self.* = undefined;
            }

            pub fn cloneOwned(self: @This(), allocator: std.mem.Allocator) !EqEvals {
                const y = try allocator.dupe(Secure, self.y);
                errdefer allocator.free(y);
                return .{ .y = y, .evals = try self.evals.cloneOwned(allocator) };
            }

            /// Borrows one immutable table for the current GKR layer scope.
            pub fn borrowed(self: @This()) EqEvals {
                return .{ .y = self.y, .owns_y = false, .evals = self.evals.borrowed() };
            }

            fn forNextRound(self: @This(), allocator: std.mem.Allocator) !EqEvals {
                if (!self.owns_y and !self.evals.owns_evals) return self;
                return self.cloneOwned(allocator);
            }

            pub fn ySlice(self: @This()) []const Secure {
                return self.y;
            }

            pub fn at(self: @This(), index: usize) Secure {
                return self.evals.evalsSlice()[index];
            }

            pub fn generate(allocator: std.mem.Allocator, y: []const Secure) !EqEvals {
                const y_owned = try allocator.dupe(Secure, y);
                errdefer allocator.free(y_owned);

                const evals = blk: {
                    if (y.len == 0) {
                        break :blk try MleSecure.initOwned(try allocator.dupe(Secure, &[_]Secure{Secure.one()}));
                    }
                    const v = Secure.one().sub(y[0]);
                    break :blk try genEqEvals(allocator, y[1..], v);
                };
                errdefer {
                    var e = evals;
                    e.deinit(allocator);
                }

                return .{
                    .y = y_owned,
                    .evals = evals,
                };
            }
        };

        /// A layer in a binary-tree GKR circuit.
        pub const Layer = union(enum) {
            GrandProduct: MleSecure,
            LogUpGeneric: struct {
                numerators: MleSecure,
                denominators: MleSecure,
            },
            LogUpMultiplicities: struct {
                numerators: MleBase,
                denominators: MleSecure,
            },
            LogUpSingles: struct {
                denominators: MleSecure,
            },

            pub fn deinit(self: *Layer, allocator: std.mem.Allocator) void {
                switch (self.*) {
                    .GrandProduct => |*mle| mle.deinit(allocator),
                    .LogUpGeneric => |*inner| {
                        inner.numerators.deinit(allocator);
                        inner.denominators.deinit(allocator);
                    },
                    .LogUpMultiplicities => |*inner| {
                        inner.numerators.deinit(allocator);
                        inner.denominators.deinit(allocator);
                    },
                    .LogUpSingles => |*inner| inner.denominators.deinit(allocator),
                }
                self.* = undefined;
            }

            pub fn borrowed(self: Layer) Layer {
                return switch (self) {
                    .GrandProduct => |v| .{ .GrandProduct = v.borrowed() },
                    .LogUpGeneric => |v| .{ .LogUpGeneric = .{ .numerators = v.numerators.borrowed(), .denominators = v.denominators.borrowed() } },
                    .LogUpMultiplicities => |v| .{ .LogUpMultiplicities = .{ .numerators = v.numerators.borrowed(), .denominators = v.denominators.borrowed() } },
                    .LogUpSingles => |v| .{ .LogUpSingles = .{ .denominators = v.denominators.borrowed() } },
                };
            }

            pub fn cloneOwned(self: Layer, allocator: std.mem.Allocator) !Layer {
                return switch (self) {
                    .GrandProduct => |mle| .{ .GrandProduct = try mle.cloneOwned(allocator) },
                    .LogUpGeneric => |inner| blk: {
                        var numerator = try inner.numerators.cloneOwned(allocator);
                        errdefer numerator.deinit(allocator);
                        break :blk .{ .LogUpGeneric = .{ .numerators = numerator, .denominators = try inner.denominators.cloneOwned(allocator) } };
                    },
                    .LogUpMultiplicities => |inner| blk: {
                        var numerator = try inner.numerators.cloneOwned(allocator);
                        errdefer numerator.deinit(allocator);
                        break :blk .{ .LogUpMultiplicities = .{ .numerators = numerator, .denominators = try inner.denominators.cloneOwned(allocator) } };
                    },
                    .LogUpSingles => |inner| .{ .LogUpSingles = .{
                        .denominators = try inner.denominators.cloneOwned(allocator),
                    } },
                };
            }

            pub fn nVariables(self: Layer) usize {
                return switch (self) {
                    .GrandProduct => |mle| mle.nVariables(),
                    .LogUpGeneric => |inner| inner.denominators.nVariables(),
                    .LogUpMultiplicities => |inner| inner.denominators.nVariables(),
                    .LogUpSingles => |inner| inner.denominators.nVariables(),
                };
            }

            pub fn isOutputLayer(self: Layer) bool {
                return self.nVariables() == 0;
            }

            pub fn nextLayer(self: Layer, allocator: std.mem.Allocator) !?Layer {
                if (self.isOutputLayer()) return null;

                return switch (self) {
                    .GrandProduct => |mle| try nextGrandProductLayer(allocator, mle),
                    .LogUpGeneric => |inner| try nextLogupLayer(
                        allocator,
                        .{ .MleSecure = &inner.numerators },
                        &inner.denominators,
                    ),
                    .LogUpMultiplicities => |inner| try nextLogupLayer(
                        allocator,
                        .{ .MleBase = &inner.numerators },
                        &inner.denominators,
                    ),
                    .LogUpSingles => |inner| try nextLogupLayer(
                        allocator,
                        .{ .Constant = Secure.one() },
                        &inner.denominators,
                    ),
                };
            }

            /// Same adjacent-pair product/fraction authority applied twice,
            /// without retaining the intermediate N/2 secure planes.
            pub fn nextLayerTwice(self: Layer, allocator: std.mem.Allocator) !Layer {
                if (self.nVariables() < 2) return GkrProverError.InvalidLayerStructure;
                return switch (self) {
                    .GrandProduct => |mle| try nextGrandProductTwoLayers(allocator, mle),
                    .LogUpGeneric => |inner| try nextLogupTwoLayers(allocator, .{ .MleSecure = &inner.numerators }, &inner.denominators),
                    .LogUpMultiplicities => |inner| try nextLogupTwoLayers(allocator, .{ .MleBase = &inner.numerators }, &inner.denominators),
                    .LogUpSingles => |inner| try nextLogupTwoLayers(allocator, .{ .Constant = Secure.one() }, &inner.denominators),
                };
            }

            pub fn outputLayerValues(self: Layer, allocator: std.mem.Allocator) GkrProverError![]Secure {
                if (!self.isOutputLayer()) return GkrProverError.NotOutputLayer;

                return switch (self) {
                    .GrandProduct => |mle| blk: {
                        const out = try allocator.alloc(Secure, 1);
                        out[0] = mle.evalsSlice()[0];
                        break :blk out;
                    },
                    .LogUpGeneric => |inner| blk: {
                        const out = try allocator.alloc(Secure, 2);
                        out[0] = inner.numerators.evalsSlice()[0];
                        out[1] = inner.denominators.evalsSlice()[0];
                        break :blk out;
                    },
                    .LogUpMultiplicities => |inner| blk: {
                        const out = try allocator.alloc(Secure, 2);
                        out[0] = Secure.fromBase(inner.numerators.evalsSlice()[0]);
                        out[1] = inner.denominators.evalsSlice()[0];
                        break :blk out;
                    },
                    .LogUpSingles => |inner| blk: {
                        const out = try allocator.alloc(Secure, 2);
                        out[0] = Secure.one();
                        out[1] = inner.denominators.evalsSlice()[0];
                        break :blk out;
                    },
                };
            }

            pub fn fixFirstVariable(
                self: Layer,
                allocator: std.mem.Allocator,
                x0: Secure,
            ) !Layer {
                if (self.nVariables() == 0) return self.cloneOwned(allocator);

                return switch (self) {
                    .GrandProduct => |mle| .{ .GrandProduct = try mle.fixFirstVariable(allocator, x0) },
                    .LogUpGeneric => |inner| blk: {
                        var numerator = try inner.numerators.fixFirstVariable(allocator, x0);
                        errdefer numerator.deinit(allocator);
                        break :blk .{ .LogUpGeneric = .{ .numerators = numerator, .denominators = try inner.denominators.fixFirstVariable(allocator, x0) } };
                    },
                    .LogUpMultiplicities => |inner| blk: {
                        var numerator = try inner.numerators.fixFirstVariable(allocator, x0);
                        errdefer numerator.deinit(allocator);
                        break :blk .{ .LogUpGeneric = .{ .numerators = numerator, .denominators = try inner.denominators.fixFirstVariable(allocator, x0) } };
                    },
                    .LogUpSingles => |inner| .{ .LogUpSingles = .{
                        .denominators = try inner.denominators.fixFirstVariable(allocator, x0),
                    } },
                };
            }

            /// Internal exclusive-owner path. Every failed partial fold still
            /// owns valid buffers for deinit; the caller aborts the proof.
            pub fn fixFirstVariableInPlace(self: *Layer, allocator: std.mem.Allocator, x0: Secure) !void {
                if (self.nVariables() == 0) return;
                switch (self.*) {
                    .GrandProduct => |*mle| try mle.foldOwnedSecure(allocator, x0),
                    .LogUpGeneric => |*inner| {
                        try inner.numerators.foldOwnedSecure(allocator, x0);
                        try inner.denominators.foldOwnedSecure(allocator, x0);
                    },
                    .LogUpSingles => |*inner| try inner.denominators.foldOwnedSecure(allocator, x0),
                    .LogUpMultiplicities => {
                        // The first base-to-secure lift keeps its existing
                        // failure-atomic allocation path and immutable input.
                        const next = try self.fixFirstVariable(allocator, x0);
                        self.deinit(allocator);
                        self.* = next;
                    },
                }
            }

            /// Moves this internal layer; the immutable Eq owner must outlive
            /// the oracle and all sumcheck rounds. No input/table copy occurs.
            pub fn intoMultivariatePolyOwned(self: Layer, lambda: Secure, eq_evals: *const EqEvals) GkrMultivariatePolyOracle {
                return .{ .eq_evals = eq_evals.borrowed(), .input_layer = self, .eq_fixed_var_correction = Secure.one(), .lambda = lambda };
            }

            pub fn intoMultivariatePoly(
                self: Layer,
                allocator: std.mem.Allocator,
                lambda: Secure,
                eq_evals: *const EqEvals,
            ) !GkrMultivariatePolyOracle {
                var eq_owned = try eq_evals.cloneOwned(allocator);
                errdefer eq_owned.deinit(allocator);
                return .{
                    .eq_evals = eq_owned,
                    .input_layer = try self.cloneOwned(allocator),
                    .eq_fixed_var_correction = Secure.one(),
                    .lambda = lambda,
                };
            }
        };

        /// Multivariate polynomial oracle used by GKR sum-check.
        pub const GkrMultivariatePolyOracle = struct {
            eq_evals: EqEvals,
            input_layer: Layer,
            eq_fixed_var_correction: Secure,
            lambda: Secure,

            pub fn deinit(self: *GkrMultivariatePolyOracle, allocator: std.mem.Allocator) void {
                self.eq_evals.deinit(allocator);
                self.input_layer.deinit(allocator);
                self.* = undefined;
            }

            pub fn cloneOwned(self: GkrMultivariatePolyOracle, allocator: std.mem.Allocator) !GkrMultivariatePolyOracle {
                var eq_owned = try self.eq_evals.cloneOwned(allocator);
                errdefer eq_owned.deinit(allocator);
                return .{
                    .eq_evals = eq_owned,
                    .input_layer = try self.input_layer.cloneOwned(allocator),
                    .eq_fixed_var_correction = self.eq_fixed_var_correction,
                    .lambda = self.lambda,
                };
            }

            pub fn nVariables(self: GkrMultivariatePolyOracle) usize {
                const in_vars = self.input_layer.nVariables();
                return if (in_vars == 0) 0 else in_vars - 1;
            }

            pub fn isConstant(self: GkrMultivariatePolyOracle) bool {
                return self.nVariables() == 0;
            }

            pub fn sumAsPolyInFirstVariable(
                self: GkrMultivariatePolyOracle,
                allocator: std.mem.Allocator,
                claim: Secure,
            ) (std.mem.Allocator.Error || GkrProverError)!utils.UnivariatePoly(Secure) {
                const n_variables = self.nVariables();
                if (n_variables == 0) return GkrProverError.InvalidLayerStructure;

                const n_terms: usize = @as(usize, 1) << @intCast(n_variables - 1);

                var eval_pair: [2]Secure = undefined;
                switch (self.input_layer) {
                    .GrandProduct => |mle| {
                        eval_pair = evalGrandProductSum(&self.eq_evals, &mle, n_terms);
                    },
                    .LogUpGeneric => |inner| {
                        eval_pair = evalLogupSum(
                            Secure,
                            &self.eq_evals,
                            &inner.numerators,
                            &inner.denominators,
                            n_terms,
                            self.lambda,
                        );
                    },
                    .LogUpMultiplicities => |inner| {
                        eval_pair = evalLogupSum(
                            M31,
                            &self.eq_evals,
                            &inner.numerators,
                            &inner.denominators,
                            n_terms,
                            self.lambda,
                        );
                    },
                    .LogUpSingles => |inner| {
                        eval_pair = evalLogupSinglesSum(
                            &self.eq_evals,
                            &inner.denominators,
                            n_terms,
                            self.lambda,
                        );
                    },
                }

                const eval_at_0 = eval_pair[0].mul(self.eq_fixed_var_correction);
                const eval_at_2 = eval_pair[1].mul(self.eq_fixed_var_correction);
                return try correctSumAsPolyInFirstVariable(
                    allocator,
                    eval_at_0,
                    eval_at_2,
                    claim,
                    self.eq_evals.ySlice(),
                    n_variables,
                );
            }

            pub fn fixFirstVariable(
                self: GkrMultivariatePolyOracle,
                allocator: std.mem.Allocator,
                challenge: Secure,
            ) !GkrMultivariatePolyOracle {
                if (self.isConstant()) return self.cloneOwned(allocator);

                const n_variables = self.nVariables();
                const z0 = self.eq_evals.ySlice()[self.eq_evals.ySlice().len - n_variables];
                const eq_term = utils.eq(
                    Secure,
                    &[_]Secure{challenge},
                    &[_]Secure{z0},
                ) catch return GkrProverError.ShapeMismatch;

                var eq_owned = try self.eq_evals.forNextRound(allocator);
                errdefer eq_owned.deinit(allocator);
                return .{
                    .eq_evals = eq_owned,
                    .eq_fixed_var_correction = self.eq_fixed_var_correction.mul(eq_term),
                    .input_layer = try self.input_layer.fixFirstVariable(allocator, challenge),
                    .lambda = self.lambda,
                };
            }

            /// Optional sumcheck owner interface: keep immutable Eq custody,
            /// consume only exclusive layer buffers, and preserve borrowed
            /// caller matrices. Failure permits deinit only, not oracle reuse.
            pub fn fixFirstVariableInPlace(self: *GkrMultivariatePolyOracle, allocator: std.mem.Allocator, challenge: Secure) !void {
                if (self.isConstant()) return;
                const n_variables = self.nVariables();
                const z0 = self.eq_evals.ySlice()[self.eq_evals.ySlice().len - n_variables];
                const eq_term = utils.eq(Secure, &.{challenge}, &.{z0}) catch return GkrProverError.ShapeMismatch;
                try self.input_layer.fixFirstVariableInPlace(allocator, challenge);
                self.eq_fixed_var_correction = self.eq_fixed_var_correction.mul(eq_term);
            }

            pub fn tryIntoMask(
                self: GkrMultivariatePolyOracle,
                allocator: std.mem.Allocator,
            ) GkrProverError!gkr_verifier_field.GkrMask {
                if (!self.isConstant()) return GkrProverError.NotConstantPoly;

                return switch (self.input_layer) {
                    .GrandProduct => |mle| blk: {
                        if (mle.evalsSlice().len != 2) return GkrProverError.InvalidLayerStructure;
                        break :blk gkr_verifier_field.GkrMask.initOwned(
                            try allocator.dupe([2]Secure, &[_][2]Secure{.{
                                mle.evalsSlice()[0],
                                mle.evalsSlice()[1],
                            }}),
                        );
                    },
                    .LogUpGeneric => |inner| blk: {
                        if (inner.numerators.evalsSlice().len != 2 or inner.denominators.evalsSlice().len != 2) {
                            return GkrProverError.InvalidLayerStructure;
                        }
                        const cols = try allocator.dupe([2]Secure, &[_][2]Secure{
                            .{ inner.numerators.evalsSlice()[0], inner.numerators.evalsSlice()[1] },
                            .{ inner.denominators.evalsSlice()[0], inner.denominators.evalsSlice()[1] },
                        });
                        break :blk gkr_verifier_field.GkrMask.initOwned(cols);
                    },
                    .LogUpMultiplicities => |inner| blk: {
                        if (inner.numerators.evalsSlice().len != 2 or inner.denominators.evalsSlice().len != 2) {
                            return GkrProverError.InvalidLayerStructure;
                        }
                        const cols = try allocator.dupe([2]Secure, &[_][2]Secure{
                            .{ Secure.fromBase(inner.numerators.evalsSlice()[0]), Secure.fromBase(inner.numerators.evalsSlice()[1]) },
                            .{ inner.denominators.evalsSlice()[0], inner.denominators.evalsSlice()[1] },
                        });
                        break :blk gkr_verifier_field.GkrMask.initOwned(cols);
                    },
                    .LogUpSingles => |inner| blk: {
                        if (inner.denominators.evalsSlice().len != 2) return GkrProverError.InvalidLayerStructure;
                        const cols = try allocator.dupe([2]Secure, &[_][2]Secure{
                            .{ Secure.one(), Secure.one() },
                            .{ inner.denominators.evalsSlice()[0], inner.denominators.evalsSlice()[1] },
                        });
                        break :blk gkr_verifier_field.GkrMask.initOwned(cols);
                    },
                };
            }
        };
        /// Computes `r(t) = sum_x eq((t, x), y[-k:]) * p(t, x)` from evaluations of
        /// `f(t) = sum_x eq(({0}^(n-k), 0, x), y) * p(t, x)`.
        pub fn correctSumAsPolyInFirstVariable(
            allocator: std.mem.Allocator,
            f_at_0: Secure,
            f_at_2: Secure,
            claim: Secure,
            y: []const Secure,
            k: usize,
        ) (std.mem.Allocator.Error || GkrProverError)!utils.UnivariatePoly(Secure) {
            if (k == 0 or k > y.len) return GkrProverError.InvalidK;

            const n = y.len;
            const prefix_len = n - k + 1;
            const eq_prefix = try eqZerosPrefix(y[0..prefix_len]);
            const a_const = Secure.one().div(eq_prefix) catch return GkrProverError.DivisionByZero;

            const y_idx = y[n - k];
            const denom = Secure.one().sub(y_idx.add(y_idx));
            const b_const = Secure.one().sub(y_idx).div(denom) catch return GkrProverError.DivisionByZero;

            const eq_at_0 = Secure.one().sub(y_idx);

            const x_two = Secure.fromBase(M31.fromCanonical(2));
            const eq_at_2 = utils.eq(
                Secure,
                &[_]Secure{x_two},
                &[_]Secure{y_idx},
            ) catch return GkrProverError.ShapeMismatch;

            const r_at_0 = f_at_0.mul(eq_at_0).mul(a_const);
            const r_at_1 = claim.sub(r_at_0);
            const r_at_2 = f_at_2.mul(eq_at_2).mul(a_const);
            return interpolate012WithRoot(allocator, .{ r_at_0, r_at_1, r_at_2 }, b_const);
        }
        /// The GKR cubic has the known fourth value r(b)=0. Newton's basis
        /// avoids generic Lagrange factors and needs one secure inverse here.
        /// b=0,1,2 remains a pole: zero numerators never mask that failure.
        pub fn interpolate012WithRoot(allocator: std.mem.Allocator, values: [3]Secure, b: Secure) (std.mem.Allocator.Error || GkrProverError)!utils.UnivariatePoly(Secure) {
            const one = Secure.one();
            const two = one.add(one);
            const bm1 = b.sub(one);
            const bm2 = b.sub(two);
            const denominator = b.mul(bm1).mul(bm2);
            const delta = values[1].sub(values[0]);
            const quadratic = values[2].sub(values[1].add(values[1])).add(values[0]).mulM31(M31.fromCanonical(1073741824));
            const at_b = values[0].add(delta.mul(b)).add(quadratic.mul(b).mul(bm1));
            const cubic = at_b.neg().div(denominator) catch return GkrProverError.DivisionByZero;
            const coeffs = try allocator.alloc(Secure, 4);
            coeffs[0] = values[0];
            coeffs[1] = delta.sub(quadratic).add(cubic.add(cubic));
            coeffs[2] = quadratic.sub(cubic.add(cubic).add(cubic));
            coeffs[3] = cubic;
            return utils.UnivariatePoly(Secure).initOwned(coeffs);
        }

        pub fn buildLayers(allocator: std.mem.Allocator, input_layer: Layer) ![]Layer {
            return buildLayersImpl(allocator, input_layer, true);
        }

        /// The caller retains the original matrix until all returned layers
        /// are deinitialized. Upper layers have their ordinary independent owners.
        pub fn buildLayersBorrowedInput(allocator: std.mem.Allocator, input_layer: Layer) ![]Layer {
            return buildLayersImpl(allocator, input_layer, false);
        }

        fn buildLayersImpl(allocator: std.mem.Allocator, input_layer: Layer, comptime clone_input: bool) ![]Layer {
            var out = std.ArrayList(Layer).empty;
            errdefer {
                for (out.items) |*layer| layer.deinit(allocator);
                out.deinit(allocator);
            }

            var current = if (clone_input) try input_layer.cloneOwned(allocator) else input_layer.borrowed();
            out.append(allocator, current) catch |err| {
                current.deinit(allocator);
                return err;
            };

            while (try current.nextLayer(allocator)) |next| {
                current = next;
                out.append(allocator, next) catch |err| {
                    current.deinit(allocator);
                    return err;
                };
            }

            return out.toOwnedSlice(allocator);
        }

        fn nextGrandProductLayer(allocator: std.mem.Allocator, layer: MleSecure) !Layer {
            const values = layer.evalsSlice();
            const out = try allocator.alloc(Secure, values.len / 2);
            const Context = struct {
                input: []const Secure,
                output: []Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    const tail = Packed.nextProduct(ctx.input, ctx.output, first, end);
                    for (tail..end) |i| ctx.output[i] = ctx.input[2 * i].mul(ctx.input[2 * i + 1]);
                }
            };
            rows.fill(out.len, Context{ .input = values, .output = out });
            return .{ .GrandProduct = try MleSecure.initOwned(out) };
        }

        const MleExpr = union(enum) {
            Constant: Secure,
            MleSecure: *const MleSecure,
            MleBase: *const MleBase,

            fn at(self: MleExpr, index: usize) Secure {
                return switch (self) {
                    .Constant => |v| v,
                    .MleSecure => |mle| mle.evalsSlice()[index],
                    .MleBase => |mle| Secure.fromBase(mle.evalsSlice()[index]),
                };
            }
        };

        fn nextLogupLayer(
            allocator: std.mem.Allocator,
            numerators: MleExpr,
            denominators: *const MleSecure,
        ) !Layer {
            const den_values = denominators.evalsSlice();
            const half_n = den_values.len / 2;

            const next_numerators = try allocator.alloc(Secure, half_n);
            errdefer allocator.free(next_numerators);
            const next_denominators = try allocator.alloc(Secure, half_n);
            errdefer allocator.free(next_denominators);

            const Context = struct {
                nums: MleExpr,
                dens: []const Secure,
                out_n: []Secure,
                out_d: []Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    const tail = switch (ctx.nums) {
                        .MleBase => |n| Packed.nextLogup(M31, n.evalsSlice(), ctx.dens, ctx.out_n, ctx.out_d, first, end),
                        .MleSecure => |n| Packed.nextLogup(Secure, n.evalsSlice(), ctx.dens, ctx.out_n, ctx.out_d, first, end),
                        .Constant => |v| if (v.eql(Secure.one())) Packed.nextLogup(void, &.{}, ctx.dens, ctx.out_n, ctx.out_d, first, end) else first,
                    };
                    for (tail..end) |i| {
                        const value = if (ctx.nums == .MleBase) baseFraction(ctx.nums.MleBase.evalsSlice()[2 * i], ctx.dens[2 * i]).add(baseFraction(ctx.nums.MleBase.evalsSlice()[2 * i + 1], ctx.dens[2 * i + 1])) else fraction.Fraction(Secure, Secure).new(ctx.nums.at(2 * i), ctx.dens[2 * i]).add(fraction.Fraction(Secure, Secure).new(ctx.nums.at(2 * i + 1), ctx.dens[2 * i + 1]));
                        ctx.out_n[i] = value.numerator;
                        ctx.out_d[i] = value.denominator;
                    }
                }
            };
            rows.fill(half_n, Context{ .nums = numerators, .dens = den_values, .out_n = next_numerators, .out_d = next_denominators });

            return .{ .LogUpGeneric = .{
                .numerators = try MleSecure.initOwned(next_numerators),
                .denominators = try MleSecure.initOwned(next_denominators),
            } };
        }

        fn nextGrandProductTwoLayers(a: std.mem.Allocator, input: MleSecure) !Layer {
            const output = try a.alloc(Secure, input.evals.len / 4);
            const Context = struct {
                input: []const Secure,
                output: []Secure,
                pub fn fillRange(self: @This(), start: usize, end: usize) void {
                    for (start..end) |i| {
                        const k = 4 * i;
                        self.output[i] = self.input[k].mul(self.input[k + 1]).mul(self.input[k + 2].mul(self.input[k + 3]));
                    }
                }
            };
            rows.fill(output.len, Context{ .input = input.evals, .output = output });
            return .{ .GrandProduct = try MleSecure.initOwned(output) };
        }
        fn nextLogupTwoLayers(a: std.mem.Allocator, nums: MleExpr, dens: *const MleSecure) !Layer {
            const numerator = try a.alloc(Secure, dens.evals.len / 4);
            errdefer a.free(numerator);
            const denominator = try a.alloc(Secure, dens.evals.len / 4);
            errdefer a.free(denominator);
            const Context = struct {
                nums: MleExpr,
                dens: []const Secure,
                n: []Secure,
                d: []Secure,
                fn pair(self: @This(), k: usize) fraction.Fraction(Secure, Secure) {
                    // This is exactly nextLogupLayer's first reduction,
                    // including its base-valued numerator specialization.
                    return if (self.nums == .MleBase)
                        baseFraction(self.nums.MleBase.evals[k], self.dens[k]).add(baseFraction(self.nums.MleBase.evals[k + 1], self.dens[k + 1]))
                    else
                        fraction.Fraction(Secure, Secure).new(self.nums.at(k), self.dens[k]).add(fraction.Fraction(Secure, Secure).new(self.nums.at(k + 1), self.dens[k + 1]));
                }
                pub fn fillRange(self: @This(), start: usize, end: usize) void {
                    for (start..end) |i| {
                        const value = self.pair(4 * i).add(self.pair(4 * i + 2));
                        self.n[i] = value.numerator;
                        self.d[i] = value.denominator;
                    }
                }
            };
            rows.fill(numerator.len, Context{ .nums = nums, .dens = dens.evals, .n = numerator, .d = denominator });
            return .{ .LogUpGeneric = .{ .numerators = try MleSecure.initOwned(numerator), .denominators = try MleSecure.initOwned(denominator) } };
        }

        fn evalGrandProductSum(
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

        fn evalLogupSum(
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

        fn evalLogupSinglesSum(
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

        fn genEqEvals(
            allocator: std.mem.Allocator,
            y: []const Secure,
            scale: Secure,
        ) !MleSecure {
            if (y.len == 0) {
                return try MleSecure.initOwned(try allocator.dupe(Secure, &[_]Secure{scale}));
            }

            var tail = try genEqEvals(allocator, y[1..], scale);
            defer tail.deinit(allocator);

            const tail_values = tail.evalsSlice();
            const out = try allocator.alloc(Secure, tail_values.len * 2);

            const eq0 = Secure.one().sub(y[0]);
            const eq1 = y[0];
            const Context = struct {
                input: []const Secure,
                output: []Secure,
                zero: Secure,
                one: Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    const p0 = Packed.splat(ctx.zero);
                    const p1 = Packed.splat(ctx.one);
                    var at = first;
                    while (at + @import("packed_rows.zig").WIDTH <= end) : (at += @import("packed_rows.zig").WIDTH) {
                        const v = Packed.load(ctx.input, at, 1);
                        Packed.store(ctx.output, at, Packed.mul(v, p0));
                        Packed.store(ctx.output, at + ctx.input.len, Packed.mul(v, p1));
                    }
                    for (at..end) |i| {
                        ctx.output[i] = ctx.input[i].mul(ctx.zero);
                        ctx.output[i + ctx.input.len] = ctx.input[i].mul(ctx.one);
                    }
                }
            };
            // The current input level stays immutable until every disjoint
            // output-half range joins; recursive tail release happens later.
            rows.fill(tail_values.len, Context{ .input = tail_values, .output = out, .zero = eq0, .one = eq1 });

            return try MleSecure.initOwned(out);
        }

        pub fn eqZerosPrefix(y: []const Secure) GkrProverError!Secure {
            var out = Secure.one();
            for (y) |yi| {
                out = out.mul(Secure.one().sub(yi));
            }
            if (out.isZero()) return GkrProverError.DivisionByZero;
            return out;
        }

        const BaseFraction = struct {
            numerator: M31,
            denominator: Secure,
            fn add(self: @This(), rhs: @This()) fraction.Fraction(Secure, Secure) {
                return .{ .numerator = rhs.denominator.mulM31(self.numerator).add(self.denominator.mulM31(rhs.numerator)), .denominator = self.denominator.mul(rhs.denominator) };
            }
        };
        fn baseFraction(n: M31, d: Secure) BaseFraction {
            return .{ .numerator = n, .denominator = d };
        }
    };
}
