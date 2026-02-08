const std = @import("std");
const fraction = @import("../../core/fraction.zig");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const gkr_verifier = @import("gkr_verifier.zig");
const mle_mod = @import("mle.zig");
const sumcheck = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const MleBase = mle_mod.Mle(M31);
const MleSecure = mle_mod.Mle(QM31);

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
};

/// Evaluations of `eq((0, x), y)` over the boolean hypercube.
pub const EqEvals = struct {
    y: []QM31,
    evals: MleSecure,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.y);
        self.evals.deinit(allocator);
        self.* = undefined;
    }

    pub fn cloneOwned(self: @This(), allocator: std.mem.Allocator) !EqEvals {
        return .{
            .y = try allocator.dupe(QM31, self.y),
            .evals = try self.evals.cloneOwned(allocator),
        };
    }

    pub fn ySlice(self: @This()) []const QM31 {
        return self.y;
    }

    pub fn at(self: @This(), index: usize) QM31 {
        return self.evals.evalsSlice()[index];
    }

    pub fn generate(allocator: std.mem.Allocator, y: []const QM31) !EqEvals {
        const y_owned = try allocator.dupe(QM31, y);
        errdefer allocator.free(y_owned);

        const evals = blk: {
            if (y.len == 0) {
                break :blk try MleSecure.initOwned(try allocator.dupe(QM31, &[_]QM31{QM31.one()}));
            }
            const v = QM31.one().sub(y[0]);
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

    pub fn cloneOwned(self: Layer, allocator: std.mem.Allocator) !Layer {
        return switch (self) {
            .GrandProduct => |mle| .{ .GrandProduct = try mle.cloneOwned(allocator) },
            .LogUpGeneric => |inner| .{ .LogUpGeneric = .{
                .numerators = try inner.numerators.cloneOwned(allocator),
                .denominators = try inner.denominators.cloneOwned(allocator),
            } },
            .LogUpMultiplicities => |inner| .{ .LogUpMultiplicities = .{
                .numerators = try inner.numerators.cloneOwned(allocator),
                .denominators = try inner.denominators.cloneOwned(allocator),
            } },
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
                .{ .Constant = QM31.one() },
                &inner.denominators,
            ),
        };
    }

    pub fn outputLayerValues(self: Layer, allocator: std.mem.Allocator) GkrProverError![]QM31 {
        if (!self.isOutputLayer()) return GkrProverError.NotOutputLayer;

        return switch (self) {
            .GrandProduct => |mle| blk: {
                const out = allocator.alloc(QM31, 1) catch return GkrProverError.ShapeMismatch;
                out[0] = mle.evalsSlice()[0];
                break :blk out;
            },
            .LogUpGeneric => |inner| blk: {
                const out = allocator.alloc(QM31, 2) catch return GkrProverError.ShapeMismatch;
                out[0] = inner.numerators.evalsSlice()[0];
                out[1] = inner.denominators.evalsSlice()[0];
                break :blk out;
            },
            .LogUpMultiplicities => |inner| blk: {
                const out = allocator.alloc(QM31, 2) catch return GkrProverError.ShapeMismatch;
                out[0] = QM31.fromBase(inner.numerators.evalsSlice()[0]);
                out[1] = inner.denominators.evalsSlice()[0];
                break :blk out;
            },
            .LogUpSingles => |inner| blk: {
                const out = allocator.alloc(QM31, 2) catch return GkrProverError.ShapeMismatch;
                out[0] = QM31.one();
                out[1] = inner.denominators.evalsSlice()[0];
                break :blk out;
            },
        };
    }

    pub fn fixFirstVariable(
        self: Layer,
        allocator: std.mem.Allocator,
        x0: QM31,
    ) !Layer {
        if (self.nVariables() == 0) return self.cloneOwned(allocator);

        return switch (self) {
            .GrandProduct => |mle| .{ .GrandProduct = try mle.fixFirstVariable(allocator, x0) },
            .LogUpGeneric => |inner| .{ .LogUpGeneric = .{
                .numerators = try inner.numerators.fixFirstVariable(allocator, x0),
                .denominators = try inner.denominators.fixFirstVariable(allocator, x0),
            } },
            .LogUpMultiplicities => |inner| .{ .LogUpGeneric = .{
                .numerators = try inner.numerators.fixFirstVariable(allocator, x0),
                .denominators = try inner.denominators.fixFirstVariable(allocator, x0),
            } },
            .LogUpSingles => |inner| .{ .LogUpSingles = .{
                .denominators = try inner.denominators.fixFirstVariable(allocator, x0),
            } },
        };
    }

    pub fn intoMultivariatePoly(
        self: Layer,
        allocator: std.mem.Allocator,
        lambda: QM31,
        eq_evals: *const EqEvals,
    ) !GkrMultivariatePolyOracle {
        return .{
            .eq_evals = try eq_evals.cloneOwned(allocator),
            .input_layer = try self.cloneOwned(allocator),
            .eq_fixed_var_correction = QM31.one(),
            .lambda = lambda,
        };
    }
};

/// Multivariate polynomial oracle used by GKR sum-check.
pub const GkrMultivariatePolyOracle = struct {
    eq_evals: EqEvals,
    input_layer: Layer,
    eq_fixed_var_correction: QM31,
    lambda: QM31,

    pub fn deinit(self: *GkrMultivariatePolyOracle, allocator: std.mem.Allocator) void {
        self.eq_evals.deinit(allocator);
        self.input_layer.deinit(allocator);
        self.* = undefined;
    }

    pub fn cloneOwned(self: GkrMultivariatePolyOracle, allocator: std.mem.Allocator) !GkrMultivariatePolyOracle {
        return .{
            .eq_evals = try self.eq_evals.cloneOwned(allocator),
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
        claim: QM31,
    ) (std.mem.Allocator.Error || GkrProverError)!utils.UnivariatePoly(QM31) {
        const n_variables = self.nVariables();
        if (n_variables == 0) return GkrProverError.InvalidLayerStructure;

        const n_terms: usize = @as(usize, 1) << @intCast(n_variables - 1);

        var eval_pair: [2]QM31 = undefined;
        switch (self.input_layer) {
            .GrandProduct => |mle| {
                eval_pair = evalGrandProductSum(&self.eq_evals, &mle, n_terms);
            },
            .LogUpGeneric => |inner| {
                eval_pair = evalLogupSum(
                    QM31,
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
        challenge: QM31,
    ) !GkrMultivariatePolyOracle {
        if (self.isConstant()) return self.cloneOwned(allocator);

        const n_variables = self.nVariables();
        const z0 = self.eq_evals.ySlice()[self.eq_evals.ySlice().len - n_variables];
        const eq_term = utils.eq(
            QM31,
            &[_]QM31{challenge},
            &[_]QM31{z0},
        ) catch return GkrProverError.ShapeMismatch;

        return .{
            .eq_evals = try self.eq_evals.cloneOwned(allocator),
            .eq_fixed_var_correction = self.eq_fixed_var_correction.mul(eq_term),
            .input_layer = try self.input_layer.fixFirstVariable(allocator, challenge),
            .lambda = self.lambda,
        };
    }

    pub fn tryIntoMask(
        self: GkrMultivariatePolyOracle,
        allocator: std.mem.Allocator,
    ) GkrProverError!gkr_verifier.GkrMask {
        if (!self.isConstant()) return GkrProverError.NotConstantPoly;

        return switch (self.input_layer) {
            .GrandProduct => |mle| blk: {
                if (mle.evalsSlice().len != 2) return GkrProverError.InvalidLayerStructure;
                break :blk gkr_verifier.GkrMask.initOwned(
                    allocator.dupe([2]QM31, &[_][2]QM31{.{
                        mle.evalsSlice()[0],
                        mle.evalsSlice()[1],
                    }}) catch return GkrProverError.ShapeMismatch,
                );
            },
            .LogUpGeneric => |inner| blk: {
                if (inner.numerators.evalsSlice().len != 2 or inner.denominators.evalsSlice().len != 2) {
                    return GkrProverError.InvalidLayerStructure;
                }
                const cols = allocator.dupe([2]QM31, &[_][2]QM31{
                    .{ inner.numerators.evalsSlice()[0], inner.numerators.evalsSlice()[1] },
                    .{ inner.denominators.evalsSlice()[0], inner.denominators.evalsSlice()[1] },
                }) catch return GkrProverError.ShapeMismatch;
                break :blk gkr_verifier.GkrMask.initOwned(cols);
            },
            .LogUpMultiplicities => |inner| blk: {
                if (inner.numerators.evalsSlice().len != 2 or inner.denominators.evalsSlice().len != 2) {
                    return GkrProverError.InvalidLayerStructure;
                }
                const cols = allocator.dupe([2]QM31, &[_][2]QM31{
                    .{ QM31.fromBase(inner.numerators.evalsSlice()[0]), QM31.fromBase(inner.numerators.evalsSlice()[1]) },
                    .{ inner.denominators.evalsSlice()[0], inner.denominators.evalsSlice()[1] },
                }) catch return GkrProverError.ShapeMismatch;
                break :blk gkr_verifier.GkrMask.initOwned(cols);
            },
            .LogUpSingles => |inner| blk: {
                if (inner.denominators.evalsSlice().len != 2) return GkrProverError.InvalidLayerStructure;
                const cols = allocator.dupe([2]QM31, &[_][2]QM31{
                    .{ QM31.one(), QM31.one() },
                    .{ inner.denominators.evalsSlice()[0], inner.denominators.evalsSlice()[1] },
                }) catch return GkrProverError.ShapeMismatch;
                break :blk gkr_verifier.GkrMask.initOwned(cols);
            },
        };
    }
};

pub const ProveBatchResult = struct {
    proof: gkr_verifier.GkrBatchProof,
    artifact: gkr_verifier.GkrArtifact,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.artifact.deinit(allocator);
        self.* = undefined;
    }
};

/// Batch-proves lookup circuits with GKR.
pub fn proveBatch(
    allocator: std.mem.Allocator,
    channel: anytype,
    input_layer_by_instance: []const Layer,
) (std.mem.Allocator.Error || GkrProverError)!ProveBatchResult {
    if (input_layer_by_instance.len == 0) return GkrProverError.EmptyBatch;

    const n_instances = input_layer_by_instance.len;

    const n_layers_by_instance = try allocator.alloc(usize, n_instances);
    defer allocator.free(n_layers_by_instance);

    var n_layers: usize = 0;
    for (input_layer_by_instance, 0..) |layer, i| {
        n_layers_by_instance[i] = layer.nVariables();
        n_layers = @max(n_layers, n_layers_by_instance[i]);
    }

    const layers_by_instance = try allocator.alloc([]Layer, n_instances);
    errdefer allocator.free(layers_by_instance);
    var layers_initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < layers_initialized) : (i += 1) {
            for (layers_by_instance[i]) |*layer| layer.deinit(allocator);
            allocator.free(layers_by_instance[i]);
        }
    }

    for (input_layer_by_instance, 0..) |input_layer, i| {
        layers_by_instance[i] = try genLayers(allocator, input_layer);
        layers_initialized += 1;
    }

    defer {
        for (layers_by_instance) |layers| {
            for (layers) |*layer| layer.deinit(allocator);
            allocator.free(layers);
        }
        allocator.free(layers_by_instance);
    }

    const next_layer_idx = try allocator.alloc(usize, n_instances);
    defer allocator.free(next_layer_idx);
    for (layers_by_instance, 0..) |layers, i| next_layer_idx[i] = layers.len;

    var output_claims_by_instance = try allocator.alloc(?[]QM31, n_instances);
    defer {
        for (output_claims_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| allocator.free(claims);
        }
        allocator.free(output_claims_by_instance);
    }
    @memset(output_claims_by_instance, null);

    var claims_to_verify_by_instance = try allocator.alloc(?[]QM31, n_instances);
    defer {
        for (claims_to_verify_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| allocator.free(claims);
        }
        allocator.free(claims_to_verify_by_instance);
    }
    @memset(claims_to_verify_by_instance, null);

    const mask_builders = try allocator.alloc(std.ArrayList(gkr_verifier.GkrMask), n_instances);
    defer {
        for (mask_builders) |*builder| {
            for (builder.items) |*mask| mask.deinit(allocator);
            builder.deinit(allocator);
        }
        allocator.free(mask_builders);
    }
    for (mask_builders) |*builder| builder.* = .empty;

    var sumcheck_proofs = std.ArrayList(sumcheck.SumcheckProof).empty;
    defer {
        for (sumcheck_proofs.items) |*proof| proof.deinit(allocator);
        sumcheck_proofs.deinit(allocator);
    }

    var ood_point = try allocator.alloc(QM31, 0);
    defer allocator.free(ood_point);

    var layer_idx: usize = 0;
    while (layer_idx < n_layers) : (layer_idx += 1) {
        const n_remaining_layers = n_layers - layer_idx;

        var instance: usize = 0;
        while (instance < n_instances) : (instance += 1) {
            if (n_layers_by_instance[instance] == n_remaining_layers) {
                const output_layer = try popNextLayer(
                    layers_by_instance[instance],
                    &next_layer_idx[instance],
                );
                const output_values = try output_layer.outputLayerValues(allocator);
                try replaceOwnedSlice(
                    allocator,
                    &claims_to_verify_by_instance[instance],
                    try allocator.dupe(QM31, output_values),
                );
                try replaceOwnedSlice(
                    allocator,
                    &output_claims_by_instance[instance],
                    output_values,
                );
            }
        }

        for (claims_to_verify_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| channel.mixFelts(claims);
        }

        var eq_evals = try EqEvals.generate(allocator, ood_point);
        defer eq_evals.deinit(allocator);

        const sumcheck_alpha = channel.drawSecureFelt();
        const instance_lambda = channel.drawSecureFelt();

        var sumcheck_oracles = std.ArrayList(GkrMultivariatePolyOracle).empty;
        defer {
            for (sumcheck_oracles.items) |*oracle| oracle.deinit(allocator);
            sumcheck_oracles.deinit(allocator);
        }

        var sumcheck_claims = std.ArrayList(QM31).empty;
        defer sumcheck_claims.deinit(allocator);

        var sumcheck_instances = std.ArrayList(usize).empty;
        defer sumcheck_instances.deinit(allocator);

        instance = 0;
        while (instance < n_instances) : (instance += 1) {
            if (claims_to_verify_by_instance[instance]) |claims| {
                const layer = try popNextLayer(
                    layers_by_instance[instance],
                    &next_layer_idx[instance],
                );
                try sumcheck_oracles.append(
                    allocator,
                    try layer.intoMultivariatePoly(
                        allocator,
                        instance_lambda,
                        &eq_evals,
                    ),
                );
                try sumcheck_claims.append(
                    allocator,
                    utils.randomLinearCombination(claims, instance_lambda),
                );
                try sumcheck_instances.append(allocator, instance);
            }
        }

        const sumcheck_result = sumcheck.proveBatch(
            GkrMultivariatePolyOracle,
            allocator,
            sumcheck_claims.items,
            sumcheck_oracles.items,
            sumcheck_alpha,
            channel,
        ) catch |err| switch (err) {
            std.mem.Allocator.Error.OutOfMemory => return error.OutOfMemory,
            else => return GkrProverError.InvalidSumcheck,
        };

        try sumcheck_proofs.append(allocator, sumcheck_result.proof);

        const masks = try allocator.alloc(gkr_verifier.GkrMask, sumcheck_result.constant_polys.len);
        var masks_initialized: usize = 0;
        errdefer {
            for (masks[0..masks_initialized]) |*mask| mask.deinit(allocator);
            allocator.free(masks);
        }

        for (sumcheck_result.constant_polys, 0..) |oracle, i| {
            masks[i] = try oracle.tryIntoMask(allocator);
            masks_initialized += 1;
        }

        for (sumcheck_result.constant_polys) |*oracle| oracle.deinit(allocator);
        allocator.free(sumcheck_result.constant_polys);

        for (masks, sumcheck_instances.items) |mask, instance_idx| {
            const flattened = try flattenMaskColumns(allocator, &mask);
            defer allocator.free(flattened);
            channel.mixFelts(flattened);
            try mask_builders[instance_idx].append(allocator, mask);
        }

        const challenge = channel.drawSecureFelt();

        const next_ood = try allocator.alloc(QM31, sumcheck_result.assignment.len + 1);
        @memcpy(next_ood[0..sumcheck_result.assignment.len], sumcheck_result.assignment);
        next_ood[sumcheck_result.assignment.len] = challenge;
        allocator.free(ood_point);
        allocator.free(sumcheck_result.assignment);
        ood_point = next_ood;

        allocator.free(sumcheck_result.claimed_evals);

        for (masks, sumcheck_instances.items) |mask, instance_idx| {
            const reduced = try mask.reduceAtPoint(allocator, challenge);
            try replaceOwnedSlice(
                allocator,
                &claims_to_verify_by_instance[instance_idx],
                reduced,
            );
        }

        allocator.free(masks);
    }

    const proof_sumcheck = try sumcheck_proofs.toOwnedSlice(allocator);

    const proof_layer_masks = try allocator.alloc([]gkr_verifier.GkrMask, n_instances);
    for (mask_builders, 0..) |*builder, i| {
        proof_layer_masks[i] = try builder.toOwnedSlice(allocator);
    }

    const proof_output_claims = try allocator.alloc([]QM31, n_instances);
    for (output_claims_by_instance, 0..) |*maybe_claims, i| {
        proof_output_claims[i] = maybe_claims.* orelse return GkrProverError.InvalidLayerStructure;
        maybe_claims.* = null;
    }

    const artifact_claims = try allocator.alloc([]QM31, n_instances);
    for (claims_to_verify_by_instance, 0..) |*maybe_claims, i| {
        artifact_claims[i] = maybe_claims.* orelse return GkrProverError.InvalidLayerStructure;
        maybe_claims.* = null;
    }

    const artifact_n_vars = try allocator.dupe(usize, n_layers_by_instance);

    const proof = gkr_verifier.GkrBatchProof{
        .sumcheck_proofs = proof_sumcheck,
        .layer_masks_by_instance = proof_layer_masks,
        .output_claims_by_instance = proof_output_claims,
    };

    const artifact = gkr_verifier.GkrArtifact{
        .ood_point = ood_point,
        .claims_to_verify_by_instance = artifact_claims,
        .n_variables_by_instance = artifact_n_vars,
    };

    ood_point = &[_]QM31{};
    return .{ .proof = proof, .artifact = artifact };
}

/// Computes `r(t) = sum_x eq((t, x), y[-k:]) * p(t, x)` from evaluations of
/// `f(t) = sum_x eq(({0}^(n-k), 0, x), y) * p(t, x)`.
pub fn correctSumAsPolyInFirstVariable(
    allocator: std.mem.Allocator,
    f_at_0: QM31,
    f_at_2: QM31,
    claim: QM31,
    y: []const QM31,
    k: usize,
) (std.mem.Allocator.Error || GkrProverError)!utils.UnivariatePoly(QM31) {
    if (k == 0 or k > y.len) return GkrProverError.InvalidK;

    const n = y.len;
    const prefix_len = n - k + 1;
    const eq_prefix = try eqZerosPrefix(y[0..prefix_len]);
    const a_const = QM31.one().div(eq_prefix) catch return GkrProverError.DivisionByZero;

    const y_idx = y[n - k];
    const denom = QM31.one().sub(y_idx.add(y_idx));
    const b_const = QM31.one().sub(y_idx).div(denom) catch return GkrProverError.DivisionByZero;

    const eq_at_0 = QM31.one().sub(y_idx);

    const x_two = QM31.fromBase(M31.fromCanonical(2));
    const eq_at_2 = utils.eq(
        QM31,
        &[_]QM31{x_two},
        &[_]QM31{y_idx},
    ) catch return GkrProverError.ShapeMismatch;

    const r_at_0 = f_at_0.mul(eq_at_0).mul(a_const);
    const r_at_1 = claim.sub(r_at_0);
    const r_at_2 = f_at_2.mul(eq_at_2).mul(a_const);
    const r_at_b = QM31.zero();

    const xs = [_]QM31{ QM31.zero(), QM31.one(), x_two, b_const };
    const ys = [_]QM31{ r_at_0, r_at_1, r_at_2, r_at_b };
    return utils.UnivariatePoly(QM31).interpolateLagrange(allocator, xs[0..], ys[0..]) catch |err| switch (err) {
        utils.LookupUtilsError.ShapeMismatch => GkrProverError.ShapeMismatch,
        utils.LookupUtilsError.DivisionByZero => GkrProverError.DivisionByZero,
        else => err,
    };
}

fn popNextLayer(layers: []const Layer, next_idx: *usize) GkrProverError!Layer {
    if (next_idx.* == 0) return GkrProverError.InvalidLayerStructure;
    next_idx.* -= 1;
    return layers[next_idx.*];
}

fn replaceOwnedSlice(
    allocator: std.mem.Allocator,
    slot: *?[]QM31,
    next: []QM31,
) !void {
    if (slot.*) |old| allocator.free(old);
    slot.* = next;
}

fn flattenMaskColumns(allocator: std.mem.Allocator, mask: *const gkr_verifier.GkrMask) ![]QM31 {
    const out = try allocator.alloc(QM31, mask.columnsSlice().len * 2);
    for (mask.columnsSlice(), 0..) |column, i| {
        out[2 * i] = column[0];
        out[2 * i + 1] = column[1];
    }
    return out;
}

fn genLayers(allocator: std.mem.Allocator, input_layer: Layer) ![]Layer {
    var out = std.ArrayList(Layer).empty;
    errdefer {
        for (out.items) |*layer| layer.deinit(allocator);
        out.deinit(allocator);
    }

    var current = try input_layer.cloneOwned(allocator);
    try out.append(allocator, current);

    while (try current.nextLayer(allocator)) |next| {
        current = next;
        try out.append(allocator, next);
    }

    return out.toOwnedSlice(allocator);
}

fn nextGrandProductLayer(allocator: std.mem.Allocator, layer: MleSecure) !Layer {
    const values = layer.evalsSlice();
    const out = try allocator.alloc(QM31, values.len / 2);
    for (out, 0..) |*dst, i| {
        dst.* = values[2 * i].mul(values[2 * i + 1]);
    }
    return .{ .GrandProduct = try MleSecure.initOwned(out) };
}

const MleExpr = union(enum) {
    Constant: QM31,
    MleSecure: *const MleSecure,
    MleBase: *const MleBase,

    fn at(self: MleExpr, index: usize) QM31 {
        return switch (self) {
            .Constant => |v| v,
            .MleSecure => |mle| mle.evalsSlice()[index],
            .MleBase => |mle| QM31.fromBase(mle.evalsSlice()[index]),
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

    const next_numerators = try allocator.alloc(QM31, half_n);
    errdefer allocator.free(next_numerators);
    const next_denominators = try allocator.alloc(QM31, half_n);
    errdefer allocator.free(next_denominators);

    for (0..half_n) |i| {
        const a = fraction.Fraction(QM31, QM31).new(
            numerators.at(2 * i),
            den_values[2 * i],
        );
        const b = fraction.Fraction(QM31, QM31).new(
            numerators.at(2 * i + 1),
            den_values[2 * i + 1],
        );
        const res = a.add(b);
        next_numerators[i] = res.numerator;
        next_denominators[i] = res.denominator;
    }

    return .{ .LogUpGeneric = .{
        .numerators = try MleSecure.initOwned(next_numerators),
        .denominators = try MleSecure.initOwned(next_denominators),
    } };
}

fn evalGrandProductSum(
    eq_evals: *const EqEvals,
    input_layer: *const MleSecure,
    n_terms: usize,
) [2]QM31 {
    var eval_at_0 = QM31.zero();
    var eval_at_2 = QM31.zero();

    const input = input_layer.evalsSlice();
    for (0..n_terms) |i| {
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
    input_numerators: *const mle_mod.Mle(F),
    input_denominators: *const MleSecure,
    n_terms: usize,
    lambda: QM31,
) [2]QM31 {
    var eval_at_0 = QM31.zero();
    var eval_at_2 = QM31.zero();

    const numerators = input_numerators.evalsSlice();
    const denominators = input_denominators.evalsSlice();

    for (0..n_terms) |i| {
        const num_r0i0 = asSecure(F, numerators[i * 2]);
        const den_r0i0 = denominators[i * 2];
        const num_r0i1 = asSecure(F, numerators[i * 2 + 1]);
        const den_r0i1 = denominators[i * 2 + 1];

        const num_r1i0 = asSecure(F, numerators[(n_terms + i) * 2]);
        const den_r1i0 = denominators[(n_terms + i) * 2];
        const num_r1i1 = asSecure(F, numerators[(n_terms + i) * 2 + 1]);
        const den_r1i1 = denominators[(n_terms + i) * 2 + 1];

        const num_r2i0 = num_r1i0.add(num_r1i0).sub(num_r0i0);
        const den_r2i0 = den_r1i0.add(den_r1i0).sub(den_r0i0);
        const num_r2i1 = num_r1i1.add(num_r1i1).sub(num_r0i1);
        const den_r2i1 = den_r1i1.add(den_r1i1).sub(den_r0i1);

        const frac_r0 = fraction.Fraction(QM31, QM31).new(num_r0i0, den_r0i0)
            .add(fraction.Fraction(QM31, QM31).new(num_r0i1, den_r0i1));
        const frac_r2 = fraction.Fraction(QM31, QM31).new(num_r2i0, den_r2i0)
            .add(fraction.Fraction(QM31, QM31).new(num_r2i1, den_r2i1));

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

fn evalLogupSinglesSum(
    eq_evals: *const EqEvals,
    input_denominators: *const MleSecure,
    n_terms: usize,
    lambda: QM31,
) [2]QM31 {
    var eval_at_0 = QM31.zero();
    var eval_at_2 = QM31.zero();

    const denominators = input_denominators.evalsSlice();
    const R = utils.Reciprocal(QM31);

    for (0..n_terms) |i| {
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

fn asSecure(comptime F: type, value: F) QM31 {
    if (F == QM31) return value;
    if (F == M31) return QM31.fromBase(value);
    @compileError("unsupported field in gkr prover helper");
}

fn genEqEvals(
    allocator: std.mem.Allocator,
    y: []const QM31,
    scale: QM31,
) !MleSecure {
    if (y.len == 0) {
        return try MleSecure.initOwned(try allocator.dupe(QM31, &[_]QM31{scale}));
    }

    var tail = try genEqEvals(allocator, y[1..], scale);
    defer tail.deinit(allocator);

    const tail_values = tail.evalsSlice();
    const out = try allocator.alloc(QM31, tail_values.len * 2);

    const eq0 = QM31.one().sub(y[0]);
    const eq1 = y[0];
    for (tail_values, 0..) |v, i| {
        out[i] = v.mul(eq0);
        out[i + tail_values.len] = v.mul(eq1);
    }

    return try MleSecure.initOwned(out);
}

fn eqZerosPrefix(y: []const QM31) GkrProverError!QM31 {
    var out = QM31.one();
    for (y) |yi| {
        out = out.mul(QM31.one().sub(yi));
    }
    if (out.isZero()) return GkrProverError.DivisionByZero;
    return out;
}

test "gkr prover: eq evals generation matches direct eq" {
    const alloc = std.testing.allocator;

    const y = [_]QM31{
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(11, 0, 0, 0),
    };

    var eq_evals = try EqEvals.generate(alloc, y[0..]);
    defer eq_evals.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1) << 2, eq_evals.evals.evalsSlice().len);

    const zero = QM31.zero();
    const one = QM31.one();
    const points = [_][2]QM31{
        .{ zero, zero },
        .{ zero, one },
        .{ one, zero },
        .{ one, one },
    };

    for (points) |point| {
        const got = try eq_evals.evals.evalAtPoint(alloc, point[0..]);
        const expected = try utils.eq(
            QM31,
            &[_]QM31{ zero, point[0], point[1] },
            y[0..],
        );
        try std.testing.expect(got.eql(expected));
    }
}

test "gkr prover: corrected sum polynomial interpolation" {
    const alloc = std.testing.allocator;

    const y = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
    };
    const k: usize = 2;
    const n = y.len;
    const y_idx = y[n - k];

    const c0 = QM31.fromU32Unchecked(2, 0, 0, 0);
    const c1 = QM31.fromU32Unchecked(5, 0, 0, 0);
    const c2 = QM31.fromU32Unchecked(9, 0, 0, 0);
    const c3 = QM31.fromU32Unchecked(6, 0, 0, 0);

    const evalR = struct {
        fn at(t: QM31, c0_: QM31, c1_: QM31, c2_: QM31, c3_: QM31) QM31 {
            return c0_
                .add(c1_.mul(t))
                .add(c2_.mul(t.square()))
                .add(c3_.mul(t.square().mul(t)));
        }
    }.at;

    const zero = QM31.zero();
    const one = QM31.one();
    const two = QM31.fromBase(M31.fromCanonical(2));

    const prefix_len = n - k + 1;
    const eq_prefix = try eqZerosPrefix(y[0..prefix_len]);
    const a_const = QM31.one().div(eq_prefix) catch return GkrProverError.DivisionByZero;

    const denom = QM31.one().sub(y_idx.add(y_idx));
    const b_const = QM31.one().sub(y_idx).div(denom) catch return GkrProverError.DivisionByZero;

    const r0 = evalR(zero, c0, c1, c2, c3);
    const r1 = evalR(one, c0, c1, c2, c3);
    const r2 = evalR(two, c0, c1, c2, c3);

    const eq_at_0 = QM31.one().sub(y_idx);
    const eq_at_2 = try utils.eq(QM31, &[_]QM31{two}, &[_]QM31{y_idx});

    const f0 = r0.div(eq_at_0.mul(a_const)) catch return GkrProverError.DivisionByZero;
    const f2 = r2.div(eq_at_2.mul(a_const)) catch return GkrProverError.DivisionByZero;
    const claim = r0.add(r1);

    var poly = try correctSumAsPolyInFirstVariable(alloc, f0, f2, claim, y[0..], k);
    defer poly.deinit(alloc);

    try std.testing.expect(poly.evalAtPoint(zero).eql(r0));
    try std.testing.expect(poly.evalAtPoint(one).eql(r1));
    try std.testing.expect(poly.evalAtPoint(two).eql(r2));
    try std.testing.expect(poly.evalAtPoint(b_const).isZero());
}

test "gkr prover: grand product prove and verify" {
    const alloc = std.testing.allocator;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;

    var draw_channel = Channel{};
    const values = try draw_channel.drawSecureFelts(alloc, 1 << 5);

    var claim = QM31.one();
    for (values) |v| claim = claim.mul(v);

    var mle = try MleSecure.initOwned(values);
    defer mle.deinit(alloc);
    var mle_check = try mle.cloneOwned(alloc);
    defer mle_check.deinit(alloc);

    const input_layers = [_]Layer{.{ .GrandProduct = mle }};

    var prover_channel = Channel{};
    var result = try proveBatch(alloc, &prover_channel, input_layers[0..]);
    defer result.deinit(alloc);

    var verify_channel = Channel{};
    var verify_artifact = try gkr_verifier.partiallyVerifyBatch(
        alloc,
        &[_]gkr_verifier.Gate{.GrandProduct},
        &result.proof,
        &verify_channel,
    );
    defer verify_artifact.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), result.proof.output_claims_by_instance.len);
    try std.testing.expect(result.proof.output_claims_by_instance[0][0].eql(claim));

    const expected = try mle_check.evalAtPoint(alloc, verify_artifact.ood_point);
    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][0].eql(expected));
}

test "gkr prover: logup generic prove and verify" {
    const alloc = std.testing.allocator;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;

    var draw_channel = Channel{};
    const numerators_values = try draw_channel.drawSecureFelts(alloc, 1 << 5);
    const denominators_values = try draw_channel.drawSecureFelts(alloc, 1 << 5);

    const terms = try alloc.alloc(fraction.Fraction(QM31, QM31), numerators_values.len);
    defer alloc.free(terms);

    for (numerators_values, denominators_values, 0..) |n, d, i| {
        terms[i] = fraction.Fraction(QM31, QM31).new(n, d);
    }
    const sum = fraction.sumFractions(QM31, QM31, terms);

    var numerators = try MleSecure.initOwned(numerators_values);
    defer numerators.deinit(alloc);
    var denominators = try MleSecure.initOwned(denominators_values);
    defer denominators.deinit(alloc);

    var numerators_check = try numerators.cloneOwned(alloc);
    defer numerators_check.deinit(alloc);
    var denominators_check = try denominators.cloneOwned(alloc);
    defer denominators_check.deinit(alloc);

    const input_layers = [_]Layer{.{ .LogUpGeneric = .{
        .numerators = numerators,
        .denominators = denominators,
    } }};

    var prover_channel = Channel{};
    var result = try proveBatch(alloc, &prover_channel, input_layers[0..]);
    defer result.deinit(alloc);

    var verify_channel = Channel{};
    var verify_artifact = try gkr_verifier.partiallyVerifyBatch(
        alloc,
        &[_]gkr_verifier.Gate{.LogUp},
        &result.proof,
        &verify_channel,
    );
    defer verify_artifact.deinit(alloc);

    try std.testing.expect(result.proof.output_claims_by_instance[0][0].eql(sum.numerator));
    try std.testing.expect(result.proof.output_claims_by_instance[0][1].eql(sum.denominator));

    const expected_num = try numerators_check.evalAtPoint(alloc, verify_artifact.ood_point);
    const expected_den = try denominators_check.evalAtPoint(alloc, verify_artifact.ood_point);

    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][0].eql(expected_num));
    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][1].eql(expected_den));
}

test "gkr prover: logup singles prove and verify" {
    const alloc = std.testing.allocator;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;

    var draw_channel = Channel{};
    const denominators_values = try draw_channel.drawSecureFelts(alloc, 1 << 5);

    const terms = try alloc.alloc(fraction.Fraction(QM31, QM31), denominators_values.len);
    defer alloc.free(terms);
    for (denominators_values, 0..) |d, i| {
        terms[i] = fraction.Fraction(QM31, QM31).new(QM31.one(), d);
    }
    const sum = fraction.sumFractions(QM31, QM31, terms);

    var denominators = try MleSecure.initOwned(denominators_values);
    defer denominators.deinit(alloc);
    var denominators_check = try denominators.cloneOwned(alloc);
    defer denominators_check.deinit(alloc);

    const input_layers = [_]Layer{.{ .LogUpSingles = .{ .denominators = denominators } }};

    var prover_channel = Channel{};
    var result = try proveBatch(alloc, &prover_channel, input_layers[0..]);
    defer result.deinit(alloc);

    var verify_channel = Channel{};
    var verify_artifact = try gkr_verifier.partiallyVerifyBatch(
        alloc,
        &[_]gkr_verifier.Gate{.LogUp},
        &result.proof,
        &verify_channel,
    );
    defer verify_artifact.deinit(alloc);

    try std.testing.expect(result.proof.output_claims_by_instance[0][0].eql(sum.numerator));
    try std.testing.expect(result.proof.output_claims_by_instance[0][1].eql(sum.denominator));

    const expected_den = try denominators_check.evalAtPoint(alloc, verify_artifact.ood_point);
    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][0].eql(QM31.one()));
    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][1].eql(expected_den));
}

test "gkr prover: logup multiplicities prove and verify" {
    const alloc = std.testing.allocator;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;

    var draw_channel = Channel{};
    const numerator_secure = try draw_channel.drawSecureFelts(alloc, 1 << 5);
    defer alloc.free(numerator_secure);

    const numerators_values = try alloc.alloc(M31, numerator_secure.len);
    for (numerator_secure, 0..) |v, i| {
        numerators_values[i] = v.toM31Array()[0];
    }

    const denominators_values = try draw_channel.drawSecureFelts(alloc, 1 << 5);

    const terms = try alloc.alloc(fraction.Fraction(QM31, QM31), numerators_values.len);
    defer alloc.free(terms);
    for (numerators_values, denominators_values, 0..) |n, d, i| {
        terms[i] = fraction.Fraction(QM31, QM31).new(QM31.fromBase(n), d);
    }
    const sum = fraction.sumFractions(QM31, QM31, terms);

    var numerators = try MleBase.initOwned(numerators_values);
    defer numerators.deinit(alloc);
    var denominators = try MleSecure.initOwned(denominators_values);
    defer denominators.deinit(alloc);

    var numerators_check = try numerators.cloneOwned(alloc);
    defer numerators_check.deinit(alloc);
    var denominators_check = try denominators.cloneOwned(alloc);
    defer denominators_check.deinit(alloc);

    const input_layers = [_]Layer{.{ .LogUpMultiplicities = .{
        .numerators = numerators,
        .denominators = denominators,
    } }};

    var prover_channel = Channel{};
    var result = try proveBatch(alloc, &prover_channel, input_layers[0..]);
    defer result.deinit(alloc);

    var verify_channel = Channel{};
    var verify_artifact = try gkr_verifier.partiallyVerifyBatch(
        alloc,
        &[_]gkr_verifier.Gate{.LogUp},
        &result.proof,
        &verify_channel,
    );
    defer verify_artifact.deinit(alloc);

    try std.testing.expect(result.proof.output_claims_by_instance[0][0].eql(sum.numerator));
    try std.testing.expect(result.proof.output_claims_by_instance[0][1].eql(sum.denominator));

    const expected_num = try numerators_check.evalAtPoint(alloc, verify_artifact.ood_point);
    const expected_den = try denominators_check.evalAtPoint(alloc, verify_artifact.ood_point);

    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][0].eql(expected_num));
    try std.testing.expect(verify_artifact.claims_to_verify_by_instance[0][1].eql(expected_den));
}
