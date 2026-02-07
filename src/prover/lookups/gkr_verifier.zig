const std = @import("std");
const fraction = @import("../../core/fraction.zig");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const sumcheck = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const GkrError = error{
    MalformedProof,
    InvalidMask,
    NumInstancesMismatch,
    InvalidSumcheck,
    CircuitCheckFailure,
    ShapeMismatch,
};

/// Values obtained from partial GKR verification.
pub const GkrArtifact = struct {
    ood_point: []QM31,
    claims_to_verify_by_instance: [][]QM31,
    n_variables_by_instance: []usize,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.ood_point);
        for (self.claims_to_verify_by_instance) |claims| allocator.free(claims);
        allocator.free(self.claims_to_verify_by_instance);
        allocator.free(self.n_variables_by_instance);
        self.* = undefined;
    }
};

/// Stores two evaluations of each column in a GKR layer.
pub const GkrMask = struct {
    columns: [][2]QM31,

    pub fn initOwned(columns: [][2]QM31) GkrMask {
        return .{ .columns = columns };
    }

    pub fn cloneOwned(self: GkrMask, allocator: std.mem.Allocator) !GkrMask {
        return .{ .columns = try allocator.dupe([2]QM31, self.columns) };
    }

    pub fn deinit(self: *GkrMask, allocator: std.mem.Allocator) void {
        allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn columnsSlice(self: GkrMask) []const [2]QM31 {
        return self.columns;
    }

    pub fn toRows(self: GkrMask, allocator: std.mem.Allocator) ![2][]QM31 {
        var rows: [2][]QM31 = undefined;
        rows[0] = try allocator.alloc(QM31, self.columns.len);
        errdefer allocator.free(rows[0]);
        rows[1] = try allocator.alloc(QM31, self.columns.len);
        errdefer allocator.free(rows[1]);

        for (self.columns, 0..) |column, i| {
            rows[0][i] = column[0];
            rows[1][i] = column[1];
        }
        return rows;
    }

    pub fn reduceAtPoint(self: GkrMask, allocator: std.mem.Allocator, x: QM31) ![]QM31 {
        const out = try allocator.alloc(QM31, self.columns.len);
        for (self.columns, 0..) |column, i| {
            out[i] = utils.foldMleEvals(QM31, x, column[0], column[1]);
        }
        return out;
    }
};

/// Batch GKR proof.
pub const GkrBatchProof = struct {
    sumcheck_proofs: []sumcheck.SumcheckProof,
    layer_masks_by_instance: [][]GkrMask,
    output_claims_by_instance: [][]QM31,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.sumcheck_proofs) |*proof| proof.deinit(allocator);
        allocator.free(self.sumcheck_proofs);

        for (self.layer_masks_by_instance) |masks| {
            for (masks) |*mask| mask.deinit(allocator);
            allocator.free(masks);
        }
        allocator.free(self.layer_masks_by_instance);

        for (self.output_claims_by_instance) |claims| allocator.free(claims);
        allocator.free(self.output_claims_by_instance);

        self.* = undefined;
    }
};

/// Local gate relation used by GKR.
pub const Gate = enum {
    LogUp,
    GrandProduct,

    pub fn eval(
        self: Gate,
        allocator: std.mem.Allocator,
        mask: *const GkrMask,
    ) GkrError![]QM31 {
        return switch (self) {
            .LogUp => blk: {
                if (mask.columns.len != 2) return GkrError.InvalidMask;

                const numerator = mask.columns[0];
                const denominator = mask.columns[1];

                const a = fraction.Fraction(QM31, QM31).new(numerator[0], denominator[0]);
                const b = fraction.Fraction(QM31, QM31).new(numerator[1], denominator[1]);
                const res = a.add(b);

                const out = allocator.alloc(QM31, 2) catch return GkrError.ShapeMismatch;
                out[0] = res.numerator;
                out[1] = res.denominator;
                break :blk out;
            },
            .GrandProduct => blk: {
                if (mask.columns.len != 1) return GkrError.InvalidMask;
                const out = allocator.alloc(QM31, 1) catch return GkrError.ShapeMismatch;
                out[0] = mask.columns[0][0].mul(mask.columns[0][1]);
                break :blk out;
            },
        };
    }
};

/// Partially verifies a batch GKR proof.
pub fn partiallyVerifyBatch(
    allocator: std.mem.Allocator,
    gate_by_instance: []const Gate,
    proof: *const GkrBatchProof,
    channel: anytype,
) (std.mem.Allocator.Error || GkrError)!GkrArtifact {
    if (proof.layer_masks_by_instance.len != proof.output_claims_by_instance.len) {
        return GkrError.MalformedProof;
    }

    const n_instances = proof.layer_masks_by_instance.len;
    var n_layers: usize = 0;
    for (proof.layer_masks_by_instance) |masks| {
        n_layers = @max(n_layers, masks.len);
    }

    if (n_layers != proof.sumcheck_proofs.len) return GkrError.MalformedProof;
    if (gate_by_instance.len != n_instances) return GkrError.NumInstancesMismatch;

    var ood_point = try allocator.alloc(QM31, 0);
    errdefer allocator.free(ood_point);

    var claims_to_verify_by_instance = try allocator.alloc(?[]QM31, n_instances);
    errdefer {
        for (claims_to_verify_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| allocator.free(claims);
        }
        allocator.free(claims_to_verify_by_instance);
    }
    @memset(claims_to_verify_by_instance, null);

    for (proof.sumcheck_proofs, 0..) |*sumcheck_proof, layer| {
        const n_remaining_layers = n_layers - layer;

        for (0..n_instances) |instance| {
            if (proof.layer_masks_by_instance[instance].len == n_remaining_layers) {
                const fresh_claims = try allocator.dupe(
                    QM31,
                    proof.output_claims_by_instance[instance],
                );
                try replaceClaim(
                    allocator,
                    &claims_to_verify_by_instance[instance],
                    fresh_claims,
                );
            }
        }

        for (claims_to_verify_by_instance) |maybe_claims| {
            if (maybe_claims) |claims| channel.mixFelts(claims);
        }

        const sumcheck_alpha = channel.drawSecureFelt();
        const instance_lambda = channel.drawSecureFelt();

        var sumcheck_claims = std.ArrayList(QM31).init(allocator);
        defer sumcheck_claims.deinit();

        var sumcheck_instances = std.ArrayList(usize).init(allocator);
        defer sumcheck_instances.deinit();

        for (claims_to_verify_by_instance, 0..) |maybe_claims, instance| {
            if (maybe_claims) |claims| {
                const n_unused_variables = n_layers - proof.layer_masks_by_instance[instance].len;
                const claim = utils.randomLinearCombination(claims, instance_lambda)
                    .mulM31(pow2Base(n_unused_variables));
                try sumcheck_claims.append(claim);
                try sumcheck_instances.append(instance);
            }
        }

        const sumcheck_claim = utils.randomLinearCombination(sumcheck_claims.items, sumcheck_alpha);

        var sumcheck_artifact = sumcheck.partiallyVerify(
            allocator,
            sumcheck_claim,
            sumcheck_proof,
            channel,
        ) catch |err| switch (err) {
            sumcheck.SumcheckError.DegreeInvalid,
            sumcheck.SumcheckError.SumInvalid,
            => return GkrError.InvalidSumcheck,
            else => return err,
        };
        defer sumcheck_artifact.deinit(allocator);

        var layer_evals = std.ArrayList(QM31).init(allocator);
        defer layer_evals.deinit();

        for (sumcheck_instances.items) |instance| {
            const n_unused = n_layers - proof.layer_masks_by_instance[instance].len;
            if (layer < n_unused) return GkrError.MalformedProof;
            const instance_layer = layer - n_unused;
            if (instance_layer >= proof.layer_masks_by_instance[instance].len) {
                return GkrError.MalformedProof;
            }

            const mask = &proof.layer_masks_by_instance[instance][instance_layer];
            const gate_output = gate_by_instance[instance].eval(allocator, mask) catch |err| switch (err) {
                GkrError.InvalidMask => return GkrError.InvalidMask,
                else => return err,
            };
            defer allocator.free(gate_output);

            const eq_eval = utils.eq(
                QM31,
                ood_point[n_unused..],
                sumcheck_artifact.assignment[n_unused..],
            ) catch return GkrError.ShapeMismatch;

            try layer_evals.append(
                eq_eval.mul(utils.randomLinearCombination(gate_output, instance_lambda)),
            );
        }

        const layer_eval = utils.randomLinearCombination(layer_evals.items, sumcheck_alpha);
        if (!sumcheck_artifact.claimed_eval.eql(layer_eval)) {
            return GkrError.CircuitCheckFailure;
        }

        for (sumcheck_instances.items) |instance| {
            const n_unused = n_layers - proof.layer_masks_by_instance[instance].len;
            const instance_layer = layer - n_unused;
            const mask = &proof.layer_masks_by_instance[instance][instance_layer];
            const flattened = try flattenMaskColumns(allocator, mask);
            defer allocator.free(flattened);
            channel.mixFelts(flattened);
        }

        const challenge = channel.drawSecureFelt();
        const next_ood = try allocator.alloc(QM31, sumcheck_artifact.assignment.len + 1);
        @memcpy(next_ood[0..sumcheck_artifact.assignment.len], sumcheck_artifact.assignment);
        next_ood[sumcheck_artifact.assignment.len] = challenge;
        allocator.free(ood_point);
        ood_point = next_ood;

        for (sumcheck_instances.items) |instance| {
            const n_unused = n_layers - proof.layer_masks_by_instance[instance].len;
            const instance_layer = layer - n_unused;
            const mask = &proof.layer_masks_by_instance[instance][instance_layer];
            const reduced = try mask.reduceAtPoint(allocator, challenge);
            try replaceClaim(allocator, &claims_to_verify_by_instance[instance], reduced);
        }
    }

    const finalized_claims = try allocator.alloc([]QM31, n_instances);
    errdefer allocator.free(finalized_claims);

    for (claims_to_verify_by_instance, 0..) |maybe_claims, i| {
        const claims = maybe_claims orelse return GkrError.MalformedProof;
        finalized_claims[i] = claims;
        claims_to_verify_by_instance[i] = null;
    }

    const n_variables_by_instance = try allocator.alloc(usize, n_instances);
    for (proof.layer_masks_by_instance, 0..) |masks, i| {
        n_variables_by_instance[i] = masks.len;
    }

    allocator.free(claims_to_verify_by_instance);
    return .{
        .ood_point = ood_point,
        .claims_to_verify_by_instance = finalized_claims,
        .n_variables_by_instance = n_variables_by_instance,
    };
}

fn replaceClaim(
    allocator: std.mem.Allocator,
    slot: *?[]QM31,
    next: []QM31,
) !void {
    if (slot.*) |old| allocator.free(old);
    slot.* = next;
}

fn flattenMaskColumns(allocator: std.mem.Allocator, mask: *const GkrMask) ![]QM31 {
    const out = try allocator.alloc(QM31, mask.columns.len * 2);
    for (mask.columns, 0..) |column, i| {
        out[2 * i] = column[0];
        out[2 * i + 1] = column[1];
    }
    return out;
}

fn pow2Base(n: usize) M31 {
    var out = M31.one();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out = out.add(out);
    }
    return out;
}

test "gkr verifier: mask reduce and gate eval" {
    const alloc = std.testing.allocator;

    var mask = GkrMask.initOwned(try alloc.dupe([2]QM31, &[_][2]QM31{
        .{ QM31.fromU32Unchecked(2, 0, 0, 0), QM31.fromU32Unchecked(5, 0, 0, 0) },
    }));
    defer mask.deinit(alloc);

    const x = QM31.fromU32Unchecked(3, 0, 0, 0);
    const reduced = try mask.reduceAtPoint(alloc, x);
    defer alloc.free(reduced);
    const expected = utils.foldMleEvals(QM31, x, mask.columns[0][0], mask.columns[0][1]);
    try std.testing.expect(reduced[0].eql(expected));

    const gp = try Gate.GrandProduct.eval(alloc, &mask);
    defer alloc.free(gp);
    try std.testing.expect(gp[0].eql(mask.columns[0][0].mul(mask.columns[0][1])));
}

test "gkr verifier: one-layer grand-product partial verification" {
    const alloc = std.testing.allocator;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;

    const a = QM31.fromU32Unchecked(7, 0, 0, 0);
    const b = QM31.fromU32Unchecked(11, 0, 0, 0);
    const output_claim = a.mul(b);

    var proof = GkrBatchProof{
        .sumcheck_proofs = try alloc.dupe(sumcheck.SumcheckProof, &[_]sumcheck.SumcheckProof{
            .{ .round_polys = try alloc.alloc(utils.UnivariatePoly(QM31), 0) },
        }),
        .layer_masks_by_instance = try alloc.dupe([]GkrMask, &[_][]GkrMask{
            try alloc.dupe(GkrMask, &[_]GkrMask{
                GkrMask.initOwned(try alloc.dupe([2]QM31, &[_][2]QM31{.{ a, b }})),
            }),
        }),
        .output_claims_by_instance = try alloc.dupe([]QM31, &[_][]QM31{
            try alloc.dupe(QM31, &[_]QM31{output_claim}),
        }),
    };
    defer proof.deinit(alloc);

    var channel = Channel{};
    var artifact = try partiallyVerifyBatch(
        alloc,
        &[_]Gate{.GrandProduct},
        &proof,
        &channel,
    );
    defer artifact.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), artifact.ood_point.len);
    try std.testing.expectEqual(@as(usize, 1), artifact.claims_to_verify_by_instance.len);
    try std.testing.expectEqual(@as(usize, 1), artifact.claims_to_verify_by_instance[0].len);

    const expected_claim = utils.foldMleEvals(QM31, artifact.ood_point[0], a, b);
    try std.testing.expect(artifact.claims_to_verify_by_instance[0][0].eql(expected_claim));
    try std.testing.expectEqual(@as(usize, 1), artifact.n_variables_by_instance[0]);
}
