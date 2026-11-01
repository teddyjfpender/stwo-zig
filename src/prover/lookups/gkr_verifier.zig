const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const sumcheck = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

const kernel = @import("verifier_kernel.zig");
pub const GkrError = kernel.GkrError;

/// Values obtained from partial GKR verification.
pub const GkrArtifact = kernel.Artifact(QM31);

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
        return kernel.evalGate(QM31, allocator, self, mask.columns);
    }
};

/// Partially verifies a batch GKR proof.
pub const NativeChecks = struct {
    pub fn requireEq(_: NativeChecks, lhs: QM31, rhs: QM31, check: kernel.Check) GkrError!void {
        if (!lhs.eql(rhs)) return switch (check) {
            .sum => error.InvalidSumcheck,
            .gate, .terminal => error.CircuitCheckFailure,
        };
    }
};
pub fn partiallyVerifyBatch(a: std.mem.Allocator, gates: []const Gate, proof: *const GkrBatchProof, channel: anytype) (std.mem.Allocator.Error || GkrError)!GkrArtifact {
    return kernel.partiallyVerifyBatch(QM31, a, gates, proof, channel, NativeChecks{});
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
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;

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
