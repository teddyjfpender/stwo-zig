const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const sumcheck_module = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

const kernel = @import("verifier_kernel.zig");
pub const GkrError = kernel.GkrError;

const sumcheck = sumcheck_module;
pub const ForField = @import("gkr_verifier_field.zig").ForField;

pub const GkrArtifact = ForField(QM31).GkrArtifact;
pub const GkrMask = ForField(QM31).GkrMask;
pub const GkrBatchProof = ForField(QM31).GkrBatchProof;
pub const Gate = ForField(QM31).Gate;
pub const NativeChecks = ForField(QM31).NativeChecks;
pub const partiallyVerifyBatch = ForField(QM31).partiallyVerifyBatch;

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
