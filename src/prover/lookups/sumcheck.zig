const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const lookup_utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const MAX_DEGREE: usize = @import("verifier_kernel.zig").MAX_DEGREE;

pub const SumcheckError = error{
    EmptyBatch,
    ShapeMismatch,
    DegreeInvalid,
    SumInvalid,
    DivisionByZero,
    NotPowerOfTwo,
    PointDimensionMismatch,
};

pub const ForField = @import("sumcheck_field.zig").ForField;

pub const SumcheckProof = ForField(QM31).SumcheckProof;
pub const ProveBatchResult = ForField(QM31).ProveBatchResult;
pub const PartialVerifyResult = ForField(QM31).PartialVerifyResult;
pub const proveBatch = ForField(QM31).proveBatch;
pub const partiallyVerify = ForField(QM31).partiallyVerify;

test "sumcheck: prove and partially verify single mle" {
    const alloc = std.testing.allocator;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const mle_mod = @import("mle.zig");
    const MleSecure = mle_mod.Mle(QM31);

    var sample_channel = Channel{};
    const values = try sample_channel.drawSecureFelts(alloc, 32);

    var claim = QM31.zero();
    for (values) |value| claim = claim.add(value);

    var mle = try MleSecure.initOwned(values);
    defer mle.deinit(alloc);

    var prover_channel = Channel{};
    const lambda = QM31.one();
    var prove_result = try proveBatch(
        MleSecure,
        alloc,
        &[_]QM31{claim},
        &[_]MleSecure{mle},
        lambda,
        &prover_channel,
    );
    defer prove_result.deinit(alloc);

    var verify_channel = Channel{};
    var partial = try partiallyVerify(alloc, claim, &prove_result.proof, &verify_channel);
    defer partial.deinit(alloc);

    const eval = try mle.evalAtPoint(alloc, partial.assignment);
    try std.testing.expect(eval.eql(partial.claimed_eval));
}

test "sumcheck: invalid proof is rejected" {
    const alloc = std.testing.allocator;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const mle_mod = @import("mle.zig");
    const MleSecure = mle_mod.Mle(QM31);

    var draw_channel = Channel{};
    const values = try draw_channel.drawSecureFelts(alloc, 8);

    var claim = QM31.zero();
    for (values) |value| claim = claim.add(value);

    values[0] = values[0].add(QM31.one());

    var bad_claim = QM31.zero();
    for (values) |value| bad_claim = bad_claim.add(value);

    var bad_mle = try MleSecure.initOwned(values);
    defer bad_mle.deinit(alloc);

    var prover_channel = Channel{};
    var proof_result = try proveBatch(
        MleSecure,
        alloc,
        &[_]QM31{bad_claim},
        &[_]MleSecure{bad_mle},
        QM31.one(),
        &prover_channel,
    );
    defer proof_result.deinit(alloc);

    var verify_channel = Channel{};
    try std.testing.expectError(
        SumcheckError.SumInvalid,
        partiallyVerify(alloc, claim, &proof_result.proof, &verify_channel),
    );
}
