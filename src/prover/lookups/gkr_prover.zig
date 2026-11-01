const std = @import("std");
const fraction = @import("stwo_core").fraction;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const gkr_circuit_module = @import("gkr_circuit.zig");
const gkr_verifier_module = @import("gkr_verifier.zig");
const mle_mod = @import("mle.zig");
const sumcheck_module = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const MleBase = mle_mod.Mle(M31);
const MleSecure = mle_mod.Mle(QM31);

const sumcheck = sumcheck_module;
const gkr_circuit = gkr_circuit_module;
const gkr_verifier = gkr_verifier_module;
pub const ForField = @import("gkr_prover_field.zig").ForField;

pub const GkrProverError = ForField(QM31).GkrProverError;
pub const EqEvals = ForField(QM31).EqEvals;
pub const Layer = ForField(QM31).Layer;
pub const GkrMultivariatePolyOracle = ForField(QM31).GkrMultivariatePolyOracle;
pub const correctSumAsPolyInFirstVariable = ForField(QM31).correctSumAsPolyInFirstVariable;
pub const ProveBatchResult = ForField(QM31).ProveBatchResult;
pub const proveBatch = ForField(QM31).proveBatch;

test "gkr prover: grand product prove and verify" {
    const alloc = std.testing.allocator;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;

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
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;

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
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;

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
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;

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
