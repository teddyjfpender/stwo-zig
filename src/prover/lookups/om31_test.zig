//! Actual OM31 GKR protocol arithmetic tests. This is not a production receiver or security certificate.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const P = @import("gkr_prover.zig").ForField(O);
const V = @import("gkr_verifier.zig").ForField(O);
const M = @import("mle.zig");
const K = @import("verifier_kernel.zig");
const A = std.testing.allocator;

const Channel = core.channel.raw_mod_m31.Om31Channel;

fn scalar(n: u32) O {
    return O.fromBase(M31.fromCanonical(n));
}
fn values(comptime n: usize, seed: u32) [n]O {
    var out: [n]O = undefined;
    for (&out, 0..) |*v, i| v.* = scalar(seed + @as(u32, @intCast(i))).add(O.basis().mulBase(M31.fromCanonical(@intCast(i + 1))));
    return out;
}
fn expectedInputs(a: std.mem.Allocator, layers: []const P.Layer, artifact: *const V.GkrArtifact) ![][]O {
    const expected = try a.alloc([]O, layers.len);
    errdefer a.free(expected);
    var initialized: usize = 0;
    errdefer for (expected[0..initialized]) |v| a.free(v);
    for (layers, 0..) |layer, i| {
        const n = layer.nVariables();
        const point = artifact.ood_point[artifact.ood_point.len - n ..];
        expected[i] = switch (layer) {
            .GrandProduct => |v| try a.dupe(O, &.{try v.evalAtPoint(a, point)}),
            .LogUpGeneric => |v| try a.dupe(O, &.{ try v.numerators.evalAtPoint(a, point), try v.denominators.evalAtPoint(a, point) }),
            .LogUpMultiplicities => |v| try a.dupe(O, &.{ try v.numerators.evalAtPoint(a, point), try v.denominators.evalAtPoint(a, point) }),
            .LogUpSingles => |v| try a.dupe(O, &.{ O.one(), try v.denominators.evalAtPoint(a, point) }),
        };
        initialized += 1;
    }
    return expected;
}
fn destroyExpected(a: std.mem.Allocator, expected: [][]O) void {
    for (expected) |v| a.free(v);
    a.free(expected);
}
fn verify(a: std.mem.Allocator, layers: []const P.Layer, gates: []const V.Gate, proof: *const V.GkrBatchProof) !void {
    var channel = Channel.init();
    var artifact = try V.partiallyVerifyBatch(a, gates, proof, &channel);
    defer artifact.deinit(a);
    const expected = try expectedInputs(a, layers, &artifact);
    defer destroyExpected(a, expected);
    try K.verifyTerminalInputs(O, &artifact, expected, V.NativeChecks{});
}
fn exercise(a: std.mem.Allocator) !void {
    var gp = values(8, 2);
    var numerator = values(16, 11);
    var denominator = values(16, 31);
    var short_den = values(4, 101);
    var counts = [_]M31{ M31.one(), M31.zero(), M31.fromCanonical(2), M31.fromCanonical(core.fields.m31.Modulus - 1) };
    const layers = [_]P.Layer{
        .{ .GrandProduct = try M.MleFor(O, O).initBorrowed(&gp) },
        .{ .LogUpGeneric = .{ .numerators = try M.MleFor(O, O).initBorrowed(&numerator), .denominators = try M.MleFor(O, O).initBorrowed(&denominator) } },
        .{ .LogUpMultiplicities = .{ .numerators = try M.MleFor(O, M31).initBorrowed(&counts), .denominators = try M.MleFor(O, O).initBorrowed(&short_den) } },
        .{ .LogUpSingles = .{ .denominators = try M.MleFor(O, O).initBorrowed(&gp) } },
    };
    const gates = [_]V.Gate{ .GrandProduct, .LogUp, .LogUp, .LogUp };
    var channel = Channel.init();
    var result = try P.proveBatch(a, &channel, &layers);
    defer result.deinit(a);
    try verify(a, &layers, &gates, &result.proof);
    // Independent arithmetic sums check the proven projective output, rather
    // than relying on prover/verifier agreement alone.
    var product = O.one();
    for (gp) |v| product = product.mul(v);
    try std.testing.expect(product.eql(result.proof.output_claims_by_instance[0][0]));
    var sum = O.zero();
    for (numerator, denominator) |n, d| sum = sum.add(try n.div(d));
    const generic = result.proof.output_claims_by_instance[1];
    try std.testing.expect(!generic[1].isZero());
    try std.testing.expect(sum.eql(try generic[0].div(generic[1])));
    sum = O.zero();
    for (counts, short_den) |n, d| sum = sum.add(try O.fromBase(n).div(d));
    const weighted = result.proof.output_claims_by_instance[2];
    try std.testing.expect(!weighted[1].isZero());
    try std.testing.expect(sum.eql(try weighted[0].div(weighted[1])));
    sum = O.zero();
    for (gp) |d| sum = sum.add(try O.one().div(d));
    const singles = result.proof.output_claims_by_instance[3];
    try std.testing.expect(!singles[1].isZero());
    try std.testing.expect(sum.eql(try singles[0].div(singles[1])));
}
test "OM31 actual mixed-height GKR accepts and binds all terminal MLE inputs" {
    try exercise(A);
}
test "OM31 actual prover and verifier allocation failures release every owned layer" {
    try std.testing.checkAllAllocationFailures(A, exerciseAllocationFailure, .{});
}
test "OM31 actual GKR rejects sumcheck mask output and terminal mutations" {
    var den = values(8, 2);
    const layers = [_]P.Layer{.{ .LogUpSingles = .{ .denominators = try M.MleFor(O, O).initBorrowed(&den) } }};
    const gates = [_]V.Gate{.LogUp};
    var channel = Channel.init();
    var result = try P.proveBatch(A, &channel, &layers);
    defer result.deinit(A);
    try verify(A, &layers, &gates, &result.proof);
    const coeff = findCoefficient(&result.proof);
    coeff.* = coeff.add(O.one());
    try std.testing.expectError(error.InvalidSumcheck, verify(A, &layers, &gates, &result.proof));
    coeff.* = coeff.sub(O.one());
    const mask = &result.proof.layer_masks_by_instance[0][0].columns[0][0];
    mask.* = mask.add(O.one());
    try std.testing.expectError(error.CircuitCheckFailure, verify(A, &layers, &gates, &result.proof));
    mask.* = mask.sub(O.one());
    const claim = &result.proof.output_claims_by_instance[0][0];
    claim.* = claim.add(O.one());
    try std.testing.expectError(error.CircuitCheckFailure, verify(A, &layers, &gates, &result.proof));
    claim.* = claim.sub(O.one());
    den[0] = den[0].add(O.one());
    try std.testing.expectError(error.CircuitCheckFailure, verify(A, &layers, &gates, &result.proof));
}

fn findCoefficient(proof: *V.GkrBatchProof) *O {
    for (proof.sumcheck_proofs) |*sum| for (sum.round_polys) |*poly| {
        if (poly.coeffsSlice().len != 0) return &poly.coeffs[0];
    };
    unreachable;
}

fn exerciseAllocationFailure(a: std.mem.Allocator) !void {
    // Legacy core maps a few allocator failures to ShapeMismatch/InvalidSumcheck.
    // Fixed valid input is separately accepted above; preserve its public errors.
    exercise(a) catch |err| switch (err) {
        error.ShapeMismatch, error.InvalidSumcheck => return error.OutOfMemory,
        else => return err,
    };
}
