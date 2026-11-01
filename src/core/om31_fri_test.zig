//! Wide-field FRI mechanics against direct butterfly oracles.
const std = @import("std");
const core = @import("mod.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const O = core.fields.om31.OM31;
const Folding = @import("fri/folding.zig");
const Wide = Folding.ForField(O);
const a = std.testing.allocator;
fn value(i: usize) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, k| v.* = M.fromCanonical(@intCast((i + 1) * 97 + k * 31));
    return O.fromM31Array(coordinates);
}

test "wide FRI: high-coordinate line folds match independent butterflies" {
    const domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(5));
    var input: [32]O = undefined;
    for (&input, 0..) |*x, i| x.* = value(i);
    const alpha = value(41);
    const result = try Wide.foldLine(a, &input, domain, alpha);
    defer a.free(result.values);
    for (result.values, 0..) |got, i| {
        const inv_x = try domain.at(core.utils.bitReverseIndex(i * 2, 5)).inv();
        const expected = input[2 * i].add(input[2 * i + 1]).add(alpha.mul(input[2 * i].sub(input[2 * i + 1]).mulM31(inv_x)));
        try std.testing.expect(got.eql(expected));
    }
}

test "wide FRI: coordinate and secure circle folds match the row oracle" {
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var input: [32]O = undefined;
    var planes: [8][32]M = undefined;
    var columns: [8][]const M = undefined;
    for (&input, 0..) |*x, i| {
        x.* = value(i);
        for (x.toM31Array(), 0..) |coordinate, j| planes[j][i] = coordinate;
    }
    for (&columns, &planes) |*column, *plane| column.* = plane;
    var actual: [16]O = undefined;
    var column_fold: [16]O = undefined;
    for (&actual, &column_fold, 0..) |*x, *y, i| {
        x.* = value(i + 53);
        y.* = x.*;
    }
    const initial = actual;
    const alpha = value(41);
    var workspace = try Wide.FoldCircleWorkspace.init(a, actual.len);
    defer workspace.deinit(a);
    try Wide.foldCircleIntoLineWithWorkspace(a, &actual, &input, domain, alpha, &workspace);
    try Wide.foldCircleColumnsIntoLineWithWorkspace(a, &column_fold, columns, domain, alpha, &workspace);
    for (actual, column_fold, 0..) |got, got_columns, i| {
        const inv_y = try domain.at(core.utils.bitReverseIndex(i * 2, 5)).y.inv();
        const butterfly = input[2 * i].add(input[2 * i + 1]).add(alpha.mul(input[2 * i].sub(input[2 * i + 1]).mulM31(inv_y)));
        const expected = initial[i].mul(alpha.square()).add(butterfly);
        try std.testing.expect(got.eql(expected));
        try std.testing.expect(got_columns.eql(expected));
    }
}

test "wide FRI: QM31 facade keeps its concrete public types" {
    try std.testing.expect(Folding.FoldLineResult == Folding.ForField(Q).FoldLineResult);
    try std.testing.expect(core.fri.FriProof == core.fri.ForField(Q).FriProof);
}

test "wide FRI: proof carrier, captures and verifier instantiate with eight coordinates" {
    const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
    const Channel = core.channel.raw_mod_m31.Om31Channel;
    const MC = struct {
        pub fn mixRoot(channel: *Channel, root: H.Hash) void {
            core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, root);
        }
    };
    const F = core.fri.ForField(O);
    const Verifier = F.FriVerifier(H, MC);
    _ = @sizeOf(Verifier);
    _ = @sizeOf(F.FriProof(H));
    _ = @sizeOf(F.FriQueryCapture(H));
    var coefficients = [_]O{ value(0), value(1), value(2), value(3) };
    var poly = core.poly.line.LinePolyFor(O).initOwned(try a.dupe(O, &coefficients));
    defer poly.deinit(a);
    const point = value(11);
    const expected = coefficients[0].add(coefficients[1].mul(core.circle.CirclePoint(O).doubleX(point))).add(coefficients[2].mul(point)).add(coefficients[3].mul(point).mul(core.circle.CirclePoint(O).doubleX(point)));
    try std.testing.expect((try poly.evalAtPoint(a, point)).eql(expected));
}
