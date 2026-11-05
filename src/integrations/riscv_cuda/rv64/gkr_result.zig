//! Compact device traversal readback to the unchanged native proof schema.
//! This is framing only. The services NumericalStage independently verifies
//! the returned proof and reconstructs its transcript and binding artifact.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const G = engine.lookups.gkr_verifier.ForField(O);
const S = engine.lookups.sumcheck.ForField(O);
const Poly = engine.lookups.utils.UnivariatePoly(O);
const A = @import("abi.zig");
pub const Layer = struct { records: []const u32, masks: []const u32 };
pub const Readback = struct {
    variables: []const u32,
    roots: []const u32,
    layers: []const Layer,
};
fn felt(words: []const u32) !O {
    if (words.len != 8) return error.InvalidGkrReadback;
    var coordinates: [8]M = undefined;
    for (words, &coordinates) |v, *out| {
        if (v >= core.fields.m31.Modulus) return error.NonCanonicalGkrReadback;
        out.* = M.fromCanonical(v);
    }
    return O.fromM31Array(coordinates);
}
pub fn assemble(a: std.mem.Allocator, input: Readback) !G.GkrBatchProof {
    if (input.variables.len == 0 or input.variables.len > A.batch_max_oracles or input.roots.len != input.variables.len * 16) return error.InvalidGkrReadback;
    var max_variables: u32 = 0;
    for (input.variables) |v| {
        if (v == 0 or v > @import("gkr.zig").max_variables) return error.InvalidGkrReadback;
        max_variables = @max(max_variables, v);
    }
    if (input.layers.len != max_variables) return error.InvalidGkrReadback;
    // Validate all framing before allocating proof ownership.
    for (input.layers, 0..) |layer, depth| {
        var active: usize = 0;
        for (input.variables) |v| active += @intFromBool(v >= max_variables - depth);
        if (layer.records.len != depth * A.round_record_words or layer.masks.len != active * 32) return error.InvalidGkrReadback;
        for (0..depth) |round| {
            const record = layer.records[round * A.round_record_words ..][0..A.round_record_words];
            if (record[40] > 4 or record[41] != round or record[42] != 0 or record[43] != 0) return error.InvalidGkrReadback;
            for (0..4) |c| {
                const coefficient = try felt(record[c * 8 ..][0..8]);
                if (c >= record[40] and !coefficient.isZero()) return error.InvalidGkrReadback;
            }
            _ = try felt(record[32..40]); // Recorded challenge is canonical; verifier derives its own.
        }
    }
    var proof_owned = false;
    const sumchecks = try a.alloc(S.SumcheckProof, max_variables);
    errdefer if (!proof_owned) a.free(sumchecks);
    const masks = try a.alloc([]G.GkrMask, input.variables.len);
    errdefer if (!proof_owned) a.free(masks);
    const roots = try a.alloc([]O, input.variables.len);
    for (sumchecks) |*v| v.* = .{ .round_polys = &.{} };
    @memset(masks, &.{});
    @memset(roots, &.{});
    var proof = G.GkrBatchProof{ .sumcheck_proofs = sumchecks, .layer_masks_by_instance = masks, .output_claims_by_instance = roots };
    proof_owned = true;
    errdefer proof.deinit(a);
    for (input.variables, 0..) |v, instance| {
        roots[instance] = try a.alloc(O, 2);
        roots[instance][0] = try felt(input.roots[instance * 16 ..][0..8]);
        roots[instance][1] = try felt(input.roots[instance * 16 + 8 ..][0..8]);
        masks[instance] = try a.alloc(G.GkrMask, v);
        for (masks[instance]) |*mask| mask.* = .{ .columns = &.{} };
    }
    for (input.layers, 0..) |layer, depth| {
        sumchecks[depth].round_polys = try a.alloc(Poly, depth);
        for (sumchecks[depth].round_polys) |*poly| poly.* = Poly.initOwned(&.{});
        for (sumchecks[depth].round_polys, 0..) |*poly, round| {
            const record = layer.records[round * A.round_record_words ..][0..A.round_record_words];
            const coefficients = try a.alloc(O, record[40]);
            poly.* = .{ .coeffs = coefficients, .len = coefficients.len, .owns_coeffs = true };
            for (coefficients, 0..) |*coefficient, c| coefficient.* = try felt(record[c * 8 ..][0..8]);
            if (coefficients.len != 0 and coefficients[coefficients.len - 1].isZero()) return error.InvalidGkrReadback;
        }
        var active: usize = 0;
        const remaining = max_variables - depth;
        for (input.variables, 0..) |v, instance| {
            if (v < remaining) continue;
            const columns = try a.alloc([2]O, 2);
            masks[instance][v - remaining] = .{ .columns = columns };
            for (0..2) |column| for (0..2) |side| {
                columns[column][side] = try felt(layer.masks[32 * active + (2 * column + side) * 8 ..][0..8]);
            };
            active += 1;
        }
    }
    return proof;
}
fn store(out: []u32, value: O) void {
    for (out, value.toM31Array()) |*word, coordinate| word.* = coordinate.v;
}
fn allocationProbe(a: std.mem.Allocator, input: Readback) !void {
    var proof = try assemble(a, input);
    proof.deinit(a);
}
test "device compact GKR readback preserves native proof and fails atomically" {
    const a = std.testing.allocator;
    const GP = engine.lookups.gkr_prover.ForField(O);
    const C = core.channel.raw_mod_m31.Om31Channel;
    const n: [8]O = @splat(O.zero());
    const d: [8]O = @splat(O.one());
    const inputs = [_]GP.Layer{
        .{ .LogUpGeneric = .{ .numerators = .{ .evals = @constCast(&n), .owns_evals = false }, .denominators = .{ .evals = @constCast(&d), .owns_evals = false } } },
        .{ .LogUpGeneric = .{ .numerators = .{ .evals = @constCast(n[0..2]), .owns_evals = false }, .denominators = .{ .evals = @constCast(d[0..2]), .owns_evals = false } } },
    };
    var native_channel = C.init();
    var native = try GP.proveBatch(a, &native_channel, &inputs);
    defer native.deinit(a);
    var roots: [32]u32 = undefined;
    for (native.proof.output_claims_by_instance, 0..) |claims, instance| for (claims, 0..) |value, c| store(roots[instance * 16 + c * 8 ..][0..8], value);
    var record_storage: [3][88]u32 = @splat(@splat(0));
    var mask_storage: [3][64]u32 = undefined;
    var layers: [3]Layer = undefined;
    for (&layers, 0..) |*layer, depth| {
        for (native.proof.sumcheck_proofs[depth].round_polys, 0..) |poly, round| {
            const record = record_storage[depth][round * 44 ..][0..44];
            for (poly.coeffsSlice(), 0..) |value, c| store(record[c * 8 ..][0..8], value);
            record[40] = @intCast(poly.coeffsSlice().len);
            record[41] = @intCast(round);
        }
        var active: usize = 0;
        for ([_]usize{ 3, 1 }, 0..) |v, instance| {
            if (v < 3 - depth) continue;
            for (native.proof.layer_masks_by_instance[instance][v - (3 - depth)].columns, 0..) |pair, column|
                for (pair, 0..) |value, side| store(mask_storage[depth][32 * active + (2 * column + side) * 8 ..][0..8], value);
            active += 1;
        }
        layer.* = .{ .records = record_storage[depth][0 .. depth * 44], .masks = mask_storage[depth][0 .. active * 32] };
    }
    const input = Readback{ .variables = &.{ 3, 1 }, .roots = &roots, .layers = &layers };
    var proof = try assemble(a, input);
    defer proof.deinit(a);
    var verified_channel = C.init();
    var artifact = try G.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp }, &proof, &verified_channel);
    defer artifact.deinit(a);
    try std.testing.expectEqualSlices(u8, &native_channel.inner.digest, &verified_channel.inner.digest);
    try std.testing.expectEqual(native_channel.inner.n_draws, verified_channel.inner.n_draws);
    try std.testing.expectEqualSlices(O, native.artifact.ood_point, artifact.ood_point);
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{input});
    roots[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalGkrReadback, assemble(a, input));
    roots[0] = 0;
    record_storage[1][42] = 1;
    try std.testing.expectError(error.InvalidGkrReadback, assemble(a, input));
    record_storage[1][42] = 0;
    layers[2].masks = mask_storage[2][0..63];
    try std.testing.expectError(error.InvalidGkrReadback, assemble(a, input));
}
