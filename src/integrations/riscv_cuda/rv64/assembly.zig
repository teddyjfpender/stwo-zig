//! Decode only the compact proof/terminal readback after the owner joins.
//! Calls the existing native sumcheck verifier and LogUp gate authority.
//! This is numerical admission: physical source binding/PCS is still required.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const S = engine.lookups.sumcheck.ForField(O);
const V = engine.lookups.gkr_verifier.ForField(O);
const Poly = engine.lookups.utils.UnivariatePoly(O);
const Channel = core.channel.raw_mod_m31.Om31Channel;
const abi = @import("abi.zig");
pub const NumericalResult = struct {
    proof: S.SumcheckProof,
    assignment: []O,
    terminal: [2][2]O,
    claimed_eval: O,
    end_channel: Channel,
    pub fn deinit(self: *NumericalResult, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        allocator.free(self.assignment);
        self.* = undefined;
    }
};

pub fn verifyReadback(allocator: std.mem.Allocator, initial: Channel, claim: O, point: []const O, lambda: O, records: []const u32, state: *const [40]u32, terminal_words: *const [32]u32) !NumericalResult {
    const variables = point.len;
    if (variables == 0 or variables > 27 or records.len != variables * abi.round_record_words)
        return error.InvalidRecordGeometry;
    if (state[10] != 0) return error.DeviceRoundFailure;
    if (state[9] != variables or state[11] != variables or !std.mem.allEqual(u32, state[36..40], 0))
        return error.IncompleteDeviceRounds;
    const polys = try allocator.alloc(Poly, variables);
    var initialized: usize = 0;
    errdefer {
        for (polys[0..initialized]) |*p| p.deinit(allocator);
        allocator.free(polys);
    }
    for (polys, 0..) |*poly, i| {
        const r = records[i * abi.round_record_words ..][0..abi.round_record_words];
        const length = r[40];
        if (length > 4 or r[41] != i or r[42] != 0 or r[43] != 0) return error.InvalidRecordFraming;
        var coefficients: [4]O = undefined;
        for (&coefficients, 0..) |*v, j| v.* = try decode(r[8 * j ..][0..8]);
        if (length > 0 and coefficients[length - 1].isZero()) return error.NoncanonicalPolynomialLength;
        for (coefficients[length..]) |v| if (!v.isZero()) return error.NoncanonicalPolynomialLength;
        poly.* = Poly.initOwned(try allocator.dupe(O, coefficients[0..length]));
        initialized += 1;
    }
    const proof = S.SumcheckProof{ .round_polys = polys };
    var channel = initial;
    var verified = try S.partiallyVerify(allocator, claim, &proof, &channel);
    defer verified.deinit(allocator);
    for (verified.assignment, 0..) |x, i| {
        const recorded = try decode(records[i * abi.round_record_words + 32 ..][0..8]);
        if (!x.eql(recorded)) return error.DeviceChallengeMismatch;
    }
    for (0..8) |i| {
        if (std.mem.readInt(u32, channel.inner.digest[4 * i ..][0..4], .little) != state[i])
            return error.DeviceTranscriptMismatch;
    }
    if (channel.inner.n_draws != state[8]) return error.DeviceTranscriptMismatch;
    if (!verified.claimed_eval.eql(try decode(state[12..20]))) return error.DeviceClaimMismatch;
    var columns: [2][2]O = undefined;
    for (&columns, 0..) |*pair, c| for (pair, 0..) |*v, j| {
        v.* = try decode(terminal_words[(c * 2 + j) * 8 ..][0..8]);
    };
    var mask = V.GkrMask{ .columns = &columns };
    const gate = try V.Gate.LogUp.eval(allocator, &mask);
    defer allocator.free(gate);
    const eq = try engine.lookups.utils.eq(O, point, verified.assignment);
    if (!eq.eql(try decode(state[20..28]))) return error.DeviceCorrectionMismatch;
    var prefix = O.one();
    for (point) |y| prefix = prefix.mul(O.one().sub(y));
    if (!prefix.eql(try decode(state[28..36]))) return error.DevicePrefixMismatch;
    const terminal_eval = eq.mul(engine.lookups.utils.hornerEval(O, gate, lambda));
    if (!verified.claimed_eval.eql(terminal_eval)) return error.TerminalGateMismatch;
    return .{
        .proof = proof,
        .assignment = try allocator.dupe(O, verified.assignment),
        .terminal = columns,
        .claimed_eval = verified.claimed_eval,
        .end_channel = channel,
    };
}
fn decode(words: []const u32) !O {
    var fields: [8]M = undefined;
    for (&fields, words) |*f, word| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalField;
        f.* = M.fromCanonical(word);
    }
    return O.fromM31Array(fields);
}
