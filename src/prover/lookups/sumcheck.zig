const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const lookup_utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const MAX_DEGREE: usize = 3;

pub const SumcheckError = error{
    EmptyBatch,
    ShapeMismatch,
    DegreeInvalid,
    SumInvalid,
    DivisionByZero,
    NotPowerOfTwo,
    PointDimensionMismatch,
};

pub const SumcheckProof = struct {
    round_polys: []lookup_utils.UnivariatePoly(QM31),

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.round_polys) |*poly| poly.deinit(allocator);
        allocator.free(self.round_polys);
        self.* = undefined;
    }
};

pub fn ProveBatchResult(comptime O: type) type {
    return struct {
        proof: SumcheckProof,
        assignment: []QM31,
        constant_polys: []O,
        claimed_evals: []QM31,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            allocator.free(self.assignment);
            for (self.constant_polys) |*poly| poly.deinit(allocator);
            allocator.free(self.constant_polys);
            allocator.free(self.claimed_evals);
            self.* = undefined;
        }
    };
}

pub const PartialVerifyResult = struct {
    assignment: []QM31,
    claimed_eval: QM31,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.assignment);
        self.* = undefined;
    }
};

fn OracleErrorSet(comptime O: type) type {
    const clone_ret = @typeInfo(@typeInfo(@TypeOf(O.cloneOwned)).@"fn".return_type.?);
    const sum_ret = @typeInfo(@typeInfo(@TypeOf(O.sumAsPolyInFirstVariable)).@"fn".return_type.?);
    const fix_ret = @typeInfo(@typeInfo(@TypeOf(O.fixFirstVariable)).@"fn".return_type.?);

    return clone_ret.error_union.error_set ||
        sum_ret.error_union.error_set ||
        fix_ret.error_union.error_set;
}

/// Performs batched sum-check on a random linear combination of oracle polynomials.
///
/// Required oracle interface (on type `O`):
/// - `nVariables(self: O) usize`
/// - `cloneOwned(self: O, allocator) !O`
/// - `sumAsPolyInFirstVariable(self: O, allocator, claim: QM31) !UnivariatePoly(QM31)`
/// - `fixFirstVariable(self: O, allocator, challenge: QM31) !O`
pub fn proveBatch(
    comptime O: type,
    allocator: std.mem.Allocator,
    claims_in: []const QM31,
    multivariate_polys_in: []const O,
    lambda: QM31,
    channel: anytype,
) (std.mem.Allocator.Error || SumcheckError || OracleErrorSet(O))!ProveBatchResult(O) {
    if (claims_in.len == 0) return SumcheckError.EmptyBatch;
    if (claims_in.len != multivariate_polys_in.len) return SumcheckError.ShapeMismatch;

    var n_variables: usize = 0;
    for (multivariate_polys_in) |poly| {
        n_variables = @max(n_variables, poly.nVariables());
    }

    const claims = try allocator.dupe(QM31, claims_in);
    errdefer allocator.free(claims);

    const multivariate_polys = try allocator.alloc(O, multivariate_polys_in.len);
    var initialized_polys: usize = 0;
    errdefer {
        for (multivariate_polys[0..initialized_polys]) |*poly| poly.deinit(allocator);
        allocator.free(multivariate_polys);
    }

    for (multivariate_polys_in, 0..) |poly, i| {
        multivariate_polys[i] = try poly.cloneOwned(allocator);
        initialized_polys += 1;
    }

    for (multivariate_polys, 0..) |poly, i| {
        const n_unused_variables = n_variables - poly.nVariables();
        claims[i] = claims[i].mulM31(pow2Base(n_unused_variables));
    }

    var round_polys_builder = std.ArrayList(lookup_utils.UnivariatePoly(QM31)).empty;
    defer round_polys_builder.deinit(allocator);
    errdefer {
        for (round_polys_builder.items) |*poly| poly.deinit(allocator);
    }

    var assignment_builder = std.ArrayList(QM31).empty;
    defer assignment_builder.deinit(allocator);

    var round: usize = 0;
    while (round < n_variables) : (round += 1) {
        const n_remaining_rounds = n_variables - round;

        const this_round_polys = try allocator.alloc(lookup_utils.UnivariatePoly(QM31), multivariate_polys.len);
        var initialized_round_polys: usize = 0;
        defer {
            for (this_round_polys[0..initialized_round_polys]) |*poly| poly.deinit(allocator);
            allocator.free(this_round_polys);
        }

        for (multivariate_polys, claims, 0..) |poly, claim, i| {
            var round_poly: lookup_utils.UnivariatePoly(QM31) = undefined;
            if (n_remaining_rounds == poly.nVariables()) {
                round_poly = try poly.sumAsPolyInFirstVariable(allocator, claim);
            } else {
                const half_claim = claim.divM31(M31.fromCanonical(2)) catch {
                    return SumcheckError.DivisionByZero;
                };
                round_poly = lookup_utils.UnivariatePoly(QM31).initOwned(
                    try allocator.dupe(QM31, &[_]QM31{half_claim}),
                );
            }

            this_round_polys[i] = round_poly;
            initialized_round_polys += 1;

            const eval_at_0 = round_poly.evalAtPoint(QM31.zero());
            const eval_at_1 = round_poly.evalAtPoint(QM31.one());
            if (!eval_at_0.add(eval_at_1).eql(claim)) return SumcheckError.SumInvalid;
            if (round_poly.degree() > MAX_DEGREE) return SumcheckError.DegreeInvalid;
        }

        var round_poly = try randomLinearCombination(
            allocator,
            this_round_polys[0..initialized_round_polys],
            lambda,
        );
        errdefer round_poly.deinit(allocator);

        channel.mixFelts(round_poly.coeffsSlice());
        const challenge = channel.drawSecureFelt();

        for (this_round_polys[0..initialized_round_polys], 0..) |poly, i| {
            claims[i] = poly.evalAtPoint(challenge);
        }

        for (multivariate_polys) |*poly| {
            if (n_remaining_rounds != poly.nVariables()) continue;
            const fixed = try poly.fixFirstVariable(allocator, challenge);
            poly.deinit(allocator);
            poly.* = fixed;
        }

        try round_polys_builder.append(allocator, round_poly);
        try assignment_builder.append(allocator, challenge);
    }

    return .{
        .proof = .{ .round_polys = try round_polys_builder.toOwnedSlice(allocator) },
        .assignment = try assignment_builder.toOwnedSlice(allocator),
        .constant_polys = multivariate_polys,
        .claimed_evals = claims,
    };
}

/// Partially verifies a sum-check proof and returns `(assignment, claimed_eval)`.
pub fn partiallyVerify(
    allocator: std.mem.Allocator,
    claim_in: QM31,
    proof: *const SumcheckProof,
    channel: anytype,
) (std.mem.Allocator.Error || SumcheckError)!PartialVerifyResult {
    var claim = claim_in;
    var assignment = std.ArrayList(QM31).empty;
    defer assignment.deinit(allocator);

    for (proof.round_polys) |round_poly| {
        if (round_poly.degree() > MAX_DEGREE) return SumcheckError.DegreeInvalid;

        const sum = round_poly.evalAtPoint(QM31.zero()).add(round_poly.evalAtPoint(QM31.one()));
        if (!claim.eql(sum)) return SumcheckError.SumInvalid;

        channel.mixFelts(round_poly.coeffsSlice());
        const challenge = channel.drawSecureFelt();
        claim = round_poly.evalAtPoint(challenge);
        try assignment.append(allocator, challenge);
    }

    return .{
        .assignment = try assignment.toOwnedSlice(allocator),
        .claimed_eval = claim,
    };
}

fn randomLinearCombination(
    allocator: std.mem.Allocator,
    polys: []const lookup_utils.UnivariatePoly(QM31),
    alpha: QM31,
) !lookup_utils.UnivariatePoly(QM31) {
    var acc = lookup_utils.UnivariatePoly(QM31).initOwned(try allocator.alloc(QM31, 0));
    errdefer acc.deinit(allocator);

    var i = polys.len;
    while (i > 0) {
        i -= 1;

        const scaled = try acc.mulScalar(allocator, alpha);
        acc.deinit(allocator);
        acc = scaled;

        const next = try acc.add(allocator, polys[i]);
        acc.deinit(allocator);
        acc = next;
    }

    return acc;
}

fn pow2Base(n: usize) M31 {
    var out = M31.one();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out = out.add(out);
    }
    return out;
}

test "sumcheck: prove and partially verify single mle" {
    const alloc = std.testing.allocator;
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
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
    const Channel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
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
