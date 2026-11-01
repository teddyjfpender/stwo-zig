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

/// One algorithm authority for the selected secure extension; Q entrypoints below remain compatible.
pub fn ForField(comptime Secure: type) type {
    return struct {
        pub const SumcheckProof = struct {
            round_polys: []lookup_utils.UnivariatePoly(Secure),

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                for (self.round_polys) |*poly| poly.deinit(allocator);
                allocator.free(self.round_polys);
                self.* = undefined;
            }
        };

        pub fn ProveBatchResult(comptime O: type) type {
            return struct {
                proof: SumcheckProof,
                assignment: []Secure,
                constant_polys: []O,
                claimed_evals: []Secure,

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
            assignment: []Secure,
            claimed_eval: Secure,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                allocator.free(self.assignment);
                self.* = undefined;
            }
        };

        fn OracleErrorSet(comptime O: type) type {
            const clone_ret = @typeInfo(@typeInfo(@TypeOf(O.cloneOwned)).@"fn".return_type.?);
            const sum_ret = @typeInfo(@typeInfo(@TypeOf(O.sumAsPolyInFirstVariable)).@"fn".return_type.?);
            const fix_ret = @typeInfo(@typeInfo(@TypeOf(O.fixFirstVariable)).@"fn".return_type.?);

            const inplace_errors = if (@hasDecl(O, "fixFirstVariableInPlace"))
                @typeInfo(@typeInfo(@TypeOf(O.fixFirstVariableInPlace)).@"fn".return_type.?).error_union.error_set
            else
                error{};
            return clone_ret.error_union.error_set ||
                sum_ret.error_union.error_set ||
                fix_ret.error_union.error_set || inplace_errors;
        }

        /// Performs batched sum-check on a random linear combination of oracle polynomials.
        ///
        /// Required oracle interface (on type `O`):
        /// - `nVariables(self: O) usize`
        /// - `cloneOwned(self: O, allocator) !O`
        /// - `sumAsPolyInFirstVariable(self: O, allocator, claim: Secure) !UnivariatePoly(Secure)`
        /// - `fixFirstVariable(self: O, allocator, challenge: Secure) !O`
        /// Optional `fixFirstVariableInPlace(*O, allocator, challenge) !void`
        /// consumes exclusive internal state; on error it remains deinitializable.
        /// Original caller-owned oracles are cloned before this interface runs.
        pub fn proveBatch(
            comptime O: type,
            allocator: std.mem.Allocator,
            claims_in: []const Secure,
            multivariate_polys_in: []const O,
            lambda: Secure,
            channel: anytype,
        ) (std.mem.Allocator.Error || SumcheckError || OracleErrorSet(O))!ProveBatchResult(O) {
            return proveBatchImpl(O, allocator, claims_in, multivariate_polys_in, lambda, channel, false);
        }

        /// Consumes the oracle array and its elements on success and every
        /// error, including malformed claims. Any borrowed oracle context must
        /// remain live through the returned constant-polynomial result.
        pub fn proveBatchOwned(
            comptime O: type,
            allocator: std.mem.Allocator,
            claims_in: []const Secure,
            multivariate_polys_in: []O,
            lambda: Secure,
            channel: anytype,
        ) (std.mem.Allocator.Error || SumcheckError || OracleErrorSet(O))!ProveBatchResult(O) {
            return proveBatchImpl(O, allocator, claims_in, multivariate_polys_in, lambda, channel, true);
        }

        fn proveBatchImpl(
            comptime O: type,
            allocator: std.mem.Allocator,
            claims_in: []const Secure,
            multivariate_polys_in: []const O,
            lambda: Secure,
            channel: anytype,
            comptime take_owned: bool,
        ) (std.mem.Allocator.Error || SumcheckError || OracleErrorSet(O))!ProveBatchResult(O) {
            var multivariate_polys: []O = if (take_owned) @constCast(multivariate_polys_in) else &.{};
            var initialized_polys: usize = if (take_owned) multivariate_polys.len else 0;
            errdefer {
                for (multivariate_polys[0..initialized_polys]) |*poly| poly.deinit(allocator);
                allocator.free(multivariate_polys);
            }
            if (claims_in.len == 0) return SumcheckError.EmptyBatch;
            if (claims_in.len != multivariate_polys_in.len) return SumcheckError.ShapeMismatch;

            var n_variables: usize = 0;
            for (multivariate_polys_in) |poly| {
                n_variables = @max(n_variables, poly.nVariables());
            }

            const claims = try allocator.dupe(Secure, claims_in);
            errdefer allocator.free(claims);

            if (!take_owned) {
                multivariate_polys = try allocator.alloc(O, multivariate_polys_in.len);
                for (multivariate_polys_in, 0..) |poly, i| {
                    multivariate_polys[i] = try poly.cloneOwned(allocator);
                    initialized_polys += 1;
                }
            }

            for (multivariate_polys, 0..) |poly, i| {
                const n_unused_variables = n_variables - poly.nVariables();
                claims[i] = lookup_utils.mulBaseFor(Secure, claims[i], pow2Base(n_unused_variables));
            }

            var round_polys_builder = std.ArrayList(lookup_utils.UnivariatePoly(Secure)).empty;
            defer round_polys_builder.deinit(allocator);
            errdefer {
                for (round_polys_builder.items) |*poly| poly.deinit(allocator);
            }

            var assignment_builder = std.ArrayList(Secure).empty;
            defer assignment_builder.deinit(allocator);

            var round: usize = 0;
            while (round < n_variables) : (round += 1) {
                const n_remaining_rounds = n_variables - round;

                const this_round_polys = try allocator.alloc(lookup_utils.UnivariatePoly(Secure), multivariate_polys.len);
                var initialized_round_polys: usize = 0;
                defer {
                    for (this_round_polys[0..initialized_round_polys]) |*poly| poly.deinit(allocator);
                    allocator.free(this_round_polys);
                }

                for (multivariate_polys, claims, 0..) |poly, claim, i| {
                    var round_poly: lookup_utils.UnivariatePoly(Secure) = undefined;
                    if (n_remaining_rounds == poly.nVariables()) {
                        round_poly = try poly.sumAsPolyInFirstVariable(allocator, claim);
                    } else {
                        const half_claim = lookup_utils.divBaseFor(Secure, claim, M31.fromCanonical(2)) catch {
                            return SumcheckError.DivisionByZero;
                        };
                        round_poly = lookup_utils.UnivariatePoly(Secure).initOwned(
                            try allocator.dupe(Secure, &[_]Secure{half_claim}),
                        );
                    }

                    this_round_polys[i] = round_poly;
                    initialized_round_polys += 1;

                    const eval_at_0 = round_poly.evalAtPoint(Secure.zero());
                    const eval_at_1 = round_poly.evalAtPoint(Secure.one());
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
                    if (comptime @hasDecl(O, "fixFirstVariableInPlace")) {
                        try poly.fixFirstVariableInPlace(allocator, challenge);
                    } else {
                        const fixed = try poly.fixFirstVariable(allocator, challenge);
                        poly.deinit(allocator);
                        poly.* = fixed;
                    }
                }

                try round_polys_builder.append(allocator, round_poly);
                round_poly = lookup_utils.UnivariatePoly(Secure).initOwned(&.{});
                try assignment_builder.append(allocator, challenge);
            }

            const assignment = try assignment_builder.toOwnedSlice(allocator);
            errdefer allocator.free(assignment);
            return .{
                .proof = .{ .round_polys = try round_polys_builder.toOwnedSlice(allocator) },
                .assignment = assignment,
                .constant_polys = multivariate_polys,
                .claimed_evals = claims,
            };
        }

        /// Partially verifies a sum-check proof and returns `(assignment, claimed_eval)`.
        const NativeChecks = struct {
            pub fn requireEq(_: NativeChecks, lhs: Secure, rhs: Secure, _: @import("verifier_kernel.zig").Check) SumcheckError!void {
                if (!lhs.eql(rhs)) return error.SumInvalid;
            }
        };
        pub fn partiallyVerify(a: std.mem.Allocator, claim: Secure, proof: *const SumcheckProof, channel: anytype) (std.mem.Allocator.Error || SumcheckError)!PartialVerifyResult {
            const result = try @import("verifier_kernel.zig").verifySumcheck(Secure, a, claim, proof, channel, NativeChecks{});
            return .{ .assignment = result.assignment, .claimed_eval = result.claimed_eval };
        }

        fn randomLinearCombination(
            allocator: std.mem.Allocator,
            polys: []const lookup_utils.UnivariatePoly(Secure),
            alpha: Secure,
        ) !lookup_utils.UnivariatePoly(Secure) {
            var acc = lookup_utils.UnivariatePoly(Secure).initOwned(try allocator.alloc(Secure, 0));
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
    };
}
