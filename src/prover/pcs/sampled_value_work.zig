//! Allocation-free exact logical-work audit for host sampled-value evaluation.
//!
//! The audit follows the schedule that actually ran. It deliberately counts
//! plan-key point folds and cached barycentric-context construction in addition
//! to polynomial evaluation: those are field operations executed inside the
//! measured prover boundary, not structural estimates. Checked overflow makes
//! the audit unavailable without changing proof execution.

const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;

pub const Audit = struct {
    counters: work_profile.Counters = .{},
    complete: bool = true,

    pub fn merge(self: *Audit, other: Audit) void {
        if (!self.complete or !other.complete) {
            self.complete = false;
            return;
        }
        self.counters = self.counters.add(other.counters) catch {
            self.complete = false;
            return;
        };
    }

    /// Optimized secure-circle doubling schedule:
    /// `x' = 2*x^2 - 1`, `y' = 2*x*y`.
    pub fn observePointFolds(self: *Audit, fold_count: u32) void {
        self.addScaled(3, 2, 0, fold_count);
    }

    /// Point-factor construction stores y and x directly, then applies
    /// `doubleX` for factors 2..log_size-1.
    pub fn observeFactorConstruction(self: *Audit, log_size: u32) void {
        if (log_size <= 2) return;
        const doubles = log_size - 2;
        self.addScaled(2, 1, 0, doubles);
    }

    /// Carry-style coefficient evaluation performs one multiply/add for every
    /// non-root merge in the size-2^log_size reduction tree.
    pub fn observeIterativeEvaluations(
        self: *Audit,
        log_size: u32,
        evaluation_count: usize,
    ) void {
        if (evaluation_count == 0) return;
        const coefficient_count = pow2(log_size) orelse {
            self.complete = false;
            return;
        };
        const merges = coefficient_count - 1;
        self.addProductPair(merges, evaluation_count);
    }

    /// Multi-column evaluation materializes one subset-product basis per
    /// point, then executes `n` base-scalar multiplies and `n` additions per
    /// polynomial/point. For log sizes above eight the current block schedule
    /// deliberately recomputes each high block's first product; this audit
    /// counts that executed multiplication rather than the ideal `n-1` basis.
    pub fn observeSubsetEvaluations(
        self: *Audit,
        log_size: u32,
        point_count: usize,
        polynomial_count: usize,
    ) void {
        if (point_count == 0 or polynomial_count == 0 or log_size == 0) return;
        const coefficient_count = pow2(log_size) orelse {
            self.complete = false;
            return;
        };
        const low_log = @min(log_size, 8);
        const low_len = pow2(low_log) orelse unreachable;
        const block_count = coefficient_count / low_len;
        var basis_multiplications = low_len - 1;
        if (block_count > 1) {
            const per_high_block = checkedAdd(low_len, 1) orelse {
                self.complete = false;
                return;
            };
            const high_work = checkedMul(block_count - 1, per_high_block) orelse {
                self.complete = false;
                return;
            };
            basis_multiplications = checkedAdd(basis_multiplications, high_work) orelse {
                self.complete = false;
                return;
            };
        }
        const all_basis_work = checkedMul(basis_multiplications, point_count) orelse {
            self.complete = false;
            return;
        };
        self.addOperations(0, all_basis_work, 0);
        const evaluations = checkedMul(point_count, polynomial_count) orelse {
            self.complete = false;
            return;
        };
        self.addProductPair(coefficient_count, evaluations);
    }

    /// One cached barycentric context for a domain of size 2^log_size. The
    /// derivative loop calls the production coset-vanishing routine at every
    /// smaller canonic log size, then the context constructs one shifted point.
    pub fn observeBarycentricContext(self: *Audit, log_size: u32) void {
        const domain_size = pow2(log_size) orelse {
            self.complete = false;
            return;
        };
        var per_point_additions: usize = 0;
        var per_point_multiplications: usize = 0;

        // Derivative exponent powers.
        if (log_size > 0) {
            per_point_multiplications = log_size - 1;
        }
        var inner_log: u32 = 1;
        while (inner_log < log_size) : (inner_log += 1) {
            // Two circle additions in cosetVanishing.
            per_point_additions = checkedAdd(per_point_additions, 4) orelse
                return self.invalidate();
            per_point_multiplications = checkedAdd(per_point_multiplications, 8) orelse
                return self.invalidate();
            // Its x-coordinate doubleX chain.
            const doubles = inner_log - 1;
            per_point_additions = addScaledValue(per_point_additions, 2, doubles) orelse
                return self.invalidate();
            per_point_multiplications = addScaledValue(
                per_point_multiplications,
                1,
                doubles,
            ) orelse return self.invalidate();
            // Accumulate this vanishing factor.
            per_point_multiplications = checkedAdd(per_point_multiplications, 1) orelse
                return self.invalidate();
        }
        // exp * vanishing, then the two multiplications forming si_i.
        per_point_multiplications = checkedAdd(per_point_multiplications, 3) orelse
            return self.invalidate();

        const additions = checkedMul(per_point_additions, domain_size) orelse
            return self.invalidate();
        const multiplications = checkedMul(per_point_multiplications, domain_size) orelse
            return self.invalidate();
        self.addOperations(additions, multiplications, 0);
        // `-initial + half_step` is one circle addition.
        self.addOperations(2, 4, 0);
    }

    /// One evaluation through an already-constructed barycentric context.
    pub fn observeBarycentricEvaluation(
        self: *Audit,
        log_size: u32,
        fold_count: u32,
    ) void {
        const domain_size = pow2(log_size) orelse {
            self.complete = false;
            return;
        };
        self.observePointFolds(fold_count);

        // Per-domain denominator: one point subtraction, `1+h.x`, and si*h.y.
        self.addScaled(3, 5, 0, domain_size);

        // Classic batch inverse as implemented by batchInverseInto:
        // prefix n-1, one terminal product, reverse 2(n-1), one inversion.
        const inverse_multiplications = checkedAdd(
            checkedMul(domain_size - 1, 3) orelse return self.invalidate(),
            1,
        ) orelse return self.invalidate();
        self.addOperations(0, inverse_multiplications, 1);

        // Shifted point plus the log_size-1 doubleX chain.
        self.addOperations(2, 4, 0);
        if (log_size > 1) self.addScaled(2, 1, 0, log_size - 1);

        // Apply vn and the saved post-factor, then evaluate the base column.
        self.addScaled(0, 2, 0, domain_size);
        self.addScaled(1, 1, 0, domain_size);
    }

    fn addProductPair(
        self: *Audit,
        operations_per_evaluation: usize,
        evaluation_count: usize,
    ) void {
        const operations = checkedMul(operations_per_evaluation, evaluation_count) orelse {
            self.complete = false;
            return;
        };
        self.addOperations(operations, operations, 0);
    }

    fn addScaled(
        self: *Audit,
        additions: usize,
        multiplications: usize,
        inversions: usize,
        scale: anytype,
    ) void {
        const encoded_scale = std.math.cast(usize, scale) orelse {
            self.complete = false;
            return;
        };
        const scaled_additions = checkedMul(additions, encoded_scale) orelse
            return self.invalidate();
        const scaled_multiplications = checkedMul(multiplications, encoded_scale) orelse
            return self.invalidate();
        const scaled_inversions = checkedMul(inversions, encoded_scale) orelse
            return self.invalidate();
        self.addOperations(scaled_additions, scaled_multiplications, scaled_inversions);
    }

    fn addOperations(
        self: *Audit,
        additions: usize,
        multiplications: usize,
        inversions: usize,
    ) void {
        if (!self.complete) return;
        const delta = work_profile.Counters{
            .field_additions = std.math.cast(u64, additions) orelse
                return self.invalidate(),
            .field_multiplications = std.math.cast(u64, multiplications) orelse
                return self.invalidate(),
            .field_inversions = std.math.cast(u64, inversions) orelse
                return self.invalidate(),
        };
        self.counters = self.counters.add(delta) catch return self.invalidate();
    }

    fn invalidate(self: *Audit) void {
        self.complete = false;
    }
};

fn pow2(log_size: u32) ?usize {
    if (log_size >= @bitSizeOf(usize)) return null;
    return @as(usize, 1) << @intCast(log_size);
}

fn checkedAdd(lhs: usize, rhs: usize) ?usize {
    return std.math.add(usize, lhs, rhs) catch null;
}

fn checkedMul(lhs: usize, rhs: usize) ?usize {
    return std.math.mul(usize, lhs, rhs) catch null;
}

fn addScaledValue(base: usize, value: usize, scale: anytype) ?usize {
    const encoded_scale = std.math.cast(usize, scale) orelse return null;
    return checkedAdd(base, checkedMul(value, encoded_scale) orelse return null);
}

test "sampled work: optimized folds factors and iterative evaluation are exact" {
    var audit: Audit = .{};
    audit.observePointFolds(3);
    audit.observeFactorConstruction(6);
    audit.observeIterativeEvaluations(3, 2);

    try std.testing.expect(audit.complete);
    try std.testing.expectEqual(@as(u64, 31), audit.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 24), audit.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 0), audit.counters.field_inversions);
}

test "sampled work: high-block subset schedule counts executed recomputation" {
    var audit: Audit = .{};
    audit.observeSubsetEvaluations(10, 2, 3);

    try std.testing.expect(audit.complete);
    // 1,026 basis multiplications per point, plus 1,024 operations for each
    // of three polynomials at each of two points.
    try std.testing.expectEqual(@as(u64, 6_144), audit.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 8_196), audit.counters.field_multiplications);
}

test "sampled work: barycentric context and evaluation match the live schedule" {
    var context: Audit = .{};
    context.observeBarycentricContext(2);
    try std.testing.expect(context.complete);
    try std.testing.expectEqual(@as(u64, 18), context.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 56), context.counters.field_multiplications);

    var evaluation: Audit = .{};
    evaluation.observeBarycentricEvaluation(2, 3);
    try std.testing.expect(evaluation.complete);
    try std.testing.expectEqual(@as(u64, 29), evaluation.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 53), evaluation.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 1), evaluation.counters.field_inversions);
}

test "sampled work: merge is fail-closed" {
    var lhs: Audit = .{};
    lhs.observePointFolds(1);
    const rhs: Audit = .{ .complete = false };
    lhs.merge(rhs);
    try std.testing.expect(!lhs.complete);
}
