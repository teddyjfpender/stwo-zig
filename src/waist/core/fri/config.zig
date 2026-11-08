//! FRI protocol configuration and degree-bound transitions.

const std = @import("std");

/// FRI proof configuration.
pub const FriConfig = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,
    fold_step: u32 = 1, // number of folds per FRI round (stark-v uses 4)

    pub const Error = error{
        InvalidLastLayerDegreeBound,
        InvalidBlowupFactor,
    };

    pub const LOG_MIN_LAST_LAYER_DEGREE_BOUND: u32 = 0;
    pub const LOG_MAX_LAST_LAYER_DEGREE_BOUND: u32 = 10;
    pub const LOG_MIN_BLOWUP_FACTOR: u32 = 1;
    pub const LOG_MAX_BLOWUP_FACTOR: u32 = 16;

    pub fn init(
        log_last_layer_degree_bound: u32,
        log_blowup_factor: u32,
        n_queries: usize,
    ) Error!FriConfig {
        if (log_last_layer_degree_bound < LOG_MIN_LAST_LAYER_DEGREE_BOUND or
            log_last_layer_degree_bound > LOG_MAX_LAST_LAYER_DEGREE_BOUND)
        {
            return Error.InvalidLastLayerDegreeBound;
        }
        if (log_blowup_factor < LOG_MIN_BLOWUP_FACTOR or
            log_blowup_factor > LOG_MAX_BLOWUP_FACTOR)
        {
            return Error.InvalidBlowupFactor;
        }
        return .{
            .log_blowup_factor = log_blowup_factor,
            .log_last_layer_degree_bound = log_last_layer_degree_bound,
            .n_queries = n_queries,
        };
    }

    pub inline fn lastLayerDomainSize(self: FriConfig) usize {
        return @as(usize, 1) << @intCast(self.log_last_layer_degree_bound + self.log_blowup_factor);
    }

    pub inline fn securityBits(self: FriConfig) u32 {
        return self.log_blowup_factor * @as(u32, @intCast(self.n_queries));
    }

    pub fn default() FriConfig {
        return FriConfig.init(0, 1, 3) catch unreachable;
    }
};

/// Upstream Stwo folds one level per FRI layer. Alternative schedules must be
/// selected explicitly through `FriConfig.fold_step` and remain protocol-bound.
pub const FOLD_STEP: u32 = 1;

/// Folds performed by the next FRI layer when `remaining` line folds are
/// left before the last layer: `fold_step`, clamped so the schedule never
/// overshoots. The core verifier, the prover's FRI commit, `FriGeometry` and
/// the circuit verifier's `compute_all_fold_steps` derive their steps from
/// this rule. Some RISC-V recursion fixtures still inline the same clamp.
pub inline fn foldStepAt(fold_step: u32, remaining: u32) u32 {
    return @min(fold_step, remaining);
}

/// Number of FRI inner layers that fold `degree_log_ratio` levels with steps
/// of at most `fold_step`: `ceil(degree_log_ratio / fold_step)`.
pub fn nFoldSteps(degree_log_ratio: u32, fold_step: u32) usize {
    std.debug.assert(fold_step != 0);
    return std.math.divCeil(u32, degree_log_ratio, fold_step) catch unreachable;
}

/// `compute_all_fold_steps(degree_log_ratio, fold_step)` of
/// `crates/stark_verifier/src/fri_proof.rs` (starkware-libs/proving at
/// 5a7c5ede4299c91a61df19a07cba4f7502c14230): `nFoldSteps` steps of
/// `fold_step`, the last one being `degree_log_ratio % fold_step` when that is
/// nonzero. This is `foldStepAt` applied layer by layer. Writes into `out`,
/// which must hold `nFoldSteps(...)` entries, and returns the written prefix.
pub fn allFoldSteps(degree_log_ratio: u32, fold_step: u32, out: []u32) []u32 {
    const n = nFoldSteps(degree_log_ratio, fold_step);
    std.debug.assert(out.len >= n);
    var remaining = degree_log_ratio;
    for (out[0..n]) |*step| {
        step.* = foldStepAt(fold_step, remaining);
        remaining -= step.*;
    }
    std.debug.assert(remaining == 0);
    return out[0..n];
}

test "fri fold steps: match compute_all_fold_steps around the step boundary" {
    var buf: [16]u32 = undefined;
    // r = s - 1, s, s + 1 and 4k + 2 for s = 4, plus the fold_step = 1 schedule.
    try std.testing.expectEqualSlices(u32, &.{3}, allFoldSteps(3, 4, &buf));
    try std.testing.expectEqualSlices(u32, &.{4}, allFoldSteps(4, 4, &buf));
    try std.testing.expectEqualSlices(u32, &.{ 4, 1 }, allFoldSteps(5, 4, &buf));
    try std.testing.expectEqualSlices(u32, &.{ 4, 4, 4, 2 }, allFoldSteps(14, 4, &buf));
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1 }, allFoldSteps(3, 1, &buf));
    try std.testing.expectEqual(@as(usize, 0), allFoldSteps(0, 4, &buf).len);
    try std.testing.expectEqual(@as(usize, 4), nFoldSteps(14, 4));
}

/// Number of folds when reducing circle to line polynomial.
pub const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;

/// STWO packs four consecutive QM31 evaluations into each FRI Merkle leaf
/// whenever a layer folds more than one level.
pub const LOG_PACKED_LEAF_SIZE: u32 = 2;

pub const FriVerificationError = error{
    InvalidNumFriLayers,
    FirstLayerEvaluationsInvalid,
    FirstLayerCommitmentInvalid,
    InnerLayerCommitmentInvalid,
    InnerLayerEvaluationsInvalid,
    LastLayerDegreeInvalid,
    LastLayerEvaluationsInvalid,
};

pub const CirclePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub inline fn init(log_degree_bound: u32) CirclePolyDegreeBound {
        return .{ .log_degree_bound = log_degree_bound };
    }

    pub inline fn logDegreeBound(self: CirclePolyDegreeBound) u32 {
        return self.log_degree_bound;
    }

    pub inline fn foldToLine(self: CirclePolyDegreeBound) LinePolyDegreeBound {
        return self.foldToLineWithStep(CIRCLE_TO_LINE_FOLD_STEP);
    }

    pub inline fn foldToLineWithStep(self: CirclePolyDegreeBound, fold_step: u32) LinePolyDegreeBound {
        return .{ .log_degree_bound = self.log_degree_bound - fold_step };
    }
};

pub const LinePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub inline fn logDegreeBound(self: LinePolyDegreeBound) u32 {
        return self.log_degree_bound;
    }

    pub fn fold(self: LinePolyDegreeBound, n_folds: u32) ?LinePolyDegreeBound {
        if (self.log_degree_bound < n_folds) return null;
        return .{ .log_degree_bound = self.log_degree_bound - n_folds };
    }
};
