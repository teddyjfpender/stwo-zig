const std = @import("std");
const qm31 = @import("fields/qm31.zig");

const QM31 = qm31.QM31;

/// FRI proof configuration.
pub const FriConfig = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,

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

/// Number of folds for univariate polynomials.
pub const FOLD_STEP: u32 = 1;

/// Number of folds when reducing circle to line polynomial.
pub const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;

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

    pub inline fn foldToLine(self: CirclePolyDegreeBound) LinePolyDegreeBound {
        return .{ .log_degree_bound = self.log_degree_bound - CIRCLE_TO_LINE_FOLD_STEP };
    }
};

pub const LinePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub fn fold(self: LinePolyDegreeBound, n_folds: u32) ?LinePolyDegreeBound {
        if (self.log_degree_bound < n_folds) return null;
        return .{ .log_degree_bound = self.log_degree_bound - n_folds };
    }
};

pub fn accumulateLine(layer_query_evals: []QM31, column_query_evals: []const QM31, folding_alpha: QM31) void {
    std.debug.assert(layer_query_evals.len == column_query_evals.len);
    const alpha_sq = folding_alpha.square();
    for (layer_query_evals, 0..) |*curr, i| {
        curr.* = curr.*.mul(alpha_sq).add(column_query_evals[i]);
    }
}

test "fri config: security bits" {
    const config = try FriConfig.init(10, 10, 70);
    try std.testing.expectEqual(@as(u32, 700), config.securityBits());
}

test "fri config: default values" {
    const cfg = FriConfig.default();
    try std.testing.expectEqual(@as(u32, 0), cfg.log_last_layer_degree_bound);
    try std.testing.expectEqual(@as(u32, 1), cfg.log_blowup_factor);
    try std.testing.expectEqual(@as(usize, 3), cfg.n_queries);
}

test "fri config: bounds checks" {
    try std.testing.expectError(FriConfig.Error.InvalidLastLayerDegreeBound, FriConfig.init(11, 1, 1));
    try std.testing.expectError(FriConfig.Error.InvalidBlowupFactor, FriConfig.init(0, 0, 1));
}

test "fri: degree bound folding" {
    const circle_bound = CirclePolyDegreeBound.init(7);
    const line_bound = circle_bound.foldToLine();
    try std.testing.expectEqual(@as(u32, 6), line_bound.log_degree_bound);
    try std.testing.expectEqual(@as(u32, 5), (line_bound.fold(1) orelse unreachable).log_degree_bound);
    try std.testing.expect((line_bound.fold(7)) == null);
}

test "fri: accumulate line" {
    var layer = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    };
    const folded = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const alpha = QM31.fromU32Unchecked(5, 0, 0, 0);
    accumulateLine(layer[0..], folded[0..], alpha);

    const alpha_sq = alpha.square();
    try std.testing.expect(layer[0].eql(QM31.fromU32Unchecked(1, 0, 0, 0).mul(alpha_sq).add(folded[0])));
    try std.testing.expect(layer[1].eql(QM31.fromU32Unchecked(2, 0, 0, 0).mul(alpha_sq).add(folded[1])));
}
