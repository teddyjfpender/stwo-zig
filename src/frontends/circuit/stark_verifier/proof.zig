//! The shape of a circuit STARK proof: `ProofConfig` (the AIR and PCS
//! parameters a verifier circuit is built for) and `ProofInfo` (its size).
//!
//! Ports the config half of `crates/stark_verifier/src/proof.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The `Proof(T)` value type and
//! its single `guess` traversal build on the circuit builder and land with
//! it; `ProofInfo.totalBytes` is the size model the `CircuitSerialize`
//! reader and writer (M3) must agree with, computed from the same config
//! walk rather than a second model.

const std = @import("std");
const core = @import("stwo_core");
const oods = @import("oods.zig");

const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const SECURE_EXTENSION_DEGREE = core.fields.qm31.SECURE_EXTENSION_DEGREE;

/// Committed trees: preprocessed, trace, interaction, composition.
pub const N_TRACES: usize = 4;
const N_U8S_PER_U32: usize = 4;
/// Bytes of one `HashValue`: eight u32 words.
const HASH_SIZE: usize = 2 * SECURE_EXTENSION_DEGREE * N_U8S_PER_U32;
/// Bytes of one QM31.
const QM31_SIZE: usize = SECURE_EXTENSION_DEGREE * N_U8S_PER_U32;

/// Trace and interaction column counts of one component.
pub const ComponentShape = struct {
    trace_columns: usize,
    interaction_columns: usize,
};

pub const ConfigError = error{
    /// A component has fewer interaction columns than its cumulative sum.
    TooFewInteractionColumns,
    /// The preprocessed tree is lifted to a different height than the
    /// others; the circuit verifier checks every tree against one domain.
    MismatchedLiftingLogSizes,
    /// `trace_lifting_log_size < log_blowup_factor`.
    LiftingBelowBlowup,
} || std.mem.Allocator.Error;

/// `ProofConfig`: the structure of a proof.
pub const ProofConfig = struct {
    n_interaction_pow_bits: u32,
    n_preprocessed_columns: usize,
    n_trace_columns: usize,
    n_interaction_columns: usize,
    /// One entry per component, in the order the statement iterates its
    /// components in `compute_composition_polynomial`.
    component_shapes: []const ComponentShape,
    /// Per interaction column: whether it is a cumulative-sum column (and so
    /// also sampled at the previous point).
    cumulative_sum_columns: []const bool,
    log_trace_size: usize,
    fri: FriConfigV2,

    /// `ProofConfig::new`. Copies `component_shapes`; free with `deinit`.
    pub fn init(
        allocator: std.mem.Allocator,
        component_shapes: []const ComponentShape,
        n_preprocessed_columns: usize,
        pcs_config: PcsConfigV2,
        n_interaction_pow_bits: u32,
    ) ConfigError!ProofConfig {
        var n_trace_columns: usize = 0;
        var n_interaction_columns: usize = 0;
        for (component_shapes) |shape| {
            if (shape.interaction_columns < SECURE_EXTENSION_DEGREE) return error.TooFewInteractionColumns;
            n_trace_columns += shape.trace_columns;
            n_interaction_columns += shape.interaction_columns;
        }
        if (pcs_config.trace_lifting_log_size != pcs_config.preprocessed_lifting_log_size)
            return error.MismatchedLiftingLogSizes;
        const log_trace_size = std.math.sub(
            u32,
            pcs_config.trace_lifting_log_size,
            pcs_config.fri_config.log_blowup_factor,
        ) catch return error.LiftingBelowBlowup;

        const shapes = try allocator.dupe(ComponentShape, component_shapes);
        errdefer allocator.free(shapes);
        const cumulative = try allocator.alloc(bool, n_interaction_columns);
        var at: usize = 0;
        for (component_shapes) |shape| {
            // The last SECURE_EXTENSION_DEGREE interaction columns of every
            // component are its cumulative sum.
            const plain = shape.interaction_columns - SECURE_EXTENSION_DEGREE;
            @memset(cumulative[at..][0..plain], false);
            @memset(cumulative[at + plain ..][0..SECURE_EXTENSION_DEGREE], true);
            at += shape.interaction_columns;
        }
        return .{
            .n_interaction_pow_bits = n_interaction_pow_bits,
            .n_preprocessed_columns = n_preprocessed_columns,
            .n_trace_columns = n_trace_columns,
            .n_interaction_columns = n_interaction_columns,
            .component_shapes = shapes,
            .cumulative_sum_columns = cumulative,
            .log_trace_size = log_trace_size,
            .fri = pcs_config.fri_config,
        };
    }

    pub fn deinit(self: *ProofConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.component_shapes);
        allocator.free(self.cumulative_sum_columns);
        self.* = undefined;
    }

    pub fn nComponents(self: ProofConfig) usize {
        return self.component_shapes.len;
    }

    pub fn logEvaluationDomainSize(self: ProofConfig) usize {
        return self.log_trace_size + self.fri.log_blowup_factor;
    }

    pub fn nQueries(self: ProofConfig) usize {
        return self.fri.n_queries;
    }

    /// Columns of the preprocessed, trace, interaction and composition trees.
    pub fn nColumnsPerTrace(self: ProofConfig) [N_TRACES]usize {
        return .{
            self.n_preprocessed_columns,
            self.n_trace_columns,
            self.n_interaction_columns,
            oods.N_COMPOSITION_COLUMNS,
        };
    }

    /// Number of FRI inner layers (`compute_all_fold_steps(..).len()`).
    pub fn nFriLayers(self: ProofConfig) usize {
        return core.fri.nFoldSteps(self.degreeLogRatio(), self.fri.fold_step);
    }

    fn degreeLogRatio(self: ProofConfig) u32 {
        return @as(u32, @intCast(self.log_trace_size)) - self.fri.log_last_layer_degree_bound;
    }
};

/// `ProofInfo`: the proof size breakdown in bytes, from the config alone.
/// Fields that scale with `n_queries` hold the per-query cost.
pub const ProofInfo = struct {
    log_trace_size: usize,
    log_blowup_factor: usize,
    n_queries: usize,
    n_columns_per_trace: [N_TRACES]usize,
    /// channel_salt, three roots, pow_nonce and interaction_pow_nonce.
    fixed: usize,
    /// One packed QM31 per component.
    claim: usize,
    /// One QM31 per column, plus the previous-point sample of every
    /// cumulative-sum column.
    oods: usize,
    fri_commitments: usize,
    fri_last_layer: usize,
    eval_samples_per_query: usize,
    eval_auth_per_query: usize,
    fri_auth_per_query: usize,
    fri_witness_per_query: usize,

    /// `ProofInfo::from_config`.
    pub fn fromConfig(config: ProofConfig) ProofInfo {
        const n_queries = config.nQueries();
        const log_eval_domain = config.logEvaluationDomainSize();
        const n_columns_per_trace = config.nColumnsPerTrace();
        var total_columns: usize = 0;
        for (n_columns_per_trace) |n| total_columns += n;
        var n_cumsum: usize = 0;
        for (config.cumulative_sum_columns) |is_cumsum| n_cumsum += @intFromBool(is_cumsum);

        var steps_buffer: [32]u32 = undefined;
        const fold_steps = core.fri.allFoldSteps(config.degreeLogRatio(), config.fri.fold_step, &steps_buffer);

        var fri_auth_per_query: usize = 0;
        var fri_witness_per_query: usize = 0;
        var log_layer_size = log_eval_domain;
        for (fold_steps) |step| {
            log_layer_size -= step;
            fri_auth_per_query += log_layer_size * HASH_SIZE;
            fri_witness_per_query += (@as(usize, 1) << @intCast(step)) * QM31_SIZE;
        }

        return .{
            .log_trace_size = config.log_trace_size,
            .log_blowup_factor = config.fri.log_blowup_factor,
            .n_queries = n_queries,
            .n_columns_per_trace = n_columns_per_trace,
            .fixed = (1 + 3 * 2 + 1 + 1) * QM31_SIZE,
            .claim = config.nComponents() * QM31_SIZE,
            .oods = (total_columns + n_cumsum) * QM31_SIZE,
            .fri_commitments = fold_steps.len * HASH_SIZE,
            .fri_last_layer = (@as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound)) * QM31_SIZE,
            .eval_samples_per_query = total_columns * N_U8S_PER_U32,
            .eval_auth_per_query = N_TRACES * log_eval_domain * HASH_SIZE,
            .fri_auth_per_query = fri_auth_per_query,
            .fri_witness_per_query = fri_witness_per_query,
        };
    }

    /// `ProofInfo::total_bytes`: the `CircuitSerialize` length of a proof.
    pub fn totalBytes(self: ProofInfo) usize {
        return self.fixed + self.claim + self.oods + self.fri_commitments + self.fri_last_layer +
            (self.eval_samples_per_query + self.eval_auth_per_query + self.fri_auth_per_query +
                self.fri_witness_per_query) * self.n_queries;
    }
};

test "proof config: cumulative-sum columns are the last four of each component" {
    const shapes = [_]ComponentShape{
        .{ .trace_columns = 3, .interaction_columns = 8 },
        .{ .trace_columns = 1, .interaction_columns = 4 },
    };
    const fri = try FriConfigV2.init(10, 0, 1, 3, 1);
    var config = try ProofConfig.init(std.testing.allocator, &shapes, 5, PcsConfigV2.fromFriAndTraceSize(fri, 6), 20);
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), config.n_trace_columns);
    try std.testing.expectEqualSlices(bool, &.{
        false, false, false, false, true, true, true, true,
        true,  true,  true,  true,
    }, config.cumulative_sum_columns);
    try std.testing.expectEqual(@as(usize, 6), config.log_trace_size);
    try std.testing.expectEqual(@as(usize, 7), config.logEvaluationDomainSize());
    try std.testing.expectEqual([N_TRACES]usize{ 5, 4, 12, 8 }, config.nColumnsPerTrace());
}

test "proof config: rejects unequal lifting heights and short interaction traces" {
    const fri = try FriConfigV2.init(10, 0, 1, 3, 1);
    var pcs = PcsConfigV2.fromFriAndTraceSize(fri, 6);
    try std.testing.expectError(error.TooFewInteractionColumns, ProofConfig.init(
        std.testing.allocator,
        &.{.{ .trace_columns = 1, .interaction_columns = 3 }},
        0,
        pcs,
        0,
    ));
    pcs.preprocessed_lifting_log_size -= 1;
    try std.testing.expectError(error.MismatchedLiftingLogSizes, ProofConfig.init(std.testing.allocator, &.{}, 0, pcs, 0));
}
