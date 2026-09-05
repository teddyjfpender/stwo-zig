//! Full staged PCS-residency model for lower-width Poseidon candidates.
//!
//! Every non-candidate tree is supplied as an explicit per-column log array.
//! The model therefore cannot silently replace a full Ethereum proof with a
//! Tree-1-only estimate. It exposes two lifetime assumptions separately:
//! retained opening data after all four commitments, and the current scheme's
//! commit transient in which prior trees remain resident while the current
//! source and extended evaluations coexist.

const std = @import("std");
const candidate = @import("typed_poseidon2_degree_bounded_candidate.zig");
const residency = @import("stwo_prover_engine").pcs.residency_estimate;

pub const RetentionPolicy = residency.RetentionPolicy;

pub const Error = residency.Error || error{
    IncompleteStageAuthority,
    LogDegreeOverflow,
    ResidencyEstimateOverflow,
};

pub const Stage = struct {
    column_count: u64,
    source_cells: u64,
    extended_cells: u64,
    source_bytes: u64,
    retained_coefficient_bytes: u64,
    extended_evaluation_bytes: u64,
    minimum_resident_bytes: u64,

    fn from(value: residency.Estimate) Stage {
        return .{
            .column_count = value.column_count,
            .source_cells = value.source_cells,
            .extended_cells = value.extended_cells,
            .source_bytes = value.source_bytes,
            .retained_coefficient_bytes = value.retained_coefficient_bytes,
            .extended_evaluation_bytes = value.extended_evaluation_bytes,
            .minimum_resident_bytes = value.minimum_resident_bytes,
        };
    }

    fn combine(lhs: Stage, rhs: Stage) Error!Stage {
        return .{
            .column_count = try add(lhs.column_count, rhs.column_count),
            .source_cells = try add(lhs.source_cells, rhs.source_cells),
            .extended_cells = try add(lhs.extended_cells, rhs.extended_cells),
            .source_bytes = try add(lhs.source_bytes, rhs.source_bytes),
            .retained_coefficient_bytes = try add(
                lhs.retained_coefficient_bytes,
                rhs.retained_coefficient_bytes,
            ),
            .extended_evaluation_bytes = try add(
                lhs.extended_evaluation_bytes,
                rhs.extended_evaluation_bytes,
            ),
            .minimum_resident_bytes = try add(
                lhs.minimum_resident_bytes,
                rhs.minimum_resident_bytes,
            ),
        };
    }

    fn commitTransientBytes(self: Stage) Error!u64 {
        return add(self.source_bytes, self.extended_evaluation_bytes);
    }
};

pub const Request = struct {
    profile: candidate.Profile,
    trace_log_size: u32,
    log_blowup_factor: u32,
    retention_policy: RetentionPolicy,
    /// Complete Tree 0, including every base/extension coordinate column.
    tree0_log_sizes: []const u32,
    /// Complete non-candidate part of Tree 1. Candidate main columns are
    /// inserted independently at `trace_log_size` by this module.
    tree1_non_candidate_log_sizes: []const u32,
    /// Complete Tree 2, including every base/extension coordinate column.
    tree2_log_sizes: []const u32,
};

pub const Estimate = struct {
    tree0: Stage,
    tree1_candidate: Stage,
    tree1_non_candidate: Stage,
    tree1: Stage,
    tree2: Stage,
    composition: Stage,
    composition_column_log_size: u32,
    /// All committed-tree LDEs and policy-retained coefficients remain live
    /// for openings when the composition tree has also been committed.
    retained_opening_lower_bound_bytes: u64,
    /// Ordered current-scheme assumption: before committing tree K, all prior
    /// minimum-resident data remains live; K's source and full extended
    /// evaluations coexist during its transform/commit. This is not allocator
    /// overhead or a hardware forecast.
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,
    retention_policy: RetentionPolicy,

    pub fn requireWithin(self: Estimate, budget: u64) residency.Error!void {
        if (self.staged_peak_lower_bound_bytes > budget)
            return error.PcsResidentBudgetExceeded;
    }
};

pub fn estimate(request: Request) Error!Estimate {
    if (request.tree0_log_sizes.len == 0 or
        request.tree1_non_candidate_log_sizes.len == 0 or
        request.tree2_log_sizes.len == 0)
    {
        return error.IncompleteStageAuthority;
    }

    const tree0 = Stage.from(try residency.estimate(
        request.tree0_log_sizes,
        request.log_blowup_factor,
        request.retention_policy,
    ));
    const tree1_candidate = Stage.from(try residency.estimateUniform(
        request.profile.expected().main_columns,
        request.trace_log_size,
        request.log_blowup_factor,
        request.retention_policy,
    ));
    const tree1_non_candidate = Stage.from(try residency.estimate(
        request.tree1_non_candidate_log_sizes,
        request.log_blowup_factor,
        request.retention_policy,
    ));
    const tree1 = try Stage.combine(tree1_candidate, tree1_non_candidate);
    const tree2 = Stage.from(try residency.estimate(
        request.tree2_log_sizes,
        request.log_blowup_factor,
        request.retention_policy,
    ));
    const composition_column_log_size =
        try request.profile.compositionColumnLogSize(request.trace_log_size);
    const composition = Stage.from(try residency.estimateUniform(
        request.profile.compositionColumns(),
        composition_column_log_size,
        request.log_blowup_factor,
        request.retention_policy,
    ));

    var retained_prior: u64 = 0;
    var transient_peak: u64 = 0;
    inline for (.{ tree0, tree1, tree2, composition }) |stage| {
        transient_peak = @max(
            transient_peak,
            try add(retained_prior, try stage.commitTransientBytes()),
        );
        retained_prior = try add(retained_prior, stage.minimum_resident_bytes);
    }
    const retained_opening = retained_prior;
    return .{
        .tree0 = tree0,
        .tree1_candidate = tree1_candidate,
        .tree1_non_candidate = tree1_non_candidate,
        .tree1 = tree1,
        .tree2 = tree2,
        .composition = composition,
        .composition_column_log_size = composition_column_log_size,
        .retained_opening_lower_bound_bytes = retained_opening,
        .commit_transient_lower_bound_bytes = transient_peak,
        .staged_peak_lower_bound_bytes = @max(
            retained_opening,
            transient_peak,
        ),
        .retention_policy = request.retention_policy,
    };
}

/// Exact aggregate retained from the safe real-segment-0 geometry breakpoint.
/// It is intentionally Tree-1-only and cannot be passed to `estimate`, which
/// still requires the missing Tree0/Tree2 per-column authorities.
pub const RealSegment0Tree1 = struct {
    pub const trace_log_size: u32 = 24;
    pub const legacy_poseidon_columns: u64 = 445;
    pub const legacy_base_cells: u64 = 7_910_607_776;
    pub const extension_cells: u64 = 90_562;
    pub const non_poseidon_base_cells: u64 = legacy_base_cells -
        legacy_poseidon_columns * (@as(u64, 1) << trace_log_size);

    pub fn candidateStage(
        profile: candidate.Profile,
        retention_policy: RetentionPolicy,
    ) Error!Stage {
        const candidate_cells = std.math.mul(
            u64,
            profile.expected().main_columns,
            @as(u64, 1) << trace_log_size,
        ) catch return error.ResidencyEstimateOverflow;
        const source_cells = try add(
            try add(non_poseidon_base_cells, extension_cells),
            candidate_cells,
        );
        const extended_cells = std.math.mul(u64, source_cells, 2) catch
            return error.ResidencyEstimateOverflow;
        const source_bytes = std.math.mul(u64, source_cells, 4) catch
            return error.ResidencyEstimateOverflow;
        const extended_bytes = std.math.mul(u64, extended_cells, 4) catch
            return error.ResidencyEstimateOverflow;
        const retained_coefficients = switch (retention_policy) {
            .always => source_bytes,
            .auto, .never => 0,
        };
        return .{
            .column_count = profile.expected().main_columns,
            .source_cells = source_cells,
            .extended_cells = extended_cells,
            .source_bytes = source_bytes,
            .retained_coefficient_bytes = retained_coefficients,
            .extended_evaluation_bytes = extended_bytes,
            .minimum_resident_bytes = try add(
                retained_coefficients,
                extended_bytes,
            ),
        };
    }

    pub fn tree1PlusCompositionFloor(
        profile: candidate.Profile,
        retention_policy: RetentionPolicy,
    ) Error!u64 {
        const tree1 = try candidateStage(profile, retention_policy);
        const composition = Stage.from(try residency.estimateUniform(
            profile.compositionColumns(),
            try profile.compositionColumnLogSize(trace_log_size),
            1,
            retention_policy,
        ));
        return add(
            tree1.minimum_resident_bytes,
            composition.minimum_resident_bytes,
        );
    }
};

fn add(lhs: u64, rhs: u64) Error!u64 {
    return std.math.add(u64, lhs, rhs) catch
        error.ResidencyEstimateOverflow;
}
