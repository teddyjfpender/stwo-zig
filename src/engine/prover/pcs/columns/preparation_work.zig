//! Exact PCS column-transform work planning, receipt validation and logical counters.
//! Ownership-preserving preparation of PCS columns for commitment.

const std = @import("std");
const prover_circle = @import("../../poly/circle/mod.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const WorkRecorder = work_profile.Recorder(true);

pub const PreparationWorkPlan = enum {
    passthrough,
    interpolate_only,
    interpolate_and_extend,
    combined,
};

pub fn coefficientExtensionFftButterflies(
    comptime B: type,
    coefficients: []const prover_circle.CircleCoefficients,
    log_blowup_factor: u32,
) !u64 {
    var total: u64 = 0;
    for (coefficients) |coefficient| {
        const extended_log_size = std.math.add(
            u32,
            coefficient.logSize(),
            log_blowup_factor,
        ) catch return error.CounterOverflow;
        // Generic backend hooks consume materialized zero tails and perform a
        // full FFT. The host engine alone uses its exact-2x degenerate-layer
        // specialization, and small domains deliberately fall back to full.
        const skipped_layers: u32 = if (!(comptime @hasDecl(B, "evaluateCircleBuffers")) and
            log_blowup_factor == 1 and extended_log_size > 2)
            1
        else
            0;
        total = std.math.add(
            u64,
            total,
            try work_profile.logicalFftButterflies(extended_log_size, skipped_layers),
        ) catch return error.CounterOverflow;
    }
    return total;
}

pub fn validateCombinedExecution(
    execution: work_profile.M31CircleLdeExecution,
    base_log_size: u32,
    extended_log_size: u32,
    column_count: usize,
) !void {
    try execution.validate();
    const columns = std.math.cast(u64, column_count) orelse
        return error.CounterOverflow;
    if (execution.interpolation.log_size != base_log_size or
        execution.interpolation.column_count != columns or
        execution.forward.log_size != extended_log_size or
        execution.forward.column_count != columns)
    {
        return error.InvalidProducerCoverage;
    }
}

pub fn recordFftButterflies(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    count: u64,
) !void {
    return recordM31TransformCompletion(recorder, site, null, count);
}

/// Records the complete scalar-field work of a forward M31 FFT together with
/// its logical butterfly count. This intentionally excludes interpolation
/// normalization/inversion, whose formula is a separate producer boundary.
pub fn recordM31ForwardFftWork(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    butterflies: u64,
) !void {
    if (recorder == null) return;
    const fields = try work_profile.logicalM31ForwardFftFieldOperations(
        butterflies,
    );
    return recordM31TransformCompletion(
        recorder,
        site,
        .{
            .field_additions = fields.additions,
            .field_multiplications = fields.multiplications,
            .field_inversions = fields.inversions,
            .fft_butterflies = butterflies,
        },
        butterflies,
    );
}

pub fn recordM31TransformCompletion(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    exact_work: ?work_profile.Counters,
    diagnostic_butterflies: u64,
) !void {
    const active = recorder orelse return;
    try active.recordCompletedDelta(.{
        .site = site,
        .producer = work_profile.boundaryForSite(site),
        .source_mask = if (exact_work != null)
            .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
                work_profile.SourceMask.one(.field_multiplications).bits |
                work_profile.SourceMask.one(.field_inversions).bits |
                work_profile.SourceMask.one(.fft_butterflies).bits }
        else
            work_profile.SourceMask.one(.fft_butterflies),
        .counters = exact_work orelse .{
            .fft_butterflies = diagnostic_butterflies,
        },
    });
}

pub fn planPreparationWork(
    recorder: ?*WorkRecorder,
    plan: PreparationWorkPlan,
) !void {
    const active = recorder orelse return;
    switch (plan) {
        .passthrough => {
            try active.expectProducer(.column_passthrough_fft);
            // work-profile-plan:column-passthrough-fft
        },
        .interpolate_only => {
            try active.expectProducer(.column_interpolate_only_fft);
            // work-profile-plan:column-interpolate-only-fft
        },
        .interpolate_and_extend => {
            try active.expectProducer(.column_interpolate_for_extension_fft);
            // work-profile-plan:column-interpolate-for-extension-fft
            try active.expectProducer(.column_extension_fft);
            // work-profile-plan:column-extension-fft
        },
        .combined => {
            try active.expectProducer(.column_combined_fft);
            // work-profile-plan:column-combined-fft
        },
    }
}
