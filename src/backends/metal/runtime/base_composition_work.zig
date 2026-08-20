//! Exact work receipt derivation for resident/hybrid base composition.

const std = @import("std");
const core = @import("stwo_core");
const composition_work = @import("stwo_prover_engine").air.composition_work;

const QM31 = core.fields.qm31.QM31;

/// Reconstructs the exact completed Metal/host schedule from authenticated
/// component formulas and the accumulators that actually ran. The receipt is
/// built before ownership-changing merges and published only after finalize
/// succeeds, so failures and route declines cannot leak a partial completion.
pub fn build(
    allocator: std.mem.Allocator,
    components: anytype,
    total_constraints: usize,
    max_log_size: u32,
    semantic_jobs: anytype,
    lookup_jobs: anytype,
    host_workers: anytype,
    buckets: anytype,
) !?composition_work.Receipt {
    var builder = composition_work.Builder.init(if (host_workers.len == 0)
        .metal_riscv_resident
    else
        .metal_hybrid_resident);
    const profiles = try allocator.alloc(
        composition_work.ComponentProfile,
        components.len,
    );
    defer allocator.free(profiles);

    var denominator_rows: u64 = 0;
    for (components, 0..) |component, ordinal| {
        const profile = try component.compositionWorkProfile(allocator) orelse
            return null;
        profiles[ordinal] = profile;
        try builder.addComponent(ordinal, &profiles[ordinal]);
        denominator_rows = try checkedAdd(denominator_rows, profile.row_count);
        try builder.addAccumulator(
            "component-denominator-setup",
            try composition_work.denominatorSetupWork(
                profile.evaluation_log_size - 1,
                profile.evaluation_log_size,
            ),
            &.{
                @as(u64, @intCast(ordinal)),
                @as(u64, profile.evaluation_log_size),
                profile.row_count,
            },
        );
    }

    try builder.addAccumulator(
        "random-powers",
        try composition_work.randomPowersWork(total_constraints),
        &.{@as(u64, @intCast(total_constraints))},
    );
    try builder.addAccumulator(
        "vanishing-denominator-row-products",
        .{ .multiplications = denominator_rows },
        &.{denominator_rows},
    );

    var resident_rows: u64 = 0;
    for (semantic_jobs) |job|
        resident_rows = try checkedAdd(resident_rows, @intCast(job.row_count));
    for (lookup_jobs) |job|
        resident_rows = try checkedAdd(resident_rows, @intCast(job.row_count));
    try builder.addAccumulator(
        "resident-output-coordinate-folds",
        .{ .additions = try checkedMul(
            resident_rows,
            core.fields.qm31.SECURE_EXTENSION_DEGREE,
        ) },
        &.{
            resident_rows,
            @as(u64, @intCast(semantic_jobs.len)),
            @as(u64, @intCast(lookup_jobs.len)),
        },
    );

    const slot_count = try checkedAdd(@as(u64, max_log_size), 1);
    var merge_additions = try checkedMul(@intCast(host_workers.len), slot_count);
    const occupied = try allocator.alloc(bool, @as(usize, max_log_size) + 1);
    defer allocator.free(occupied);
    @memset(occupied, false);
    var final_constant = QM31.zero();
    for (host_workers) |worker| {
        for (worker.accumulator.constant_accumulations) |value|
            final_constant = final_constant.add(value);
        for (worker.accumulator.sub_accumulations, 0..) |maybe_column, log_size| {
            const column = maybe_column orelse continue;
            if (occupied[log_size]) {
                merge_additions = try checkedAdd(
                    merge_additions,
                    try checkedMul(
                        @intCast(column.len()),
                        core.fields.qm31.SECURE_EXTENSION_DEGREE,
                    ),
                );
            } else occupied[log_size] = true;
        }
    }
    var resident_bucket_count: u64 = 0;
    for (buckets, 0..) |maybe_bucket, log_size| {
        const bucket = maybe_bucket orelse continue;
        resident_bucket_count = try checkedAdd(resident_bucket_count, 1);
        if (occupied[log_size]) {
            merge_additions = try checkedAdd(
                merge_additions,
                try checkedMul(
                    @intCast(bucket.len()),
                    core.fields.qm31.SECURE_EXTENSION_DEGREE,
                ),
            );
        } else occupied[log_size] = true;
    }
    try builder.addAccumulator(
        "accumulator-merges",
        .{ .additions = merge_additions },
        &.{
            @as(u64, @intCast(host_workers.len)),
            resident_bucket_count,
            slot_count,
        },
    );

    var nonconstant_count: u64 = 0;
    var sole_log_size: usize = 0;
    for (occupied, 0..) |is_occupied, log_size| if (is_occupied) {
        nonconstant_count += 1;
        sole_log_size = log_size;
    };
    if (max_log_size >= @bitSizeOf(u64)) return error.CountOverflow;
    const max_rows = @as(u64, 1) << @intCast(max_log_size);
    var finalize_additions = slot_count;
    if (nonconstant_count == 1 and sole_log_size == max_log_size) {
        if (!final_constant.eql(QM31.zero()))
            finalize_additions = try checkedAdd(finalize_additions, max_rows);
    } else {
        finalize_additions = try checkedAdd(
            finalize_additions,
            try checkedMul(nonconstant_count, max_rows),
        );
        if (nonconstant_count != 0 and !final_constant.eql(QM31.zero()))
            finalize_additions = try checkedAdd(finalize_additions, max_rows);
    }
    try builder.addAccumulator(
        "accumulator-finalize",
        .{ .additions = finalize_additions },
        &.{
            nonconstant_count,
            max_rows,
            @intFromBool(!final_constant.eql(QM31.zero())),
        },
    );
    return try builder.finish();
}

fn checkedAdd(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.CountOverflow;
}

fn checkedMul(lhs: u64, rhs: u64) !u64 {
    return std.math.mul(u64, lhs, rhs) catch error.CountOverflow;
}
