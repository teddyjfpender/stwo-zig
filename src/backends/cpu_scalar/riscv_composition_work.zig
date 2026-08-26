//! Exact logical-work receipts and resource estimates for CPU RISC-V composition.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition_work = prover.air.composition_work;

const qm31 = core.fields.qm31;
const QM31 = qm31.QM31;

/// Derives one aggregate receipt after every worker has completed but before
/// ownership-changing merges begin. Missing component authority is not guessed:
/// the caller receives no receipt and the proof-level ledger remains incomplete.
pub fn buildWorkReceipt(
    allocator: std.mem.Allocator,
    components: anytype,
    total_constraints: usize,
    max_log_size: u32,
    eligible: []const bool,
    pairs: anytype,
    buckets: anytype,
    host_workers: anytype,
    finalize_into: bool,
) !?composition_work.Receipt {
    var builder = composition_work.Builder.init(.cpu_riscv_packed);
    const profiles = try allocator.alloc(
        composition_work.ComponentProfile,
        components.len,
    );
    defer allocator.free(profiles);
    for (components, 0..) |component, ordinal| {
        const profile = try component.compositionWorkProfile(allocator) orelse
            return null;
        profiles[ordinal] = profile;
        try builder.addComponent(ordinal, &profiles[ordinal]);
    }

    try builder.addAccumulator(
        "random-powers",
        try composition_work.randomPowersWork(total_constraints),
        &.{@as(u64, @intCast(total_constraints))},
    );

    var denominator_rows: u64 = 0;
    var host_cursor: usize = 0;
    for (components, eligible, 0..) |component, is_eligible, ordinal| {
        if (is_eligible) continue;
        const eval_log_size = component.maxConstraintLogDegreeBound();
        const profile = profiles[ordinal];
        denominator_rows = std.math.add(u64, denominator_rows, profile.row_count) catch
            return error.CountOverflow;
        try builder.addAccumulator(
            "host-denominator-setup",
            try composition_work.denominatorSetupWork(
                eval_log_size - 1,
                eval_log_size,
            ),
            &.{
                @as(u64, @intCast(ordinal)),
                @as(u64, eval_log_size),
                profile.row_count,
            },
        );
        host_cursor += 1;
    }
    std.debug.assert(host_cursor == host_workers.len);

    for (buckets, 0..) |bucket, ordinal| {
        denominator_rows = std.math.add(
            u64,
            denominator_rows,
            @intCast(bucket.row_count),
        ) catch return error.CountOverflow;
        try builder.addAccumulator(
            "packed-bucket-denominator-setup",
            try composition_work.denominatorSetupWork(
                bucket.eval_log_size - 1,
                bucket.eval_log_size,
            ),
            &.{
                @as(u64, @intCast(ordinal)),
                @as(u64, bucket.eval_log_size),
                @as(u64, @intCast(bucket.row_count)),
                @as(u64, @intCast(bucket.pair_indices.len)),
            },
        );
    }
    try builder.addAccumulator(
        "vanishing-denominator-row-products",
        .{ .multiplications = denominator_rows },
        &.{denominator_rows},
    );

    var pair_rows: u64 = 0;
    for (pairs) |pair| {
        if (pair.eval_log_size >= @bitSizeOf(u64)) return error.CountOverflow;
        pair_rows = std.math.add(
            u64,
            pair_rows,
            @as(u64, 1) << @intCast(pair.eval_log_size),
        ) catch return error.CountOverflow;
    }
    const pair_combines = std.math.mul(u64, pair_rows, 2) catch
        return error.CountOverflow;
    try builder.addAccumulator(
        "packed-pair-and-bucket-folds",
        .{ .additions = pair_combines },
        &.{ pair_rows, @as(u64, @intCast(pairs.len)) },
    );

    const slot_count = std.math.add(u64, @as(u64, max_log_size), 1) catch
        return error.CountOverflow;
    var merge_additions = std.math.mul(
        u64,
        @intCast(host_workers.len),
        slot_count,
    ) catch return error.CountOverflow;
    const occupied = try allocator.alloc(bool, @as(usize, max_log_size) + 1);
    defer allocator.free(occupied);
    @memset(occupied, false);
    var final_constant = QM31.zero();
    for (host_workers) |worker| {
        for (worker.accumulator.constant_accumulations) |value| {
            final_constant = final_constant.add(value);
        }
        for (worker.accumulator.sub_accumulations, 0..) |maybe_column, log_size| {
            const column = maybe_column orelse continue;
            if (occupied[log_size]) {
                const coordinate_rows = std.math.mul(
                    u64,
                    @intCast(column.len()),
                    qm31.SECURE_EXTENSION_DEGREE,
                ) catch return error.CountOverflow;
                merge_additions = std.math.add(
                    u64,
                    merge_additions,
                    coordinate_rows,
                ) catch return error.CountOverflow;
            } else occupied[log_size] = true;
        }
    }
    for (buckets) |bucket| {
        const log_size: usize = @intCast(bucket.eval_log_size);
        if (occupied[log_size]) {
            const coordinate_rows = std.math.mul(
                u64,
                @intCast(bucket.row_count),
                qm31.SECURE_EXTENSION_DEGREE,
            ) catch return error.CountOverflow;
            merge_additions = std.math.add(
                u64,
                merge_additions,
                coordinate_rows,
            ) catch return error.CountOverflow;
        } else occupied[log_size] = true;
    }
    try builder.addAccumulator(
        "accumulator-merges",
        .{ .additions = merge_additions },
        &.{
            @as(u64, @intCast(host_workers.len)),
            @as(u64, @intCast(buckets.len)),
            slot_count,
        },
    );

    var nonconstant_count: u64 = 0;
    var sole_log_size: usize = 0;
    for (occupied, 0..) |is_occupied, log_size| if (is_occupied) {
        nonconstant_count += 1;
        sole_log_size = log_size;
    };
    const max_rows = @as(u64, 1) << @intCast(max_log_size);
    var finalize_additions = slot_count;
    if (finalize_into) {
        finalize_additions = std.math.add(
            u64,
            finalize_additions,
            std.math.mul(u64, nonconstant_count, max_rows) catch
                return error.CountOverflow,
        ) catch return error.CountOverflow;
    } else if (nonconstant_count == 1 and sole_log_size == max_log_size) {
        if (!final_constant.eql(QM31.zero())) {
            finalize_additions = std.math.add(
                u64,
                finalize_additions,
                max_rows,
            ) catch return error.CountOverflow;
        }
    } else {
        finalize_additions = std.math.add(
            u64,
            finalize_additions,
            std.math.mul(u64, nonconstant_count, max_rows) catch
                return error.CountOverflow,
        ) catch return error.CountOverflow;
        if (nonconstant_count != 0 and !final_constant.eql(QM31.zero())) {
            finalize_additions = std.math.add(
                u64,
                finalize_additions,
                max_rows,
            ) catch return error.CountOverflow;
        }
    }
    try builder.addAccumulator(
        if (finalize_into) "accumulator-finalize-into" else "accumulator-finalize",
        .{ .additions = finalize_additions },
        &.{ nonconstant_count, max_rows, @intFromBool(!final_constant.eql(QM31.zero())) },
    );
    return try builder.finish();
}

pub fn requireHeapBackedResources(resources: prover.task_graph.ResourceReservation) !void {
    if (resources.exclusive_scratch_bytes != 0 or resources.device_resident_bytes != 0) {
        return error.FiniteCompositionByteBudgetUnsupported;
    }
}

pub fn componentWorkEstimate(component: anytype, rows: u64) !u64 {
    return prover.task_graph.checkedWorkEstimate(&.{
        rows,
        std.math.cast(u64, component.nConstraints()) orelse
            return error.WorkEstimateOverflow,
    });
}

pub fn componentRows(component: anytype) !u64 {
    const log_size = component.maxConstraintLogDegreeBound();
    if (log_size >= @bitSizeOf(u64)) return error.WorkEstimateOverflow;
    return @as(u64, 1) << @intCast(log_size);
}
