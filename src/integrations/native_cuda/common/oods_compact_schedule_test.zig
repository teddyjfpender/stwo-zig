//! CPU-oracle coverage for descriptor-driven compact OODS schedules.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const batches = @import("oods_batches.zig");

const prime: u64 = 2_147_483_647;

fn device(
    comptime T: type,
    address: usize,
    len: usize,
) column.DeviceSlice(T) {
    return .{ .address = address, .len = len, .owner = 31 };
}

fn evaluate(
    coefficients: []const u32,
    factors: []const u32,
) u32 {
    var width = coefficients.len;
    var level = [_]u32{0} ** 32;
    std.debug.assert(width <= level.len and std.math.isPowerOfTwo(width));
    @memcpy(level[0..width], coefficients);
    var factor_index = factors.len;
    while (width > 1) {
        factor_index -= 1;
        for (0..width / 2) |index| {
            const product =
                (@as(u64, level[2 * index + 1]) * factors[factor_index]) %
                prime;
            const sum = @as(u64, level[2 * index]) + product;
            level[index] = @intCast(if (sum >= prime) sum - prime else sum);
        }
        width /= 2;
    }
    return level[0];
}

test "more than eight mixed cohorts preserve direct CPU sample order" {
    const source_count = 12;
    var sources: [source_count]batches.CompactSource = undefined;
    var source_words: usize = 5;
    for (&sources, 0..) |*source, index| {
        const log_size: u32 = @intCast(3 + index % 3);
        const rows = @as(usize, 1) << @intCast(log_size);
        const stride = rows + 1 + index % 2;
        source.* = .{
            .offset_words = source_words,
            .stride_words = @intCast(stride),
            .log_size = log_size,
        };
        source_words += stride + 2;
    }

    const samples = [_]batches.CompactSample{
        .{ .source_index = 0 },
        .{ .source_index = 1 },
        .{ .source_index = 0 },
        .{ .source_index = 2 },
        .{ .source_index = 3 },
        .{ .source_index = 4 },
        .{ .source_index = 5 },
        .{ .source_index = 6 },
        .{ .source_index = 7 },
        .{ .source_index = 8 },
        .{ .source_index = 9 },
        .{ .source_index = 10 },
        .{ .source_index = 11 },
    };
    var cohort_storage: [samples.len]batches.CompactCohort = undefined;
    const schedule = try batches.compileCompactSchedule(
        &sources,
        &samples,
        source_words,
        &cohort_storage,
    );
    try std.testing.expect(schedule.cohorts.len > 8);
    try std.testing.expectEqual(samples.len, schedule.sample_count);

    const allocator = std.testing.allocator;
    const backing = try allocator.alloc(u32, source_words);
    defer allocator.free(backing);
    @memset(backing, 2_000_000_000);
    for (sources, 0..) |source, source_index| {
        const rows = @as(usize, 1) << @intCast(source.log_size);
        const offset: usize = @intCast(source.offset_words);
        for (0..rows) |row| {
            backing[offset + row] = @intCast(
                17 + source_index * 101 + row * 7,
            );
        }
    }

    var direct: [samples.len]u32 = undefined;
    for (samples, 0..) |sample, sample_index| {
        const source = sources[sample.source_index];
        const rows = @as(usize, 1) << @intCast(source.log_size);
        const offset: usize = @intCast(source.offset_words);
        var factors: [5]u32 = undefined;
        for (factors[0..source.log_size], 0..) |*factor, index| {
            factor.* = @intCast(3 + sample_index * 11 + index * 5);
        }
        direct[sample_index] = evaluate(
            backing[offset .. offset + rows],
            factors[0..source.log_size],
        );
    }

    var scheduled: [samples.len]u32 = undefined;
    for (schedule.cohorts) |cohort| {
        for (0..cohort.sample_count) |local_sample| {
            const sample_index = cohort.first_sample + local_sample;
            const rows =
                @as(usize, 1) << @intCast(cohort.coefficient_log_size);
            const offset = cohort.source_offset_words +
                local_sample * cohort.source_stride_words;
            var factors: [5]u32 = undefined;
            for (factors[0..cohort.coefficient_log_size], 0..) |*factor, index| {
                factor.* = @intCast(3 + sample_index * 11 + index * 5);
            }
            scheduled[sample_index] = evaluate(
                backing[offset .. offset + rows],
                factors[0..cohort.coefficient_log_size],
            );
        }
    }
    try std.testing.expectEqualDeep(direct, scheduled);

    var points: [samples.len]field.CirclePointBaseField = undefined;
    const folds = [_]u32{0} ** samples.len;
    var indices: [samples.len]u32 = undefined;
    var factor_count: usize = 0;
    for (samples, 0..) |sample, index| {
        points[index] = .{ .x = 1, .y = 0 };
        indices[index] = @intCast(index);
        factor_count += sources[sample.source_index].log_size;
    }
    const ingress = .{
        .oods_offset_points = points[0..],
        .oods_fold_counts = folds[0..],
        .oods_output_indices = indices[0..],
    };
    const views = .{
        .oods = .{
            .parameter = device(field.SecureField, 0x1000, 1),
            .offset_points = device(
                field.CirclePointBaseField,
                0x2000,
                samples.len,
            ),
            .fold_counts = device(u32, 0x3000, samples.len),
            .output_indices = device(u32, 0x4000, samples.len),
            .sample_points = device(
                field.SecureCirclePoint,
                0x5000,
                samples.len,
            ),
            .evaluation_points = device(
                field.SecureCirclePoint,
                0x6000,
                samples.len,
            ),
            .folding_factors = device(
                field.SecureField,
                0x7000,
                factor_count,
            ),
            .reduce_a = device(
                field.SecureField,
                0x8000,
                samples.len,
            ),
            .reduce_b = device(
                field.SecureField,
                0x9000,
                samples.len,
            ),
            .sampled_values = device(
                field.SecureField,
                0xa000,
                samples.len,
            ),
        },
        .quotient = .{
            .challenge = device(field.SecureField, 0xb000, 1),
        },
    };
    var batch_storage: [samples.len]batches.Batch = undefined;
    const bound = try batches.bindCompact(
        ingress,
        views,
        device(u32, 0x10000, source_words),
        schedule,
        &batch_storage,
    );
    try std.testing.expect(bound.len > 8);
}

test "compact schedule rejects malformed source and sample descriptors" {
    const good_source = [_]batches.CompactSource{
        .{ .offset_words = 4, .stride_words = 8, .log_size = 3 },
    };
    const good_sample = [_]batches.CompactSample{.{ .source_index = 0 }};
    var storage: [1]batches.CompactCohort = undefined;

    var short_stride = good_source;
    short_stride[0].stride_words = 7;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        batches.compileCompactSchedule(
            &short_stride,
            &good_sample,
            12,
            &storage,
        ),
    );
    var out_of_bounds = good_source;
    out_of_bounds[0].offset_words = 5;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        batches.compileCompactSchedule(
            &out_of_bounds,
            &good_sample,
            12,
            &storage,
        ),
    );
    var overflow = good_source;
    overflow[0].offset_words = std.math.maxInt(u64);
    try std.testing.expectError(
        error.SizeOverflow,
        batches.compileCompactSchedule(
            &overflow,
            &good_sample,
            12,
            &storage,
        ),
    );
    const bad_sample = [_]batches.CompactSample{.{ .source_index = 1 }};
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        batches.compileCompactSchedule(
            &good_source,
            &bad_sample,
            12,
            &storage,
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        batches.compileCompactSchedule(
            &good_source,
            &good_sample,
            12,
            &.{},
        ),
    );
}

test "compact cohorts bind exact resident ranges and canonical sample offsets" {
    const sources = [_]batches.CompactSource{
        .{ .offset_words = 0, .stride_words = 8, .log_size = 3 },
        .{ .offset_words = 8, .stride_words = 8, .log_size = 3 },
        .{ .offset_words = 16, .stride_words = 16, .log_size = 4 },
    };
    const samples = [_]batches.CompactSample{
        .{ .source_index = 0 },
        .{ .source_index = 1 },
        .{ .source_index = 0 },
        .{ .source_index = 2 },
    };
    var cohort_storage: [samples.len]batches.CompactCohort = undefined;
    const schedule = try batches.compileCompactSchedule(
        &sources,
        &samples,
        32,
        &cohort_storage,
    );
    try std.testing.expectEqual(@as(usize, 3), schedule.cohorts.len);

    const points = [_]field.CirclePointBaseField{
        .{ .x = 1, .y = 0 },
        .{ .x = 1, .y = 0 },
        .{ .x = 1, .y = 0 },
        .{ .x = 1, .y = 0 },
    };
    const folds = [_]u32{ 0, 1, 2, 3 };
    const indices = [_]u32{ 2, 0, 3, 1 };
    const ingress = .{
        .oods_offset_points = points[0..],
        .oods_fold_counts = folds[0..],
        .oods_output_indices = indices[0..],
    };
    const views = .{
        .oods = .{
            .parameter = device(field.SecureField, 0x1000, 1),
            .offset_points = device(field.CirclePointBaseField, 0x2000, 4),
            .fold_counts = device(u32, 0x3000, 4),
            .output_indices = device(u32, 0x4000, 4),
            .sample_points = device(field.SecureCirclePoint, 0x5000, 4),
            .evaluation_points = device(field.SecureCirclePoint, 0x6000, 4),
            .folding_factors = device(field.SecureField, 0x7000, 13),
            .reduce_a = device(field.SecureField, 0x8000, 4),
            .reduce_b = device(field.SecureField, 0x9000, 4),
            .sampled_values = device(field.SecureField, 0xa000, 4),
        },
        .quotient = .{
            .challenge = device(field.SecureField, 0xb000, 1),
        },
    };
    var batch_storage: [samples.len]batches.Batch = undefined;
    const bound = try batches.bindCompact(
        ingress,
        views,
        device(u32, 0x10000, 32),
        schedule,
        &batch_storage,
    );
    try std.testing.expectEqual(@as(usize, 3), bound.len);
    try std.testing.expectEqual(@as(usize, 2), bound[0].sample_count);
    try std.testing.expectEqual(@as(usize, 16), bound[0].coefficients.storage.len);
    try std.testing.expectEqual(@as(usize, 0x10000), bound[0].coefficients.storage.address);
    try std.testing.expectEqual(@as(usize, 0), bound[0].factor_first);
    try std.testing.expectEqual(@as(usize, 0), bound[0].scratch_first);
    try std.testing.expectEqual(@as(usize, 1), bound[1].sample_count);
    try std.testing.expectEqual(@as(usize, 0x10000), bound[1].coefficients.storage.address);
    try std.testing.expectEqual(@as(usize, 6), bound[1].factor_first);
    try std.testing.expectEqual(@as(usize, 2), bound[1].scratch_first);
    try std.testing.expectEqual(@as(usize, 0x10040), bound[2].coefficients.storage.address);
    try std.testing.expectEqual(@as(usize, 9), bound[2].factor_first);
    try std.testing.expectEqual(@as(usize, 3), bound[2].scratch_first);

    const duplicate_indices = [_]u32{ 2, 0, 2, 1 };
    const duplicate_ingress = .{
        .oods_offset_points = points[0..],
        .oods_fold_counts = folds[0..],
        .oods_output_indices = duplicate_indices[0..],
    };
    try std.testing.expectError(
        error.DuplicateOutputIndex,
        batches.bindCompact(
            duplicate_ingress,
            views,
            device(u32, 0x10000, 32),
            schedule,
            &batch_storage,
        ),
    );
}
