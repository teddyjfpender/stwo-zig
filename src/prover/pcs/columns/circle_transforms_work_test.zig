//! Focused work-receipt tests for batched circle transforms.

const std = @import("std");
const canonic = @import("stwo_core").poly.circle.canonic;
const M31 = @import("stwo_core").fields.m31.M31;
const work_profile = @import("stwo_prover_api").work_profile;
const owner = @import("circle_transforms.zig");

const WorkRecorder = work_profile.Recorder(true);
const IfftWorkItem = owner.testing.IfftWorkItem;
const FftEvalWorkItem = owner.testing.FftEvalWorkItem;
const preferredCpuFftBatchLenForWorkers = owner.testing.preferredCpuFftBatchLenForWorkers;
const recordInterpolationCompletion = owner.testing.recordInterpolationCompletion;
const recordForwardCompletion = owner.testing.recordForwardCompletion;
const materializeBackendExtensionZeros = owner.testing.materializeBackendExtensionZeros;

test "circle transforms: CPU FFT batch exposes one task per worker" {
    try std.testing.expectEqual(
        @as(usize, 8),
        preferredCpuFftBatchLenForWorkers(16, 32, 4),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        preferredCpuFftBatchLenForWorkers(16, 4, 12),
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        preferredCpuFftBatchLenForWorkers(16, 64, 2),
    );
}

test "circle transforms: interpolation completion preserves actual batches" {
    var first_storage: [3][1]M31 = undefined;
    var first_slices = [_][]M31{
        first_storage[0][0..],
        first_storage[1][0..],
        first_storage[2][0..],
    };
    var second_storage: [2][1]M31 = undefined;
    var second_slices = [_][]M31{
        second_storage[0][0..],
        second_storage[1][0..],
    };
    const items = [_]IfftWorkItem{
        .{
            .values = first_slices[0..],
            .domain = canonic.CanonicCoset.new(1).circleDomain(),
            .twiddle_tree = undefined,
        },
        .{
            .values = second_slices[0..],
            .domain = canonic.CanonicCoset.new(3).circleDomain(),
            .twiddle_tree = undefined,
        },
    };
    var recorder = WorkRecorder{};
    try recorder.expectProducer(.column_interpolate_only_fft);
    try recordInterpolationCompletion(
        &recorder,
        .column_interpolate_only_fft,
        items[0..],
        true,
    );

    try std.testing.expectEqual(@as(u64, 54), recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 52), recorder.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 2), recorder.counters.field_inversions);
    try std.testing.expectEqual(@as(u64, 27), recorder.counters.fft_butterflies);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.column_interpolate_only_fft)],
    );
}

test "circle transforms: backend interpolation receipt owns normalization batches" {
    var storage: [4][8]M31 = undefined;
    var slices = [_][]M31{
        storage[0][0..],
        storage[1][0..],
        storage[2][0..],
        storage[3][0..],
    };
    const domain = canonic.CanonicCoset.new(3).circleDomain();
    const item = IfftWorkItem{
        .values = slices[0..],
        .domain = domain,
        .twiddle_tree = undefined,
        .backend_execution = .{
            .log_size = 3,
            .column_count = 4,
            .batch_count = 1,
        },
    };
    var recorder = WorkRecorder{};
    try recorder.expectProducer(.column_interpolate_for_extension_fft);
    try recordInterpolationCompletion(
        &recorder,
        .column_interpolate_for_extension_fft,
        &.{item},
        false,
    );
    try std.testing.expectEqual(@as(u64, 96), recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 80), recorder.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 1), recorder.counters.field_inversions);
    try std.testing.expectEqual(@as(u64, 48), recorder.counters.fft_butterflies);

    var malformed = item;
    malformed.backend_execution.?.column_count = 3;
    var malformed_recorder = WorkRecorder{};
    try std.testing.expectError(
        error.InvalidCounterGroup,
        recordInterpolationCompletion(
            &malformed_recorder,
            .column_interpolate_for_extension_fft,
            &.{malformed},
            false,
        ),
    );
}

test "circle transforms: backend forward receipt owns executed layers" {
    var storage: [2][16]M31 = undefined;
    var slices = [_][]M31{ storage[0][0..], storage[1][0..] };
    const domain = canonic.CanonicCoset.new(4).circleDomain();
    const backend_item = FftEvalWorkItem{
        .values = slices[0..],
        .domain = domain,
        .twiddle_tree = undefined,
        .extension = true,
        .backend_execution = .{
            .log_size = 4,
            .column_count = 2,
            .skipped_layers = 0,
        },
    };
    var backend_recorder = WorkRecorder{};
    try backend_recorder.expectProducer(.column_extension_fft);
    try recordForwardCompletion(
        &backend_recorder,
        .column_extension_fft,
        &.{backend_item},
        true,
    );
    try std.testing.expectEqual(@as(u64, 128), backend_recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 64), backend_recorder.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 64), backend_recorder.counters.fft_butterflies);

    var generic_recorder = WorkRecorder{};
    try generic_recorder.expectProducer(.column_extension_fft);
    try recordForwardCompletion(
        &generic_recorder,
        .column_extension_fft,
        &.{FftEvalWorkItem{
            .values = slices[0..],
            .domain = domain,
            .twiddle_tree = undefined,
            .extension = true,
        }},
        false,
    );
    try std.testing.expectEqual(@as(u64, 48), generic_recorder.counters.fft_butterflies);

    var malformed = backend_item;
    malformed.backend_execution.?.log_size = 3;
    var malformed_recorder = WorkRecorder{};
    try std.testing.expectError(
        error.InvalidCounterGroup,
        recordForwardCompletion(
            &malformed_recorder,
            .column_extension_fft,
            &.{malformed},
            true,
        ),
    );
}

test "circle transforms: backend extension buffers materialize implicit zeros" {
    const allocator = std.testing.allocator;
    const values = try allocator.alloc(M31, 16);
    defer allocator.free(values);
    @memset(values, M31.fromCanonical(0x5a5a));

    var slices = [_][]M31{values};
    const items = [_]FftEvalWorkItem{.{
        .values = slices[0..],
        .domain = canonic.CanonicCoset.new(4).circleDomain(),
        .twiddle_tree = undefined,
        .extension = true,
    }};
    materializeBackendExtensionZeros(items[0..]);

    for (values[0..8]) |value| try std.testing.expectEqual(M31.fromCanonical(0x5a5a), value);
    for (values[8..]) |value| try std.testing.expectEqual(M31.zero(), value);
}
