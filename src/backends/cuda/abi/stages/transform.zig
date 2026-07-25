//! Allocation-free circle transform entry points on an explicit proof stream.

/// One compact coefficient source and its exact destination in a shared
/// proof-owned arena. Offsets are words from the arena base, never host or
/// device pointers.
pub const AddressedLdeDescriptor = extern struct {
    coefficient_offset_words: u64,
    evaluation_offset_words: u64,
    coefficient_log_size: u32,
    reserved: u32 = 0,

    pub fn init(
        coefficient_offset_words: u64,
        evaluation_offset_words: u64,
        coefficient_log_size: u32,
    ) AddressedLdeDescriptor {
        return .{
            .coefficient_offset_words = coefficient_offset_words,
            .evaluation_offset_words = evaluation_offset_words,
            .coefficient_log_size = coefficient_log_size,
        };
    }

    pub fn validate(
        self: AddressedLdeDescriptor,
        arena_words: u64,
        expected_evaluation_offset_words: u64,
        evaluation_log_size: u32,
    ) error{InvalidKernelDescriptor}!void {
        if (self.reserved != 0 or
            evaluation_log_size < 3 or
            evaluation_log_size > 30 or
            self.coefficient_log_size >= evaluation_log_size)
        {
            return error.InvalidKernelDescriptor;
        }
        const coefficient_words =
            @as(u64, 1) << @intCast(self.coefficient_log_size);
        const evaluation_words =
            @as(u64, 1) << @intCast(evaluation_log_size);
        const coefficient_end = std.math.add(
            u64,
            self.coefficient_offset_words,
            coefficient_words,
        ) catch return error.InvalidKernelDescriptor;
        const evaluation_end = std.math.add(
            u64,
            self.evaluation_offset_words,
            evaluation_words,
        ) catch return error.InvalidKernelDescriptor;
        if (coefficient_end > arena_words or
            evaluation_end > arena_words or
            self.evaluation_offset_words != expected_evaluation_offset_words or
            rangesOverlap(
                self.coefficient_offset_words,
                coefficient_end,
                self.evaluation_offset_words,
                evaluation_end,
            ))
        {
            return error.InvalidKernelDescriptor;
        }
    }
};

/// Stages independently packed compact coefficient columns into one
/// contiguous reusable LDE tile, then performs N2B in place. Descriptor and
/// twiddle storage are resident in `arena`; the call performs no allocation,
/// transfer, synchronization, or pointer-table construction.
pub extern "c" fn stwo_lde_n2b_addressed_on(
    arena: [*]u32,
    arena_words: usize,
    descriptors: [*]const AddressedLdeDescriptor,
    descriptor_count: u32,
    evaluation_tile_offset_words: usize,
    log_n: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
    include_circle: u32,
    launches_out: *u32,
) c_int;

/// Normalized B2N transform with one N-word coefficient image per column.
/// Inputs and outputs may be disjoint or exactly alias with equal strides.
pub extern "c" fn stwo_ntt_b2n_columns_compact_on(
    inputs: [*]const u32,
    input_column_stride_words: usize,
    outputs: [*]u32,
    output_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
    launches_out: *u32,
) c_int;

const std = @import("std");

fn rangesOverlap(
    left_start: u64,
    left_end: u64,
    right_start: u64,
    right_end: u64,
) bool {
    return left_start < right_end and right_start < left_end;
}

test "addressed LDE descriptor is a stable offset-only ABI" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(AddressedLdeDescriptor));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(AddressedLdeDescriptor));
    try std.testing.expectEqual(
        @as(usize, 0),
        @offsetOf(AddressedLdeDescriptor, "coefficient_offset_words"),
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        @offsetOf(AddressedLdeDescriptor, "evaluation_offset_words"),
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        @offsetOf(AddressedLdeDescriptor, "coefficient_log_size"),
    );
}

test "addressed LDE descriptor rejects aliases and malformed geometry" {
    try AddressedLdeDescriptor.init(64, 512, 6).validate(1024, 512, 8);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        AddressedLdeDescriptor.init(500, 512, 6).validate(1024, 512, 8),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        AddressedLdeDescriptor.init(64, 513, 6).validate(1024, 512, 8),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        AddressedLdeDescriptor.init(520, 512, 6).validate(1024, 512, 8),
    );
    var reserved = AddressedLdeDescriptor.init(64, 512, 6);
    reserved.reserved = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        reserved.validate(1024, 512, 8),
    );
}

/// Compatibility transform whose normalized N-word image is duplicated into
/// both halves of each 2N-word retained output column.
pub extern "c" fn stwo_ntt_b2n_columns_to_retained_on(
    inputs: [*]const u32,
    input_column_stride_words: usize,
    retained_outputs: [*]u32,
    output_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
    launches_out: *u32,
) c_int;

pub extern "c" fn stwo_ntt_n2b_columns_on(
    device_values: [*]u32,
    column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
    launches_out: *u32,
) c_int;

pub extern "c" fn stwo_lde_n2b_columns_on(
    coefficient_values: [*]const u32,
    coefficient_column_stride_words: usize,
    coefficient_log_sizes: [*]const u32,
    device_values: [*]u32,
    evaluation_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
    launches_out: *u32,
) c_int;

pub extern "c" fn stwo_lde_n2b_columns_before_circle_on(
    coefficient_values: [*]const u32,
    coefficient_column_stride_words: usize,
    coefficient_log_sizes: [*]const u32,
    device_values: [*]u32,
    evaluation_column_stride_words: usize,
    log_n: u32,
    num_poly: u32,
    twiddles: [*]const u32,
    twiddle_words: u32,
    evaluation_domain_size: u32,
    stream: *anyopaque,
    launches_out: *u32,
) c_int;
