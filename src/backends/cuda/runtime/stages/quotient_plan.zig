//! Ingress-only construction of validated quotient topology capabilities.

const std = @import("std");
const abi = @import("../../abi/stages/quotient.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");

const PreparedTermDescriptors = column.DeviceSlice(abi.PreparedTermDescriptor);
const BatchTermDescriptors = column.DeviceSlice(abi.BatchTermDescriptor);

pub const PreparedGroups = struct {
    descriptors: PreparedTermDescriptors,
    sample_count: u32,
    offsets: common.Words,
    term_indices: common.Words,
    group_count: u32,
};

pub const NumeratorTopology = struct {
    offsets: common.Words,
    terms: BatchTermDescriptors,
    group_log_sizes: common.Words,
    group_count: u32,
    max_output_size: u32,
    source_count: u32,
    source_stride_words: usize,
    line_term_count: u32,
};

pub const CombineTopology = struct {
    partial_log_sizes: common.Words,
    sample_count: u32,
    domain_log_size: u32,
    partial_stride_words: usize,
};

pub fn prepareGroups(
    allocator: std.mem.Allocator,
    session: anytype,
    host_terms: []const abi.PreparedTermDescriptor,
    host_offsets: []const u32,
    host_term_indices: []const u32,
    device_terms: PreparedTermDescriptors,
    device_offsets: common.Words,
    device_term_indices: common.Words,
    sample_count: usize,
) (runtime_error.Error || std.mem.Allocator.Error)!PreparedGroups {
    try common.requireStage(session, .ingress);
    const term_count = try common.count(host_terms.len);
    const sample_count_u32 = try common.count(sample_count);
    if (term_count == 0 or sample_count_u32 == 0 or host_offsets.len < 2 or
        host_term_indices.len != term_count or
        host_offsets[0] != 0 or
        host_offsets[host_offsets.len - 1] != term_count)
    {
        return error.InvalidKernelDescriptor;
    }
    for (host_terms, 0..) |descriptor, index| {
        const exponent = std.math.cast(u32, index) orelse
            return error.SizeOverflow;
        if (descriptor.sample_index >= sample_count_u32 or
            descriptor.exponent != exponent or descriptor.periodic > 1)
        {
            return error.InvalidKernelDescriptor;
        }
        if (descriptor.periodic == 0) {
            if (descriptor.period_x != 0 or descriptor.period_y != 0)
                return error.InvalidKernelDescriptor;
        } else if (!validCirclePoint(
            descriptor.period_x,
            descriptor.period_y,
        )) {
            return error.InvalidKernelDescriptor;
        }
    }
    const group_count = try common.count(host_offsets.len - 1);
    if (group_count > 65_535) return error.InvalidKernelDescriptor;
    var seen = try allocator.alloc(bool, term_count);
    defer allocator.free(seen);
    @memset(seen, false);
    for (0..group_count) |group| {
        const begin = host_offsets[group];
        const end = host_offsets[group + 1];
        if (begin >= end or end > term_count)
            return error.InvalidKernelDescriptor;
        const representative = host_term_indices[begin];
        if (representative >= term_count)
            return error.InvalidKernelDescriptor;
        const shape = structuralPoint(host_terms[representative]);
        for (host_term_indices[begin..end]) |term| {
            if (term >= term_count or seen[term] or
                !sameStructuralPoint(shape, structuralPoint(host_terms[term])))
            {
                return error.InvalidKernelDescriptor;
            }
            seen[term] = true;
        }
    }
    const exact_terms = try device_terms.sub(0, host_terms.len);
    const exact_offsets = try device_offsets.sub(0, host_offsets.len);
    const exact_indices = try device_term_indices.sub(
        0,
        host_term_indices.len,
    );
    try session.context.uploadSlice(
        abi.PreparedTermDescriptor,
        exact_terms,
        host_terms,
    );
    try session.context.uploadSlice(u32, exact_offsets, host_offsets);
    try session.context.uploadSlice(u32, exact_indices, host_term_indices);
    return .{
        .descriptors = exact_terms,
        .sample_count = sample_count_u32,
        .offsets = exact_offsets,
        .term_indices = exact_indices,
        .group_count = group_count,
    };
}

pub fn prepareNumeratorTopology(
    session: anytype,
    host_offsets: []const u32,
    host_terms: []const abi.BatchTermDescriptor,
    host_group_log_sizes: []const u32,
    device_offsets: common.Words,
    device_terms: BatchTermDescriptors,
    device_group_log_sizes: common.Words,
    max_output_size: u32,
    source_count: usize,
    source_stride_words: usize,
    line_term_count: usize,
) runtime_error.Error!NumeratorTopology {
    try common.requireStage(session, .ingress);
    const group_count = try common.count(host_group_log_sizes.len);
    const term_count = try common.count(host_terms.len);
    const source_count_u32 = try common.count(source_count);
    const line_term_count_u32 = try common.count(line_term_count);
    if (group_count == 0 or group_count > 65_535 or term_count == 0 or
        source_count_u32 == 0 or source_stride_words == 0 or
        line_term_count_u32 == 0 or
        !std.math.isPowerOfTwo(max_output_size) or
        host_offsets.len != host_group_log_sizes.len + 1 or
        host_offsets[0] != 0 or host_offsets[host_offsets.len - 1] != term_count)
    {
        return error.InvalidKernelDescriptor;
    }
    var largest_size: u32 = 0;
    for (host_group_log_sizes, 0..) |group_log, group| {
        if (group_log == 0 or group_log > 30)
            return error.InvalidKernelDescriptor;
        const group_size = @as(u32, 1) << @intCast(group_log);
        largest_size = @max(largest_size, group_size);
        const begin = host_offsets[group];
        const end = host_offsets[group + 1];
        if (begin >= end or end > term_count)
            return error.InvalidKernelDescriptor;
        for (host_terms[begin..end]) |term| {
            if (term.source_index >= source_count_u32 or
                term.term_index >= line_term_count_u32 or
                term.source_log_size == 0 or
                term.source_log_size > group_log or
                term.source_log_size > 30 or
                (@as(usize, 1) << @intCast(term.source_log_size)) >
                    source_stride_words)
            {
                return error.InvalidKernelDescriptor;
            }
        }
    }
    if (largest_size != max_output_size)
        return error.InvalidKernelDescriptor;

    const exact_offsets = try device_offsets.sub(0, host_offsets.len);
    const exact_terms = try device_terms.sub(0, host_terms.len);
    const exact_logs = try device_group_log_sizes.sub(
        0,
        host_group_log_sizes.len,
    );
    try session.context.uploadSlice(u32, exact_offsets, host_offsets);
    try session.context.uploadSlice(
        abi.BatchTermDescriptor,
        exact_terms,
        host_terms,
    );
    try session.context.uploadSlice(
        u32,
        exact_logs,
        host_group_log_sizes,
    );
    return .{
        .offsets = exact_offsets,
        .terms = exact_terms,
        .group_log_sizes = exact_logs,
        .group_count = group_count,
        .max_output_size = max_output_size,
        .source_count = source_count_u32,
        .source_stride_words = source_stride_words,
        .line_term_count = line_term_count_u32,
    };
}

pub fn prepareCombineTopology(
    session: anytype,
    host_partial_log_sizes: []const u32,
    device_partial_log_sizes: common.Words,
    domain_log_size: u32,
    partial_stride_words: usize,
) runtime_error.Error!CombineTopology {
    try common.requireStage(session, .ingress);
    const sample_count = try common.count(host_partial_log_sizes.len);
    if (sample_count == 0 or domain_log_size == 0 or domain_log_size > 30 or
        partial_stride_words == 0)
    {
        return error.InvalidKernelDescriptor;
    }
    for (host_partial_log_sizes) |partial_log| {
        if (partial_log == 0 or partial_log > domain_log_size or
            partial_log > 30 or
            (@as(usize, 1) << @intCast(partial_log)) > partial_stride_words)
        {
            return error.InvalidKernelDescriptor;
        }
    }
    const exact = try device_partial_log_sizes.sub(
        0,
        host_partial_log_sizes.len,
    );
    try session.context.uploadSlice(u32, exact, host_partial_log_sizes);
    return .{
        .partial_log_sizes = exact,
        .sample_count = sample_count,
        .domain_log_size = domain_log_size,
        .partial_stride_words = partial_stride_words,
    };
}

const StructuralPoint = struct {
    sample_index: u32,
    periodic: u32,
    period_x: u32,
    period_y: u32,
};

fn structuralPoint(descriptor: abi.PreparedTermDescriptor) StructuralPoint {
    return .{
        .sample_index = descriptor.sample_index,
        .periodic = descriptor.periodic,
        .period_x = descriptor.period_x,
        .period_y = descriptor.period_y,
    };
}

fn sameStructuralPoint(left: StructuralPoint, right: StructuralPoint) bool {
    return std.meta.eql(left, right);
}

fn validCirclePoint(x: u32, y: u32) bool {
    const prime: u32 = 2_147_483_647;
    if (x >= prime or y >= prime) return false;
    return addM31(mulM31(x, x), mulM31(y, y)) == 1;
}

fn mulM31(left: u32, right: u32) u32 {
    const product = @as(u64, left) * right;
    const first = product + (product >> 31);
    return @intCast((product + (first >> 31)) & 2_147_483_647);
}

fn addM31(left: u32, right: u32) u32 {
    const sum = @as(u64, left) + right;
    return @intCast(if (sum < 2_147_483_647) sum else sum - 2_147_483_647);
}

test "term validation rejects non-canonical exponents and periods" {
    const valid = abi.PreparedTermDescriptor{
        .sample_index = 0,
        .exponent = 0,
        .periodic = 1,
        .period_x = 1,
        .period_y = 0,
    };
    try std.testing.expect(validCirclePoint(valid.period_x, valid.period_y));
    try std.testing.expect(!validCirclePoint(2_147_483_647, 0));
}
