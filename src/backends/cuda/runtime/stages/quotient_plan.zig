//! Ingress-only construction of validated quotient topology capabilities.

const std = @import("std");
const abi = @import("../../abi/stages/quotient.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");

const PreparedTermDescriptors = column.DeviceSlice(abi.PreparedTermDescriptor);
const BatchTermDescriptors = column.DeviceSlice(abi.BatchTermDescriptor);
const CompactSourceDescriptors =
    column.DeviceSlice(abi.CompactSourceDescriptor);
const AddressedSourceDescriptors =
    column.DeviceSlice(abi.AddressedSourceDescriptor);

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

pub const CompactNumeratorTopology = struct {
    offsets: common.Words,
    terms: BatchTermDescriptors,
    sources: CompactSourceDescriptors,
    group_log_sizes: common.Words,
    group_count: u32,
    max_output_size: u32,
    source_count: u32,
    source_word_count: usize,
    line_term_count: u32,
};

pub const AddressedNumeratorTopology = struct {
    offsets: common.Words,
    terms: BatchTermDescriptors,
    sources: AddressedSourceDescriptors,
    resident_sources: []const common.Words,
    group_log_sizes: common.Words,
    output_offsets: column.DeviceSlice(u64),
    group_count: u32,
    max_output_size: u32,
    output_word_count: usize,
    source_count: u32,
    line_term_count: u32,
};

pub const CombineTopology = struct {
    partial_log_sizes: common.Words,
    sample_count: u32,
    domain_log_size: u32,
    partial_stride_words: usize,
};

pub const CompactCombineTopology = struct {
    partial_log_sizes: common.Words,
    partial_offsets: column.DeviceSlice(u64),
    sample_count: u32,
    domain_log_size: u32,
    partial_word_count: usize,
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
    // Equivalent circle points may use different sample indices plus periodic
    // shifts. Ingress authenticates the grouping and this layer validates its
    // exact partition rather than comparing descriptor representations.
    for (0..group_count) |group| {
        const begin = host_offsets[group];
        const end = host_offsets[group + 1];
        if (begin >= end or end > term_count)
            return error.InvalidKernelDescriptor;
        for (host_term_indices[begin..end]) |term| {
            if (term >= term_count or seen[term]) {
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

pub fn prepareCompactNumeratorTopology(
    session: anytype,
    host_offsets: []const u32,
    host_terms: []const abi.BatchTermDescriptor,
    host_sources: []const abi.CompactSourceDescriptor,
    host_group_log_sizes: []const u32,
    device_offsets: common.Words,
    device_terms: BatchTermDescriptors,
    device_sources: CompactSourceDescriptors,
    device_group_log_sizes: common.Words,
    max_output_size: u32,
    source_word_count: usize,
    line_term_count: usize,
) runtime_error.Error!CompactNumeratorTopology {
    try common.requireStage(session, .ingress);
    const group_count = try common.count(host_group_log_sizes.len);
    const term_count = try common.count(host_terms.len);
    const source_count = try common.count(host_sources.len);
    const line_count = try common.count(line_term_count);
    if (group_count == 0 or group_count > 65_535 or term_count == 0 or
        source_count == 0 or source_word_count == 0 or line_count == 0 or
        !std.math.isPowerOfTwo(max_output_size) or
        host_offsets.len != host_group_log_sizes.len + 1 or
        host_offsets[0] != 0 or host_offsets[host_offsets.len - 1] != term_count)
    {
        return error.InvalidKernelDescriptor;
    }

    for (host_sources) |source| {
        if (source.log_size == 0 or source.log_size > 30 or
            source.stride_words == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        const logical_words = @as(usize, 1) << @intCast(source.log_size);
        if (logical_words > source.stride_words)
            return error.InvalidKernelDescriptor;
        const offset = std.math.cast(usize, source.offset_words) orelse
            return error.SizeOverflow;
        const end = std.math.add(
            usize,
            offset,
            source.stride_words,
        ) catch return error.SizeOverflow;
        if (end > source_word_count) return error.InvalidKernelDescriptor;
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
            if (term.source_index >= source_count or
                term.term_index >= line_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const source = host_sources[term.source_index];
            if (term.source_log_size != source.log_size or
                source.log_size > group_log)
            {
                return error.InvalidKernelDescriptor;
            }
        }
    }
    if (largest_size != max_output_size)
        return error.InvalidKernelDescriptor;

    const exact_offsets = try device_offsets.sub(0, host_offsets.len);
    const exact_terms = try device_terms.sub(0, host_terms.len);
    const exact_sources = try device_sources.sub(0, host_sources.len);
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
        abi.CompactSourceDescriptor,
        exact_sources,
        host_sources,
    );
    try session.context.uploadSlice(
        u32,
        exact_logs,
        host_group_log_sizes,
    );
    return .{
        .offsets = exact_offsets,
        .terms = exact_terms,
        .sources = exact_sources,
        .group_log_sizes = exact_logs,
        .group_count = group_count,
        .max_output_size = max_output_size,
        .source_count = source_count,
        .source_word_count = source_word_count,
        .line_term_count = line_count,
    };
}

/// Publishes an exact multi-arena source graph at ingress. The descriptor
/// addresses must match the resident slices retained by the caller for the
/// whole proof epoch; execution never reconstructs or repacks this graph.
pub fn prepareAddressedNumeratorTopology(
    session: anytype,
    host_offsets: []const u32,
    host_terms: []const abi.BatchTermDescriptor,
    host_sources: []const abi.AddressedSourceDescriptor,
    resident_sources: []const common.Words,
    host_group_log_sizes: []const u32,
    host_output_offsets: []const u64,
    device_offsets: common.Words,
    device_terms: BatchTermDescriptors,
    device_sources: AddressedSourceDescriptors,
    device_group_log_sizes: common.Words,
    device_output_offsets: column.DeviceSlice(u64),
    max_output_size: u32,
    line_term_count: usize,
) runtime_error.Error!AddressedNumeratorTopology {
    try common.requireStage(session, .ingress);
    const group_count = try common.count(host_group_log_sizes.len);
    const term_count = try common.count(host_terms.len);
    const source_count = try common.count(host_sources.len);
    const line_count = try common.count(line_term_count);
    if (group_count == 0 or group_count > 65_535 or term_count == 0 or
        source_count == 0 or line_count == 0 or
        resident_sources.len != host_sources.len or
        !std.math.isPowerOfTwo(max_output_size) or
        host_offsets.len != host_group_log_sizes.len + 1 or
        host_output_offsets.len != host_group_log_sizes.len + 1 or
        host_offsets[0] != 0 or
        host_offsets[host_offsets.len - 1] != term_count or
        host_output_offsets[0] != 0)
    {
        return error.InvalidKernelDescriptor;
    }
    for (host_sources, resident_sources) |source, resident| {
        if (source.address == 0 or
            source.address != resident.address or
            source.log_size == 0 or source.log_size > 30 or
            source.stride_words == 0 or
            source.stride_words != resident.len or
            resident.owner == 0 or resident.generation == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        const logical_words = @as(usize, 1) <<
            @intCast(source.log_size);
        if (logical_words > source.stride_words)
            return error.InvalidKernelDescriptor;
    }

    var largest_size: u32 = 0;
    for (host_group_log_sizes, 0..) |group_log, group| {
        if (group_log == 0 or group_log > 30)
            return error.InvalidKernelDescriptor;
        largest_size = @max(
            largest_size,
            @as(u32, 1) << @intCast(group_log),
        );
        const begin = host_offsets[group];
        const end = host_offsets[group + 1];
        if (begin >= end or end > term_count)
            return error.InvalidKernelDescriptor;
        for (host_terms[begin..end]) |term| {
            if (term.source_index >= source_count or
                term.term_index >= line_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const descriptor = host_sources[term.source_index];
            if (term.source_log_size != descriptor.log_size or
                descriptor.log_size > group_log)
            {
                return error.InvalidKernelDescriptor;
            }
        }
        const output_begin = host_output_offsets[group];
        const output_end = host_output_offsets[group + 1];
        const output_words = @as(u64, 1) << @intCast(group_log);
        if (output_end < output_begin or
            output_end - output_begin != output_words)
        {
            return error.InvalidKernelDescriptor;
        }
    }
    if (largest_size != max_output_size)
        return error.InvalidKernelDescriptor;

    const exact_offsets = try device_offsets.sub(0, host_offsets.len);
    const exact_terms = try device_terms.sub(0, host_terms.len);
    const exact_sources = try device_sources.sub(0, host_sources.len);
    const exact_logs = try device_group_log_sizes.sub(
        0,
        host_group_log_sizes.len,
    );
    const exact_output_offsets = try device_output_offsets.sub(
        0,
        host_output_offsets.len,
    );
    try session.context.uploadSlice(u32, exact_offsets, host_offsets);
    try session.context.uploadSlice(
        abi.BatchTermDescriptor,
        exact_terms,
        host_terms,
    );
    try session.context.uploadSlice(
        abi.AddressedSourceDescriptor,
        exact_sources,
        host_sources,
    );
    try session.context.uploadSlice(
        u32,
        exact_logs,
        host_group_log_sizes,
    );
    try session.context.uploadSlice(
        u64,
        exact_output_offsets,
        host_output_offsets,
    );
    const output_word_count = std.math.cast(
        usize,
        host_output_offsets[host_output_offsets.len - 1],
    ) orelse return error.SizeOverflow;
    if (output_word_count == 0)
        return error.InvalidKernelDescriptor;
    return .{
        .offsets = exact_offsets,
        .terms = exact_terms,
        .sources = exact_sources,
        .resident_sources = resident_sources,
        .group_log_sizes = exact_logs,
        .output_offsets = exact_output_offsets,
        .group_count = group_count,
        .max_output_size = max_output_size,
        .output_word_count = output_word_count,
        .source_count = source_count,
        .line_term_count = line_count,
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

pub fn prepareCompactCombineTopology(
    session: anytype,
    host_partial_log_sizes: []const u32,
    host_partial_offsets: []const u64,
    device_partial_log_sizes: common.Words,
    device_partial_offsets: column.DeviceSlice(u64),
    domain_log_size: u32,
    partial_word_count: usize,
) runtime_error.Error!CompactCombineTopology {
    try common.requireStage(session, .ingress);
    const sample_count = try validateCompactCombineGeometry(
        host_partial_log_sizes,
        host_partial_offsets,
        domain_log_size,
        partial_word_count,
    );

    const exact_logs = try device_partial_log_sizes.sub(
        0,
        host_partial_log_sizes.len,
    );
    const exact_offsets = try device_partial_offsets.sub(
        0,
        host_partial_offsets.len,
    );
    try session.context.uploadSlice(
        u32,
        exact_logs,
        host_partial_log_sizes,
    );
    try session.context.uploadSlice(
        u64,
        exact_offsets,
        host_partial_offsets,
    );
    return .{
        .partial_log_sizes = exact_logs,
        .partial_offsets = exact_offsets,
        .sample_count = sample_count,
        .domain_log_size = domain_log_size,
        .partial_word_count = partial_word_count,
    };
}

fn validateCompactCombineGeometry(
    partial_log_sizes: []const u32,
    partial_offsets: []const u64,
    domain_log_size: u32,
    partial_word_count: usize,
) runtime_error.Error!u32 {
    const sample_count = try common.count(partial_log_sizes.len);
    if (sample_count == 0 or domain_log_size == 0 or
        domain_log_size > 30 or partial_word_count == 0 or
        partial_offsets.len != partial_log_sizes.len + 1 or
        partial_offsets[0] != 0)
    {
        return error.InvalidKernelDescriptor;
    }
    var expected_offset: u64 = 0;
    for (partial_log_sizes, partial_offsets[1..]) |partial_log, end| {
        if (partial_log == 0 or partial_log > domain_log_size or
            partial_log > 30)
        {
            return error.InvalidKernelDescriptor;
        }
        expected_offset = std.math.add(
            u64,
            expected_offset,
            @as(u64, 1) << @intCast(partial_log),
        ) catch return error.SizeOverflow;
        if (end != expected_offset)
            return error.InvalidKernelDescriptor;
    }
    if (expected_offset != partial_word_count)
        return error.InvalidKernelDescriptor;
    return sample_count;
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

test "compact mixed-height addressing matches a dense CPU oracle" {
    const prime: u64 = 2_147_483_647;
    const max_rows = 32;
    const group_count = 2;
    const Coordinate = [4]u32;
    const Line = struct {
        subtract: Coordinate,
        scale: Coordinate,
    };
    const Oracle = struct {
        fn addTerm(
            accumulator: *Coordinate,
            line: Line,
            scalar: u32,
        ) void {
            for (accumulator, line.subtract, line.scale) |*result, sub, mul| {
                const product = (@as(u64, mul) * scalar) % prime;
                const difference = if (product >= sub)
                    product - sub
                else
                    product + prime - sub;
                const sum = @as(u64, result.*) + difference;
                result.* = @intCast(if (sum >= prime) sum - prime else sum);
            }
        }

        fn sourceRow(row: usize, group_log: u32, source_log: u32) usize {
            const ratio = group_log - source_log;
            return (row >> @intCast(ratio + 1) << 1) + (row & 1);
        }
    };

    const sources = [_]abi.CompactSourceDescriptor{
        .{ .offset_words = 3, .stride_words = 11, .log_size = 3 },
        .{ .offset_words = 17, .stride_words = 19, .log_size = 4 },
        .{ .offset_words = 41, .stride_words = 37, .log_size = 5 },
    };
    var compact = [_]u32{2_000_000_000} ** 78;
    var dense = [_][max_rows]u32{
        [_]u32{0} ** max_rows,
        [_]u32{0} ** max_rows,
        [_]u32{0} ** max_rows,
    };
    for (sources, 0..) |source, source_index| {
        const rows = @as(usize, 1) << @intCast(source.log_size);
        const base: usize = @intCast(source.offset_words);
        for (0..rows) |row| {
            const value: u32 = @intCast(
                101 + source_index * 97 + row * 13,
            );
            compact[base + row] = value;
            dense[source_index][row] = value;
        }
    }

    const terms = [_]abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 3 },
        .{ .source_index = 2, .term_index = 1, .source_log_size = 5 },
        .{ .source_index = 1, .term_index = 2, .source_log_size = 4 },
        .{ .source_index = 0, .term_index = 3, .source_log_size = 3 },
    };
    const offsets = [_]u32{ 0, 2, 4 };
    const group_logs = [_]u32{ 5, 4 };
    const lines = [_]Line{
        .{ .subtract = .{ 1, 2, 3, 4 }, .scale = .{ 5, 7, 11, 13 } },
        .{ .subtract = .{ 17, 19, 23, 29 }, .scale = .{ 31, 37, 41, 43 } },
        .{ .subtract = .{ 47, 53, 59, 61 }, .scale = .{ 67, 71, 73, 79 } },
        .{ .subtract = .{ 83, 89, 97, 101 }, .scale = .{ 103, 107, 109, 113 } },
    };
    var compact_result =
        [_][max_rows]Coordinate{[_]Coordinate{.{ 0, 0, 0, 0 }} ** max_rows} **
        group_count;
    var dense_result = compact_result;

    for (0..group_count) |group| {
        const rows = @as(usize, 1) << @intCast(group_logs[group]);
        for (0..rows) |row| {
            for (offsets[group]..offsets[group + 1]) |term_index| {
                const term = terms[term_index];
                const source = sources[term.source_index];
                const source_row = Oracle.sourceRow(
                    row,
                    group_logs[group],
                    source.log_size,
                );
                const base: usize = @intCast(source.offset_words);
                Oracle.addTerm(
                    &compact_result[group][row],
                    lines[term.term_index],
                    compact[base + source_row],
                );
                Oracle.addTerm(
                    &dense_result[group][row],
                    lines[term.term_index],
                    dense[term.source_index][source_row],
                );
            }
        }
    }
    try std.testing.expectEqualDeep(dense_result, compact_result);
}

test "compact quotient combine admits exact mixed-height offsets" {
    const logs = [_]u32{ 4, 7, 9 };
    const offsets = [_]u64{ 0, 16, 144, 656 };
    try std.testing.expectEqual(
        @as(u32, 3),
        try validateCompactCombineGeometry(
            &logs,
            &offsets,
            10,
            656,
        ),
    );
    var mutated = offsets;
    mutated[2] += 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        validateCompactCombineGeometry(&logs, &mutated, 10, 657),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        validateCompactCombineGeometry(&logs, &offsets, 8, 656),
    );
}
