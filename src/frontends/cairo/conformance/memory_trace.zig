//! Rust-oracle comparison for Cairo memory base-trace components.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const memory = @import("../common/memory.zig");
const cpu_multiplicity = @import("../witness/cpu_memory_multiplicity.zig");
const feed_bundle = @import("../witness/feed_bundle.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const memory_tables = @import("../witness/memory_tables.zig");
const witness_bundle = @import("../witness/bundle.zig");
const checkpoint = @import("checkpoint.zig");
const recorded_trace = @import("recorded_trace.zig");

const target_labels = [_][]const u8{
    "memory_address_to_id",
    "memory_id_to_big[0]",
    "memory_id_to_small",
};

pub const Match = struct {
    ordinal: u32,
    label: []const u8,
    row_count: u64,
    column_count: u32,
};

pub const MismatchKind = enum {
    column_digest,
    accumulator,
};

pub const Mismatch = struct {
    kind: MismatchKind,
    component_ordinal: u32,
    component_label: []const u8,
    column_ordinal: ?u32 = null,
    expected_digest: checkpoint.Digest,
    actual_digest: checkpoint.Digest,
};

pub const Report = struct {
    matches: [target_labels.len]Match = undefined,
    match_count: usize = 0,
    mismatch: ?Mismatch = null,
};

pub const Error = error{
    InvalidReceiptGeometry,
    MissingReceiptComponent,
    NonCanonicalComponentOrder,
};

/// Generates the three logical memory tables from source inputs, hashes their
/// raw columns, and stops at the first Rust receipt mismatch.
pub fn compare(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness: *const witness_bundle.Bundle,
    feeds: *const feed_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Report {
    var counts = try cpu_multiplicity.collect(
        allocator,
        input,
        witness,
        feeds,
        expected_components,
    );
    defer counts.deinit();
    return compareCounts(allocator, input, &counts, expected_components);
}

pub fn compareTopology(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    topology: feed_topology.Loaded,
    producers: []const recorded_trace.ProducerOutput,
    expected_components: []const checkpoint.Component,
) !Report {
    var counts = try cpu_multiplicity.collectTopology(
        allocator,
        input,
        topology,
        producers,
    );
    defer counts.deinit();
    return compareCounts(allocator, input, &counts, expected_components);
}

fn compareCounts(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_multiplicity.Counts,
    expected_components: []const checkpoint.Component,
) !Report {
    var report = Report{};
    var accumulator: ?checkpoint.Digest = null;
    for (target_labels, 0..) |label, target_index| {
        const expected = try expectedComponent(expected_components, label);
        if (target_index == 0) {
            if (expected.ordinal == 0 or expected.ordinal > expected_components.len)
                return Error.NonCanonicalComponentOrder;
            accumulator = expected_components[expected.ordinal - 1].accumulator;
        } else if (expected.ordinal != report.matches[target_index - 1].ordinal + 1) {
            return Error.NonCanonicalComponentOrder;
        }
        if (try compareComponent(allocator, input, counts, expected, accumulator.?)) |mismatch| {
            report.mismatch = mismatch;
            return report;
        }
        accumulator = expected.accumulator;
        report.matches[target_index] = .{
            .ordinal = expected.ordinal,
            .label = expected.label,
            .row_count = expected.columns[0].row_count,
            .column_count = @intCast(expected.columns.len),
        };
        report.match_count += 1;
    }
    return report;
}

fn compareComponent(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_multiplicity.Counts,
    expected: checkpoint.Component,
    previous_accumulator: checkpoint.Digest,
) !?Mismatch {
    const geometry = try validateGeometry(input, expected);
    const actual_columns = try allocator.alloc(checkpoint.Column, expected.columns.len);
    defer allocator.free(actual_columns);
    const values = try allocator.alloc(u32, geometry.row_count);
    defer allocator.free(values);

    for (expected.columns, actual_columns, 0..) |expected_column, *actual_column, column_index| {
        try writeColumn(input, counts, geometry.kind, column_index, values);
        const actual_digest = try checkpoint.digestColumn(
            expected.ordinal,
            expected.label,
            @intCast(column_index),
            values,
        );
        if (!std.mem.eql(u8, &expected_column.sha256, &actual_digest)) return .{
            .kind = .column_digest,
            .component_ordinal = expected.ordinal,
            .component_label = expected.label,
            .column_ordinal = @intCast(column_index),
            .expected_digest = expected_column.sha256,
            .actual_digest = actual_digest,
        };
        actual_column.* = .{
            .ordinal = @intCast(column_index),
            .row_count = @intCast(geometry.row_count),
            .sha256 = actual_digest,
        };
    }
    const actual_accumulator = try checkpoint.extendAccumulator(
        previous_accumulator,
        expected.ordinal,
        expected.label,
        actual_columns,
    );
    if (!std.mem.eql(u8, &expected.accumulator, &actual_accumulator)) return .{
        .kind = .accumulator,
        .component_ordinal = expected.ordinal,
        .component_label = expected.label,
        .expected_digest = expected.accumulator,
        .actual_digest = actual_accumulator,
    };
    return null;
}

const Kind = enum { address, big, small };
const Geometry = struct { kind: Kind, row_count: usize };

fn validateGeometry(input: *const adapter.ProverInput, expected: checkpoint.Component) !Geometry {
    const geometry: Geometry = if (std.mem.eql(u8, expected.label, target_labels[0]))
        .{ .kind = .address, .row_count = try memory_tables.addressRowCount(input) }
    else if (std.mem.eql(u8, expected.label, target_labels[1]))
        .{ .kind = .big, .row_count = try memory_tables.bigRowCount(input, 0) }
    else if (std.mem.eql(u8, expected.label, target_labels[2]))
        .{ .kind = .small, .row_count = try memory_tables.smallRowCount(input) }
    else
        return Error.MissingReceiptComponent;
    const expected_columns: usize = switch (geometry.kind) {
        .address => memory_tables.address_column_count,
        .big => memory_tables.big_column_count,
        .small => memory_tables.small_column_count,
    };
    if (expected.columns.len != expected_columns) return Error.InvalidReceiptGeometry;
    for (expected.columns, 0..) |column, column_index| {
        if (column.ordinal != column_index or column.row_count != geometry.row_count)
            return Error.InvalidReceiptGeometry;
    }
    return geometry;
}

fn writeColumn(
    input: *const adapter.ProverInput,
    counts: *const cpu_multiplicity.Counts,
    kind: Kind,
    column: usize,
    destination: []u32,
) !void {
    switch (kind) {
        .address => {
            const is_multiplicity = column % 2 == 1;
            const chunk = column / 2;
            for (destination, 0..) |*value, row| {
                const flat = chunk * destination.len + row;
                if (is_multiplicity) {
                    value.* = if (flat < counts.address.len) counts.address[flat] else 0;
                } else {
                    value.* = if (flat < input.memory.address_to_id.len -| 1)
                        input.memory.address_to_id[flat + 1].raw
                    else
                        0;
                }
            }
        },
        .big => if (column == 0) {
            for (destination, 0..) |*value, row|
                value.* = if (row < counts.big.len) counts.big[row] else 0;
        } else {
            try memory_tables.writeBigValueColumn(input, 0, column - 1, destination);
        },
        .small => if (column == 0) {
            for (destination, 0..) |*value, row|
                value.* = if (row < counts.small.len) counts.small[row] else 0;
        } else {
            try memory_tables.writeSmallValueColumn(input, column - 1, destination);
        },
    }
}

fn expectedComponent(components: []const checkpoint.Component, label: []const u8) Error!checkpoint.Component {
    for (components) |component| if (std.mem.eql(u8, component.label, label)) return component;
    return Error.MissingReceiptComponent;
}

test "Cairo memory trace: address split and value-table padding are exact" {
    var grouped = @import("../adapter/opcodes.zig").CasmStatesByOpcode.init(std.testing.allocator);
    defer grouped.deinit(std.testing.allocator);
    var addresses = [_]memory.EncodedMemoryValueId{
        memory.EncodedMemoryValueId.EMPTY,
        memory.EncodedMemoryValueId.small(0),
        memory.EncodedMemoryValueId.f252(0),
    };
    var big_values = [_]memory.F252{.{ 0x3fe00, 0, 0, 0, 0, 0, 0, 0 }};
    var small_values = [_]u128{0x3fe00};
    var input = adapter.ProverInput{
        .state_transitions = .{ .initial_state = undefined, .final_state = undefined, .casm_states_by_opcode = grouped },
        .memory = .{ .config = .{}, .address_to_id = &addresses, .f252_values = &big_values, .small_values = &small_values },
        .pc_count = 0,
        .public_memory_addresses = &.{},
        .builtin_segments = .{},
        .public_segment_context = [_]bool{false} ** adapter.N_PUBLIC_SEGMENTS,
    };
    var address_counts = [_]u32{ 7, 11 } ++ [_]u32{0} ** 14;
    var big_counts = [_]u32{13} ++ [_]u32{0} ** 15;
    var small_counts = [_]u32{17} ++ [_]u32{0} ** 15;
    const counts = cpu_multiplicity.Counts{
        .allocator = undefined,
        .address = &address_counts,
        .big = &big_counts,
        .small = &small_counts,
    };
    var column: [memory_tables.lane_count]u32 = undefined;
    try writeColumn(&input, &counts, .address, 0, &column);
    try std.testing.expectEqualSlices(u32, &.{ 0, memory.LARGE_MEMORY_VALUE_ID_BASE }, column[0..2]);
    try writeColumn(&input, &counts, .address, 1, &column);
    try std.testing.expectEqualSlices(u32, &.{ 7, 11 }, column[0..2]);
    try writeColumn(&input, &counts, .big, 2, &column);
    try std.testing.expectEqual(@as(u32, 511), column[0]);
    try writeColumn(&input, &counts, .big, 0, &column);
    try std.testing.expectEqual(@as(u32, 13), column[0]);
    try writeColumn(&input, &counts, .small, 0, &column);
    try std.testing.expectEqual(@as(u32, 17), column[0]);
}
