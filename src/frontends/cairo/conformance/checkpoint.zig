//! Canonical per-component Cairo base-trace checkpoints.
//!
//! Rust is the final correctness oracle. Backends compute these receipts from
//! their raw base-trace columns before interpolation; comparison stops at the
//! first component or column whose geometry or values differ.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31;

pub const Digest = [32]u8;
pub const initial_accumulator = [_]u8{0} ** 32;

pub const column_domain = "STWO_CAIRO_BASE_COLUMN_V1\x00";
pub const accumulator_domain = "STWO_CAIRO_BASE_ACCUMULATOR_V1\x00";

/// A column and accumulator domain pair (`Domains` of
/// `tools/stwo-trace-digest`); every lane's receipts share the record
/// layout and differ only here.
pub const Domains = struct {
    column: []const u8,
    accumulator: []const u8,
};

pub const cairo_base_domains = Domains{ .column = column_domain, .accumulator = accumulator_domain };

pub const Column = struct {
    ordinal: u32,
    row_count: u64,
    sha256: Digest,
};

pub const Component = struct {
    ordinal: u32,
    label: []const u8,
    columns: []const Column,
    accumulator: Digest,
};

pub const MismatchKind = enum {
    component_ordinal,
    component_label,
    column_count,
    column_ordinal,
    row_count,
    column_digest,
    accumulator,
};

pub const Mismatch = struct {
    kind: MismatchKind,
    component_ordinal: u32,
    column_ordinal: ?u32 = null,
};

pub const Error = error{
    EmptyLabel,
    LabelTooLong,
    EmptyComponent,
    NonCanonicalM31,
    RowCountOverflow,
};

/// Hashes one raw base column in logical row order. The component identity and
/// geometry are included so a correct value vector cannot be moved elsewhere.
pub fn digestColumn(
    component_ordinal: u32,
    label: []const u8,
    column_ordinal: u32,
    values: []const u32,
) Error!Digest {
    return digestColumnIn(cairo_base_domains, component_ordinal, label, column_ordinal, values);
}

/// `digestColumn` under `domains`.
pub fn digestColumnIn(
    domains: Domains,
    component_ordinal: u32,
    label: []const u8,
    column_ordinal: u32,
    values: []const u32,
) Error!Digest {
    try validateLabel(label);
    const row_count = std.math.cast(u64, values.len) orelse return Error.RowCountOverflow;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domains.column);
    updateInt(&hasher, u32, component_ordinal);
    updateInt(&hasher, u32, @intCast(label.len));
    hasher.update(label);
    updateInt(&hasher, u32, column_ordinal);
    updateInt(&hasher, u64, row_count);
    for (values) |value| {
        if (value >= M31.Modulus) return Error.NonCanonicalM31;
        updateInt(&hasher, u32, value);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

/// Extends the receipt chain after all columns of one component are known.
/// Column entries must remain in their canonical committed order.
pub fn extendAccumulator(
    previous: Digest,
    component_ordinal: u32,
    label: []const u8,
    columns: []const Column,
) Error!Digest {
    return extendAccumulatorIn(cairo_base_domains, previous, component_ordinal, label, columns);
}

/// `extendAccumulator` under `domains`.
pub fn extendAccumulatorIn(
    domains: Domains,
    previous: Digest,
    component_ordinal: u32,
    label: []const u8,
    columns: []const Column,
) Error!Digest {
    try validateLabel(label);
    if (columns.len == 0) return Error.EmptyComponent;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domains.accumulator);
    hasher.update(&previous);
    updateInt(&hasher, u32, component_ordinal);
    updateInt(&hasher, u32, @intCast(label.len));
    hasher.update(label);
    updateInt(&hasher, u32, @intCast(columns.len));
    for (columns) |column| {
        updateInt(&hasher, u32, column.ordinal);
        updateInt(&hasher, u64, column.row_count);
        hasher.update(&column.sha256);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

/// Returns the first structural or value mismatch within a component receipt.
pub fn compare(expected: Component, actual: Component) ?Mismatch {
    if (expected.ordinal != actual.ordinal) return .{
        .kind = .component_ordinal,
        .component_ordinal = expected.ordinal,
    };
    if (!std.mem.eql(u8, expected.label, actual.label)) return .{
        .kind = .component_label,
        .component_ordinal = expected.ordinal,
    };
    if (expected.columns.len != actual.columns.len) return .{
        .kind = .column_count,
        .component_ordinal = expected.ordinal,
    };
    for (expected.columns, actual.columns) |expected_column, actual_column| {
        if (expected_column.ordinal != actual_column.ordinal) return .{
            .kind = .column_ordinal,
            .component_ordinal = expected.ordinal,
            .column_ordinal = expected_column.ordinal,
        };
        if (expected_column.row_count != actual_column.row_count) return .{
            .kind = .row_count,
            .component_ordinal = expected.ordinal,
            .column_ordinal = expected_column.ordinal,
        };
        if (!std.mem.eql(u8, &expected_column.sha256, &actual_column.sha256)) return .{
            .kind = .column_digest,
            .component_ordinal = expected.ordinal,
            .column_ordinal = expected_column.ordinal,
        };
    }
    if (!std.mem.eql(u8, &expected.accumulator, &actual.accumulator)) return .{
        .kind = .accumulator,
        .component_ordinal = expected.ordinal,
    };
    return null;
}

fn validateLabel(label: []const u8) Error!void {
    if (label.len == 0) return Error.EmptyLabel;
    if (label.len > std.math.maxInt(u32)) return Error.LabelTooLong;
}

fn updateInt(hasher: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hasher.update(&bytes);
}

test "Cairo checkpoint: column digest binds identity geometry and values" {
    const digest = try digestColumn(3, "ret_opcode", 7, &.{ 0, 1, 2, M31.Modulus - 1 });
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0xd3, 0xd3, 0x6f, 0x29, 0xe7, 0xdb, 0x87, 0x27,
            0x11, 0x94, 0x1d, 0x9e, 0xca, 0x50, 0xd3, 0x8d,
            0x5f, 0x0a, 0x33, 0x12, 0x11, 0x30, 0xab, 0x02,
            0xfa, 0x40, 0xa1, 0xac, 0xe6, 0x1a, 0x64, 0x10,
        },
        &digest,
    );
    try std.testing.expectError(
        Error.NonCanonicalM31,
        digestColumn(3, "ret_opcode", 7, &.{M31.Modulus}),
    );
}

test "Cairo checkpoint: cumulative receipt and first mismatch are deterministic" {
    const first_digest = try digestColumn(3, "ret_opcode", 0, &.{ 1, 2, 3, 5 });
    const second_digest = try digestColumn(3, "ret_opcode", 1, &.{ 8, 13, 21, 34 });
    var expected_columns = [_]Column{
        .{ .ordinal = 0, .row_count = 4, .sha256 = first_digest },
        .{ .ordinal = 1, .row_count = 4, .sha256 = second_digest },
    };
    const accumulator = try extendAccumulator(initial_accumulator, 3, "ret_opcode", &expected_columns);
    const expected = Component{
        .ordinal = 3,
        .label = "ret_opcode",
        .columns = &expected_columns,
        .accumulator = accumulator,
    };
    try std.testing.expect(compare(expected, expected) == null);

    var actual_columns = expected_columns;
    actual_columns[1].row_count = 8;
    const actual = Component{
        .ordinal = 3,
        .label = "ret_opcode",
        .columns = &actual_columns,
        .accumulator = accumulator,
    };
    const mismatch = compare(expected, actual).?;
    try std.testing.expectEqual(MismatchKind.row_count, mismatch.kind);
    try std.testing.expectEqual(@as(?u32, 1), mismatch.column_ordinal);
}
