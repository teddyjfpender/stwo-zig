//! Cairo AIR layout facts shared by the Cairo frontend and circuit recursion.
//!
//! The Cairo prover and the in-circuit Cairo verifier must agree on the
//! preprocessed-trace variants, the ordered preprocessed column ids of each
//! variant, the builtin memory-cell sizes, and the components a leaf verifier
//! circuit disables per variant. Design §2.2 forbids the circuit frontend from
//! importing the Cairo frontend, so these dependency-free facts live one layer
//! down, next to `preprocessed_tables` (design §2.1). The Cairo frontend
//! re-exports them (`preprocessed.trace.Variant`,
//! `claim_generator.PreprocessedVariant`, `air_layout`), so its bytes are
//! unchanged.
//!
//! Upstream (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230):
//! - `crates/common/src/preprocessed_columns/preprocessed_trace.rs`
//!   (`PreProcessedTraceVariant`, `PreProcessedTrace::{canonical, canonical_small,
//!   canonical_without_pedersen}`, the stable sort by log size);
//! - `crates/common/src/builtins.rs` (memory-cell sizes);
//! - `crates/cairo_verifier/src/statement.rs` (`verify_builtins` order and its
//!   Pedersen component choice);
//! - `crates/leaf_prover/src/consts.rs` and `prove_leaf.rs`
//!   (`DISABLED_COMPONENTS_*`, `disabled_components`, `leaf_verifier_components`).
//!
//! `vectors/circuit/r6/cairo_statement.json` pins all of them; the Cairo
//! frontend's `tests/circuit_leaf_statement.zig` compares against it.

const std = @import("std");

/// `PreProcessedTraceVariant`, with the same tags as the Cairo lane's
/// historical `preprocessed.trace.Variant` and `claim_generator.PreprocessedVariant`.
pub const Variant = enum {
    canonical,
    canonical_without_pedersen,
    canonical_small,

    /// `PreProcessedTraceVariant::n_columns`.
    pub fn columnCount(self: Variant) usize {
        return switch (self) {
            .canonical => 161,
            .canonical_without_pedersen => 105,
            .canonical_small => 156,
        };
    }

    pub fn traceCellCount(self: Variant) u64 {
        return switch (self) {
            .canonical => 543_100_528,
            .canonical_without_pedersen => 73_338_480,
            .canonical_small => 10_161_776,
        };
    }

    pub fn maxLogSize(self: Variant) u32 {
        return switch (self) {
            .canonical, .canonical_without_pedersen => 25,
            .canonical_small => 20,
        };
    }

    /// The largest `seq_{n}` column: `MAX_SEQUENCE_LOG_SIZE` or
    /// `SMALL_MAX_SEQUENCE_LOG_SIZE`.
    pub fn maxSequenceLogSize(self: Variant) u32 {
        return self.maxLogSize();
    }
};

/// `INTERACTION_POW_BITS` of `crates/cairo_verifier/src/verify.rs`: the
/// interaction grind of a Cairo proof, which the leaf verifier re-checks.
pub const interaction_pow_bits: u32 = 24;

pub const Error = error{
    /// `disabled_components` panics for `CanonicalWithoutPedersen`.
    UnsupportedLeafVariant,
    /// A disabled component is missing from, or repeated in, the slot order.
    UnknownComponent,
    SlotCountMismatch,
    PreprocessedColumnOverflow,
};

// ---------------------------------------------------------------------------
// Builtins

/// The ten builtins `CairoStatement::verify_builtins` checks, in its order.
/// The output builtin is validated separately and is not listed.
pub const Builtin = enum {
    pedersen,
    range_check,
    bitwise,
    poseidon,
    ec_op,
    ecdsa,
    keccak,
    range_check96,
    add_mod,
    mul_mod,

    /// `*_MEMORY_CELLS` of `crates/common/src/builtins.rs`.
    pub fn memoryCells(self: Builtin) u32 {
        return switch (self) {
            .pedersen => 3,
            .range_check => 1,
            .bitwise => 5,
            .poseidon => 6,
            .ec_op => 7,
            .ecdsa => 2,
            .keccak => 16,
            .range_check96 => 1,
            .add_mod => 7,
            .mul_mod => 7,
        };
    }

    /// The component whose size bounds this builtin's uses. For Pedersen it
    /// depends on the variant exactly as in `verify_builtins`:
    /// `CanonicalSmall` uses the narrow-window component, and both other
    /// variants use `pedersen_builtin`.
    pub fn componentName(self: Builtin, variant: Variant) []const u8 {
        return switch (self) {
            .pedersen => pedersenBuiltinComponent(variant),
            .range_check => "range_check_builtin",
            .bitwise => "bitwise_builtin",
            .poseidon => "poseidon_builtin",
            .ec_op => "ec_op_builtin",
            .ecdsa => "ecdsa_builtin",
            .keccak => "keccak_builtin",
            .range_check96 => "range_check96_builtin",
            .add_mod => "add_mod_builtin",
            .mul_mod => "mul_mod_builtin",
        };
    }
};

/// `verify_builtins` order.
pub const verify_builtins_order = std.enums.values(Builtin);

pub fn pedersenBuiltinComponent(variant: Variant) []const u8 {
    return switch (variant) {
        .canonical_small => "pedersen_builtin_narrow_windows",
        .canonical, .canonical_without_pedersen => "pedersen_builtin",
    };
}

// ---------------------------------------------------------------------------
// Leaf verifier components

pub const leaf_disabled_component_count = 4;

/// `DISABLED_COMPONENTS_CANONICAL_PREPROCESSED`.
pub const disabled_components_canonical = [leaf_disabled_component_count][]const u8{
    "pedersen_builtin_narrow_windows",
    "pedersen_aggregator_window_bits_9",
    "partial_ec_mul_window_bits_9",
    "pedersen_points_table_window_bits_9",
};

/// `DISABLED_COMPONENTS_SMALL_PREPROCESSED`.
pub const disabled_components_small = [leaf_disabled_component_count][]const u8{
    "pedersen_builtin",
    "pedersen_aggregator_window_bits_18",
    "partial_ec_mul_window_bits_18",
    "pedersen_points_table_window_bits_18",
};

/// `prove_leaf.rs::disabled_components`; fails closed where upstream panics.
pub fn leafDisabledComponents(
    variant: Variant,
) Error!*const [leaf_disabled_component_count][]const u8 {
    return switch (variant) {
        .canonical => &disabled_components_canonical,
        .canonical_small => &disabled_components_small,
        .canonical_without_pedersen => Error.UnsupportedLeafVariant,
    };
}

/// `leaf_verifier_components(...).enabled_bits` over `slot_names`, the
/// 83-slot `all_components()` order supplied by the caller (the projection
/// on the circuit side, `official_claim_registry` on the Cairo side). Every
/// disabled name must occur in `slot_names` exactly once; upstream would
/// silently keep an unknown name enabled, which here is a layout drift and
/// fails closed. Returns the number of enabled components.
pub fn leafEnabledBits(
    variant: Variant,
    slot_names: []const []const u8,
    out: []bool,
) Error!usize {
    if (out.len != slot_names.len) return Error.SlotCountMismatch;
    const disabled = try leafDisabledComponents(variant);
    var seen = [_]u8{0} ** leaf_disabled_component_count;
    var enabled: usize = 0;
    for (slot_names, out) |name, *bit| {
        bit.* = true;
        for (disabled, &seen) |disabled_name, *count| {
            if (!std.mem.eql(u8, name, disabled_name)) continue;
            bit.* = false;
            count.* += 1;
        }
        if (bit.*) enabled += 1;
    }
    for (seen) |count| if (count != 1) return Error.UnknownComponent;
    return enabled;
}

// ---------------------------------------------------------------------------
// Preprocessed column ids

/// Upper bound on any variant's column count.
pub const max_preprocessed_columns = 161;
/// Upper bound on an id's length ("range_check_3_3_3_3_3_column_4" is 30).
pub const max_column_id_len = 40;

pub const ColumnId = struct {
    bytes: [max_column_id_len]u8,
    len: u8,
    log_size: u32,
    /// Position in upstream insertion order; ties in `log_size` keep it.
    source_ordinal: u32,

    pub fn name(self: *const ColumnId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const RangeShape = struct {
    name: []const u8,
    widths: []const u5,
    log_size: u32,
};

/// The `RangeCheck` preprocessed tables, in upstream insertion order.
pub const range_shapes = [_]RangeShape{
    rangeShape("4_3", &.{ 4, 3 }),
    rangeShape("4_4", &.{ 4, 4 }),
    rangeShape("9_9", &.{ 9, 9 }),
    rangeShape("7_2_5", &.{ 7, 2, 5 }),
    rangeShape("3_6_6_3", &.{ 3, 6, 6, 3 }),
    rangeShape("4_4_4_4", &.{ 4, 4, 4, 4 }),
    rangeShape("3_3_3_3_3", &.{ 3, 3, 3, 3, 3 }),
};

fn rangeShape(comptime shape_name: []const u8, comptime widths: []const u5) RangeShape {
    var log_size: u32 = 0;
    for (widths) |width| log_size += width;
    return .{ .name = shape_name, .widths = widths, .log_size = log_size };
}

pub const xor_bits = [_]u32{ 4, 7, 8, 9, 10 };
pub const min_sequence_log_size: u32 = 4;
pub const poseidon_round_key_columns = 30;
pub const blake_sigma_columns = 16;
pub const pedersen_point_columns = 56;

/// `PreProcessedTraceVariant::to_preprocessed_trace().ids()` with log sizes:
/// columns in upstream insertion order (seq, bitwise_xor, range_check,
/// poseidon_round_keys, blake_sigma, pedersen_points[_small]), then stably
/// sorted by log size. Returns the filled prefix of `out`.
pub fn preprocessedColumns(
    variant: Variant,
    out: *[max_preprocessed_columns]ColumnId,
) Error![]ColumnId {
    var builder = ColumnBuilder{ .out = out };
    var log_size = min_sequence_log_size;
    while (log_size <= variant.maxSequenceLogSize()) : (log_size += 1)
        try builder.add("seq_{}", .{log_size}, log_size);
    for (xor_bits) |bits| for (0..3) |column|
        try builder.add("bitwise_xor_{}_{}", .{ bits, column }, bits * 2);
    inline for (range_shapes) |shape| for (0..shape.widths.len) |column|
        try builder.add("range_check_{s}_column_{}", .{ shape.name, column }, shape.log_size);
    for (0..poseidon_round_key_columns) |column|
        try builder.add("poseidon_round_keys_{}", .{column}, 6);
    for (0..blake_sigma_columns) |column|
        try builder.add("blake_sigma_{}", .{column}, 4);
    switch (variant) {
        .canonical_without_pedersen => {},
        .canonical => for (0..pedersen_point_columns) |column|
            try builder.add("pedersen_points_{}", .{column}, 23),
        .canonical_small => for (0..pedersen_point_columns) |column|
            try builder.add("pedersen_points_small_{}", .{column}, 15),
    }
    const columns = out[0..builder.len];
    std.sort.block(ColumnId, columns, {}, logSizeLessThan);
    return columns;
}

fn logSizeLessThan(_: void, lhs: ColumnId, rhs: ColumnId) bool {
    return lhs.log_size < rhs.log_size;
}

const ColumnBuilder = struct {
    out: *[max_preprocessed_columns]ColumnId,
    len: usize = 0,

    fn add(self: *ColumnBuilder, comptime fmt: []const u8, args: anytype, log_size: u32) Error!void {
        if (self.len == self.out.len) return Error.PreprocessedColumnOverflow;
        const column = &self.out[self.len];
        const written = std.fmt.bufPrint(&column.bytes, fmt, args) catch
            return Error.PreprocessedColumnOverflow;
        column.len = @intCast(written.len);
        column.log_size = log_size;
        column.source_ordinal = @intCast(self.len);
        self.len += 1;
    }
};

test "leaf enabled bits disable exactly the four variant components" {
    const slots = [_][]const u8{
        "a",                                  "pedersen_builtin",                     "pedersen_builtin_narrow_windows",
        "pedersen_aggregator_window_bits_18", "pedersen_aggregator_window_bits_9",    "partial_ec_mul_window_bits_18",
        "partial_ec_mul_window_bits_9",       "pedersen_points_table_window_bits_18", "pedersen_points_table_window_bits_9",
    };
    var bits: [slots.len]bool = undefined;
    try std.testing.expectEqual(@as(usize, 5), try leafEnabledBits(.canonical_small, &slots, &bits));
    try std.testing.expectEqualSlices(bool, &.{ true, false, true, false, true, false, true, false, true }, &bits);
    try std.testing.expectEqual(@as(usize, 5), try leafEnabledBits(.canonical, &slots, &bits));
    try std.testing.expectEqualSlices(bool, &.{ true, true, false, true, false, true, false, true, false }, &bits);
    try std.testing.expectError(Error.UnsupportedLeafVariant, leafEnabledBits(.canonical_without_pedersen, &slots, &bits));
    try std.testing.expectError(Error.UnknownComponent, leafEnabledBits(.canonical, slots[0..8], bits[0..8]));
    try std.testing.expectError(Error.SlotCountMismatch, leafEnabledBits(.canonical, &slots, bits[0..3]));
}

test "preprocessed column ids match each variant's column count and are sorted by log size" {
    var storage: [max_preprocessed_columns]ColumnId = undefined;
    for (std.enums.values(Variant)) |variant| {
        const columns = try preprocessedColumns(variant, &storage);
        try std.testing.expectEqual(variant.columnCount(), columns.len);
        var cells: u64 = 0;
        for (columns, 0..) |column, index| {
            cells += @as(u64, 1) << @intCast(column.log_size);
            if (index > 0) {
                const previous = columns[index - 1];
                try std.testing.expect(previous.log_size < column.log_size or
                    (previous.log_size == column.log_size and previous.source_ordinal < column.source_ordinal));
            }
        }
        try std.testing.expectEqual(variant.traceCellCount(), cells);
        try std.testing.expectEqual(variant.maxLogSize(), columns[columns.len - 1].log_size);
    }
}

test "verify_builtins picks the Pedersen component by variant" {
    try std.testing.expectEqualStrings("pedersen_builtin_narrow_windows", Builtin.pedersen.componentName(.canonical_small));
    try std.testing.expectEqualStrings("pedersen_builtin", Builtin.pedersen.componentName(.canonical));
    try std.testing.expectEqualStrings("pedersen_builtin", Builtin.pedersen.componentName(.canonical_without_pedersen));
    try std.testing.expectEqual(@as(usize, 10), verify_builtins_order.len);
}
