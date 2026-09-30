//! The circuit AIR's component list: order, names, relation ids and the
//! static per-component facts that the in-circuit verifier, the circuit hash
//! and the circuit prover must agree on.
//!
//! Ports `crates/circuit_verifier/src/{circuit_components,relations}.rs` and
//! the `INTERACTION_POW_BITS` constant of `statement.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). This is the single definition
//! of `ComponentList` and `PerComponent`: the evaluator table
//! (`air_eval/circuit_components.zig`), the statements, the circuit hash and
//! the prover's `air/component_list.zig` import it instead of re-listing
//! the order.

const std = @import("std");

/// `ComponentList` in declaration order. The tag names are the canonical
/// component names (`COMPONENT_NAMES`, the keys of `all_circuit_components`),
/// so `@tagName` is the Rust `ComponentList::name`.
pub const ComponentList = enum(u8) {
    eq,
    qm31_ops,
    triple_xor,
    m_31_to_u_32,
    blake_g_gate,
    verify_bitwise_xor_8,
    verify_bitwise_xor_12,
    verify_bitwise_xor_4,
    verify_bitwise_xor_7,
    verify_bitwise_xor_9,
    range_check_16,

    /// `ComponentList::idx`: the slot in the static components array.
    pub inline fn idx(self: ComponentList) usize {
        return @intFromEnum(self);
    }

    /// `ComponentList::name`.
    pub inline fn name(self: ComponentList) []const u8 {
        return @tagName(self);
    }
};

pub const N_COMPONENTS: usize = std.enums.values(ComponentList).len;

/// `COMPONENT_NAMES`, in `ComponentList` order.
pub const COMPONENT_NAMES: [N_COMPONENTS][]const u8 = blk: {
    var names: [N_COMPONENTS][]const u8 = undefined;
    for (std.enums.values(ComponentList), 0..) |component, index| names[index] = @tagName(component);
    break :blk names;
};

/// `PerComponent<T>`: one `T` per component, fields in `ComponentList` order.
pub fn PerComponent(comptime T: type) type {
    return struct {
        eq: T,
        qm31_ops: T,
        triple_xor: T,
        m_31_to_u_32: T,
        blake_g_gate: T,
        verify_bitwise_xor_8: T,
        verify_bitwise_xor_12: T,
        verify_bitwise_xor_4: T,
        verify_bitwise_xor_7: T,
        verify_bitwise_xor_9: T,
        range_check_16: T,

        const Self = @This();

        comptime {
            // The field order is the ComponentList order; `toArray` and the
            // circuit hash's byte order rely on it.
            for (std.meta.fields(Self), std.enums.values(ComponentList)) |field, component| {
                if (!std.mem.eql(u8, field.name, @tagName(component)))
                    @compileError("PerComponent field order differs from ComponentList");
            }
        }

        /// `PerComponent::into_array`.
        pub fn toArray(self: Self) [N_COMPONENTS]T {
            var out: [N_COMPONENTS]T = undefined;
            inline for (std.meta.fields(Self), 0..) |field, index| out[index] = @field(self, field.name);
            return out;
        }

        pub fn fromArray(values: [N_COMPONENTS]T) Self {
            var out: Self = undefined;
            inline for (std.meta.fields(Self), 0..) |field, index| @field(out, field.name) = values[index];
            return out;
        }

        pub fn get(self: Self, component: ComponentList) T {
            return self.toArray()[component.idx()];
        }
    };
}

// Relation ids (`relations.rs`).
pub const GATE_RELATION_ID: u32 = 378353459;
pub const RANGE_CHECK_16_RELATION_ID: u32 = 1008385708;
pub const VERIFY_BITWISE_XOR_4_RELATION_ID: u32 = 45448144;
pub const VERIFY_BITWISE_XOR_7_RELATION_ID: u32 = 62225763;
pub const VERIFY_BITWISE_XOR_8_RELATION_ID: u32 = 112558620;
pub const VERIFY_BITWISE_XOR_8_B_RELATION_ID: u32 = 521092554;
pub const VERIFY_BITWISE_XOR_9_RELATION_ID: u32 = 95781001;
pub const VERIFY_BITWISE_XOR_12_RELATION_ID: u32 = 648362599;

/// Size of the common lookup-elements relation (`COMMON_LOOKUP_ELEMENTS_SIZE`).
pub const COMMON_LOOKUP_ELEMENTS_SIZE: usize = 128;

/// Interaction proof-of-work bits of circuit proofs (`statement.rs`).
pub const INTERACTION_POW_BITS: u32 = 20;

/// `circuit_common::N_RESERVED`: output wires of a verifier circuit, one per
/// word of the unreduced Blake2s digest.
pub const N_RESERVED: usize = 8;

/// `circuit_common::N_LANES`: the SIMD width that bounds the smallest padded
/// component.
pub const N_LANES: usize = 16;

/// One `RelationUse` of `relation_uses_per_row`.
pub const RelationUse = struct {
    relation_id: []const u8,
    uses: u64,
};

/// How a component's log size is resolved (`CircuitEval::log_size`): read
/// from a preprocessed column's log size, or a constant table size.
pub const LogSizeSource = union(enum) {
    preprocessed_column: []const u8,
    fixed: u32,
};

/// Static facts of one circuit component (its `CircuitEval` constants).
pub const ComponentFacts = struct {
    trace_columns: usize,
    interaction_columns: usize,
    log_size: LogSizeSource,
    relation_uses_per_row: []const RelationUse,
};

/// The static facts of every component, from the generated evaluators in
/// `crates/circuit_verifier/src/components/*.rs`. The R3 fixture
/// (`vectors/circuit/r3/components.json`) pins the column counts and
/// relation uses; the projection-driven evaluator table must agree with it.
pub const component_facts: PerComponent(ComponentFacts) = .{
    .eq = .{
        .trace_columns = 4,
        .interaction_columns = 4,
        .log_size = .{ .preprocessed_column = "eq_in0_address" },
        .relation_uses_per_row = &.{.{ .relation_id = "Gate", .uses = 2 }},
    },
    .qm31_ops = .{
        .trace_columns = 12,
        .interaction_columns = 8,
        .log_size = .{ .preprocessed_column = "qm31_ops_in0_address" },
        .relation_uses_per_row = &.{.{ .relation_id = "Gate", .uses = 2 }},
    },
    .triple_xor = .{
        .trace_columns = 20,
        .interaction_columns = 24,
        .log_size = .{ .preprocessed_column = "triple_xor_input_addr_0" },
        .relation_uses_per_row = &.{
            .{ .relation_id = "Gate", .uses = 3 },
            .{ .relation_id = "VerifyBitwiseXor_8", .uses = 8 },
        },
    },
    .m_31_to_u_32 = .{
        .trace_columns = 4,
        .interaction_columns = 12,
        .log_size = .{ .preprocessed_column = "m31_to_u32_input_addr" },
        .relation_uses_per_row = &.{
            .{ .relation_id = "Gate", .uses = 1 },
            .{ .relation_id = "RangeCheck_16", .uses = 3 },
        },
    },
    .blake_g_gate = .{
        .trace_columns = 52,
        .interaction_columns = 52,
        .log_size = .{ .preprocessed_column = "blake_g_gate_input_addr_a" },
        .relation_uses_per_row = &.{
            .{ .relation_id = "Gate", .uses = 6 },
            .{ .relation_id = "VerifyBitwiseXor_12", .uses = 2 },
            .{ .relation_id = "VerifyBitwiseXor_4", .uses = 2 },
            .{ .relation_id = "VerifyBitwiseXor_7", .uses = 2 },
            .{ .relation_id = "VerifyBitwiseXor_8", .uses = 6 },
            .{ .relation_id = "VerifyBitwiseXor_8_B", .uses = 2 },
            .{ .relation_id = "VerifyBitwiseXor_9", .uses = 2 },
        },
    },
    .verify_bitwise_xor_8 = .{
        .trace_columns = 2,
        .interaction_columns = 4,
        .log_size = .{ .fixed = 16 },
        .relation_uses_per_row = &.{},
    },
    .verify_bitwise_xor_12 = .{
        .trace_columns = 16,
        .interaction_columns = 32,
        // (ELEM_BITS - EXPAND_BITS) * 2 with ELEM_BITS = 12, EXPAND_BITS = 2.
        .log_size = .{ .fixed = 20 },
        .relation_uses_per_row = &.{},
    },
    .verify_bitwise_xor_4 = .{
        .trace_columns = 1,
        .interaction_columns = 4,
        .log_size = .{ .fixed = 8 },
        .relation_uses_per_row = &.{},
    },
    .verify_bitwise_xor_7 = .{
        .trace_columns = 1,
        .interaction_columns = 4,
        .log_size = .{ .fixed = 14 },
        .relation_uses_per_row = &.{},
    },
    .verify_bitwise_xor_9 = .{
        .trace_columns = 1,
        .interaction_columns = 4,
        .log_size = .{ .fixed = 18 },
        .relation_uses_per_row = &.{},
    },
    .range_check_16 = .{
        .trace_columns = 1,
        .interaction_columns = 4,
        .log_size = .{ .fixed = 16 },
        .relation_uses_per_row = &.{},
    },
};

pub const LogSizeError = error{MissingPreprocessedColumn};

/// `circuit_component_log_sizes`: the static log size of every component
/// given the preprocessed-trace layout. `layout` is anything with
/// `fn logSize(self, id: []const u8) ?u32` (for example
/// `preprocessed.ColumnLayout`).
pub fn circuitComponentLogSizes(layout: anytype) LogSizeError!PerComponent(u32) {
    var out: [N_COMPONENTS]u32 = undefined;
    for (component_facts.toArray(), 0..) |facts, index| {
        out[index] = switch (facts.log_size) {
            .fixed => |value| value,
            .preprocessed_column => |id| layout.logSize(id) orelse return error.MissingPreprocessedColumn,
        };
    }
    return PerComponent(u32).fromArray(out);
}

test "component list: order and names match COMPONENT_NAMES" {
    const expected = [_][]const u8{
        "eq",                    "qm31_ops",             "triple_xor",
        "m_31_to_u_32",          "blake_g_gate",         "verify_bitwise_xor_8",
        "verify_bitwise_xor_12", "verify_bitwise_xor_4", "verify_bitwise_xor_7",
        "verify_bitwise_xor_9",  "range_check_16",
    };
    try std.testing.expectEqual(expected.len, N_COMPONENTS);
    for (expected, COMPONENT_NAMES, 0..) |want, got, index| {
        try std.testing.expectEqualStrings(want, got);
        try std.testing.expectEqual(index, @as(ComponentList, @enumFromInt(index)).idx());
    }
}

test "component list: PerComponent round-trips through its array" {
    var values: [N_COMPONENTS]u32 = undefined;
    for (&values, 0..) |*value, index| value.* = @intCast(index * 3);
    const per = PerComponent(u32).fromArray(values);
    try std.testing.expectEqual(@as(u32, 12), per.blake_g_gate);
    try std.testing.expectEqual(@as(u32, 30), per.get(.range_check_16));
    try std.testing.expectEqualSlices(u32, &values, &per.toArray());
}
