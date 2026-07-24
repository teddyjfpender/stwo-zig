//! Allocation-free relation-graph execution on the proof-owned stream.

const field = @import("../field.zig");

pub const descriptor_words: u32 = 16;
pub const use_words: u32 = 7;
pub const geometry_words: u32 = 11;
pub const launch_block: u32 = 256;
pub const inverse_block_values: u32 = 1024;

pub const TupleKind = enum(u32) {
    lookup_words = 0,
    memory_address_chunk = 1,
    memory_big_limbs = 2,
    memory_big_value = 3,
    memory_small_limbs = 4,
    memory_small_value = 5,
    bitwise_xor12 = 6,
    projected_columns = 7,
};

pub const MultiplicityKind = enum(u32) {
    one = 0,
    enabler = 1,
    lookup_word = 2,
    memory_address_chunk = 3,
    memory_big = 4,
    memory_small = 5,
    bitwise_xor12 = 6,
};

pub const UseDescriptor = extern struct {
    tuple_kind: u32,
    tuple_argument: u32,
    tuple_words: u32,
    relation_id: u32,
    multiplicity_kind: u32,
    multiplicity_argument: u32,
    negative: u32,

    pub fn init(
        tuple_kind: TupleKind,
        tuple_argument: u32,
        tuple_words: u32,
        relation_id: u32,
        multiplicity_kind: MultiplicityKind,
        multiplicity_argument: u32,
        negative: bool,
    ) UseDescriptor {
        return .{
            .tuple_kind = @intFromEnum(tuple_kind),
            .tuple_argument = tuple_argument,
            .tuple_words = tuple_words,
            .relation_id = relation_id,
            .multiplicity_kind = @intFromEnum(multiplicity_kind),
            .multiplicity_argument = multiplicity_argument,
            .negative = @intFromBool(negative),
        };
    }
};

pub const ColumnDescriptor = extern struct {
    arity: u32,
    first: UseDescriptor,
    second: UseDescriptor,
    reserved: u32 = 0,

    pub fn single(first: UseDescriptor) ColumnDescriptor {
        return .{
            .arity = 1,
            .first = first,
            .second = std.mem.zeroes(UseDescriptor),
        };
    }

    pub fn pair(first: UseDescriptor, second: UseDescriptor) ColumnDescriptor {
        return .{
            .arity = 2,
            .first = first,
            .second = second,
        };
    }
};

/// Exact mirror of `RELATION_*` geometry words in `batch_inverse.cuh`.
pub const Geometry = extern struct {
    pair_first: u32,
    pair_blocks: u32,
    inverse_first: u32,
    inverse_blocks: u32,
    row_first: u32,
    row_blocks: u32,
    rows: u32,
    columns: u32,
    real_rows: u32,
    source_offset_rows: u32,
    inverse_rows: u32,
};

pub extern "c" fn stwo_relation_expand_challenges_on(
    drawn_z_alpha: [*]const field.SecureField,
    alpha_powers: [*]field.SecureField,
    n_alpha_powers: u32,
    z: *field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_relation_pairs_global_on(
    source_tables: [*]const u32,
    descriptors: [*]const u32,
    output_tables: [*]const u32,
    denominator_slabs: [*]const u32,
    geometry: [*]const Geometry,
    n_instances: u32,
    total_pair_blocks: u32,
    alpha_powers: [*]const field.SecureField,
    n_alpha_powers: u32,
    z: *const field.SecureField,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_relation_fraction_chain_global_on(
    output_tables: [*]const u32,
    denominator_slabs: [*]const u32,
    geometry: [*]const Geometry,
    n_instances: u32,
    total_inverse_blocks: u32,
    total_chain_blocks: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_relation_tail_global_on(
    output_tables: [*]const u32,
    claimed_sums: [*]const u32,
    geometry: [*]const Geometry,
    n_instances: u32,
    total_row_blocks: u32,
    reduction_partials: [*]u32,
    reduction_capacity: u32,
    scan_block_sums: [*]u32,
    scan_capacity: u32,
    stream: *anyopaque,
) c_int;

const std = @import("std");

test "relation descriptors preserve the CUDA word ABI" {
    try std.testing.expectEqual(
        @as(usize, descriptor_words * @sizeOf(u32)),
        @sizeOf(ColumnDescriptor),
    );
    try std.testing.expectEqual(
        @as(usize, geometry_words * @sizeOf(u32)),
        @sizeOf(Geometry),
    );
    try std.testing.expectEqual(
        @as(usize, use_words * @sizeOf(u32)),
        @sizeOf(UseDescriptor),
    );
}
