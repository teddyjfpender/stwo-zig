//! Allocation-free relation-graph execution on the proof-owned stream.

const std = @import("std");
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
    /// A tuple made directly from consecutive source columns. Unlike
    /// `projected_columns`, the first tuple word is not a relation id.
    projected_columns_no_id = 8,
};

pub const MultiplicityKind = enum(u32) {
    one = 0,
    enabler = 1,
    lookup_word = 2,
    memory_address_chunk = 3,
    memory_big = 4,
    memory_small = 5,
    bitwise_xor12 = 6,
    source_column = 7,
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

    pub fn validate(
        self: UseDescriptor,
        bounds: SourceBounds,
    ) error{InvalidKernelDescriptor}!void {
        if (self.tuple_words == 0 or
            self.tuple_words > bounds.max_alpha_powers or
            self.negative > 1)
        {
            return error.InvalidKernelDescriptor;
        }
        const tuple_kind = std.meta.intToEnum(
            TupleKind,
            self.tuple_kind,
        ) catch return error.InvalidKernelDescriptor;
        const multiplicity_kind = std.meta.intToEnum(
            MultiplicityKind,
            self.multiplicity_kind,
        ) catch return error.InvalidKernelDescriptor;
        if (tuple_kind == .projected_columns_no_id and
            self.relation_id != 0)
        {
            return error.InvalidKernelDescriptor;
        }
        switch (tuple_kind) {
            .lookup_words => try requireLookupColumns(
                bounds,
                self.tuple_argument,
                self.tuple_words,
            ),
            .projected_columns => try requireSources(
                bounds,
                self.tuple_argument,
                self.tuple_words - 1,
            ),
            .projected_columns_no_id => try requireSources(
                bounds,
                self.tuple_argument,
                self.tuple_words,
            ),
            .memory_address_chunk => {
                if (self.tuple_words > 2)
                    try requireSources(
                        bounds,
                        try checkedMul(self.tuple_argument, 2),
                        1,
                    );
            },
            .memory_big_limbs, .memory_small_limbs => try requireSources(
                bounds,
                self.tuple_argument,
                self.tuple_words - 1,
            ),
            .memory_big_value, .memory_small_value => {
                if (self.tuple_words > 2)
                    try requireSources(bounds, 0, self.tuple_words - 2);
            },
            .bitwise_xor12 => {
                if (self.tuple_words > 4)
                    return error.InvalidKernelDescriptor;
            },
        }
        switch (multiplicity_kind) {
            .one, .enabler => {},
            .lookup_word => try requireLookupColumns(
                bounds,
                self.multiplicity_argument,
                1,
            ),
            .memory_address_chunk => try requireSources(
                bounds,
                try checkedAdd(
                    try checkedMul(self.multiplicity_argument, 2),
                    1,
                ),
                1,
            ),
            .memory_big,
            .memory_small,
            .bitwise_xor12,
            .source_column,
            => try requireSources(
                bounds,
                self.multiplicity_argument,
                1,
            ),
        }
    }
};

pub const SourceBounds = struct {
    source_pointer_count: u32,
    lookup_word_columns: u32 = 0,
    max_alpha_powers: u32,
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

    pub fn validate(
        self: ColumnDescriptor,
        bounds: SourceBounds,
    ) error{InvalidKernelDescriptor}!void {
        if (self.reserved != 0 or (self.arity != 1 and self.arity != 2))
            return error.InvalidKernelDescriptor;
        try self.first.validate(bounds);
        if (self.arity == 2) {
            try self.second.validate(bounds);
        } else if (!std.meta.eql(
            self.second,
            std.mem.zeroes(UseDescriptor),
        )) {
            return error.InvalidKernelDescriptor;
        }
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

fn requireSources(
    bounds: SourceBounds,
    first: u32,
    count: u32,
) error{InvalidKernelDescriptor}!void {
    const end = checkedAdd(first, count) catch
        return error.InvalidKernelDescriptor;
    if (end > bounds.source_pointer_count)
        return error.InvalidKernelDescriptor;
}

fn requireLookupColumns(
    bounds: SourceBounds,
    first: u32,
    count: u32,
) error{InvalidKernelDescriptor}!void {
    if (bounds.source_pointer_count == 0)
        return error.InvalidKernelDescriptor;
    const end = checkedAdd(first, count) catch
        return error.InvalidKernelDescriptor;
    if (end > bounds.lookup_word_columns)
        return error.InvalidKernelDescriptor;
}

fn checkedAdd(left: u32, right: u32) error{InvalidKernelDescriptor}!u32 {
    return std.math.add(u32, left, right) catch
        error.InvalidKernelDescriptor;
}

fn checkedMul(left: u32, right: u32) error{InvalidKernelDescriptor}!u32 {
    return std.math.mul(u32, left, right) catch
        error.InvalidKernelDescriptor;
}

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
    try std.testing.expectEqual(@as(usize, 4), @alignOf(ColumnDescriptor));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(Geometry));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(UseDescriptor));
    inline for (std.meta.fields(UseDescriptor), 0..) |entry, index| {
        try std.testing.expectEqual(
            index * @sizeOf(u32),
            @offsetOf(UseDescriptor, entry.name),
        );
    }
    try std.testing.expectEqual(
        @as(usize, 0),
        @offsetOf(ColumnDescriptor, "arity"),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        @offsetOf(ColumnDescriptor, "first"),
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        @offsetOf(ColumnDescriptor, "second"),
    );
    try std.testing.expectEqual(
        @as(usize, 60),
        @offsetOf(ColumnDescriptor, "reserved"),
    );
    inline for (std.meta.fields(Geometry), 0..) |entry, index| {
        try std.testing.expectEqual(
            index * @sizeOf(u32),
            @offsetOf(Geometry, entry.name),
        );
    }
}

test "direct projected tuples and source multiplicities pin ABI tags" {
    try std.testing.expectEqual(
        @as(u32, 8),
        @intFromEnum(TupleKind.projected_columns_no_id),
    );
    try std.testing.expectEqual(
        @as(u32, 7),
        @intFromEnum(MultiplicityKind.source_column),
    );
}

test "descriptor validation separates projected tuple and source bounds" {
    const direct = UseDescriptor.init(
        .projected_columns_no_id,
        2,
        2,
        0,
        .source_column,
        6,
        true,
    );
    try direct.validate(.{
        .source_pointer_count = 8,
        .max_alpha_powers = 2,
    });
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        direct.validate(.{
            .source_pointer_count = 3,
            .max_alpha_powers = 2,
        }),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        direct.validate(.{
            .source_pointer_count = 8,
            .max_alpha_powers = 1,
        }),
    );
}
