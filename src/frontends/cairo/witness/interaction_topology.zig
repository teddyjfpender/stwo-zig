//! Compile source-authenticated Cairo LogUp layouts into the evaluator ABI.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const feed_topology = @import("feed_topology.zig");
const interaction_trace = @import("interaction_trace.zig");

pub const Compiled = struct {
    allocator: std.mem.Allocator,
    descriptors: []u32,

    pub fn deinit(self: *Compiled) void {
        self.allocator.free(self.descriptors);
        self.* = undefined;
    }

    pub fn columnCount(self: Compiled) usize {
        return self.descriptors.len / interaction_trace.descriptor_words;
    }
};

pub const Error = error{
    AllocationSizeOverflow,
    InvalidLookupWords,
    NonCanonicalRelationId,
    NonConstantRelationId,
    UnknownLookupField,
    InvalidMultiplicityField,
};

pub fn compile(
    allocator: std.mem.Allocator,
    component: feed_topology.Component,
    lookup_words: []const u32,
    rows: usize,
) !Compiled {
    if (rows == 0 or component.lookup_words_per_row == 0 or
        lookup_words.len != std.math.mul(
            usize,
            component.lookup_words_per_row,
            rows,
        ) catch return Error.AllocationSizeOverflow)
        return Error.InvalidLookupWords;
    const descriptor_count = std.math.mul(
        usize,
        component.logup_columns.len,
        interaction_trace.descriptor_words,
    ) catch return Error.AllocationSizeOverflow;
    const descriptors = try allocator.alloc(u32, descriptor_count);
    errdefer allocator.free(descriptors);
    @memset(descriptors, 0);

    for (component.logup_columns, 0..) |column, column_index| {
        const descriptor = descriptors[column_index * interaction_trace.descriptor_words ..][0..interaction_trace.descriptor_words];
        descriptor[0] = if (column.b == null) 1 else 2;
        try writeUse(
            descriptor[1..][0..interaction_trace.use_words],
            component.lookup_fields,
            column.a,
            lookup_words,
            rows,
        );
        if (column.b) |use| try writeUse(
            descriptor[1 + interaction_trace.use_words ..][0..interaction_trace.use_words],
            component.lookup_fields,
            use,
            lookup_words,
            rows,
        );
    }
    return .{ .allocator = allocator, .descriptors = descriptors };
}

fn writeUse(
    destination: *[interaction_trace.use_words]u32,
    fields: []const feed_topology.LookupField,
    use: feed_topology.LogupUse,
    lookup_words: []const u32,
    rows: usize,
) !void {
    const relation = findField(fields, use.field) orelse
        return Error.UnknownLookupField;
    const relation_id = lookup_words[@as(usize, relation.word_base) * rows];
    if (relation_id == 0 or relation_id >= m31.Modulus)
        return Error.NonCanonicalRelationId;
    for (lookup_words[@as(usize, relation.word_base) * rows ..][0..rows]) |value| {
        if (value != relation_id) return Error.NonConstantRelationId;
    }

    const multiplicity = if (std.mem.eql(u8, use.multiplicity, "1"))
        .{ @as(u32, 0), @as(u32, 0) }
    else if (std.mem.eql(u8, use.multiplicity, "enabler"))
        .{ @as(u32, 1), @as(u32, 0) }
    else blk: {
        const field = findField(fields, use.multiplicity) orelse
            return Error.InvalidMultiplicityField;
        if (field.words != 1) return Error.InvalidMultiplicityField;
        break :blk .{ @as(u32, 2), field.word_base };
    };
    destination.* = .{
        0,
        relation.word_base,
        relation.words,
        relation_id,
        multiplicity[0],
        multiplicity[1],
        @intFromBool(use.negative),
    };
}

fn findField(
    fields: []const feed_topology.LookupField,
    name: []const u8,
) ?feed_topology.LookupField {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field;
    }
    return null;
}

test "Cairo interaction topology compiles paired source facts" {
    const fields = [_]feed_topology.LookupField{
        .{ .name = "relation_a", .word_base = 0, .words = 2 },
        .{ .name = "mults_0", .word_base = 2, .words = 1 },
        .{ .name = "relation_b", .word_base = 3, .words = 3 },
    };
    const columns = [_]feed_topology.LogupColumn{.{
        .a = .{ .field = "relation_a", .multiplicity = "mults_0", .negative = false },
        .b = .{ .field = "relation_b", .multiplicity = "enabler", .negative = true },
    }};
    const component = feed_topology.Component{
        .producer = "test_component",
        .sub_words_per_row = 0,
        .feeds = &.{},
        .lookup_words_per_row = 6,
        .lookup_fields = &fields,
        .logup_columns = &columns,
    };
    const words = [_]u32{
        17, 17,
        4,  5,
        1,  0,
        23, 23,
        6,  7,
        8,  9,
    };
    var compiled = try compile(std.testing.allocator, component, &words, 2);
    defer compiled.deinit();

    try std.testing.expectEqual(@as(usize, 1), compiled.columnCount());
    try std.testing.expectEqualSlices(
        u32,
        &.{ 2, 0, 0, 2, 17, 2, 2, 0, 0, 3, 3, 23, 1, 0, 1, 0 },
        compiled.descriptors,
    );
}

test "Cairo interaction topology rejects row-varying relation IDs" {
    const fields = [_]feed_topology.LookupField{
        .{ .name = "relation", .word_base = 0, .words = 1 },
    };
    const columns = [_]feed_topology.LogupColumn{.{
        .a = .{ .field = "relation", .multiplicity = "1", .negative = false },
        .b = null,
    }};
    const component = feed_topology.Component{
        .producer = "test_component",
        .sub_words_per_row = 0,
        .feeds = &.{},
        .lookup_words_per_row = 1,
        .lookup_fields = &fields,
        .logup_columns = &columns,
    };
    try std.testing.expectError(
        Error.NonConstantRelationId,
        compile(std.testing.allocator, component, &.{ 17, 18 }, 2),
    );
}
