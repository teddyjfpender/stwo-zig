//! AIR IR v2 semantic model built directly from the production constraint
//! program.
//!
//! This first vertical slice intentionally supports only LUI.  It declares the
//! 18 committed LUI columns, constructs `ConstraintProgram(Scalar)` once, and
//! keeps the resulting node IDs verbatim.  Unlike the uniqueness model, it
//! creates no alias columns or alias-defining constraints.

const std = @import("std");
const constraint_program = @import("../constraint_program.zig");
const entry = @import("../lookups/entry.zig");
const model = @import("model.zig");
const symbolic = @import("symbolic.zig");

const Scalar = symbolic.Scalar;
const Builder = constraint_program.Builder(Scalar);

pub const LUI_COLUMN_COUNT: usize = Builder.mainColumnCount(.lui);
pub const LUI_DIRECT_CONSTRAINT_COUNT: usize = Builder.constraintCount(.lui);
pub const LUI_LOOKUP_COUNT: usize = constraint_program.entryCount(.lui);

pub const Error = error{
    NonEmptySymbolicArena,
    InvalidLuiProgramShape,
    InvalidNodeReference,
    InvalidColumnReference,
    MissingProgramProjection,
    DuplicateProgramProjection,
};

pub const ColumnRole = enum {
    input,
    output,
    witness,
};

pub const Column = struct {
    index: u32,
    name: []const u8,
    role: ColumnRole,
};

pub const Projection = struct {
    program_event: u32,
    state_events: [2]u32,
    source_events: [0]u32 = .{},
    destination_events: [2]u32,
    next_pc: u32,
};

/// Borrowed from `arena`; valid until that arena is deinitialized.
pub const LuiProgram = struct {
    columns: [LUI_COLUMN_COUNT]Column,
    production: Builder.ConstraintProgram,
    opcode_selector: u32,
    projection: Projection,
};

pub fn buildLui(arena: *symbolic.Arena) !LuiProgram {
    if (arena.nodes.items.len != 0 or arena.names.items.len != 0)
        return error.NonEmptySymbolicArena;

    var scalar_columns: [LUI_COLUMN_COUNT]Scalar = undefined;
    try model.declareColumns(arena, .lui, &scalar_columns);
    if (arena.names.items.len != LUI_COLUMN_COUNT)
        return error.InvalidLuiProgramShape;

    const production = try Builder.build(.lui, &scalar_columns, Scalar.one());
    if (production.direct_constraints.len != LUI_DIRECT_CONSTRAINT_COUNT or
        production.lookup_entries.len != LUI_LOOKUP_COUNT)
    {
        return error.InvalidLuiProgramShape;
    }

    var roles = [_]ColumnRole{.witness} ** LUI_COLUMN_COUNT;
    for (production.lookup_entries.entries[0..production.lookup_entries.len]) |lookup| {
        const role: ?ColumnRole = if (lookup.domain == .program_access)
            .input
        else switch (lookup.role) {
            .consume => .input,
            .emit => .output,
            .request => null,
        };
        if (role) |column_role| {
            for (lookup.values[0..lookup.arity]) |value|
                try markDependencies(arena, value.id, column_role, &roles);
        }
    }

    var columns: [LUI_COLUMN_COUNT]Column = undefined;
    for (&columns, arena.names.items, roles, 0..) |*column, name, role, index| {
        if (name.len == 0) return error.InvalidLuiProgramShape;
        column.* = .{
            .index = @intCast(index),
            .name = name,
            .role = role,
        };
    }

    var program_event: ?u32 = null;
    var state_consume: ?u32 = null;
    var state_emit: ?u32 = null;
    var destination_consume: ?u32 = null;
    var destination_emit: ?u32 = null;
    var access_gap_seen = false;
    var opcode_selector: ?u32 = null;
    var next_pc: ?u32 = null;

    const direct_count: u32 = @intCast(production.direct_constraints.len);
    for (
        production.lookup_entries.entries[0..production.lookup_entries.len],
        0..,
    ) |lookup, lookup_index| {
        const event_ordinal = direct_count + @as(u32, @intCast(lookup_index));
        switch (lookup.domain) {
            .program_access => {
                if (lookup.role != .request or lookup.access_ordinal != null)
                    return error.InvalidLuiProgramShape;
                try setOnce(&program_event, event_ordinal);
                opcode_selector = lookup.values[1].id;
            },
            .registers_state => {
                if (lookup.access_ordinal != null)
                    return error.InvalidLuiProgramShape;
                switch (lookup.role) {
                    .consume => try setOnce(&state_consume, event_ordinal),
                    .emit => {
                        try setOnce(&state_emit, event_ordinal);
                        next_pc = lookup.values[0].id;
                    },
                    .request => return error.InvalidLuiProgramShape,
                }
            },
            .memory_access => {
                if (lookup.access_ordinal != 1)
                    return error.InvalidLuiProgramShape;
                switch (lookup.role) {
                    .consume => try setOnce(&destination_consume, event_ordinal),
                    .emit => try setOnce(&destination_emit, event_ordinal),
                    .request => return error.InvalidLuiProgramShape,
                }
            },
            .range_check_20 => {
                if (lookup.access_ordinal) |ordinal| {
                    if (ordinal != 1 or access_gap_seen)
                        return error.InvalidLuiProgramShape;
                    access_gap_seen = true;
                }
            },
            else => {
                if (lookup.role != .request or lookup.access_ordinal != null)
                    return error.InvalidLuiProgramShape;
            },
        }
    }
    if (!access_gap_seen) return error.InvalidLuiProgramShape;

    return .{
        .columns = columns,
        .production = production,
        .opcode_selector = opcode_selector orelse
            return error.MissingProgramProjection,
        .projection = .{
            .program_event = program_event orelse
                return error.MissingProgramProjection,
            .state_events = .{
                state_consume orelse return error.MissingProgramProjection,
                state_emit orelse return error.MissingProgramProjection,
            },
            .destination_events = .{
                destination_consume orelse return error.MissingProgramProjection,
                destination_emit orelse return error.MissingProgramProjection,
            },
            .next_pc = next_pc orelse return error.MissingProgramProjection,
        },
    };
}

fn setOnce(slot: *?u32, value: u32) !void {
    if (slot.* != null) return error.DuplicateProgramProjection;
    slot.* = value;
}

fn markDependencies(
    arena: *const symbolic.Arena,
    node_id: u32,
    role: ColumnRole,
    roles: *[LUI_COLUMN_COUNT]ColumnRole,
) !void {
    if (node_id >= arena.nodes.items.len) return error.InvalidNodeReference;
    const node = arena.nodes.items[node_id];
    switch (node.op) {
        .constant => {},
        .column => {
            if (node.value >= roles.len) return error.InvalidColumnReference;
            promote(&roles[node.value], role);
        },
        .neg => try markDependencies(arena, node.lhs, role, roles),
        .add, .sub, .mul => {
            try markDependencies(arena, node.lhs, role, roles);
            try markDependencies(arena, node.rhs, role, roles);
        },
    }
}

fn promote(slot: *ColumnRole, role: ColumnRole) void {
    if (slot.* == .input) return;
    if (role == .input or slot.* == .witness) slot.* = role;
}

test "AIR IR v2 LUI model uses only committed columns and production roots" {
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const program = try buildLui(&arena);
    try std.testing.expectEqual(LUI_COLUMN_COUNT, program.columns.len);
    try std.testing.expectEqual(LUI_COLUMN_COUNT, arena.names.items.len);
    try std.testing.expectEqual(LUI_DIRECT_CONSTRAINT_COUNT, program.production.direct_constraints.len);
    try std.testing.expectEqual(LUI_LOOKUP_COUNT, program.production.lookup_entries.len);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT), program.projection.program_event);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 1), program.projection.state_events[0]);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 2), program.projection.state_events[1]);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 4), program.projection.destination_events[0]);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 5), program.projection.destination_events[1]);
    try std.testing.expectEqual(
        program.production.lookup_entries.entries[0].values[1].id,
        program.opcode_selector,
    );
    try std.testing.expectEqual(
        program.production.lookup_entries.entries[2].values[0].id,
        program.projection.next_pc,
    );

    // The uniqueness extractor would append `bus_value_*` aliases here.
    // Production IR v2 must retain exactly the committed column prefix.
    for (program.columns) |column|
        try std.testing.expect(!std.mem.startsWith(u8, column.name, "bus_value_"));
}
