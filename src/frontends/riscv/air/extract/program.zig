//! AIR IR v2 semantic model built directly from the production constraint
//! program.
//!
//! Every RV32IM opcode family is constructed through
//! `constraint_program.Builder(Scalar)`, the same typed builder interpreted by
//! the shipped QM31 evaluator and LogUp layer.  This module adds only wire
//! metadata: committed-column roles and the exact relation-event projection.
//! It does not add alias columns or restate a production constraint.

const std = @import("std");
const constraint_program = @import("../constraint_program.zig");
const entry = @import("../lookups/entry.zig");
const typed_lui_authority = @import("../lang/typed_lui_authority.zig");
const model = @import("model.zig");
const symbolic = @import("symbolic.zig");
const trace = @import("../../runner/trace.zig");

const Scalar = symbolic.Scalar;
const Builder = constraint_program.Builder(Scalar);

pub const MAX_COLUMNS: usize = trace.MAX_FAMILY_COLUMNS;
pub const MAX_SOURCE_EVENTS: usize = 4;
pub const MAX_DESTINATION_EVENTS: usize = 2;

pub const LUI_COLUMN_COUNT: usize = Builder.mainColumnCount(.lui);
pub const LUI_DIRECT_CONSTRAINT_COUNT: usize = Builder.constraintCount(.lui);
pub const LUI_LOOKUP_COUNT: usize = constraint_program.entryCount(.lui);

pub const Error = error{
    NonEmptySymbolicArena,
    InvalidProgramShape,
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
    source_events: [MAX_SOURCE_EVENTS]u32 = undefined,
    source_event_count: u8,
    destination_events: [MAX_DESTINATION_EVENTS]u32 = undefined,
    destination_event_count: u8,
    next_pc: u32,

    pub fn sourceSlice(self: *const Projection) []const u32 {
        return self.source_events[0..self.source_event_count];
    }

    pub fn destinationSlice(self: *const Projection) []const u32 {
        return self.destination_events[0..self.destination_event_count];
    }
};

/// Borrowed from `arena`; valid until that arena is deinitialized.
pub const Program = struct {
    family: trace.OpcodeFamily,
    column_count: usize,
    columns: [MAX_COLUMNS]Column = undefined,
    production: Builder.ConstraintProgram,
    opcode_selector: u32,
    projection: Projection,

    pub fn columnSlice(self: *const Program) []const Column {
        return self.columns[0..self.column_count];
    }
};

pub fn sourceAccessCount(family: trace.OpcodeFamily) u8 {
    return switch (family) {
        .base_alu_reg,
        .shifts_reg,
        .lt_reg,
        .branch_eq,
        .branch_lt,
        .load_store,
        .mul,
        .mulh,
        .div,
        => 2,
        .base_alu_imm,
        .shifts_imm,
        .lt_imm,
        .jalr,
        => 1,
        .lui,
        .auipc,
        .jal,
        .fence,
        => 0,
    };
}

pub fn hasDestination(family: trace.OpcodeFamily) bool {
    return switch (family) {
        .branch_eq, .branch_lt, .fence => false,
        else => true,
    };
}

pub fn build(arena: *symbolic.Arena, family: trace.OpcodeFamily) !Program {
    if (arena.nodes.items.len != 0 or arena.names.items.len != 0)
        return error.NonEmptySymbolicArena;

    const column_count = Builder.mainColumnCount(family);
    if (column_count > MAX_COLUMNS) return error.InvalidProgramShape;
    var scalar_columns: [MAX_COLUMNS]Scalar = undefined;
    try model.declareColumns(arena, family, scalar_columns[0..column_count]);
    if (arena.names.items.len != column_count)
        return error.InvalidProgramShape;

    const production = try Builder.build(
        family,
        scalar_columns[0..column_count],
        Scalar.one(),
    );
    return assemble(arena, family, column_count, &production);
}

/// Shadow activation seam for LUI formal export. The complete polynomial and
/// relation program is obtained through the already-authenticated executable
/// capability; wire-role/projection assembly remains the shared canonical
/// serializer path. Production `build` is intentionally unchanged.
pub fn buildLuiFromAuthority(
    arena: *symbolic.Arena,
    compiled: *const typed_lui_authority.Authority,
) !Program {
    if (arena.nodes.items.len != 0 or arena.names.items.len != 0)
        return error.NonEmptySymbolicArena;

    const column_count = LUI_COLUMN_COUNT;
    var scalar_columns: [LUI_COLUMN_COUNT]Scalar = undefined;
    try model.declareColumns(arena, .lui, &scalar_columns);
    if (arena.names.items.len != column_count)
        return error.InvalidProgramShape;

    const fixed = try compiled.buildProgram(
        Scalar,
        &scalar_columns,
        Scalar.one(),
    );
    var direct = Builder.DirectConstraints{
        .len = typed_lui_authority.DIRECT_CONSTRAINT_COUNT,
    };
    @memcpy(
        direct.values[0..typed_lui_authority.DIRECT_CONSTRAINT_COUNT],
        &fixed.direct_constraints.values,
    );
    const production = Builder.ConstraintProgram{
        .active_row = fixed.active_row,
        .direct_constraints = direct,
        .lookup_entries = fixed.lookup_entries,
    };
    return assemble(arena, .lui, column_count, &production);
}

fn assemble(
    arena: *symbolic.Arena,
    family: trace.OpcodeFamily,
    column_count: usize,
    production: *const Builder.ConstraintProgram,
) !Program {
    if (production.direct_constraints.len != Builder.constraintCount(family) or
        production.lookup_entries.len != constraint_program.entryCount(family))
    {
        return error.InvalidProgramShape;
    }

    var roles = [_]ColumnRole{.witness} ** MAX_COLUMNS;
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
                try markDependencies(
                    arena,
                    value.id,
                    column_role,
                    roles[0..column_count],
                );
        }
    }

    var result = Program{
        .family = family,
        .column_count = column_count,
        .production = production.*,
        .opcode_selector = undefined,
        .projection = undefined,
    };
    for (
        result.columns[0..column_count],
        arena.names.items,
        roles[0..column_count],
        0..,
    ) |*column, name, role, index| {
        if (name.len == 0) return error.InvalidProgramShape;
        column.* = .{
            .index = @intCast(index),
            .name = name,
            .role = role,
        };
    }

    var program_event: ?u32 = null;
    var state_events = [_]?u32{null} ** 2;
    var source_events = [_]?u32{null} ** MAX_SOURCE_EVENTS;
    var destination_events = [_]?u32{null} ** MAX_DESTINATION_EVENTS;
    var opcode_selector: ?u32 = null;
    var next_pc: ?u32 = null;

    const source_access_count = sourceAccessCount(family);
    const destination_access: ?u8 =
        if (hasDestination(family)) source_access_count + 1 else null;
    const direct_count: u32 = @intCast(production.direct_constraints.len);
    for (
        production.lookup_entries.entries[0..production.lookup_entries.len],
        0..,
    ) |lookup, lookup_index| {
        const event_ordinal = direct_count + @as(u32, @intCast(lookup_index));
        switch (lookup.domain) {
            .program_access => {
                if (lookup.role != .request or lookup.access_ordinal != null)
                    return error.InvalidProgramShape;
                try setOnce(&program_event, event_ordinal);
                if (lookup.arity < 2) return error.InvalidProgramShape;
                opcode_selector = lookup.values[1].id;
            },
            .registers_state => {
                if (lookup.access_ordinal != null)
                    return error.InvalidProgramShape;
                switch (lookup.role) {
                    .consume => try setOnce(&state_events[0], event_ordinal),
                    .emit => {
                        try setOnce(&state_events[1], event_ordinal);
                        if (lookup.arity < 1) return error.InvalidProgramShape;
                        next_pc = lookup.values[0].id;
                    },
                    .request => return error.InvalidProgramShape,
                }
            },
            .memory_access => {
                const access_ordinal =
                    lookup.access_ordinal orelse return error.InvalidProgramShape;
                const role_offset: usize = switch (lookup.role) {
                    .consume => 0,
                    .emit => 1,
                    .request => return error.InvalidProgramShape,
                };
                if (access_ordinal <= source_access_count) {
                    const slot = (@as(usize, access_ordinal) - 1) * 2 + role_offset;
                    if (slot >= source_events.len) return error.InvalidProgramShape;
                    try setOnce(&source_events[slot], event_ordinal);
                } else if (destination_access != null and
                    access_ordinal == destination_access.?)
                {
                    try setOnce(&destination_events[role_offset], event_ordinal);
                } else {
                    return error.InvalidProgramShape;
                }
            },
            .range_check_20 => {
                if (lookup.role != .request) return error.InvalidProgramShape;
                if (lookup.access_ordinal) |ordinal| {
                    const access_count =
                        source_access_count + @as(u8, @intFromBool(destination_access != null));
                    if (ordinal == 0 or ordinal > access_count)
                        return error.InvalidProgramShape;
                }
            },
            else => {
                if (lookup.role != .request or lookup.access_ordinal != null)
                    return error.InvalidProgramShape;
            },
        }
    }

    var projection = Projection{
        .program_event = program_event orelse
            return error.MissingProgramProjection,
        .state_events = .{
            state_events[0] orelse return error.MissingProgramProjection,
            state_events[1] orelse return error.MissingProgramProjection,
        },
        .source_event_count = source_access_count * 2,
        .destination_event_count = if (destination_access != null) MAX_DESTINATION_EVENTS else 0,
        .next_pc = next_pc orelse return error.MissingProgramProjection,
    };
    for (projection.source_events[0..projection.source_event_count], 0..) |*slot, index|
        slot.* = source_events[index] orelse return error.MissingProgramProjection;
    for (
        projection.destination_events[0..projection.destination_event_count],
        0..,
    ) |*slot, index|
        slot.* = destination_events[index] orelse
            return error.MissingProgramProjection;

    result.opcode_selector = opcode_selector orelse
        return error.MissingProgramProjection;
    result.projection = projection;
    return result;
}

pub fn buildLui(arena: *symbolic.Arena) !Program {
    return build(arena, .lui);
}

fn setOnce(slot: *?u32, value: u32) !void {
    if (slot.* != null) return error.DuplicateProgramProjection;
    slot.* = value;
}

fn markDependencies(
    arena: *const symbolic.Arena,
    node_id: u32,
    role: ColumnRole,
    roles: []ColumnRole,
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

test "AIR IR v2 builds exact projections for all 17 production families" {
    for (0..trace.N_FAMILIES) |index| {
        var arena = symbolic.Arena.init(std.testing.allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();

        const family: trace.OpcodeFamily = @enumFromInt(index);
        const program = try build(&arena, family);
        try std.testing.expectEqual(
            Builder.mainColumnCount(family),
            program.column_count,
        );
        try std.testing.expectEqual(
            Builder.constraintCount(family),
            program.production.direct_constraints.len,
        );
        try std.testing.expectEqual(
            constraint_program.entryCount(family),
            program.production.lookup_entries.len,
        );
        try std.testing.expectEqual(
            @as(usize, sourceAccessCount(family) * 2),
            program.projection.sourceSlice().len,
        );
        try std.testing.expectEqual(
            if (hasDestination(family)) @as(usize, 2) else 0,
            program.projection.destinationSlice().len,
        );
        try std.testing.expectEqual(
            program.production.lookup_entries
                .entries[
                    program.projection.program_event -
                        program.production.direct_constraints.len
                ]
                .values[1].id,
            program.opcode_selector,
        );

        for (program.columnSlice()) |column|
            try std.testing.expect(!std.mem.startsWith(u8, column.name, "bus_value_"));
    }
}

test "AIR IR v2 LUI projection retains the frozen event layout" {
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const program = try buildLui(&arena);
    try std.testing.expectEqual(LUI_COLUMN_COUNT, program.column_count);
    try std.testing.expectEqual(LUI_COLUMN_COUNT, arena.names.items.len);
    try std.testing.expectEqual(LUI_DIRECT_CONSTRAINT_COUNT, program.production.direct_constraints.len);
    try std.testing.expectEqual(LUI_LOOKUP_COUNT, program.production.lookup_entries.len);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT), program.projection.program_event);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 1), program.projection.state_events[0]);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 2), program.projection.state_events[1]);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 4), program.projection.destinationSlice()[0]);
    try std.testing.expectEqual(@as(u32, LUI_DIRECT_CONSTRAINT_COUNT + 5), program.projection.destinationSlice()[1]);
    try std.testing.expectEqual(
        program.production.lookup_entries.entries[0].values[1].id,
        program.opcode_selector,
    );
    try std.testing.expectEqual(
        program.production.lookup_entries.entries[2].values[0].id,
        program.projection.next_pc,
    );
}
