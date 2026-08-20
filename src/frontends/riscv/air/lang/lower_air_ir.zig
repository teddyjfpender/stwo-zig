//! Exact AIR IR v2 compatibility projection from the validated typed shadow.
//!
//! AIR IR v2 fixes active-row placement to one and preserves historical source
//! node numbering, including commutative operand orientation. The semantic
//! compiler uses canonical typed nodes; the shadow's checked raw provenance is
//! used here only to reproduce that frozen wire schedule. The existing
//! production JSON writer remains the sole encoding implementation.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const constraint_program = @import("../constraint_program.zig");
const production_entry = @import("../lookups/entry.zig");
const program_json = @import("../extract/program_json.zig");
const program_mod = @import("../extract/program.zig");
const symbolic = @import("../extract/symbolic.zig");
const opcode_manifest = @import("../../opcode_manifest.zig");
const trace = @import("../../runner/trace.zig");
const compat_layout = @import("compat_layout.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");

const Builder = constraint_program.Builder(symbolic.Scalar);
const EntryBuilder = production_entry.Builder(symbolic.Scalar);
const no_node = std.math.maxInt(u32);
const unused_scalar = symbolic.Scalar{ .id = no_node };
const unused_entry = EntryBuilder.Entry{
    .domain = .registers_state,
    .numerator = unused_scalar,
    .values = .{unused_scalar} ** production_entry.MAX_ARITY,
    .arity = 0,
};
const unused_column = program_mod.Column{
    .index = no_node,
    .name = "",
    .role = .witness,
};

pub const Error = error{
    DuplicateProjection,
    InvalidColumn,
    InvalidNode,
    InvalidProgramShape,
    MissingProjection,
    NodeCountOverflow,
};

/// Owns the reconstructed symbolic arena. Column names in `program` and
/// `arena.names` borrow from `imported`, so this value must not outlive it.
pub const Owned = struct {
    arena: symbolic.Arena,
    program: program_mod.Program,

    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(
        self: *const Owned,
        imported: *const shadow_program.ImportedProgram,
        layout: *const compat_layout.Layout,
    ) !void {
        try layout.validate(imported);
        if (self.program.family != imported.family or
            self.program.column_count != imported.main_column_count or
            self.arena.names.items.len != imported.main_column_count or
            self.arena.interned.count() != self.arena.nodes.items.len)
        {
            return error.InvalidProgramShape;
        }
        for (self.arena.nodes.items, 0..) |node, index| {
            const expected_index = std.math.cast(u32, index) orelse
                return error.NodeCountOverflow;
            if (self.arena.interned.get(node) != expected_index)
                return error.InvalidNode;
            switch (node.op) {
                .constant => if (node.lhs != 0 or node.rhs != 0 or
                    node.value >= m31.Modulus)
                {
                    return error.InvalidNode;
                },
                .column => if (node.lhs != 0 or node.rhs != 0 or
                    node.value >= self.program.column_count)
                {
                    return error.InvalidColumn;
                },
                .add, .sub, .mul => if (node.value != 0 or
                    node.lhs >= index or node.rhs >= index)
                {
                    return error.InvalidNode;
                },
                .neg => if (node.rhs != 0 or node.value != 0 or node.lhs >= index)
                    return error.InvalidNode,
            }
        }

        for (self.program.columnSlice(), layout.main(), 0..) |column, mapped, index| {
            if (column.index != index or
                !std.mem.eql(u8, column.name, mapped.logical_name))
            {
                return error.InvalidColumn;
            }
        }
        const production = self.program.production;
        if (production.direct_constraints.len != imported.direct_constraints.len or
            production.lookup_entries.len != imported.lookups.len or
            production.lookup_entries.batch_size != imported.batch_size)
        {
            return error.InvalidProgramShape;
        }
        if (production.active_row.id >= self.arena.nodes.items.len)
            return error.InvalidNode;
        for (production.direct_constraints.values[0..production.direct_constraints.len]) |root| {
            if (root.id >= self.arena.nodes.items.len) return error.InvalidNode;
        }
        for (production.direct_constraints.values[production.direct_constraints.len..]) |unused| {
            if (unused.id != no_node) return error.InvalidProgramShape;
        }
        for (production.lookup_entries.entries[0..production.lookup_entries.len]) |entry| {
            try entry.validate();
            if (entry.numerator.id >= self.arena.nodes.items.len)
                return error.InvalidNode;
            for (entry.values[0..entry.arity]) |value| {
                if (value.id >= self.arena.nodes.items.len)
                    return error.InvalidNode;
            }
            for (entry.values[entry.arity..]) |unused| {
                if (unused.id != no_node) return error.InvalidProgramShape;
            }
        }
        for (production.lookup_entries.entries[production.lookup_entries.len..]) |unused| {
            if (!std.meta.eql(unused, unused_entry))
                return error.InvalidProgramShape;
        }
        for (self.program.columns[self.program.column_count..]) |unused| {
            if (!std.meta.eql(unused, unused_column))
                return error.InvalidProgramShape;
        }
        const derived = try deriveProjection(imported.family, &production);
        if (self.program.opcode_selector != derived.opcode_selector or
            !std.meta.eql(self.program.projection, derived.projection))
        {
            return error.InvalidProgramShape;
        }
        const expected_roles = try columnRoles(&self.arena, &production);
        for (self.program.columnSlice(), expected_roles[0..self.program.column_count]) |column, role| {
            if (column.role != role) return error.InvalidColumn;
        }
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !Owned {
    try layout.validate(imported);
    const source_nodes = imported.imported.source_nodes;
    const mapped = try allocator.alloc(u32, source_nodes.len);
    defer allocator.free(mapped);
    @memset(mapped, no_node);

    var arena = symbolic.Arena.init(allocator);
    errdefer arena.deinit();
    for (0..imported.main_column_count) |column_index| {
        const source_index = findSourceColumn(source_nodes, column_index) orelse
            return error.InvalidColumn;
        const target = try intern(&arena, .{
            .op = .column,
            .value = @intCast(column_index),
        });
        if (target != column_index) return error.InvalidColumn;
        try arena.names.append(allocator, layout.main()[column_index].logical_name);
        mapped[source_index] = target;
    }

    const selector_index: usize = imported.source_selector;
    if (selector_index >= source_nodes.len or
        source_nodes[selector_index].op != .column or
        source_nodes[selector_index].value != imported.main_column_count)
    {
        return error.InvalidColumn;
    }
    const one = try intern(&arena, .{ .op = .constant, .value = 1 });
    if (one != imported.main_column_count) return error.InvalidNode;
    mapped[selector_index] = one;

    for (source_nodes, 0..) |source_node, source_index| {
        if (mapped[source_index] != no_node) continue;
        const target_node = switch (source_node.op) {
            .constant => symbolic.Node{
                .op = .constant,
                .value = M31.fromU64(source_node.value).toU32(),
            },
            .column => return error.InvalidColumn,
            .add, .sub, .mul => symbolic.Node{
                .op = source_node.op,
                .lhs = try mappedNode(mapped, source_node.lhs),
                .rhs = try mappedNode(mapped, source_node.rhs),
            },
            .neg => symbolic.Node{
                .op = .neg,
                .lhs = try mappedNode(mapped, source_node.lhs),
            },
        };
        mapped[source_index] = try intern(&arena, target_node);
    }

    var direct = Builder.DirectConstraints{
        .values = .{unused_scalar} ** Builder.MAX_DIRECT_CONSTRAINTS,
    };
    for (imported.direct_source_roots) |source_root| {
        if (direct.len >= direct.values.len) return error.InvalidProgramShape;
        direct.values[direct.len] = .{ .id = try mappedNode(mapped, source_root) };
        direct.len += 1;
    }

    var lookups = EntryBuilder.List{
        .entries = .{unused_entry} ** production_entry.MAX_ENTRIES,
        .batch_size = imported.batch_size,
    };
    for (imported.lookups, 0..) |lookup, lookup_index| {
        const fields = imported.sourceLookupFields(lookup_index) orelse
            return error.InvalidProgramShape;
        var entry = EntryBuilder.Entry{
            .domain = productionDomain(lookup.schema) orelse
                return error.InvalidProgramShape,
            .numerator = .{ .id = try mappedNode(mapped, lookup.source_numerator) },
            .values = .{unused_scalar} ** production_entry.MAX_ARITY,
            .arity = @intCast(fields.len),
            .role = productionRole(lookup.role),
            .access_ordinal = lookup.access_ordinal,
        };
        for (fields, entry.values[0..fields.len]) |source_field, *field|
            field.* = .{ .id = try mappedNode(mapped, source_field) };
        try entry.validate();
        lookups.append(entry);
    }

    const production = Builder.ConstraintProgram{
        .active_row = .{ .id = try mappedNode(mapped, imported.source_active_row) },
        .direct_constraints = direct,
        .lookup_entries = lookups,
    };
    const projection = try deriveProjection(imported.family, &production);
    const roles = try columnRoles(&arena, &production);
    var program = program_mod.Program{
        .family = imported.family,
        .column_count = imported.main_column_count,
        .columns = .{unused_column} ** program_mod.MAX_COLUMNS,
        .production = production,
        .opcode_selector = projection.opcode_selector,
        .projection = projection.projection,
    };
    for (
        program.columns[0..program.column_count],
        layout.main(),
        roles[0..program.column_count],
        0..,
    ) |*column, mapped_column, role, index| {
        column.* = .{
            .index = @intCast(index),
            .name = mapped_column.logical_name,
            .role = role,
        };
    }
    var result = Owned{ .arena = arena, .program = program };
    try result.validate(imported, layout);
    return result;
}

pub fn emitOpcode(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
    opcode: opcode_manifest.Entry,
) !void {
    if (opcode.family != imported.family) return error.InvalidProgramShape;
    var lowered = try build(allocator, imported, layout);
    defer lowered.deinit();
    try program_json.writeProgram(
        writer,
        &lowered.arena,
        &lowered.program,
        opcode,
    );
}

pub fn emitLui(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    return emitOpcode(
        allocator,
        writer,
        imported,
        layout,
        opcode_manifest.entries[program_json.LUI_MANIFEST_ID],
    );
}

const ProjectionResult = struct {
    opcode_selector: u32,
    projection: program_mod.Projection,
};

fn deriveProjection(
    family: trace.OpcodeFamily,
    production: *const Builder.ConstraintProgram,
) !ProjectionResult {
    var program_event: ?u32 = null;
    var state_events = [_]?u32{null} ** 2;
    var source_events = [_]?u32{null} ** program_mod.MAX_SOURCE_EVENTS;
    var destination_events = [_]?u32{null} ** program_mod.MAX_DESTINATION_EVENTS;
    var opcode_selector: ?u32 = null;
    var next_pc: ?u32 = null;

    const source_access_count = program_mod.sourceAccessCount(family);
    const destination_access: ?u8 =
        if (program_mod.hasDestination(family)) source_access_count + 1 else null;
    const direct_count = std.math.cast(u32, production.direct_constraints.len) orelse
        return error.InvalidProgramShape;
    for (production.lookup_entries.entries[0..production.lookup_entries.len], 0..) |lookup, index| {
        const ordinal = std.math.add(
            u32,
            direct_count,
            std.math.cast(u32, index) orelse return error.InvalidProgramShape,
        ) catch return error.InvalidProgramShape;
        switch (lookup.domain) {
            .program_access => {
                if (lookup.role != .request or lookup.access_ordinal != null or
                    lookup.arity < 2)
                {
                    return error.InvalidProgramShape;
                }
                try setOnce(&program_event, ordinal);
                opcode_selector = lookup.values[1].id;
            },
            .registers_state => {
                if (lookup.access_ordinal != null) return error.InvalidProgramShape;
                switch (lookup.role) {
                    .consume => try setOnce(&state_events[0], ordinal),
                    .emit => {
                        if (lookup.arity < 1) return error.InvalidProgramShape;
                        try setOnce(&state_events[1], ordinal);
                        next_pc = lookup.values[0].id;
                    },
                    .request => return error.InvalidProgramShape,
                }
            },
            .memory_access => {
                const access = lookup.access_ordinal orelse
                    return error.InvalidProgramShape;
                const role_offset: usize = switch (lookup.role) {
                    .consume => 0,
                    .emit => 1,
                    .request => return error.InvalidProgramShape,
                };
                if (access <= source_access_count) {
                    if (access == 0) return error.InvalidProgramShape;
                    const slot = (@as(usize, access) - 1) * 2 + role_offset;
                    if (slot >= source_events.len) return error.InvalidProgramShape;
                    try setOnce(&source_events[slot], ordinal);
                } else if (destination_access != null and access == destination_access.?) {
                    try setOnce(&destination_events[role_offset], ordinal);
                } else return error.InvalidProgramShape;
            },
            .range_check_20 => {
                if (lookup.role != .request) return error.InvalidProgramShape;
                if (lookup.access_ordinal) |access| {
                    const access_count = source_access_count +
                        @as(u8, @intFromBool(destination_access != null));
                    if (access == 0 or access > access_count)
                        return error.InvalidProgramShape;
                }
            },
            else => if (lookup.role != .request or lookup.access_ordinal != null)
                return error.InvalidProgramShape,
        }
    }

    var projection = program_mod.Projection{
        .program_event = program_event orelse return error.MissingProjection,
        .state_events = .{
            state_events[0] orelse return error.MissingProjection,
            state_events[1] orelse return error.MissingProjection,
        },
        .source_events = .{0} ** program_mod.MAX_SOURCE_EVENTS,
        .source_event_count = source_access_count * 2,
        .destination_events = .{0} ** program_mod.MAX_DESTINATION_EVENTS,
        .destination_event_count = if (destination_access != null)
            program_mod.MAX_DESTINATION_EVENTS
        else
            0,
        .next_pc = next_pc orelse return error.MissingProjection,
    };
    for (projection.source_events[0..projection.source_event_count], 0..) |*slot, index|
        slot.* = source_events[index] orelse return error.MissingProjection;
    for (projection.destination_events[0..projection.destination_event_count], 0..) |*slot, index|
        slot.* = destination_events[index] orelse return error.MissingProjection;
    return .{
        .opcode_selector = opcode_selector orelse return error.MissingProjection,
        .projection = projection,
    };
}

fn columnRoles(
    arena: *const symbolic.Arena,
    production: *const Builder.ConstraintProgram,
) ![program_mod.MAX_COLUMNS]program_mod.ColumnRole {
    var roles = [_]program_mod.ColumnRole{.witness} ** program_mod.MAX_COLUMNS;
    for (production.lookup_entries.entries[0..production.lookup_entries.len]) |lookup| {
        const role: ?program_mod.ColumnRole = if (lookup.domain == .program_access)
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
    return roles;
}

fn markDependencies(
    arena: *const symbolic.Arena,
    node_id: u32,
    role: program_mod.ColumnRole,
    roles: *[program_mod.MAX_COLUMNS]program_mod.ColumnRole,
) !void {
    if (node_id >= arena.nodes.items.len) return error.InvalidNode;
    const node = arena.nodes.items[node_id];
    switch (node.op) {
        .constant => {},
        .column => {
            if (node.value >= roles.len) return error.InvalidColumn;
            promote(&roles[node.value], role);
        },
        .neg => try markDependencies(arena, node.lhs, role, roles),
        .add, .sub, .mul => {
            try markDependencies(arena, node.lhs, role, roles);
            try markDependencies(arena, node.rhs, role, roles);
        },
    }
}

fn promote(slot: *program_mod.ColumnRole, role: program_mod.ColumnRole) void {
    if (slot.* == .input) return;
    if (role == .input or slot.* == .witness) slot.* = role;
}

fn findSourceColumn(nodes: []const symbolic.Node, column_index: usize) ?u32 {
    for (nodes, 0..) |node, index| {
        if (node.op == .column and node.value == column_index)
            return std.math.cast(u32, index);
    }
    return null;
}

fn mappedNode(mapped: []const u32, source: u32) Error!u32 {
    if (source >= mapped.len or mapped[source] == no_node)
        return error.InvalidNode;
    return mapped[source];
}

fn intern(arena: *symbolic.Arena, node: symbolic.Node) !u32 {
    if (arena.interned.get(node)) |existing| return existing;
    const id = std.math.cast(u32, arena.nodes.items.len) orelse
        return error.NodeCountOverflow;
    try arena.nodes.append(arena.allocator, node);
    errdefer _ = arena.nodes.pop();
    try arena.interned.put(node, id);
    return id;
}

fn setOnce(slot: *?u32, value: u32) Error!void {
    if (slot.* != null) return error.DuplicateProjection;
    slot.* = value;
}

fn productionDomain(schema_id: @import("types.zig").RelationSchemaId) ?production_entry.Domain {
    const schema = relation.getById(schema_id) orelse return null;
    if (@intFromEnum(schema.domain) >=
        @typeInfo(production_entry.Domain).@"enum".fields.len)
    {
        return null;
    }
    return @enumFromInt(@intFromEnum(schema.domain));
}

fn productionRole(role: relation.Role) production_entry.EventRole {
    return @enumFromInt(@intFromEnum(role));
}

comptime {
    @setEvalBranchQuota(10_000);
    if (relation.schemas.len !=
        @typeInfo(production_entry.Domain).@"enum".fields.len)
    {
        @compileError("AIR IR compatibility requires aligned relation domains");
    }
    for (@typeInfo(relation.Domain).@"enum".fields[0..relation.schemas.len]) |field| {
        const target = std.meta.stringToEnum(
            production_entry.Domain,
            field.name,
        ) orelse @compileError("AIR IR relation domain name mismatch");
        if (@intFromEnum(target) != field.value)
            @compileError("AIR IR relation domain tag mismatch");
    }
    if (@typeInfo(relation.Role).@"enum".fields.len !=
        @typeInfo(production_entry.EventRole).@"enum".fields.len)
    {
        @compileError("AIR IR compatibility requires aligned relation roles");
    }
    for (@typeInfo(relation.Role).@"enum".fields) |field| {
        const target = std.meta.stringToEnum(
            production_entry.EventRole,
            field.name,
        ) orelse @compileError("AIR IR relation role name mismatch");
        if (@intFromEnum(target) != field.value)
            @compileError("AIR IR relation role tag mismatch");
    }
}
