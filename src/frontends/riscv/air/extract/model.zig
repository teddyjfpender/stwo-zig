//! Build one family's per-row uniqueness model by running the shipped AIR.
//!
//! Nothing here restates a constraint. `semantic_eval.Eval(Scalar)` and
//! `opcode_entries.Entries(Scalar)` are the same declarations the prover uses,
//! instantiated over the recording scalar; this module only decides which
//! columns the uniqueness question quantifies over, and that decision is
//! derived from the relation requests rather than from a hand-written table.

const std = @import("std");
const symbolic = @import("symbolic.zig");
const semantics = @import("../semantics/mod.zig");
const semantic_eval = @import("../semantic_eval.zig");
const entry_mod = @import("../lookups/entry.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const trace = @import("../../runner/trace.zig");

const Scalar = symbolic.Scalar;
const sem = semantics.Families(Scalar);
const Eval = semantic_eval.Eval(Scalar);
const Entries = opcode_entries.Entries(Scalar);

pub const Error = error{
    /// The builder no longer emits bus requests in consume/emit pairs, so the
    /// input/output split below would be silently wrong. Fail rather than model.
    UnpairedBusRequest,
} || std.mem.Allocator.Error;

/// `input` is shared between the two candidate witnesses, `output` must agree,
/// `witness` is free in each. See `docs` below for how each is derived.
pub const Role = enum { input, output, witness };

pub const Column = struct {
    name: []const u8,
    role: Role,
};

pub const Lookup = struct {
    label: []const u8,
    domain: entry_mod.Domain,
    numerator: u32,
    tuple: []const u32,
};

/// One family's model. `arena` is borrowed; `System` owns only its own slices.
pub const System = struct {
    family: trace.OpcodeFamily,
    columns: []Column,
    constraints: []u32,
    lookups: []Lookup,
    /// Bus requests that assert nothing per row, reported so a green result is
    /// read with the right scope.
    unmodelled_bus_requests: usize,

    pub fn deinit(self: *System, allocator: std.mem.Allocator) void {
        for (self.lookups) |lookup| allocator.free(lookup.tuple);
        allocator.free(self.lookups);
        allocator.free(self.constraints);
        allocator.free(self.columns);
    }
};

pub fn moduleOf(comptime family: trace.OpcodeFamily) type {
    return switch (family) {
        .base_alu_reg => sem.base_alu_reg,
        .base_alu_imm => sem.base_alu_imm,
        .shifts_reg => sem.shifts_reg,
        .shifts_imm => sem.shifts_imm,
        .lt_reg => sem.lt_reg,
        .lt_imm => sem.lt_imm,
        .branch_eq => sem.branch_eq,
        .branch_lt => sem.branch_lt,
        .lui => sem.lui,
        .auipc => sem.auipc,
        .jalr => sem.jalr,
        .jal => sem.jal,
        .load_store => sem.load_store,
        .mul => sem.mul,
        .mulh => sem.mulh,
        .div => sem.div,
        .fence => sem.fence,
    };
}

/// Install one recording column per committed trace column, named by the field
/// path `Row.from*Columns` puts it at. The name is what a counterexample reads
/// as, so it has to come from the layout adapter rather than a side table.
pub fn declareColumns(
    arena: *symbolic.Arena,
    family: trace.OpcodeFamily,
    out: []Scalar,
) !void {
    std.debug.assert(out.len == Eval.mainColumnCount(family));
    for (out, 0..) |*column, index| {
        _ = index;
        column.* = arena.column("");
    }
    switch (family) {
        inline else => |f| {
            const Module = moduleOf(f);
            const row = try parse(Module, out);
            nameLeaves(Module.Row, row, "", arena);
        },
    }
    for (arena.names.items, 0..) |name, index| {
        if (name.len == 0) arena.names.items[index] = unnamed(index);
    }
}

fn parse(comptime Module: type, columns: []const Scalar) !Module.Row {
    if (@hasDecl(Module.Row, "fromOracleColumns")) return Module.Row.fromOracleColumns(columns);
    return Module.Row.fromMainColumns(columns);
}

fn unnamed(index: usize) []const u8 {
    // Bounded because every family's column count is a compile-time constant
    // below `trace.MAX_FAMILY_COLUMNS`; the table is comptime, so no allocation.
    const table = comptime blk: {
        @setEvalBranchQuota(40_000);
        var names: [trace.MAX_FAMILY_COLUMNS][]const u8 = undefined;
        for (&names, 0..) |*name, i| name.* = std.fmt.comptimePrint("col{d}", .{i});
        break :blk names;
    };
    return table[index];
}

/// Field-path names, `_`-joined. The separator is not cosmetic: these names
/// become SMT-LIB symbols in `scripts/air_uniqueness_lib/smtlib.py`, which does
/// not quote them, so `.` and `[]` would make the query unparseable.
fn nameLeaves(
    comptime T: type,
    value: T,
    comptime path: []const u8,
    arena: *symbolic.Arena,
) void {
    if (T == Scalar) {
        const node = arena.nodes.items[value.id];
        if (node.op != .column) return;
        if (arena.names.items[node.value].len != 0) return;
        arena.names.items[node.value] = comptime if (path.len > 0 and path[0] == '_') path[1..] else path;
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.fields) |field| {
            nameLeaves(field.type, @field(value, field.name), path ++ "_" ++ field.name, arena);
        },
        .array => |info| inline for (0..info.len) |index| {
            nameLeaves(info.child, value[index], path ++ std.fmt.comptimePrint("_{d}", .{index}), arena);
        },
        else => {},
    }
}

/// Run the shipped AIR over the recording scalar and classify what it touched.
///
/// Roles are read off the relation requests, not declared:
///   * every component of a `program_access` tuple is `input` -- that tuple is
///     the fetched instruction, and granting the program bus is the only way a
///     per-row question can talk about "the same instruction" at all;
///   * every component of the consumed side of a `memory_access` or
///     `registers_state` pair is `input` -- what the row was handed;
///   * every component of the emitted side is `output` -- what the row claims
///     about the machine afterwards, which is its entire observable effect;
///   * `input` beats `output` beats `witness` where a column appears twice
///     (an access address is consumed and emitted, and is genuinely given);
///   * everything the buses never mention stays `witness`: sign bits, carries,
///     comparison markers, inverse certificates.
/// A tuple component that is an expression rather than a bare column becomes an
/// alias column with a defining constraint, which is exactly equivalent and
/// keeps one mechanism for both directions.
pub fn build(
    allocator: std.mem.Allocator,
    arena: *symbolic.Arena,
    family: trace.OpcodeFamily,
) !System {
    const n_columns = Eval.mainColumnCount(family);
    const columns = try allocator.alloc(Scalar, n_columns);
    defer allocator.free(columns);
    try declareColumns(arena, family, columns);

    const evaluation = try Eval.evaluate(family, columns, Scalar.one());
    const list = try Entries.fromMain(family, columns);

    const roles = try allocator.alloc(Role, n_columns);
    defer allocator.free(roles);
    @memset(roles, .witness);

    var constraints = try std.ArrayList(u32).initCapacity(allocator, evaluation.len);
    errdefer constraints.deinit(allocator);
    for (evaluation.values[0..evaluation.len]) |value| {
        constraints.appendAssumeCapacity(value.id);
    }

    var lookups = try std.ArrayList(Lookup).initCapacity(allocator, list.len);
    errdefer {
        for (lookups.items) |lookup| allocator.free(lookup.tuple);
        lookups.deinit(allocator);
    }

    var alias_roles = std.ArrayList(Role).empty;
    defer alias_roles.deinit(allocator);
    var alias_of = std.AutoHashMap(u32, u32).init(allocator);
    defer alias_of.deinit();

    var unmodelled: usize = 0;
    var index: usize = 0;
    while (index < list.len) {
        const item = list.entries[index];
        const paired = item.domain == .memory_access or item.domain == .registers_state;
        if (paired) {
            if (index + 1 >= list.len or list.entries[index + 1].domain != item.domain) {
                return error.UnpairedBusRequest;
            }
            unmodelled += 2;
            try classify(allocator, arena, item, .input, roles, &alias_roles, &alias_of, &constraints);
            try classify(allocator, arena, list.entries[index + 1], .output, roles, &alias_roles, &alias_of, &constraints);
            try lookups.append(allocator, try record(allocator, item, "consumed"));
            try lookups.append(allocator, try record(allocator, list.entries[index + 1], "emitted"));
            index += 2;
            continue;
        }
        if (item.domain == .program_access) {
            unmodelled += 1;
            try classify(allocator, arena, item, .input, roles, &alias_roles, &alias_of, &constraints);
        }
        try lookups.append(allocator, try record(allocator, item, "request"));
        index += 1;
    }

    std.debug.assert(arena.names.items.len == n_columns + alias_roles.items.len);
    const out_columns = try allocator.alloc(Column, arena.names.items.len);
    errdefer allocator.free(out_columns);
    for (out_columns[0..n_columns], arena.names.items[0..n_columns], roles) |*column, name, role| {
        column.* = .{ .name = name, .role = role };
    }
    for (out_columns[n_columns..], arena.names.items[n_columns..], alias_roles.items) |*column, name, role| {
        column.* = .{ .name = name, .role = role };
    }

    return .{
        .family = family,
        .columns = out_columns,
        .constraints = try constraints.toOwnedSlice(allocator),
        .lookups = try lookups.toOwnedSlice(allocator),
        .unmodelled_bus_requests = unmodelled,
    };
}

fn record(
    allocator: std.mem.Allocator,
    item: anytype,
    comptime label: []const u8,
) !Lookup {
    const tuple = try allocator.alloc(u32, item.arity);
    for (tuple, item.values[0..item.arity]) |*slot, value| slot.* = value.id;
    return .{
        .label = label,
        .domain = item.domain,
        .numerator = item.numerator.id,
        .tuple = tuple,
    };
}

fn classify(
    allocator: std.mem.Allocator,
    arena: *symbolic.Arena,
    item: anytype,
    role: Role,
    roles: []Role,
    alias_roles: *std.ArrayList(Role),
    alias_of: *std.AutoHashMap(u32, u32),
    constraints: *std.ArrayList(u32),
) !void {
    for (item.values[0..item.arity]) |value| {
        const node = arena.nodes.items[value.id];
        switch (node.op) {
            .constant => {},
            .column => promote(&roles[node.value], role),
            else => {
                if (alias_of.get(value.id)) |existing| {
                    promote(&alias_roles.items[existing], role);
                    continue;
                }
                const position: u32 = @intCast(alias_roles.items.len);
                const alias = arena.column(try aliasName(allocator, arena.names.items.len));
                try alias_roles.append(allocator, role);
                try alias_of.put(value.id, position);
                try constraints.append(allocator, alias.sub(value).id);
            },
        }
    }
}

/// Alias names are owned by the caller's allocator and borrowed by the arena;
/// both live exactly as long as the `System` being built.
fn aliasName(allocator: std.mem.Allocator, index: usize) ![]const u8 {
    return std.fmt.allocPrint(allocator, "bus_value_{d}", .{index});
}

fn promote(slot: *Role, role: Role) void {
    if (slot.* == .input) return;
    if (role == .input or slot.* == .witness) slot.* = role;
}
