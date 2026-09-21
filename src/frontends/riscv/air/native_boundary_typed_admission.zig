//! Typed equation admission for native program, memory, clock and lookup-table providers.
//! Policy validation does not activate a policy or alter any protocol identity.
const std = @import("std");
const typed = @import("lang/typed_native_boundary.zig");
const symbolic = @import("extract/symbolic.zig");
const Comparison = @import("extract/provider_equivalence.zig").Comparison;
const Relations = @import("extract/symbolic_relations.zig").Relations;
const entries = @import("lookups/entry.zig");
const logup = @import("logup_equations.zig");
const program = @import("program/interaction.zig");
const memory = @import("memory_commitment/interaction.zig");
const full_memory = @import("memory_commitment/incremental_boundary_interaction_v3.zig");
const clock = @import("clock_update_component.zig");
const clock_interaction = @import("clock_update_interaction.zig");
const tables = @import("lookups/tables/equations.zig");
const table_schema = @import("lookups/tables/schema_definition.zig");
const table_layout = @import("lookups/tables/layout.zig");
const S = symbolic.Scalar;
fn tableKind(comptime kind: Kind) table_schema.Kind {
    return @field(table_schema.Kind, @tagName(kind));
}
pub const Kind = typed.Kind;

pub fn Adapter(comptime kind: Kind) type {
    return struct {
        const D = typed.Definition(kind);
        pub const MAIN_COLUMNS = if (typed.isTable(kind)) table_layout.ConstructionMetadata.forKind(tableKind(kind)).main_columns else switch (kind) {
            .program, .program_fixed => @import("program/commitment.zig").N_MAIN_COLUMNS,
            .memory, .memory_full => @import("memory_commitment/trace.zig").N_COLUMNS,
            .clock => clock_interaction.N_MAIN_COLUMNS,
            else => unreachable,
        };
        pub const FIXED_COLUMNS = if (typed.isTable(kind)) table_schema.arity(tableKind(kind)) else if (kind == .program_fixed) program.FIXED_COLUMN_COUNT else 0;
        pub const SUMS = if (typed.isTable(kind)) 1 else switch (kind) {
            .program, .program_fixed => program.N_SUMS,
            .memory => memory.N_SUMS,
            .memory_full => full_memory.N_SUMS,
            .clock => clock_interaction.N_SUMS,
            else => unreachable,
        };
        pub const CONSTRAINTS = if (typed.isTable(kind)) table_layout.N_CONSTRAINTS else switch (kind) {
            .program => program.N_CONSTRAINTS,
            .program_fixed => program.N_FIXED_CONSTRAINTS,
            .memory => memory.N_CONSTRAINTS,
            .memory_full => full_memory.N_CONSTRAINTS,
            .clock => clock.N_CONSTRAINTS,
            else => unreachable,
        };
        pub const INTERACTION_COLUMNS = if (typed.isTable(kind)) table_layout.N_INTERACTION_COLUMNS else switch (kind) {
            .program, .program_fixed => program.N_COLUMNS,
            .memory => memory.N_COLUMNS,
            .memory_full => full_memory.N_COLUMNS,
            .clock => clock_interaction.N_INTERACTION_COLUMNS,
            else => unreachable,
        };
        pub const TABLE_LOG_SIZE = if (typed.isTable(kind)) table_schema.logSize(tableKind(kind)) else 0;
        pub fn evaluate(comptime Scalar: type, main: [D.MAIN_COLUMNS]Scalar, active: Scalar, fixed: [D.FIXED_COLUMNS]Scalar, first: Scalar, sums: [D.SUMS]Scalar, previous: [D.SUMS]Scalar, claims: [D.SUMS]Scalar, relations: anytype) ![CONSTRAINTS]Scalar {
            return switch (kind) {
                .program => program.evaluateGeneric(Scalar, main, active, first, sums, previous, claims, relations),
                .program_fixed => program.evaluateFixedGeneric(Scalar, main, fixed, active, first, sums, previous, claims, relations),
                .memory => memory.evaluateGeneric(Scalar, main, active, first, sums, previous, claims, relations),
                .memory_full => full_memory.evaluateGeneric(Scalar, main, active, first, sums, previous, claims, relations),
                .clock => try clock.evaluateGeneric(Scalar, &main, sums, previous, first, active, claims, relations),
                else => .{try tables.evaluateGeneric(Scalar, tableKind(kind), &fixed, main[0], sums[0], previous[0], first, claims[0], relations)},
            };
        }
        pub fn lookups(comptime Scalar: type, main: [D.MAIN_COLUMNS]Scalar, active: Scalar, fixed: [D.FIXED_COLUMNS]Scalar) !entries.Builder(Scalar).List {
            return switch (kind) {
                .program => program.entriesGeneric(Scalar, main),
                .program_fixed => program.entriesGenericWithPolicy(.fixed_decoded_table_v1, Scalar, main),
                .memory => memory.entriesGeneric(Scalar, main, active),
                .memory_full => full_memory.entriesGeneric(Scalar, main, active),
                .clock => clock_interaction.orderedEntriesGeneric(Scalar, try clock_interaction.RowFor(Scalar).fromMain(&main)),
                else => blk: {
                    var list: entries.Builder(Scalar).List = .{};
                    list.append(tables.tableEntryGeneric(Scalar, tableKind(kind), &fixed, main[0]));
                    break :blk list;
                },
            };
        }
    };
}
pub fn validate(comptime kind: Kind, allocator: std.mem.Allocator) !void {
    try validateSpecialization(kind, Adapter(kind), allocator);
}
pub fn validateProgram(allocator: std.mem.Allocator) !void {
    try validate(.program, allocator);
    try validate(.program_fixed, allocator);
}
pub fn validateMemory(allocator: std.mem.Allocator) !void {
    try validate(.memory, allocator);
    try validate(.memory_full, allocator);
}
pub fn validateSpecialization(comptime kind: Kind, comptime Air: type, allocator: std.mem.Allocator) !void {
    const D = typed.Definition(kind);
    if (Air.MAIN_COLUMNS != D.MAIN_COLUMNS or Air.FIXED_COLUMNS != D.FIXED_COLUMNS or Air.SUMS != D.SUMS or
        Air.CONSTRAINTS != D.SUMS + D.DIRECT_CONSTRAINTS or Air.INTERACTION_COLUMNS != 4 * D.SUMS)
        return error.NativeBoundaryTypedGeometryMismatch;
    if (comptime typed.isTable(kind)) {
        if (Air.TABLE_LOG_SIZE != typed.tableLogSize(kind)) return error.NativeBoundaryTypedGeometryMismatch;
    }
    var definition = try D.init(allocator);
    defer definition.deinit();
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    var main: [D.MAIN_COLUMNS]S = undefined;
    var fixed: [D.FIXED_COLUMNS]S = undefined;
    for (&main) |*v| v.* = arena.column("main");
    for (&fixed) |*v| v.* = arena.column("fixed");
    const active = arena.column("active");
    const first = arena.column("first");
    var sums: [D.SUMS]S = undefined;
    var previous: [D.SUMS]S = undefined;
    var claims: [D.SUMS]S = undefined;
    for (&sums) |*v| v.* = arena.column("sum");
    for (&previous) |*v| v.* = arena.column("previous");
    for (&claims) |*v| v.* = arena.column("claim");
    var relations: Relations = undefined;
    inline for (@typeInfo(Relations).@"struct".fields) |field|
        @field(relations, field.name) = .{ .z = arena.column(field.name ++ ".z"), .alpha = arena.column(field.name ++ ".alpha") };
    var expected = try definition.evaluate(S, allocator, main, active, fixed);
    const actual = try Air.evaluate(S, main, active, fixed, first, sums, previous, claims, &relations);
    const actual_lookups = try Air.lookups(S, main, active, fixed);
    var interaction: [D.SUMS]S = undefined;
    for (&interaction, 0..) |*v, i| {
        // Fixed program tables retain four physical sums but only two batches.
        const pair = if (i < (D.LOOKUPS + 1) / 2) try expected.lookups.pairWith(i, &relations) else logup.RowPairFor(S).single(S.zero(), S.one());
        v.* = logup.pairConstraintGeneric(S, sums[i], previous[i], first, claims[i], pair);
    }
    var comparison = try Comparison.init(allocator, &arena);
    defer comparison.deinit();
    comparison.roots(actual[0..D.SUMS], &interaction) catch return error.NativeBoundaryTypedSpecializationMismatch;
    comparison.roots(actual[D.SUMS..], &expected.direct) catch return error.NativeBoundaryTypedSpecializationMismatch;
    comparison.lookups(actual_lookups, expected.lookups) catch return error.NativeBoundaryTypedSpecializationMismatch;
}
