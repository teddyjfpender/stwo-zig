//! Symbolic admission of all native wide-Poseidon equations and ordered events.
const std = @import("std");
const native = @import("poseidon2_wide_equations.zig");
const typed = @import("../lang/typed_poseidon2_wide.zig");
const symbolic = @import("../extract/symbolic.zig");
const Comparison = @import("../extract/provider_equivalence.zig").Comparison;
const Relations = @import("../extract/symbolic_relations.zig").Relations;
const S = symbolic.Scalar;

pub fn validate(allocator: std.mem.Allocator) !void {
    return validateSpecialization(native, allocator);
}
pub fn validateSpecialization(comptime Air: type, allocator: std.mem.Allocator) !void {
    if (Air.N_MAIN_COLUMNS != typed.MAIN_COLUMNS or Air.N_SUMS != typed.SUMS or
        Air.N_CONSTRAINTS != typed.DIRECT_CONSTRAINTS or
        Air.N_INTERACTION_COLUMNS != typed.SUMS * 4 or Air.MAXIMUM_CONSTRAINT_DEGREE != 3)
        return error.WidePoseidonTypedGeometryMismatch;
    var definition = try typed.Definition.init(allocator);
    defer definition.deinit();
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    var main: [typed.MAIN_COLUMNS]S = undefined;
    for (&main) |*value| value.* = arena.column("main");
    const first = arena.column("first");
    var sums: [typed.SUMS]S = undefined;
    var previous: [typed.SUMS]S = undefined;
    var claims: [typed.SUMS]S = undefined;
    for (&sums) |*v| v.* = arena.column("sum");
    for (&previous) |*v| v.* = arena.column("previous");
    for (&claims) |*v| v.* = arena.column("claim");
    var relations: Relations = undefined;
    inline for (@typeInfo(Relations).@"struct".fields) |field|
        @field(relations, field.name) = .{ .z = arena.column(field.name ++ ".z"), .alpha = arena.column(field.name ++ ".alpha") };
    var expected = try definition.evaluate(S, allocator, main);
    const actual = Air.evaluateGeneric(S, main);
    const actual_interaction = Air.interactionConstraintsGeneric(S, main, first, sums, previous, claims, &relations);
    const actual_lookups = Air.entriesGeneric(S, main);
    var expected_interaction: [typed.SUMS]S = undefined;
    for (&expected_interaction, 0..) |*v, i| v.* = @import("../logup_equations.zig").pairConstraintGeneric(S, sums[i], previous[i], first, claims[i], try expected.lookups.pairWith(i, &relations));
    var comparison = try Comparison.init(allocator, &arena);
    defer comparison.deinit();
    comparison.roots(&actual, &expected.direct) catch return error.WidePoseidonTypedSpecializationMismatch;
    comparison.roots(&actual_interaction, &expected_interaction) catch return error.WidePoseidonTypedSpecializationMismatch;
    comparison.lookups(actual_lookups, expected.lookups) catch return error.WidePoseidonTypedSpecializationMismatch;
}
