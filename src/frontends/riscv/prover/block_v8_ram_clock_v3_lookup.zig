//! Shared exact conditional R20 numerator authority for V3 prover demand and
//! OODS/source projection. Canonical typed entries themselves are unchanged.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("../air/semantic_eval.zig").BaseScalar;
const Entries = @import("../air/lookups/opcode_entries.zig").Entries(Base);
const Counter = @import("../air/lookups/tables/counter.zig");
const trace = @import("../runner/trace.zig");
const Typed = @import("../air/lang/typed_load_store_authority.zig");
comptime {
    const recipe = Typed.CANONICAL_LOOKUP_RECIPE;
    if (@intFromEnum(Typed.LookupRecipe.source_clock_gap) != 10 or @intFromEnum(Typed.LookupRecipe.destination_clock_gap) != 13 or
        recipe[10].domain != .range_check_20 or recipe[13].domain != .range_check_20 or
        recipe[8].domain != .memory_access or recipe[11].domain != .memory_access or
        recipe[8].access_ordinal != 2 or recipe[11].access_ordinal != 3) @compileError("review DirectRAM V3 typed lookup ordinal binding");
}
pub fn numerator(comptime S: type, list: anytype, index: usize) !S {
    if (index >= list.len) return error.InvalidDirectRamClockProjection;
    const value = list.entries[index].numerator;
    const original = if (comptime @TypeOf(value) == S) value else S.fromBase(value.value);
    if (index != 10 and index != 13) return original;
    if (list.entries[index].domain != .range_check_20) return error.InvalidDirectRamClockProjection;
    const access_index: usize = if (index == 10) 8 else 11;
    if (access_index >= list.len or list.entries[access_index].domain != .memory_access) return error.InvalidDirectRamClockProjection;
    const space_value = list.entries[access_index].values[0];
    const space = if (comptime @TypeOf(space_value) == S) space_value else S.fromBase(space_value.value);
    return original.mul(S.one().sub(space));
}
pub fn registerGenerated(columns: *const [trace.MAX_FAMILY_COLUMNS][]core.fields.m31.M31, physical: usize, counters: *Counter.Set) !void {
    var main: [50]Base = undefined;
    for (&main, columns[0..50]) |*value, column| value.* = .fromBase(column[physical]);
    var list: @import("../air/lookups/entry.zig").Builder(Base).List = undefined;
    try Entries.fromMainInto(.load_store, &main, &list);
    for (list.entries[0..list.len], 0..) |entry, index| {
        const kind = Counter.kindForDomain(entry.domain) orelse continue;
        const weight = try numerator(Base, &list, index);
        var tuple: [@import("../air/lookups/entry.zig").MAX_ARITY]core.fields.m31.M31 = undefined;
        for (entry.values[0..entry.arity], tuple[0..entry.arity]) |value, *target| target.* = value.value;
        try counters.get(kind).registerBase(weight.value, tuple[0..entry.arity]);
    }
}
