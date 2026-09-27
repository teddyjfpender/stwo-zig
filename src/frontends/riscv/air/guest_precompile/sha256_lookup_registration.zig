//! Transactional shared-table census compiled from the canonical SHA AIRs.
//! Call before native table geometry/compact-range selection is finalized.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const relation = @import("../lang/relation.zig");
const schema = @import("../lookups/tables/schema.zig");
const counters_mod = @import("../lookups/tables/counter.zig");
const rows_mod = @import("sha256_memory_rows.zig");
const binding = @import("../../recursion/air/universal_relation_binding.zig");
pub const kinds = @import("sha256_component_profile.zig").lookup_kinds;

/// Supports the native counter Set or a view exposing get(kind). Every tuple
/// is checked before the first mutation; no extra full-size counter set exists.
pub fn register(a: std.mem.Allocator, witness: anytype, counters: anytype) !void {
    if (!std.meta.eql(witness.geometry, try rows_mod.Geometry.init(witness.geometry.calls))) return error.InvalidShaRowGeometry;
    for (kinds) |kind| {
        const counter = counters.get(kind);
        if (counter.kind != kind or counter.values.len != schema.size(kind)) return error.InvalidCounterSet;
    }
    const rows = witness.tuple();
    const Profile = @import("sha256_component_profile.zig");
    const local_zero = @TypeOf(witness.*).local_zero_custody;
    const Airs = Profile.AirsForRecipe(local_zero);
    const Roster = if (local_zero) Profile.LocalZeroRoster else Profile.Roster;
    var plans: Roster.Tuple(.plan) = undefined;
    inline for (Airs, 0..) |Air, i| {
        if (rows[i].len != @as(usize, 1) << @intCast(witness.geometry.logs[i])) return error.InvalidShaRowGeometry;
        var definition = try Air.build(a);
        defer definition.deinit();
        plans[i] = try binding.Binding(Air).authenticate(&definition);
    }
    try visit(false, witness, &plans, counters);
    visit(true, witness, &plans, counters) catch unreachable;
}

fn visit(comptime apply: bool, witness: anytype, plans: anytype, counters: anytype) !void {
    const Visitor = struct {
        target: @TypeOf(counters),
        pub fn accepts(_: *@This(), id: @import("../lang/types.zig").RelationSchemaId) bool {
            inline for (kinds) |kind| if (id == relation.id(@field(relation.Domain, @tagName(kind)))) return true;
            return false;
        }
        pub fn visit(self: *@This(), id: @import("../lang/types.zig").RelationSchemaId, numerator: M, tuple: []const M) !void {
            if (numerator.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
            if (numerator.isZero()) return;
            inline for (kinds) |kind| if (id == relation.id(@field(relation.Domain, @tagName(kind)))) {
                const index = try schema.indexBase(kind, tuple);
                if (apply) {
                    const value = &self.target.get(kind).values[index];
                    value.* = value.add(numerator);
                }
                return;
            };
            return error.UnexpectedShaLookup;
        }
    };
    var visitor = Visitor{ .target = counters };
    const rows = witness.tuple();
    inline for (@import("sha256_component_profile.zig").AirsForRecipe(@TypeOf(witness.*).local_zero_custody), 0..) |_, i| for (rows[i]) |row| try plans[i].visitPreparedBaseEntries(row, &visitor);
}

test "SHA provider shared lookup registration preserves counters on a late invalid tuple" {
    const a = std.testing.allocator;
    var witness = try rows_mod.prepare(a, &.{}, 0);
    defer witness.deinit();
    var counters = try counters_mod.Set.init(a);
    defer counters.deinit(a);
    counters.get(.range_check_20).values[0] = M.fromCanonical(17);
    try register(a, &witness, &counters);
    try std.testing.expect(!counters.get(.range_check_8_8).signedTotal().isZero());
    try std.testing.expectEqual(M.fromCanonical(17), counters.get(.range_check_20).signedTotal());
    var before: [schema.KIND_COUNT]M = undefined;
    for (&counters.counters, &before) |*counter, *total| total.* = counter.signedTotal();
    const saved = witness.compression.rounds[1][0];
    witness.compression.rounds[1][0] = M.fromCanonical(256);
    try std.testing.expectError(error.ValueOutOfRange, register(a, &witness, &counters));
    for (&counters.counters, before) |*counter, total| try std.testing.expectEqual(total, counter.signedTotal());
    witness.compression.rounds[1][0] = saved;
}
