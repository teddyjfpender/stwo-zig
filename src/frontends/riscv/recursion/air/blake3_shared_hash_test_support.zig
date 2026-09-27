//! Shared typed hash witness lookup checks.
const std = @import("std");
const group = @import("blake3_merkle_group_witness.zig");
const binding = @import("universal_relation_binding.zig");
const interaction = @import("relation_interaction.zig");
pub fn add(comptime Air: type, a: std.mem.Allocator, ledger: *interaction.TupleLedger, inputs: []const Air.Row) !void {
    var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
    defer definition.deinit();
    const plan = try binding.Binding(Air).authenticate(&definition);
    for (inputs) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain == .recursion_wire) try ledger.append(entry.domain, 0, 0, .emit, entry.numerator, entry.values[0..entry.arity]);
    };
}
pub fn rows(p: anytype) struct { []const group.g.Row, []const group.xor.Row, []const group.boundary.Row, []const group.route.Row, []const group.word.Row, []const group.select.Row } {
    return .{ p.g_rows, p.xor_rows, p.boundary_rows, p.route_rows, p.word_rows, p.select_rows };
}
