//! Exact hash-wire ledger used by full-hash and statement-identity tests.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const witness = @import("blake3_hash_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const binding = @import("universal_relation_binding.zig");
const lang = @import("../../air/lang/mod.zig");
pub fn closed(rows: *const witness.Rows) !bool {
    return closedRouted(rows, &.{}, &.{});
}
pub fn closedRouted(rows: *const witness.Rows, routes: []const @import("blake3_byte_route.zig").Row, producers: []const boundary.Row) !bool {
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M31).init(a);
    defer counts.deinit();
    inline for (.{ g, xor, boundary, @import("blake3_byte_route.zig"), boundary }, .{ rows.g_rows, rows.xor_rows, rows.boundary_rows, routes, producers }) |Air, values| {
        var d = try Air.build(a);
        defer d.deinit();
        const plan = try binding.Binding(Air).authenticate(&d);
        for (values) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M31.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (!value.isZero()) return false;
    return true;
}

