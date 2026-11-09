//! Exact hash-wire ledger used by full-hash and statement-identity tests.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const witness = @import("stwo_riscv_air_lang").modules.framework_blake3_hash_witness;
const g = @import("stwo_riscv_air_lang").modules.framework_blake3_g_call;
const xor = @import("stwo_riscv_air_lang").modules.framework_blake3_xor_call;
const boundary = @import("stwo_riscv_air_lang").modules.framework_blake3_boundary;
const binding = @import("stwo_riscv_air_lang").modules.framework_universal_relation_binding;
const canonical_lang_54a539 = @import("stwo_riscv_air_lang").modules.relation;
pub fn closed(rows: *const witness.Rows) !bool {
    return closedRouted(rows, &.{}, &.{});
}
pub fn closedRouted(rows: *const witness.Rows, routes: []const @import("stwo_riscv_air_lang").modules.framework_blake3_byte_route.Row, producers: []const boundary.Row) !bool {
    return closedExtra(@import("stwo_riscv_air_lang").modules.framework_blake3_byte_route, rows, routes, producers);
}
pub fn closedBridged(rows: *const witness.Rows, bridges: []const @import("stwo_riscv_air_lang").modules.framework_blake3_input_bridge.Row, producers: []const boundary.Row) !bool {
    return closedExtra(@import("stwo_riscv_air_lang").modules.framework_blake3_input_bridge, rows, bridges, producers);
}
fn closedExtra(comptime Extra: type, rows: *const witness.Rows, routes: []const Extra.Row, producers: []const boundary.Row) !bool {
    const a = std.testing.allocator;
    var counts = std.AutoHashMap([6]u32, M31).init(a);
    defer counts.deinit();
    inline for (.{ g, xor, boundary, Extra, boundary }, .{ rows.g_rows, rows.xor_rows, rows.boundary_rows, routes, producers }) |Air, values| {
        var d = try Air.build(a);
        defer d.deinit();
        const plan = try binding.Binding(Air).authenticate(&d);
        for (values) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != canonical_lang_54a539.id(.recursion_wire)) continue;
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
