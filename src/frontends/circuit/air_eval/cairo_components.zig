//! The 83-slot Cairo evaluator table (`circuit_cairo_verifier::all_components`).
//!
//! The slot order comes from the projection header. This module only names the
//! hand-written slots: `memory_address_to_id`, `memory_id_to_big` (slot names
//! `memory_id_to_big` and `memory_id_to_big_{1..15}`, one evaluator with an
//! index) and `verify_bitwise_xor_12`.

const std = @import("std");
const component_table = @import("component_table.zig");
const projection_mod = @import("projection.zig");
const manual_cairo = @import("manual/cairo.zig");

pub const label = "cairo";
pub const slot_count = 83;
/// Upstream `opt_n_id_to_big_components`: slots `memory_id_to_big{,_1..15}`.
pub const memory_id_to_big_count = 16;

pub fn build(gpa: std.mem.Allocator, projection: *const projection_mod.Projection) component_table.BuildError!component_table.Table {
    var table = try component_table.build(gpa, projection, label, resolve);
    errdefer table.deinit();
    if (table.entries.len != slot_count) return error.SlotCountMismatch;
    return table;
}

fn resolve(slot: []const u8, constants: manual_cairo.Constants) ?component_table.ManualSlot {
    if (std.mem.eql(u8, slot, "memory_address_to_id")) return .{
        .manual = .cairo_memory_address_to_id,
        .shape = manual_cairo.memoryAddressToIdShape(constants),
        .compiled_name = "memory_address_to_id",
    };
    if (std.mem.eql(u8, slot, "verify_bitwise_xor_12")) return .{
        .manual = .cairo_verify_bitwise_xor_12,
        .shape = manual_cairo.verify_bitwise_xor_12_shape,
        .compiled_name = "verify_bitwise_xor_12",
    };
    const index = memoryIdToBigIndex(slot) orelse return null;
    return .{
        .manual = .{ .cairo_memory_id_to_big = index },
        .shape = manual_cairo.memory_id_to_big_shape,
        // Every index replaces the one compiled `memory_id_to_big` function.
        .compiled_name = "memory_id_to_big",
    };
}

/// `memory_id_to_big` is index 0; `memory_id_to_big_{k}` is index k.
pub fn memoryIdToBigIndex(slot: []const u8) ?u32 {
    const stem = "memory_id_to_big";
    if (!std.mem.startsWith(u8, slot, stem)) return null;
    const rest = slot[stem.len..];
    if (rest.len == 0) return 0;
    if (rest[0] != '_' or rest.len < 2 or (rest.len > 2 and rest[1] == '0')) return null;
    const index = std.fmt.parseUnsigned(u32, rest[1..], 10) catch return null;
    if (index == 0 or index >= memory_id_to_big_count) return null;
    return index;
}

test "memory_id_to_big slot names map to one evaluator index" {
    try std.testing.expectEqual(@as(?u32, 0), memoryIdToBigIndex("memory_id_to_big"));
    try std.testing.expectEqual(@as(?u32, 15), memoryIdToBigIndex("memory_id_to_big_15"));
    try std.testing.expectEqual(@as(?u32, null), memoryIdToBigIndex("memory_id_to_big_0"));
    try std.testing.expectEqual(@as(?u32, null), memoryIdToBigIndex("memory_id_to_big_16"));
    try std.testing.expectEqual(@as(?u32, null), memoryIdToBigIndex("memory_id_to_small"));
}
