//! Test-only root that joins the circuit and Cairo frontends, which must never
//! depend on each other: the projection's 83 Cairo evaluator slots
//! (`circuit_cairo_verifier::all_components` at proving@5a7c5ed) must equal
//! `official_claim_registry.enable_slots` (stwo-cairo 82f2125). The two pins
//! differ, so this equality is an asserted cross-revision fact, not an
//! identity. Names differ only for `memory_id_to_big`: the registry says
//! `memory_id_to_big[k]`, the projection `memory_id_to_big` (k = 0) and
//! `memory_id_to_big_k`.

const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");

const registry = cairo.claim_registry;
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

/// The projection slot name of a registry enable slot.
fn projectionName(buffer: []u8, registry_name: []const u8) ![]const u8 {
    const stem = "memory_id_to_big[";
    if (!std.mem.startsWith(u8, registry_name, stem)) return registry_name;
    if (!std.mem.endsWith(u8, registry_name, "]")) return error.UnexpectedRegistryName;
    const index = try std.fmt.parseUnsigned(u32, registry_name[stem.len .. registry_name.len - 1], 10);
    if (index == 0) return "memory_id_to_big";
    return std.fmt.bufPrint(buffer, "memory_id_to_big_{d}", .{index});
}

test "projection Cairo slot order equals the official claim registry enable slots" {
    const gpa = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(gpa, projection_path, 4 << 20);
    defer gpa.free(bytes);
    var projection = try circuit.air_eval.projection.parse(gpa, bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.cairo_components.build(gpa, &projection);
    defer table.deinit();

    try std.testing.expectEqual(registry.enable_slot_count, table.entries.len);
    try std.testing.expectEqual(registry.memory_id_to_big_enable_slot_count, circuit.air_eval.cairo_components.memory_id_to_big_count);
    var buffer: [32]u8 = undefined;
    for (registry.enable_slots, table.entries) |slot, entry| {
        try std.testing.expectEqualStrings(try projectionName(&buffer, slot.name), entry.name);
        // Fixed-size components agree on their height.
        if (slot.fixed_log_size) |fixed| switch (entry.shape.log_size) {
            .fixed => |log_size| try std.testing.expectEqual(fixed, log_size),
            else => return error.LogSizeShapeMismatch,
        };
    }
}
