//! The 11-component circuit-AIR evaluator table
//! (`circuit_verifier::statement::all_circuit_components`).
//!
//! The slot order comes from the projection header; the prover-side circuit
//! AIR must read or assert against this same order rather than keep another
//! list. This module only names the hand-written slots: `eq` (no compiled
//! function), `qm31_ops` (compiled as `qm_31_ops`) and `verify_bitwise_xor_12`.

const std = @import("std");
const component_table = @import("component_table.zig");
const projection_mod = @import("projection.zig");
const manual_cairo = @import("manual/cairo.zig");
const manual_circuit = @import("manual/circuit.zig");

pub const label = "circuit";
pub const slot_count = 11;

pub fn build(gpa: std.mem.Allocator, projection: *const projection_mod.Projection) component_table.BuildError!component_table.Table {
    var table = try component_table.build(gpa, projection, label, resolve);
    errdefer table.deinit();
    if (table.entries.len != slot_count) return error.SlotCountMismatch;
    return table;
}

fn resolve(slot: []const u8, _: manual_cairo.Constants) ?component_table.ManualSlot {
    if (std.mem.eql(u8, slot, "eq")) return .{
        .manual = .circuit_eq,
        .shape = manual_circuit.eq_shape,
        .compiled_name = null,
    };
    if (std.mem.eql(u8, slot, "qm31_ops")) return .{
        .manual = .circuit_qm31_ops,
        .shape = manual_circuit.qm31_ops_shape,
        .compiled_name = "qm_31_ops",
    };
    if (std.mem.eql(u8, slot, "verify_bitwise_xor_12")) return .{
        .manual = .circuit_verify_bitwise_xor_12,
        .shape = manual_circuit.verify_bitwise_xor_12_shape,
        .compiled_name = "verify_bitwise_xor_12",
    };
    return null;
}
