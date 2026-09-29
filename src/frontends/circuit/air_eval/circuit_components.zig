//! The 11-component circuit-AIR evaluator table
//! (`circuit_verifier::statement::all_circuit_components`).
//!
//! `common/component_list.zig` is the single definition of the circuit
//! component order and static facts. The table is built from the projection
//! (which the oracle read from upstream) and then checked against it: the
//! projection's slot order must be `ComponentList` order, and every slot's
//! constants (column counts, relation uses and the `log_size` rule, including
//! the Gate components' `external_states[0]` column) must equal
//! `component_facts`. The hand-written slots, `eq` (no compiled function),
//! `qm31_ops` (compiled as `qm_31_ops`) and `verify_bitwise_xor_12`, take
//! their shapes from `component_facts` directly.

const std = @import("std");
const component_list = @import("../common/component_list.zig");
const component_table = @import("component_table.zig");
const projection_mod = @import("projection.zig");
const manual_cairo = @import("manual/cairo.zig");

const Shape = component_table.Shape;

pub const label = "circuit";
pub const slot_count = component_list.N_COMPONENTS;

pub fn build(gpa: std.mem.Allocator, projection: *const projection_mod.Projection) component_table.BuildError!component_table.Table {
    var table = try component_table.build(gpa, projection, label, resolve);
    errdefer table.deinit();
    if (table.entries.len != slot_count) return error.SlotCountMismatch;
    for (table.entries, component_list.COMPONENT_NAMES, component_list.component_facts.toArray()) |entry, name, facts| {
        if (!std.mem.eql(u8, entry.name, name)) return error.SlotOrderMismatch;
        if (!entry.shape.eql(Shape.fromFacts(facts))) return error.ComponentFactsMismatch;
    }
    return table;
}

fn resolve(slot: []const u8, _: manual_cairo.Constants) ?component_table.ManualSlot {
    const facts = component_list.component_facts;
    if (std.mem.eql(u8, slot, "eq")) return .{
        .manual = .circuit_eq,
        .shape = Shape.fromFacts(facts.eq),
        .compiled_name = null,
    };
    if (std.mem.eql(u8, slot, "qm31_ops")) return .{
        .manual = .circuit_qm31_ops,
        .shape = Shape.fromFacts(facts.qm31_ops),
        .compiled_name = "qm_31_ops",
    };
    if (std.mem.eql(u8, slot, "verify_bitwise_xor_12")) return .{
        .manual = .circuit_verify_bitwise_xor_12,
        .shape = Shape.fromFacts(facts.verify_bitwise_xor_12),
        .compiled_name = "verify_bitwise_xor_12",
    };
    return null;
}
