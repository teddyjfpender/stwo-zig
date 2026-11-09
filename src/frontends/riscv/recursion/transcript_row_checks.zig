const air = struct {
    const direct_constraint_program = @import("stwo_riscv_air_lang").framework_direct_constraint_program;
    const relation_interaction = @import("stwo_riscv_air_lang").framework_relation_interaction;
    const universal_relation_binding = @import("stwo_riscv_air_lang").framework_universal_relation_binding;
};
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Ledger = air.relation_interaction.TupleLedger;
const direct = air.direct_constraint_program;
const rows_mod = @import("transcript_logical_rows.zig");
pub fn checkRows(comptime component: u8, comptime Air: type, rows: anytype, ledger: *Ledger) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const Binding = air.universal_relation_binding.Binding(Air);
    const relations = try Binding.authenticate(&definition);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        const values = try rows_mod.logicalRow(component, row);
        try compiled.evaluateBaseInto(&values, &scratch, &roots);
        for (roots) |root| if (!root.isZero()) return error.TranscriptConstraintMismatch;
        const entries = try relations.entries(&definition.arena, Air.SEMANTIC_DIGEST, Binding.events(&definition), values);
        for (entries) |entry| try ledger.append(entry.domain, component, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
    }
}
