//! Pure physical sample counts; no profile schema, identity or admission authority.
const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const verifier_types = @import("stwo_core").verifier_types;
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement_mod = @import("../air/statement.zig");
const base_assembly = @import("../prover/base_component_assembly.zig");
const CircuitLayout = @import("../air/program/circuit_layout.zig").CircuitLayout;

pub fn expectedSampledValueCountWithLayout(statement: *const statement_mod.RiscVStatement, manifest: *const lookup_physical_v2.Manifest, circuit_layout: CircuitLayout) !u32 {
    try manifest.validate();
    if (statement.n_components > statement_mod.MAX_COMPONENTS or
        statement.n_infra > statement_mod.MAX_INFRA_COMPONENTS)
        return error.InvalidColumnGeometry;
    var interaction: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        interaction = std.math.add(
            u32,
            interaction,
            manifest.entryForFamily(descriptor.family)
                .lookup_authority.interaction_column_count,
        ) catch return error.ArithmeticOverflow;
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        const layout = base_assembly.infrastructureDescriptorForLayout(descriptor.kind, circuit_layout);
        if (descriptor.n_columns != layout.main_columns)
            return error.InvalidColumnGeometry;
        interaction = std.math.add(
            u32,
            interaction,
            @intCast(layout.interaction_columns),
        ) catch return error.ArithmeticOverflow;
    }
    const composition = verifier_types.compositionColumnCount(
        verifier_types.COMPOSITION_LOG_SPLIT,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidColumnGeometry;
    var total = std.math.add(
        u32,
        statement.nPreprocessedColumns(),
        statement.nMainColumns(),
    ) catch return error.ArithmeticOverflow;
    total = std.math.add(
        u32,
        total,
        std.math.mul(u32, interaction, 2) catch
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
    return std.math.add(u32, total, @intCast(composition)) catch
        return error.ArithmeticOverflow;
}
