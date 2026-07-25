//! Synthetic ingress geometry for planner-only unit tests.
//!
//! Production code must use `resident_ingress_compiler`; this helper exists
//! only in files imported from `test` blocks.

const proof_ir = @import("stwo_backend_contracts").proof_program;
const composition = @import(
    "../../../frontends/cairo/witness/composition_bundle.zig",
);
const ingress = @import("resident_plan_ingress.zig");

pub fn geometry(
    program: proof_ir.ProofProgram,
    bundle: composition.Bundle,
) !ingress.Geometry {
    var interaction_words: u64 = 0;
    for (program.commitments) |tree| {
        if (tree.role != .interaction) continue;
        const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
        for (columns) |column| {
            interaction_words += @as(u64, 1) << @intCast(column.log_rows);
        }
    }
    const evaluation = try ingress.deriveEvaluation(
        bundle,
        [_]u8{0xd4} ** 32,
    );
    return .{
        .adapted_input_words = 1,
        .adapted_input_identity = [_]u8{0xa1} ** 32,
        .statement_bootstrap_words = 1,
        .statement_bootstrap_identity = [_]u8{0xa2} ** 32,
        .writer = .{
            .launch_count = 1,
            .input_words = 1,
            .pointer_words = 1,
            .descriptor_words = 1,
            .lookup_words = 1,
            .scratch_words = 1,
            .fixed_table_words = 1,
            .memory_table_words = 1,
            .identity = [_]u8{0xb2} ** 32,
        },
        .relation = .{
            .instance_count = @intCast(bundle.components.len),
            .top_level_pointer_words = 1,
            .source_pointer_words = 1,
            .descriptor_words = 1,
            .geometry_words = 1,
            .challenge_words = 8,
            .alpha_power_words = 4,
            .denominator_words = 4,
            .claimed_sum_words = 4,
            .output_pointer_words = 1,
            .output_coordinate_words = interaction_words,
            .reduction_scratch_words = 1,
            .scan_scratch_words = 1,
            .identity = [_]u8{0xc3} ** 32,
        },
        .evaluation = evaluation,
    };
}
