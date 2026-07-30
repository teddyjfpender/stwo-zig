const prover_pcs = @import("stwo_prover_engine").pcs;
const quadratic_trace = @import("quadratic_trace_backend.zig");

pub fn materialize(
    columns: []prover_pcs.ColumnEvaluation,
    source: prover_pcs.ColumnSource,
) !void {
    switch (source) {
        .materialized => {},
        .quadratic_recurrence => |deferred| {
            if (columns.len > 256) return error.InvalidColumns;
            const FieldElement = @import("stwo_core").fields.m31.M31;
            var views: [256][]FieldElement = undefined;
            for (columns, 0..) |column, index| {
                views[index] = @constCast(column.values);
            }
            try quadratic_trace.fill(
                views[0..columns.len],
                deferred.log_n_rows,
                deferred.recipe,
            );
        },
    }
}
