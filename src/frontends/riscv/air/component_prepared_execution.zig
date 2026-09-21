//! Row-domain execution for the canonical RISC-V trace component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const memory_interaction = @import("memory_commitment/interaction.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");

const CANCELLATION_POLL_ROWS: usize = 4096;

fn secureAt(coords: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(coords[0][row], coords[1][row], coords[2][row], coords[3][row]);
}

pub fn run(
    self: anytype,
    state: anytype,
    task_context: *prover_task_graph.TaskContext,
) !void {
    const log_size = self.desc.log_size;
    const eval_log_size = state.eval_log_size;
    const eval_size = state.eval_size;
    const evaluations = state.evaluations;
    const denominator_inv = state.denominator_inv;
    const column_accumulator = &state.accumulators[0];
    const denominator_shift: std.math.Log2Int(usize) = @intCast(log_size);
    for (0..eval_size) |row| {
        if ((row & (CANCELLATION_POLL_ROWS - 1)) == 0 and
            task_context.isCancelled())
        {
            // Cancellation is not a competing failure cause. The graph
            // discards partial component output with the failed stage.
            return;
        }
        const previous_row = utils.previousBitReversedCircleDomainIndex(
            row,
            log_size,
            eval_log_size,
        );
        const is_first = QM31.fromBase(evaluations[0][row]);
        const is_active = QM31.fromBase(evaluations[1][row]);
        var row_evaluation: QM31 = undefined;
        switch (self.kind) {
            .program => {
                const main_start: usize = 2;
                const inter_start = main_start + program_commitment.N_MAIN_COLUMNS;
                var sampled: [program_commitment.N_MAIN_COLUMNS]QM31 = undefined;
                for (&sampled, 0..) |*value, column| {
                    value.* = QM31.fromBase(evaluations[main_start + column][row]);
                }
                var sums: [program_interaction.N_SUMS]QM31 = undefined;
                var previous: [program_interaction.N_SUMS]QM31 = undefined;
                for (0..program_interaction.N_SUMS) |index| {
                    sums[index] = secureAt(evaluations[inter_start + index * 4 ..][0..4], row);
                    previous[index] = secureAt(
                        evaluations[inter_start + index * 4 ..][0..4],
                        previous_row,
                    );
                }
                if (self.fixed_program_columns != null) {
                    var fixed: [program_interaction.FIXED_COLUMN_COUNT]QM31 = undefined;
                    for (&fixed, 0..) |*value, index| value.* = QM31.fromBase(evaluations[inter_start + program_interaction.N_COLUMNS + index][row]);
                    const constraints = program_interaction.evaluateFixedGeneric(QM31, sampled, fixed, is_active, is_first, sums, previous, self.program_claims, self.relations);
                    const powers = column_accumulator.random_coeff_powers;
                    row_evaluation = QM31.zero();
                    for (constraints, 0..) |constraint, index| row_evaluation = row_evaluation.add(powers[powers.len - 1 - index].mul(constraint));
                } else {
                    const constraints = program_interaction.evaluate(
                        sampled,
                        is_active,
                        is_first,
                        sums,
                        previous,
                        self.program_claims,
                        self.relations,
                    );
                    const powers = column_accumulator.random_coeff_powers;
                    row_evaluation = QM31.zero();
                    for (constraints, 0..) |constraint, index| {
                        row_evaluation = row_evaluation.add(
                            powers[powers.len - 1 - index].mul(constraint),
                        );
                    }
                }
            },
            .memory => {
                const main_start: usize = 2;
                const inter_start = main_start + 8;
                var sampled: [8]QM31 = undefined;
                for (&sampled, 0..) |*value, column| {
                    value.* = QM31.fromBase(evaluations[main_start + column][row]);
                }
                var sums: [memory_interaction.N_SUMS]QM31 = undefined;
                var previous: [memory_interaction.N_SUMS]QM31 = undefined;
                for (0..memory_interaction.N_SUMS) |index| {
                    sums[index] = secureAt(evaluations[inter_start + index * 4 ..][0..4], row);
                    previous[index] = secureAt(
                        evaluations[inter_start + index * 4 ..][0..4],
                        previous_row,
                    );
                }
                const constraints = self.evaluateMemoryConstraintsGeneric(
                    QM31,
                    sampled,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    self.memory_claims,
                    self.relations,
                );
                const powers = column_accumulator.random_coeff_powers;
                row_evaluation = QM31.zero();
                for (constraints, 0..) |constraint, index| {
                    row_evaluation = row_evaluation.add(
                        powers[powers.len - 1 - index].mul(constraint),
                    );
                }
            },
        }
        column_accumulator.accumulate(
            row,
            row_evaluation.mulM31(denominator_inv[row >> denominator_shift]),
        );
    }
}
