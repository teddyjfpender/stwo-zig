//! Row-domain execution for the canonical RISC-V trace component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const logup = @import("logup.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");
const opcode_memory = @import("opcode_memory.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");
const semantic_eval = @import("semantic_eval.zig");
const trace_mod = @import("../runner/trace.zig");

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
    const opcode_main_sources = state.opcode_main_sources;
    const has_direct_semantics = self.kind == .opcode and
        semantic_eval.isTraceCompatible(self.desc.family);
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
            .opcode => {
                const main_start: usize = 2;
                const inter_start = main_start + opcode_main_sources;
                const clk = QM31.fromBase(
                    evaluations[main_start + semantic_eval.clockColumn(self.desc.family)][row],
                );
                const pc = QM31.fromBase(
                    evaluations[main_start + semantic_eval.pcColumn(self.desc.family)][row],
                );
                const bus = main_start + self.desc.n_columns - 5;
                const next_pc = QM31.fromBase(evaluations[bus][row]);
                const opcode_id = QM31.fromBase(evaluations[bus + 1][row]);
                const value_1 = QM31.fromBase(evaluations[bus + 2][row]);
                const value_2 = QM31.fromBase(evaluations[bus + 3][row]);
                const value_3 = QM31.fromBase(evaluations[bus + 4][row]);
                const s_state = secureAt(evaluations[inter_start .. inter_start + 4], row);
                const s_prog = secureAt(evaluations[inter_start + 4 .. inter_start + 8], row);
                const s_state_prev = secureAt(
                    evaluations[inter_start .. inter_start + 4],
                    previous_row,
                );
                const s_prog_prev = secureAt(
                    evaluations[inter_start + 4 .. inter_start + 8],
                    previous_row,
                );

                const c_state = logup.pairConstraint(
                    s_state,
                    s_state_prev,
                    is_first,
                    self.state_claim,
                    logup.stateChainPair(self.relations, pc, clk, next_pc, is_active),
                );
                const c_prog = logup.pairConstraint(
                    s_prog,
                    s_prog_prev,
                    is_first,
                    self.prog_claim,
                    logup.programConsume(
                        self.relations,
                        pc,
                        opcode_id,
                        value_1,
                        value_2,
                        value_3,
                        is_active,
                    ),
                );
                const powers = column_accumulator.random_coeff_powers;
                row_evaluation = powers[powers.len - 1].mul(c_state)
                    .add(powers[powers.len - 2].mul(c_prog));
                var sampled: [trace_mod.MAX_FAMILY_COLUMNS]QM31 = undefined;
                const n_columns = semantic_eval.mainColumnCount(self.desc.family);
                for (sampled[0..n_columns], 0..) |*value, column| {
                    value.* = QM31.fromBase(evaluations[main_start + column][row]);
                }
                var memory_sums: [opcode_memory.N_ACCESSES]QM31 = undefined;
                var memory_previous: [opcode_memory.N_ACCESSES]QM31 = undefined;
                for (0..opcode_memory.N_ACCESSES) |slot| {
                    const memory_offset = inter_start + 8 + slot * 4;
                    memory_sums[slot] = secureAt(evaluations[memory_offset..][0..4], row);
                    memory_previous[slot] = secureAt(
                        evaluations[memory_offset..][0..4],
                        previous_row,
                    );
                }
                const memory_constraints = try opcode_memory.constraints(
                    self.desc.family,
                    sampled[0..n_columns],
                    is_active,
                    is_first,
                    memory_sums,
                    memory_previous,
                    self.opcode_memory_claims,
                    &self.relations.memory_access,
                );
                for (memory_constraints, 0..) |constraint, index| {
                    row_evaluation = row_evaluation.add(
                        powers[powers.len - 3 - index].mul(constraint),
                    );
                }
                if (has_direct_semantics) {
                    var constraints: semantic_eval.Evaluation = undefined;
                    try semantic_eval.evaluateInto(
                        self.desc.family,
                        sampled[0..n_columns],
                        is_active,
                        &constraints,
                    );
                    for (constraints.values[0..constraints.len], 0..) |constraint, index| {
                        row_evaluation = row_evaluation.add(
                            powers[powers.len - 3 - opcode_memory.N_ACCESSES - index].mul(constraint),
                        );
                    }
                }
            },
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
