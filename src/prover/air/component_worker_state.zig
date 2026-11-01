//! Shared worker failure and constraint-power ownership checks.
const prover_api = @import("stwo_prover_api");

pub fn validatePowerRanges(workers: anytype) !void {
    for (workers) |worker| {
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            prover_api.EvaluationDiagnostic.recordFirst(worker.diagnostic, .{
                .stage = .component_evaluation,
                .cause = error.ConstraintPowerRangeMismatch,
                .component_index = worker.component_index,
                .actual = worker.accumulator.next_power_index,
                .expected = worker.expected_next_power_index,
            });
            return error.ConstraintPowerRangeMismatch;
        }
    }
}

pub fn firstWorkerError(workers: anytype) ?anyerror {
    for (workers) |worker| {
        if (worker.err) |err| {
            prover_api.EvaluationDiagnostic.recordFirst(worker.diagnostic, .{
                .stage = .component_evaluation,
                .cause = err,
                .component_index = worker.component_index,
            });
            return err;
        }
    }
    return null;
}
