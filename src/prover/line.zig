//! Compatibility alias for the backend-neutral line-evaluation representation.

pub const LineEvaluation = @import("stwo_backend_contracts").line_evaluation.LineEvaluation;

pub fn LineEvaluationFor(comptime S: type) type {
    return @import("stwo_backend_contracts").line_evaluation.ForField(S).LineEvaluation;
}
