//! Failure-only adapters for CPU composition evaluation diagnostics.

const std = @import("std");
const prover = @import("stwo_prover_engine");

const Diagnostic = prover.engine.EvaluationDiagnostic;
const Stage = prover.engine.EvaluationStage;

pub fn record(
    output: ?*?Diagnostic,
    stage: Stage,
    cause: anyerror,
) void {
    Diagnostic.recordFirst(output, .{ .stage = stage, .cause = cause });
}

pub fn recordComponent(
    output: ?*?Diagnostic,
    component_index: usize,
    cause: anyerror,
) void {
    Diagnostic.recordFirst(output, .{
        .stage = .component_evaluation,
        .cause = cause,
        .component_index = std.math.cast(u32, component_index),
    });
}

pub fn recordLength(
    output: ?*?Diagnostic,
    stage: Stage,
    actual: usize,
    expected: usize,
    cause: anyerror,
) void {
    Diagnostic.recordFirst(output, .{
        .stage = stage,
        .cause = cause,
        .actual = actual,
        .expected = expected,
    });
}

pub fn componentResult(
    output: ?*?Diagnostic,
    component_index: usize,
    result: anytype,
) @TypeOf(result) {
    return result catch |err| {
        recordComponent(output, component_index, err);
        return err;
    };
}

pub fn lengthResult(
    output: ?*?Diagnostic,
    stage: Stage,
    actual: usize,
    expected: usize,
    result: anytype,
) @TypeOf(result) {
    return result catch |err| {
        recordLength(output, stage, actual, expected, err);
        return err;
    };
}

pub fn failure(
    output: ?*?Diagnostic,
    stage: Stage,
    cause: anyerror,
) anyerror {
    record(output, stage, cause);
    return cause;
}
