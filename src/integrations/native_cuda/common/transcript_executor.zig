//! Shared device transcript boundaries for Native CUDA proof stages.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const transcript_stage = @import("stwo_cuda_backend").runtime.stages.transcript;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const schedule_mod = @import("transcript_schedule.zig");

pub fn expectOperation(
    schedule: anytype,
    step: u32,
    expected: schedule_mod.Operation,
) !void {
    if (!std.meta.eql(try schedule.operation(step), expected))
        return error.InvalidKernelDescriptor;
}

pub fn boundary(
    schedule: anytype,
    step: u32,
    snapshot: common.Words,
) !transcript_stage.Boundary {
    const sealed = try schedule.boundary(step);
    return .{
        .expected_step = sealed.expected_step,
        .expected_chain = sealed.expected_chain,
        .next_chain = sealed.next_chain,
        .snapshot = snapshot,
    };
}

pub fn mixWords(
    comptime Transcript: type,
    session: anytype,
    stage: telemetry.Stage,
    schedule: anytype,
    transcript: anytype,
    step: u32,
    expected: schedule_mod.Operation,
    source: common.Words,
    validate_m31: bool,
) !void {
    try expectOperation(schedule, step, expected);
    try Transcript.mixWords(
        session,
        stage,
        transcript.state,
        try boundary(schedule, step, transcript.boundary_snapshot),
        source,
        validate_m31,
        try transcript.input_snapshot.sub(0, source.len),
    );
}

pub fn mixWordsPair(
    comptime Transcript: type,
    session: anytype,
    stage: telemetry.Stage,
    schedule: anytype,
    transcript: anytype,
    step: u32,
    expected: schedule_mod.Operation,
    first: common.Words,
    second: common.Words,
    validate_m31: bool,
) !void {
    try expectOperation(schedule, step, expected);
    const input_words = std.math.add(
        usize,
        first.len,
        second.len,
    ) catch return error.SizeOverflow;
    try Transcript.mixWordsPair(
        session,
        stage,
        transcript.state,
        try boundary(schedule, step, transcript.boundary_snapshot),
        first,
        second,
        validate_m31,
        try transcript.input_snapshot.sub(0, input_words),
    );
}

pub fn drawSecure(
    comptime Transcript: type,
    session: anytype,
    stage: telemetry.Stage,
    schedule: anytype,
    transcript: anytype,
    step: u32,
    expected: schedule_mod.Operation,
    felt_count: u32,
    rejection_rounds: u32,
    output: common.SecureFields,
) !void {
    try expectOperation(schedule, step, expected);
    const snapshot = try transcript.output_snapshot.cast(
        field.SecureField,
    );
    try Transcript.drawSecure(
        session,
        stage,
        transcript.state,
        try boundary(schedule, step, transcript.boundary_snapshot),
        felt_count,
        rejection_rounds,
        output,
        try snapshot.sub(0, felt_count),
    );
}

test "operation mismatch fails before a device transcript call" {
    const schedule = try schedule_mod.Schedule.init(7, 2);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        expectOperation(
            schedule,
            0,
            .mix_main_root,
        ),
    );
    try expectOperation(schedule, 0, .mix_pcs_config);
}
