//! Checked lift-and-accumulate for heterogeneous secure coordinates.

const abi = @import("../../abi/stages/composition_lift.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

const stage = telemetry.Stage.constraint_evaluation;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn accumulate(
            session: anytype,
            previous: common.WordMatrix,
            previous_log_size: u32,
            current: common.WordMatrix,
            current_log_size: u32,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (previous_log_size == 0 or
                current_log_size <= previous_log_size or
                current_log_size > 30)
            {
                return error.InvalidKernelDescriptor;
            }
            const previous_rows =
                @as(usize, 1) << @intCast(previous_log_size);
            const current_rows =
                @as(usize, 1) << @intCast(current_log_size);
            const previous_view = try exactCoordinates(
                session,
                previous,
                previous_rows,
            );
            const current_view = try exactCoordinates(
                session,
                current,
                current_rows,
            );
            try layout.requireDisjoint(
                &.{current_view.range},
                &.{previous_view.range},
            );
            const status = Api.stwo_composition_lift_accumulate_on(
                previous_view.pointer,
                previous_log_size,
                current_view.pointer,
                current_log_size,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn exactCoordinates(
    session: anytype,
    values: common.WordMatrix,
    rows: usize,
) runtime_error.Error!layout.WordMatrix {
    if (values.column_stride_words != rows or
        values.storage.len != rows * 4)
    {
        return error.InvalidKernelDescriptor;
    }
    const result = try layout.wordMatrix(session, values, rows);
    if (result.column_count != 4)
        return error.InvalidKernelDescriptor;
    return result;
}
