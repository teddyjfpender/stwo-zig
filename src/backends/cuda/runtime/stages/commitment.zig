//! Checked resident Blake2s commitment dispatch.

const abi = @import("../../abi/stages/commitment.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn progressiveInit(
            session: anytype,
            stage: telemetry.Stage,
            states: common.ProgressiveStates,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            const size = try common.count(states.len);
            const status = Api.stwo_blake2s_progressive_init_on(
                size,
                try common.states(session, states, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn progressiveAbsorb(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            absorbed_columns_before: u32,
            columns: common.PointerTable,
            states: common.ProgressiveStates,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            const column_count = try common.count(columns.len);
            try common.requireNonZero(&.{ size, column_count });
            const status = Api.stwo_blake2s_progressive_absorb_on(
                size,
                column_count,
                absorbed_columns_before,
                try common.mutableWordTable(session, columns, column_count),
                try common.states(session, states, size),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn progressiveFinalize(
            session: anytype,
            stage: telemetry.Stage,
            absorbed_columns: u32,
            states: common.ProgressiveStates,
            output: common.Hashes,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            if (states.len != output.len) return error.SizeOverflow;
            const size = try common.count(states.len);
            const status = Api.stwo_blake2s_progressive_finalize_on(
                size,
                absorbed_columns,
                try common.states(session, states, 1),
                try common.hashes(session, output, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn layer(
            session: anytype,
            stage: telemetry.Stage,
            previous: common.Hashes,
            output: common.Hashes,
            four_levels: bool,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            if (output.len == 0) return error.InvalidKernelDescriptor;
            const expected_input = if (four_levels)
                @import("std").math.mul(usize, output.len, 16) catch
                    return error.SizeOverflow
            else
                @import("std").math.mul(usize, output.len, 2) catch
                    return error.SizeOverflow;
            if (previous.len < expected_input) return error.SizeOverflow;
            const previous_pointer = try common.hashes(session, previous, expected_input);
            const output_pointer = try common.hashes(session, output, output.len);
            const output_size = try common.count(output.len);
            const status = if (four_levels)
                Api.stwo_blake2s_interior4_on(
                    previous_pointer,
                    output_size,
                    output_pointer,
                    session.context.stream,
                )
            else
                Api.stwo_blake2s_layer_on(
                    previous_pointer,
                    output_size,
                    output_pointer,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }

        pub fn friLeaves(
            session: anytype,
            coordinate_columns: common.PointerTable,
            evaluation_size: u32,
            log_rows_per_leaf: u32,
            output: common.Hashes,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{evaluation_size});
            if (!@import("std").math.isPowerOfTwo(evaluation_size) or
                (log_rows_per_leaf != 0 and log_rows_per_leaf != 2))
                return error.InvalidKernelDescriptor;
            const leaf_count = evaluation_size >> @intCast(log_rows_per_leaf);
            if (output.len != leaf_count) return error.SizeOverflow;
            const status = Api.stwo_blake2s_fri_leaf_on(
                evaluation_size,
                try common.mutableWordTable(session, coordinate_columns, 4),
                log_rows_per_leaf,
                try common.hashes(session, output, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn requireCommitStage(stage: telemetry.Stage) runtime_error.Error!void {
    switch (stage) {
        .trace_commit, .fri_commit => {},
        else => return error.StageOrderViolation,
    }
}
