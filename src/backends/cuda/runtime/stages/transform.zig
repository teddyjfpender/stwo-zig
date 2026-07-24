//! Checked resident circle-transform dispatch.

const abi = @import("../../abi/stages/transform.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn inverseToRetained(
            session: anytype,
            stage: telemetry.Stage,
            inputs: common.PointerTable,
            retained_outputs: common.PointerTable,
            log_n: u32,
            polynomial_count: u32,
            inverse_twiddles: common.Words,
            evaluation_domain_size: u32,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireNonZero(&.{ polynomial_count, evaluation_domain_size });
            const twiddle_words = try common.count(inverse_twiddles.len);
            const status = Api.stwo_ntt_b2n_columns_to_retained_on(
                try common.constWordTable(session, inputs, polynomial_count),
                try common.mutableWordTable(session, retained_outputs, polynomial_count),
                log_n,
                polynomial_count,
                try common.words(session, inverse_twiddles, 1),
                twiddle_words,
                evaluation_domain_size,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn forwardInPlace(
            session: anytype,
            stage: telemetry.Stage,
            columns: common.PointerTable,
            log_n: u32,
            polynomial_count: u32,
            twiddles: common.Words,
            evaluation_domain_size: u32,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireNonZero(&.{ polynomial_count, evaluation_domain_size });
            const status = Api.stwo_ntt_n2b_columns_on(
                try common.mutableWordTable(session, columns, polynomial_count),
                log_n,
                polynomial_count,
                try common.words(session, twiddles, 1),
                try common.count(twiddles.len),
                evaluation_domain_size,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn extend(
            session: anytype,
            stage: telemetry.Stage,
            coefficients: common.PointerTable,
            coefficient_sizes: common.Words,
            evaluations: common.PointerTable,
            log_n: u32,
            polynomial_count: u32,
            twiddles: common.Words,
            evaluation_domain_size: u32,
            before_final_circle: bool,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireNonZero(&.{ polynomial_count, evaluation_domain_size });
            const coefficient_table =
                try common.constWordTable(session, coefficients, polynomial_count);
            const size_table = try common.words(
                session,
                coefficient_sizes,
                polynomial_count,
            );
            const output_table =
                try common.mutableWordTable(session, evaluations, polynomial_count);
            const twiddle_pointer = try common.words(session, twiddles, 1);
            const twiddle_words = try common.count(twiddles.len);
            const status = if (before_final_circle)
                Api.stwo_lde_n2b_columns_before_circle_on(
                    coefficient_table,
                    size_table,
                    output_table,
                    log_n,
                    polynomial_count,
                    twiddle_pointer,
                    twiddle_words,
                    evaluation_domain_size,
                    session.context.stream,
                )
            else
                Api.stwo_lde_n2b_columns_on(
                    coefficient_table,
                    size_table,
                    output_table,
                    log_n,
                    polynomial_count,
                    twiddle_pointer,
                    twiddle_words,
                    evaluation_domain_size,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }
    };
}

fn requireTransformStage(stage: telemetry.Stage) runtime_error.Error!void {
    switch (stage) {
        .trace_commit, .oods, .quotient, .fri_commit => {},
        else => return error.StageOrderViolation,
    }
}
