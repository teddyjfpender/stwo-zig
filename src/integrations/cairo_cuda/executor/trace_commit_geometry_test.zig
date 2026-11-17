//! geometry contract cases for trace_commit.
//! Compact mixed-height Cairo trace commitment on resident CUDA storage.
//!
//! Trace writers target their final packed coefficient spans. Each contiguous
//! equal-height cohort is transformed in place and extended into a packed LDE
//! cohort. The shared progressive Blake builder then lifts those cohorts into
//! the tree's maximum leaf domain without a dense max-height expansion.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const stages = @import("stwo_cuda_backend").runtime.stages;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const geometry_compiler = @import("trace_commit/geometry.zig");

const Owner = @import("trace_commit.zig");
const Cohort = Owner.Cohort;
const Prepared = Owner.Prepared;
const Bound = Owner.Bound;
const suffixWords = Owner.suffixWords;
const totalCohortWords = Owner.totalCohortWords;

test "canonical CUDA preprocessed base reconstruction preserves the full coefficient domain" {
    const Context = struct {
        calls: usize = 0,
        pub fn copyDeviceSlice(_: *@This(), comptime T: type, destination: common.Words, source: common.Words) !void {
            if (destination.len != source.len) return error.SizeOverflow;
            const output: [*]T = @ptrFromInt(destination.address);
            const input: [*]const T = @ptrFromInt(source.address);
            @memcpy(output[0..destination.len], input[0..source.len]);
        }
    };
    const Ops = struct {
        const Transform = struct {
            pub fn forwardInPlace(session: anytype, stage: telemetry.Stage, columns: common.WordMatrix, log_n: u32, _: common.Words) !void {
                try std.testing.expectEqual(telemetry.Stage.ingress, stage);
                try std.testing.expectEqual(@as(u32, 4), log_n);
                try std.testing.expectEqual(@as(usize, 16), columns.column_stride_words);
                const values: [*]const u32 = @ptrFromInt(columns.storage.address);
                // Two full columns, including the coefficients the LDE ABI
                // would truncate when asked for a base-domain reconstruction.
                for (values[0..columns.storage.len], 0..) |value, i|
                    try std.testing.expectEqual(@as(u32, @intCast(i + 1)), value);
                session.context.calls += 1;
            }
        };
    };
    var input: [32]u32 = undefined;
    for (&input, 0..) |*value, i| value.* = @intCast(i + 1);
    var output = [_]u32{0} ** 64;
    var cohorts = [_]Cohort{.{ .first_column = 0, .column_count = 2, .trace_log_rows = 4, .evaluation_log_rows = 5, .coefficient_offset_words = 0, .coefficient_words = 32, .evaluation_offset_words = 0, .evaluation_words = 64 }};
    var prepared: Prepared = undefined;
    prepared.input_form = .coefficients;
    prepared.cohorts = &cohorts;
    var bound: Bound = undefined;
    bound.prepared = &prepared;
    bound.coefficients = .{ .address = @intFromPtr(&input), .len = input.len, .owner = 1, .generation = 1 };
    bound.evaluations = .{ .address = @intFromPtr(&output), .len = output.len, .owner = 1, .generation = 1 };
    bound.twiddles_forward = .{ .address = 1, .len = 16, .owner = 1, .generation = 1 };
    bound.base_evaluations_materialized = false;
    var context = Context{};
    try bound.materializeBaseEvaluationsWith(Ops, .{ .context = &context }, .ingress);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try std.testing.expect(bound.base_evaluations_materialized);
    try std.testing.expectEqualSlices(u32, &input, output[0..32]);
    try std.testing.expectError(error.InvalidTraceCommitState, bound.materializeBaseEvaluationsWith(Ops, .{ .context = &context }, .ingress));
}

test "canonical CUDA smaller twiddle views match separately computed domains" {
    const core = @import("stwo_core");
    const twiddle = @import("stwo_prover_engine").poly.twiddles;
    var large = try twiddle.precomputeM31(std.testing.allocator, core.poly.circle.CanonicCoset.new(8).circleDomain().half_coset);
    defer twiddle.deinitM31(std.testing.allocator, &large);
    var small = try twiddle.precomputeM31(std.testing.allocator, core.poly.circle.CanonicCoset.new(4).circleDomain().half_coset);
    defer twiddle.deinitM31(std.testing.allocator, &small);
    const Provider = struct {
        words: common.Words,
        fn slot(self: @This(), _: u32) !common.Words {
            return self.words;
        }
    };
    for ([_][]const core.fields.m31.M31{ large.twiddles, large.itwiddles }, [_][]const core.fields.m31.M31{ small.twiddles, small.itwiddles }) |all, expected| {
        const view = try suffixWords(Provider{ .words = .{ .address = @intFromPtr(all.ptr), .len = all.len, .owner = 1, .generation = 1 } }, 0, expected.len);
        const actual: [*]const core.fields.m31.M31 = @ptrFromInt(view.address);
        try std.testing.expectEqualSlices(core.fields.m31.M31, expected, actual[0..expected.len]);
    }
}

test "mixed geometry stays compact and preserves canonical cohort order" {
    const columns = [_]proof_ir.TraceColumn{
        .{ .id = 0, .component = 0, .ordinal = 0, .log_rows = 3, .role = .main },
        .{ .id = 1, .component = 0, .ordinal = 1, .log_rows = 3, .role = .main },
        .{ .id = 2, .component = 1, .ordinal = 0, .log_rows = 2, .role = .main },
        .{ .id = 3, .component = 2, .ordinal = 0, .log_rows = 4, .role = .main },
    };
    const tree = proof_ir.CommitmentTree{
        .id = 1,
        .role = .main,
        .first_column = 0,
        .column_count = columns.len,
        .evaluation_log_rows = 5,
        .log_rows_per_leaf = 5,
        .retain_openings = true,
    };
    const geometry = try geometry_compiler.compile(
        std.testing.allocator,
        &columns,
        tree,
    );
    defer geometry.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), geometry.cohorts.len);
    try std.testing.expectEqualSlices(
        u64,
        &.{ 0, 8, 16, 20, 36 },
        geometry.column_offsets,
    );
    try std.testing.expectEqual(@as(usize, 36), totalCohortWords(geometry.cohorts, false));
    try std.testing.expectEqual(@as(usize, 72), totalCohortWords(geometry.cohorts, true));
    try std.testing.expectEqual(@as(u32, 3), geometry.cohorts[0].trace_log_rows);
    try std.testing.expectEqual(@as(u32, 2), geometry.cohorts[1].trace_log_rows);
    try std.testing.expectEqual(@as(u32, 4), geometry.cohorts[2].trace_log_rows);
}
