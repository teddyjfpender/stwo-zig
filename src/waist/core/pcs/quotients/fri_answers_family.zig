//! FRI query-row orchestration over backend-independent quotient laws.

const std = @import("std");
const circle = @import("../../circle.zig");
const m31_mod = @import("../../fields/m31.zig");
const qm31_mod = @import("../../fields/qm31.zig");
const canonic = @import("../../poly/circle/canonic.zig");
const core_utils = @import("../../utils.zig");
const pcs_utils = @import("../utils.zig");

const M31 = m31_mod.M31;
const TreeVec = pcs_utils.TreeVec;

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        const CM31 = Secure.InnerField;
        const samples = @import("samples.zig").ForField(Secure);
        const row_evaluation = @import("row_evaluation.zig").ForField(Secure);
        const ColumnSampleBatch = samples.ColumnSampleBatch;
        const QuotientConstants = row_evaluation.QuotientConstants;
        const RowQuotientWorkspace = row_evaluation.RowQuotientWorkspace;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        const ColumnContribution = struct {
            batch_index: usize,
            value_coeff: QM31,
        };

        const ColumnContributionRange = struct {
            start: usize,
            len: usize,
        };

        const ColumnContributionPlan = struct {
            ranges: []ColumnContributionRange,
            contributions: []ColumnContribution,

            fn deinit(self: *ColumnContributionPlan, allocator: std.mem.Allocator) void {
                allocator.free(self.ranges);
                allocator.free(self.contributions);
                self.* = undefined;
            }
        };

        fn validateSampleBatchColumnIndices(
            sample_batches: []const ColumnSampleBatch,
            queried_values_cols: usize,
        ) !void {
            for (sample_batches) |batch| {
                for (batch.cols_vals_randpows) |sample_data| {
                    if (sample_data.column_index >= queried_values_cols) return error.ColumnIndexOutOfBounds;
                }
            }
        }

        fn buildColumnContributionPlan(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
            quotient_constants: *const QuotientConstants,
            column_count: usize,
        ) !ColumnContributionPlan {
            const counts = try allocator.alloc(usize, column_count);
            defer allocator.free(counts);
            @memset(counts, 0);

            var total_contributions: usize = 0;
            for (sample_batches) |batch| {
                for (batch.cols_vals_randpows) |sample_data| {
                    if (sample_data.column_index >= column_count) return error.ColumnIndexOutOfBounds;
                    counts[sample_data.column_index] += 1;
                    total_contributions += 1;
                }
            }

            const ranges = try allocator.alloc(ColumnContributionRange, column_count);
            errdefer allocator.free(ranges);
            var at: usize = 0;
            for (counts, 0..) |count, col_idx| {
                ranges[col_idx] = .{ .start = at, .len = count };
                at += count;
            }

            const next_offsets = try allocator.alloc(usize, column_count);
            defer allocator.free(next_offsets);
            for (ranges, 0..) |range, col_idx| next_offsets[col_idx] = range.start;

            const contributions = try allocator.alloc(ColumnContribution, total_contributions);
            errdefer allocator.free(contributions);
            for (sample_batches, 0..) |batch, batch_idx| {
                const line_coeffs = quotient_constants.line_coeffs[batch_idx];
                if (line_coeffs.len != batch.cols_vals_randpows.len) return error.ShapeMismatch;
                for (batch.cols_vals_randpows, 0..) |sample_data, coeff_idx| {
                    const write_idx = next_offsets[sample_data.column_index];
                    contributions[write_idx] = .{
                        .batch_index = batch_idx,
                        .value_coeff = line_coeffs[coeff_idx].c,
                    };
                    next_offsets[sample_data.column_index] = write_idx + 1;
                }
            }

            return .{
                .ranges = ranges,
                .contributions = contributions,
            };
        }

        /// Computes quotient answers for every queried FRI row.
        pub fn friAnswers(
            allocator: std.mem.Allocator,
            column_log_sizes: TreeVec([]u32),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            query_positions: []const usize,
            queried_values: TreeVec([][]M31),
            lifting_log_size: u32,
        ) ![]QM31 {
            const queried_values_flat = try pcs_utils.flatten([]M31, allocator, queried_values);
            defer allocator.free(queried_values_flat);

            for (queried_values_flat) |queries_per_col| {
                if (queries_per_col.len != query_positions.len) return error.ShapeMismatch;
            }

            const sample_batches = try samples.buildColumnSampleBatchesFromParallelInputs(
                allocator,
                sampled_points,
                sampled_values,
                column_log_sizes,
                lifting_log_size,
                random_coeff,
            );
            defer ColumnSampleBatch.deinitSlice(allocator, sample_batches);

            var quotient_constants = try row_evaluation.quotientConstants(allocator, sample_batches);
            defer quotient_constants.deinit(allocator);

            const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
            const domain_size = domain.size();

            try validateSampleBatchColumnIndices(sample_batches, queried_values_flat.len);
            var contribution_plan = try buildColumnContributionPlan(
                allocator,
                sample_batches,
                &quotient_constants,
                queried_values_flat.len,
            );
            defer contribution_plan.deinit(allocator);

            var workspace = try RowQuotientWorkspace.init(allocator, sample_batches);
            defer workspace.deinit(allocator);

            const out = try allocator.alloc(QM31, query_positions.len);
            for (query_positions, 0..) |position, row_idx| {
                if (position >= domain_size) return error.QueryPositionOutOfRange;
                const domain_point = domain.at(core_utils.bitReverseIndex(position, lifting_log_size));
                try workspace.beginRow(domain_point);
                for (queried_values_flat, contribution_plan.ranges) |column_queries, contribution_range| {
                    if (contribution_range.len == 0) continue;
                    const base_value = QM31.fromBase(column_queries[row_idx]);
                    const contributions = contribution_plan.contributions[contribution_range.start .. contribution_range.start + contribution_range.len];
                    for (contributions) |contribution| {
                        workspace.batch_numerators[contribution.batch_index] =
                            workspace.batch_numerators[contribution.batch_index].add(
                                base_value.mul(contribution.value_coeff),
                            );
                    }
                }
                out[row_idx] = try row_evaluation.finalizeRowQuotients(
                    &quotient_constants,
                    domain_point.y,
                    workspace.batch_numerators,
                    workspace.denominator_inverses,
                );
            }
            return out;
        }
    };
}
