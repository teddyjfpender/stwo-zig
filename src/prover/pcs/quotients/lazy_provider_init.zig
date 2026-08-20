//! Construction and admission paths for lazy quotient providers.

const std = @import("std");
const builtin = @import("builtin");
const circle = @import("stwo_core").circle;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const pcs_utils = @import("stwo_core").pcs.utils;
const canonic = @import("stwo_core").poly.circle.canonic;
const column_geometry = @import("../quotient_column_geometry.zig");
const row_executor = @import("../quotient_row_executor.zig");
const tile_executor = @import("../quotient_tile_executor.zig");
const tile_sink = @import("../quotient_tile_sink.zig");
const planning = @import("planning.zig");
const quotient_work = @import("../quotient_work_profile.zig");
const secure_column = @import("../../secure_column.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const CirclePointQM31 = circle.CirclePointQM31;
const QM31 = qm31.QM31;
const TreeVec = pcs_utils.TreeVec;
const ColumnEvaluation = column_geometry.ColumnEvaluation;
const CombinedContributionView = row_executor.CombinedContributionView;
const QuotientOpsError = column_geometry.QuotientOpsError;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const COMPACT_GROUP_MIN_SHIFT: std.math.Log2Int(usize) = 2;
const MAX_COMPACT_GROUP_BYTES: usize = 1024 * 1024;
const LAZY_QUOTIENT_CHUNK_SIZE: usize = 1024;

pub fn InitOps(comptime Owner: type, comptime InputMode: type) type {
    return struct {
        const LazyQuotientProvider = Owner;

        pub fn init(
            allocator: std.mem.Allocator,
            columns: TreeVec([]const ColumnEvaluation),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            lifting_log_size: u32,
        ) !LazyQuotientProvider {
            return initWithMode(
                allocator,
                columns,
                sampled_points,
                sampled_values,
                random_coeff,
                lifting_log_size,
                if (tile_executor.shouldUseBoundedInput(lifting_log_size))
                    .bounded_cpu
                else
                    .combined_compatibility,
            );
        }

        pub fn initWithMode(
            allocator: std.mem.Allocator,
            columns: TreeVec([]const ColumnEvaluation),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            lifting_log_size: u32,
            input_mode: InputMode,
        ) !LazyQuotientProvider {
            return initForBackendWithMode(
                void,
                allocator,
                columns,
                sampled_points,
                sampled_values,
                random_coeff,
                lifting_log_size,
                input_mode,
            );
        }

        pub fn initForBackend(
            comptime B: type,
            allocator: std.mem.Allocator,
            columns: TreeVec([]const ColumnEvaluation),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            lifting_log_size: u32,
        ) !LazyQuotientProvider {
            const backend_raw = comptime B != void and @hasDecl(B, "rawQuotientInputs") and B.rawQuotientInputs;
            return initForBackendWithMode(
                B,
                allocator,
                columns,
                sampled_points,
                sampled_values,
                random_coeff,
                lifting_log_size,
                if (backend_raw)
                    .raw_backend
                else if (tile_executor.shouldUseBoundedInput(lifting_log_size))
                    .bounded_cpu
                else
                    .combined_compatibility,
            );
        }

        pub fn initForBackendWithWorkRecorder(
            comptime B: type,
            allocator: std.mem.Allocator,
            columns: TreeVec([]const ColumnEvaluation),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            lifting_log_size: u32,
            work_recorder: ?*quotient_work.WorkRecorder,
        ) !LazyQuotientProvider {
            const backend_raw = comptime B != void and @hasDecl(B, "rawQuotientInputs") and B.rawQuotientInputs;
            return initForBackendWithModeAndWorkRecorder(
                B,
                allocator,
                columns,
                sampled_points,
                sampled_values,
                random_coeff,
                lifting_log_size,
                if (backend_raw)
                    .raw_backend
                else if (tile_executor.shouldUseBoundedInput(lifting_log_size))
                    .bounded_cpu
                else
                    .combined_compatibility,
                work_recorder,
            );
        }

        pub fn initForBackendWithMode(
            comptime B: type,
            allocator: std.mem.Allocator,
            columns: TreeVec([]const ColumnEvaluation),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            lifting_log_size: u32,
            input_mode: InputMode,
        ) !LazyQuotientProvider {
            return initForBackendWithModeAndWorkRecorder(
                B,
                allocator,
                columns,
                sampled_points,
                sampled_values,
                random_coeff,
                lifting_log_size,
                input_mode,
                null,
            );
        }

        fn initForBackendWithModeAndWorkRecorder(
            comptime B: type,
            allocator: std.mem.Allocator,
            columns: TreeVec([]const ColumnEvaluation),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            lifting_log_size: u32,
            input_mode: InputMode,
            work_recorder: ?*quotient_work.WorkRecorder,
        ) !LazyQuotientProvider {
            if (columns.items.len != sampled_points.items.len) return QuotientOpsError.ShapeMismatch;
            if (columns.items.len != sampled_values.items.len) return QuotientOpsError.ShapeMismatch;

            for (columns.items, sampled_points.items, sampled_values.items) |tree_columns, tree_points, tree_values| {
                if (tree_columns.len != tree_points.len) return QuotientOpsError.ShapeMismatch;
                if (tree_columns.len != tree_values.len) return QuotientOpsError.ShapeMismatch;
                for (tree_columns, tree_points) |column, points| {
                    try column.validate();
                    if (points.len != 0 and column.log_size > lifting_log_size) {
                        return QuotientOpsError.InvalidColumnLogSize;
                    }
                }
            }

            var column_log_sizes = try column_geometry.buildColumnLogSizes(allocator, columns);
            defer column_log_sizes.deinitDeep(allocator);

            const domain_size = try column_geometry.checkedPow2(lifting_log_size);
            const flat_columns = try column_geometry.flattenColumnsBorrowed(allocator, columns);
            errdefer allocator.free(flat_columns);

            var prepared = try planning.prepareContext(
                allocator,
                column_log_sizes,
                sampled_points,
                sampled_values,
                random_coeff,
                lifting_log_size,
                flat_columns.len,
            );
            errdefer prepared.deinit(allocator);

            const nonzero_columns = try planning.markNonzeroColumnsAndSamples(
                allocator,
                columns,
                sampled_values,
            );
            defer allocator.free(nonzero_columns);

            const backend_raw = comptime B != void and @hasDecl(B, "rawQuotientInputs") and B.rawQuotientInputs;
            if ((input_mode == .raw_backend) != backend_raw) return error.InvalidQuotientInputMode;
            var combined_views: []CombinedContributionView = &.{};
            var compact_plan = planning.CompactContributionPlan{ .groups = &.{}, .members = &.{} };
            var direct_plan = tile_executor.DirectContributionPlan{ .views = &.{}, .ranges = &.{} };
            var row_work_contribution_count: usize = 0;
            var combined_plan_source_cells: u64 = 0;
            errdefer {
                var combined_plan = planning.CombinedContributionPlan{ .views = combined_views };
                combined_plan.deinit(allocator);
                compact_plan.deinit(allocator);
                direct_plan.deinit(allocator);
            }
            switch (input_mode) {
                .combined_compatibility => {
                    if (work_recorder != null) {
                        row_work_contribution_count = try quotient_work.activeContributionCount(
                            prepared.contribution_plan.active_column_indices,
                            prepared.contribution_plan.ranges,
                            nonzero_columns,
                        );
                        combined_plan_source_cells = try quotient_work.combinedPlanSourceCells(
                            flat_columns,
                            prepared.contribution_plan.active_column_indices,
                            prepared.contribution_plan.ranges,
                            nonzero_columns,
                        );
                    }
                    const combined_plan = try planning.buildCombinedContributionPlan(
                        allocator,
                        flat_columns,
                        prepared.contribution_plan.active_column_indices,
                        prepared.contribution_plan.ranges,
                        prepared.contribution_plan.contributions,
                        nonzero_columns,
                        lifting_log_size,
                    );
                    combined_views = combined_plan.views;
                },
                .bounded_cpu => {
                    const optional_compact_plan = try planning.buildCompactContributionPlan(
                        allocator,
                        flat_columns,
                        prepared.contribution_plan.active_column_indices,
                        prepared.contribution_plan.ranges,
                        prepared.contribution_plan.contributions,
                        nonzero_columns,
                        lifting_log_size,
                        COMPACT_GROUP_MIN_SHIFT,
                        MAX_COMPACT_GROUP_BYTES,
                    );
                    const compact_admitted = optional_compact_plan != null;
                    if (optional_compact_plan) |plan| compact_plan = plan;
                    direct_plan = try tile_executor.buildDirectContributionPlan(
                        allocator,
                        flat_columns,
                        prepared.contribution_plan.active_column_indices,
                        prepared.contribution_plan.ranges,
                        nonzero_columns,
                        lifting_log_size,
                        if (compact_admitted) COMPACT_GROUP_MIN_SHIFT else null,
                    );
                    if (work_recorder != null) {
                        for (direct_plan.ranges) |range| {
                            row_work_contribution_count = std.math.add(
                                usize,
                                row_work_contribution_count,
                                range.len,
                            ) catch return error.CounterOverflow;
                        }
                        row_work_contribution_count = std.math.add(
                            usize,
                            row_work_contribution_count,
                            compact_plan.members.len,
                        ) catch return error.CounterOverflow;
                    }
                },
                .raw_backend => {
                    if (work_recorder != null)
                        row_work_contribution_count = prepared.contribution_plan.contributions.len;
                },
            }

            var workspace = try quotients.RowQuotientWorkspace.init(allocator, prepared.sample_batches);
            errdefer workspace.deinit(allocator);
            var chunk_scratch: ?row_executor.Scratch = null;
            if (input_mode == .combined_compatibility) {
                chunk_scratch = try row_executor.initScratchOrScalarFallback(
                    allocator,
                    prepared.sample_batches.len,
                    LAZY_QUOTIENT_CHUNK_SIZE,
                    domain_size,
                );
            }
            errdefer if (chunk_scratch) |*scratch| scratch.deinit(allocator);
            var direct_chunk_scratch: ?tile_executor.Scratch = null;
            if (input_mode == .bounded_cpu) {
                direct_chunk_scratch = try tile_executor.initScratchOrScalarFallback(
                    allocator,
                    prepared.sample_batches.len,
                    tile_sink.DEFAULT_TILE_ROWS,
                    domain_size,
                );
            }
            errdefer if (direct_chunk_scratch) |*scratch| scratch.deinit(allocator);

            const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

            if (work_recorder != null) {
                const preparation = try quotient_work.preparationExecution(
                    column_log_sizes,
                    sampled_points,
                    lifting_log_size,
                    prepared.sample_batches.len,
                    prepared.contribution_plan.contributions.len,
                );
                try quotient_work.recordPreparation(work_recorder, preparation);
            }

            return .{
                .prepared = prepared,
                .input_mode = input_mode,
                .combined_views = combined_views,
                .compact_plan = compact_plan,
                .direct_plan = direct_plan,
                .raw_columns = if (input_mode == .raw_backend) flat_columns else blk: {
                    allocator.free(flat_columns);
                    break :blk &.{};
                },
                .backend_residency_handles = &.{},
                .workspace = workspace,
                .chunk_scratch = chunk_scratch,
                .direct_chunk_scratch = direct_chunk_scratch,
                .allow_parallel_scalar = input_mode != .raw_backend and !row_executor.shouldBatchDomain(domain_size),
                .domain = domain,
                .lifting_log_size = lifting_log_size,
                .domain_size = domain_size,
                .work_recorder = work_recorder,
                .row_work_tally = .{
                    .combined_plan_source_cells = combined_plan_source_cells,
                },
                .row_work_next = 0,
                .row_work_path = null,
                .row_work_contribution_count = row_work_contribution_count,
                .row_work_completed = false,
            };
        }
    };
}
