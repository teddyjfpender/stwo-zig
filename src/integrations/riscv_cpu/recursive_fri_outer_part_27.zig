//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const stwo_core = context.d_stwo_core;
        const prover_air = context.d_prover_air;
        const prover_pcs = context.d_prover_pcs;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const global_closure = context.d_global_closure;
        const air = context.d_air;
        const manifest_mod = context.d_manifest_mod;
        const universal = context.d_universal;
        const framework = context.d_framework;
        const Engine = context.d_Engine;
        const CapturePublication = context.d_CapturePublication;
        const VerifierScheme = context.d_VerifierScheme;
        const STAGE_TELEMETRY_ENV = context.d_STAGE_TELEMETRY_ENV;
        const OUTER_CONFIG = context.d_OUTER_CONFIG;
        const Error = context.d_Error;
        const ProofExecutionPool = context.d_ProofExecutionPool;
        const Authority = context.d_Authority;
        const fillPreprocessed = context.d_fillPreprocessed;

        pub fn evaluateDiagnosticMasks(
            allocator: std.mem.Allocator,
            trace: *const prover_air.Trace,
            points: *const stwo_core.air.components.MaskPoints,
            lifting_log_size: u32,
        ) !stwo_core.air.components.MaskValues {
            const trees = try allocator.alloc([][]QM31, points.items.len);
            var tree_count: usize = 0;
            errdefer {
                for (trees[0..tree_count]) |columns| {
                    for (columns) |values| allocator.free(values);
                    allocator.free(columns);
                }
                allocator.free(trees);
            }
            for (points.items, 0..) |point_columns, tree_index| {
                if (tree_index >= trace.polys.items.len)
                    return error.DiagnosticTreeCountMismatch;
                if (point_columns.len != trace.polys.items[tree_index].len)
                    return error.DiagnosticColumnCountMismatch;
                const columns = try allocator.alloc([]QM31, point_columns.len);
                errdefer allocator.free(columns);
                trees[tree_index] = columns;
                var column_count: usize = 0;
                errdefer for (columns[0..column_count]) |values| allocator.free(values);
                for (point_columns, columns, 0..) |column_points, *values, column_index| {
                    if (column_index >= trace.polys.items[tree_index].len)
                        return error.DiagnosticColumnCountMismatch;
                    values.* = try allocator.alloc(QM31, column_points.len);
                    column_count += 1;
                    const coefficients = trace.polys.items[tree_index][column_index]
                        .coefficients orelse
                        return error.DiagnosticCoefficientsUnavailable;
                    const column_log_size = coefficients.logSize();
                    if (column_log_size > lifting_log_size)
                        return error.DiagnosticColumnLogOutOfRange;
                    const fold_count = lifting_log_size - column_log_size;
                    for (column_points, values.*) |sample_point, *value| value.* =
                        coefficients.evalAtPoint(sample_point.repeatedDouble(fold_count));
                }
                tree_count += 1;
            }
            return stwo_core.air.components.MaskValues.initOwned(trees);
        }

        pub fn digestWords(value: [32]u8) [8]u32 {
            var result: [8]u32 = undefined;
            for (&result, 0..) |*word, index|
                word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
            return result;
        }

        /// Allocation-free, opt-in breadcrumbs for diagnosing peak-memory exits in
        /// the wide outer proof. A missing `end` record identifies the active stage;
        /// successful stages additionally report their wall-clock duration.
        pub fn stageTelemetryBegin(comptime stage: []const u8) void {
            if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;
            std.debug.print("  recursive-outer stage={s} event=begin\n", .{stage});
        }

        pub fn stageTelemetryEnd(comptime stage: []const u8, elapsed_ns: u64) void {
            if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;
            std.debug.print(
                "  recursive-outer stage={s} event=end elapsed_ns={d}\n",
                .{ stage, elapsed_ns },
            );
        }

        pub fn stageTelemetryPoolBinding(requested: usize, visible: usize) void {
            if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;
            std.debug.print(
                "  recursive-outer pool event=bound requested_workers={d} " ++
                    "visible_workers={d} explicitly_scoped={s}\n",
                .{
                    requested,
                    visible,
                    if (requested > 1) "yes" else "no-serial-control",
                },
            );
        }

        /// Audits the coordinator-local pool at the last outer-owned boundary before
        /// `StreamingCommitter` resolves it.  The synchronous call cannot change the
        /// thread-local binding between this check and the core resolution.  The
        /// threshold values mirror the current lifted-Merkle policy solely for opt-in
        /// diagnostics; protocol behavior remains owned by the core implementation.
        pub fn stageTelemetryCommitPool(
            comptime stage: []const u8,
            execution_pool: *ProofExecutionPool,
            evaluations: []const prover_pcs.ColumnEvaluation,
        ) !void {
            const visible = try execution_pool.visibleWorkerCount();
            if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;

            var final_log_size: u32 = 0;
            var cells: usize = 0;
            for (evaluations) |evaluation| {
                final_log_size = @max(final_log_size, evaluation.log_size);
                cells = std.math.add(usize, cells, evaluation.values.len) catch
                    std.math.maxInt(usize);
            }
            const leaf_count = @as(usize, 1) << @intCast(final_log_size);
            const min_parallel_nodes: usize = 1 << 11;
            const min_nodes_per_worker: usize = 1 << 10;
            const capacity = leaf_count / min_nodes_per_worker;
            const effective = if (leaf_count >= min_parallel_nodes and capacity >= 2)
                @min(visible, capacity)
            else
                1;
            std.debug.print(
                "  recursive-outer stage={s} pool requested_workers={d} " ++
                    "visible_workers={d} columns={d} cells={d} final_log={d} " ++
                    "parallel_threshold={d} final_group_workers={d}\n",
                .{
                    stage,
                    execution_pool.requested_worker_count,
                    visible,
                    evaluations.len,
                    cells,
                    final_log_size,
                    min_parallel_nodes,
                    effective,
                },
            );
        }

        /// Audits the exact binding resolved by `pcs.scheme.proveValues` immediately
        /// before the core proof call.  Four committed trees are expected here: the
        /// three universal trace trees and the quotient tree.
        pub fn stageTelemetrySampledValuesPool(
            execution_pool: *ProofExecutionPool,
            sampled_tree_count: usize,
        ) !void {
            const visible = try execution_pool.visibleWorkerCount();
            if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;
            const effective = if (sampled_tree_count > 1)
                @min(visible, sampled_tree_count)
            else
                1;
            std.debug.print(
                "  recursive-outer stage=prover.sampled-values pool " ++
                    "requested_workers={d} visible_workers={d} trees={d} " ++
                    "parallel_threshold_trees=2 effective_workers={d}\n",
                .{
                    execution_pool.requested_worker_count,
                    visible,
                    sampled_tree_count,
                    effective,
                },
            );
        }

        /// Emits verifier-derived proof and transcript identities for deterministic
        /// N=1/N>1 parity comparisons without serializing or trusting prover bytes.
        pub fn stageTelemetryPublicationIdentity(publication: ?CapturePublication) void {
            if (!std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) return;
            const target = publication orelse return;
            switch (target) {
                .verified => |verified| std.debug.print(
                    "  recursive-outer publication capture_id={any} " ++
                        "transcript_id={any} receipt_id={any}\n",
                    .{
                        verified.seal.capture_id,
                        verified.seal.transcript_id,
                        verified.seal.receipt_id,
                    },
                ),
                .verified_v2 => |verified| std.debug.print(
                    "  recursive-outer publication capture_id={any} " ++
                        "transcript_id={any} receipt_id={any} " ++
                        "closure_id_sha256={any}\n",
                    .{
                        verified.verified_v1.seal.capture_id,
                        verified.verified_v1.seal.transcript_id,
                        verified.verified_v1.seal.receipt_id,
                        verified.global_closure.closure_id,
                    },
                ),
                .capture => {},
            }
        }

        pub fn placementOffset(
            authority: *const Authority,
            row: air.universal_roster.Component,
            tree: usize,
        ) usize {
            const placement = authority.manifest.placements[@intFromEnum(row)].?;
            return treeOffset(placement, tree);
        }

        pub fn copyInteraction(tree: *TreeStorage, offset: usize, columns: anytype) void {
            for (columns, 0..) |column, local|
                @memcpy(tree.column(offset + local), column);
        }

        pub inline fn columnRow(
            comptime column_count: usize,
            columns: *const [column_count][]M31,
            row_index: usize,
        ) [column_count]M31 {
            var row: [column_count]M31 = undefined;
            inline for (0..column_count) |column| row[column] = columns[column][row_index];
            return row;
        }

        pub fn assertPreprocessedRoot(
            allocator: std.mem.Allocator,
            authority: *const Authority,
            actual: recursion.engine.Hasher.Hash,
        ) !void {
            var scheme = try Engine.init(allocator, OUTER_CONFIG);
            defer Engine.deinit(&scheme, allocator);
            var channel = Engine.Channel{};
            var tree = try TreeStorage.init(
                allocator,
                &authority.manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
            );
            defer tree.deinit();
            try fillPreprocessed(authority, &tree);
            try tree.commit(&scheme, &channel);
            try Engine.flushPendingCommit(&scheme, allocator, &channel);
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
                return error.PreprocessedRootMismatch;
        }

        pub fn commitVerifierTree(
            allocator: std.mem.Allocator,
            scheme: *VerifierScheme,
            manifest: *const manifest_mod.Manifest,
            tree: usize,
            commitment: recursion.engine.Hasher.Hash,
            channel: *Engine.Channel,
        ) !void {
            const logs = try allocator.alloc(u32, treeColumnCount(manifest, tree));
            defer allocator.free(logs);
            for (manifest.roster_rows[0..manifest.roster_count]) |row| {
                const placement = manifest.placements[row].?;
                const offset = treeOffset(placement, tree);
                const count = treeGeometryColumns(placement.geometry, tree);
                @memset(logs[offset..][0..count], placement.geometry.log_size);
            }
            try scheme.commit(allocator, commitment, logs, channel);
        }

        pub fn ColumnBuffer(comptime column_count: usize) type {
            return struct {
                allocator: std.mem.Allocator,
                log_size: u32,
                storage: []M31,
                views: [column_count][]M31,

                const Self = @This();

                pub fn init(allocator: std.mem.Allocator, log_size: u32) !Self {
                    const size = @as(usize, 1) << @intCast(log_size);
                    const storage = try allocator.alloc(
                        M31,
                        try std.math.mul(usize, column_count, size),
                    );
                    var views: [column_count][]M31 = undefined;
                    for (&views, 0..) |*view, column|
                        view.* = storage[column * size ..][0..size];
                    return .{
                        .allocator = allocator,
                        .log_size = log_size,
                        .storage = storage,
                        .views = views,
                    };
                }

                pub fn deinit(self: *Self) void {
                    self.allocator.free(self.storage);
                    self.* = undefined;
                }

                pub fn scatter(self: *const Self, tree: *TreeStorage, offset: usize) void {
                    const size = @as(usize, 1) << @intCast(self.log_size);
                    for (self.views, 0..) |source, column| {
                        const destination = tree.column(offset + column);
                        std.debug.assert(destination.len == size);
                        for (source, 0..) |value, logical_row|
                            destination[
                                framework.committedRow(
                                    logical_row,
                                    self.log_size,
                                )
                            ] = value;
                    }
                }
            };
        }

        pub const TreeStorage = struct {
            allocator: std.mem.Allocator,
            evaluations: []prover_pcs.ColumnEvaluation,
            /// Stable column views used by the universal row-source writers. These
            /// alias `storage`; ownership remains with this transaction.
            columns: [][]M31,
            storage: []M31,
            backing: [][]M31,

            pub fn init(
                allocator: std.mem.Allocator,
                manifest: *const manifest_mod.Manifest,
                tree: usize,
            ) !TreeStorage {
                const count = treeColumnCount(manifest, tree);
                const evaluations = try allocator.alloc(prover_pcs.ColumnEvaluation, count);
                errdefer allocator.free(evaluations);
                for (manifest.roster_rows[0..manifest.roster_count]) |row| {
                    const placement = manifest.placements[row].?;
                    const offset = treeOffset(placement, tree);
                    const local_count = treeGeometryColumns(placement.geometry, tree);
                    for (evaluations[offset..][0..local_count]) |*evaluation|
                        evaluation.log_size = placement.geometry.log_size;
                }
                var cells: usize = 0;
                for (evaluations) |evaluation|
                    cells = try std.math.add(
                        usize,
                        cells,
                        @as(usize, 1) << @intCast(evaluation.log_size),
                    );
                const storage = try allocator.alloc(M31, cells);
                errdefer allocator.free(storage);
                @memset(storage, M31.zero());
                var cursor: usize = 0;
                for (evaluations) |*evaluation| {
                    const rows = @as(usize, 1) << @intCast(evaluation.log_size);
                    evaluation.values = storage[cursor..][0..rows];
                    cursor += rows;
                }
                const columns = try allocator.alloc([]M31, count);
                errdefer allocator.free(columns);
                for (evaluations, columns) |evaluation, *column_view|
                    column_view.* = @constCast(evaluation.values);
                const backing = try allocator.alloc([]M31, 1);
                errdefer allocator.free(backing);
                backing[0] = storage;
                return .{
                    .allocator = allocator,
                    .evaluations = evaluations,
                    .columns = columns,
                    .storage = storage,
                    .backing = backing,
                };
            }

            pub fn deinit(self: *TreeStorage) void {
                if (self.evaluations.len != 0) self.allocator.free(self.evaluations);
                if (self.columns.len != 0) self.allocator.free(self.columns);
                if (self.backing.len != 0) self.allocator.free(self.backing);
                if (self.storage.len != 0) self.allocator.free(self.storage);
                self.* = undefined;
            }

            pub fn column(self: *TreeStorage, index: usize) []M31 {
                return @constCast(self.evaluations[index].values);
            }

            pub fn commit(
                self: *TreeStorage,
                scheme: *Engine.Scheme,
                channel: *Engine.Channel,
            ) !void {
                const evaluations = self.evaluations;
                const backing = self.backing;
                self.evaluations = &.{};
                self.backing = &.{};
                self.storage = &.{};
                try Engine.commitWithBacking(
                    scheme,
                    self.allocator,
                    evaluations,
                    backing,
                    null,
                    channel,
                );
            }
        };

        pub fn traceLogSize(count: usize) Error!u32 {
            if (count == 0) return 1;
            if (count >= (@as(usize, 1) << 30)) return error.ArithmeticOverflow;
            return @intCast(@max(@as(usize, 1), std.math.log2_int_ceil(usize, count)));
        }

        pub fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
            return switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
                else => unreachable,
            };
        }

        pub fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
            return switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
                manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
                manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
                else => unreachable,
            };
        }

        pub fn treeGeometryColumns(geometry: manifest_mod.Geometry, tree: usize) usize {
            return switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
                else => unreachable,
            };
        }
    };
}
