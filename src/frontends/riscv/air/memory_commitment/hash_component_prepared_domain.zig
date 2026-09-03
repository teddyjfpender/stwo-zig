//! Prepared-domain ownership and worker dispatch for hash-component evaluation.

pub fn Namespace(comptime contract: anytype) type {
    return struct {
        const std = contract.std;
        const M31 = contract.M31;
        const QM31 = contract.QM31;
        const utils = contract.utils;
        const prover_air_accumulation = contract.prover_air_accumulation;
        const prepared_domain = contract.prepared_domain;
        const prover_task_graph = contract.prover_task_graph;
        const work_pool = contract.work_pool;
        const prepared_parallel = contract.prepared_parallel;
        const merkle_node = contract.merkle_node;
        const poseidon2_air = contract.poseidon2_air;
        const PREPARED_DENOMINATOR_COUNT = contract.PREPARED_DENOMINATOR_COUNT;
        const prepared_parallel_telemetry = contract.prepared_parallel_telemetry;
        const HashComponent = contract.HashComponent;
        const merkleExternalizedProviderConstraints =
            contract.merkleExternalizedProviderConstraints;
        const poseidonConstraints = contract.poseidonConstraints;
        const poseidonGeneralConstraints = contract.poseidonGeneralConstraints;
        const readMain = contract.readMain;
        const readInteraction = contract.readInteraction;
        const combineConstraints = contract.combineConstraints;

        pub const PreparedDomainState = struct {
            const CANCELLATION_POLL_ROWS: usize = 4096;
            const Kernel = enum {
                merkle,
                merkle_externalized_provider,
                poseidon_narrow,
                poseidon_general,
            };

            comptime {
                if (PREPARED_DENOMINATOR_COUNT != 2) {
                    @compileError("hash composition domains own exactly two quotient denominators");
                }
                if (CANCELLATION_POLL_ROWS == 0 or
                    CANCELLATION_POLL_ROWS > 4096 or
                    !std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS))
                {
                    @compileError("prepared domain cancellation polls must be power-of-two tiles of at most 4,096 rows");
                }
            }

            allocator: std.mem.Allocator,
            component: *const HashComponent,
            evaluations: [][]const M31,
            owned_buffers: [][]M31,
            denominator_inv: [PREPARED_DENOMINATOR_COUNT]M31,
            column_accumulator: prover_air_accumulation.ColumnAccumulator,
            direct_store: bool,
            main_start: usize,
            interaction_start: usize,
            eval_log_size: u32,
            eval_size: usize,
            failure_boundary: prepared_parallel.FailureBoundary = .{},
            range_workers: [work_pool.MAX_WORKERS]PreparedRangeWorker = undefined,

            pub const vtable = prepared_domain.VTable{
                .run = runErased,
                .deinit = deinitErased,
            };

            fn runErased(
                context: *anyopaque,
                task_context: *prover_task_graph.TaskContext,
            ) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(context));
                self.failure_boundary.reset();
                const tile_count = std.math.divCeil(
                    usize,
                    self.eval_size,
                    CANCELLATION_POLL_ROWS,
                ) catch unreachable;
                const worker_count = @min(task_context.worker_budget.count, tile_count);
                if (worker_count == 1) {
                    if (try self.evaluateRange(task_context.cancellation, 0, 0, self.eval_size)) {
                        self.finishOutput();
                    }
                    return;
                }

                std.debug.assert(task_context.task_class == .pool_exclusive);
                const tiles_per_worker = tile_count / worker_count;
                const workers_with_extra_tile = tile_count % worker_count;
                var next_tile: usize = 0;
                for (self.range_workers[0..worker_count], 0..) |*worker, index| {
                    const assigned_tiles = tiles_per_worker + @intFromBool(index < workers_with_extra_tile);
                    const end_tile = next_tile + assigned_tiles;
                    worker.* = .{
                        .state = self,
                        .parent_cancellation = task_context.cancellation,
                        .range_index = index,
                        .row_start = next_tile * CANCELLATION_POLL_ROWS,
                        .row_end = @min(self.eval_size, end_tile * CANCELLATION_POLL_ROWS),
                        .is_child = index != 0,
                    };
                    next_tile = end_tile;
                }
                std.debug.assert(next_tile == tile_count);
                for (self.range_workers[1..worker_count]) |*worker| {
                    try task_context.spawnChild(PreparedRangeWorker.run, .{worker});
                    prepared_parallel_telemetry.recordChildSubmission();
                }
                self.range_workers[0].run();
                try task_context.waitForChildren();
                // Ranges are stored in ascending row order. Inspecting failures only
                // after the join makes the selected error independent of completion
                // order while local cancellation remains only a work-saving signal.
                for (self.range_workers[0..worker_count]) |worker| {
                    if (worker.failure) |failure| return failure;
                }
                for (self.range_workers[0..worker_count]) |worker| {
                    if (!worker.completed) return;
                }
                self.finishOutput();
            }

            fn deinitErased(context: *anyopaque) void {
                const self: *@This() = @ptrCast(@alignCast(context));
                const allocator = self.allocator;
                for (self.owned_buffers) |values| allocator.free(values);
                allocator.free(self.owned_buffers);
                allocator.free(self.evaluations);
                allocator.destroy(self);
            }

            fn evaluateRange(
                self: *@This(),
                parent_cancellation: *const prover_task_graph.CancellationToken,
                range_index: usize,
                row_start: usize,
                row_end: usize,
            ) anyerror!bool {
                return switch (self.component.kind) {
                    .merkle => switch (self.component.merkle_shell) {
                        .standard => self.evaluateRangeKernel(
                            .merkle,
                            parent_cancellation,
                            range_index,
                            row_start,
                            row_end,
                        ),
                        .externalized_poseidon_provider => self.evaluateRangeKernel(
                            .merkle_externalized_provider,
                            parent_cancellation,
                            range_index,
                            row_start,
                            row_end,
                        ),
                    },
                    .poseidon2 => switch (self.component.poseidon_shell) {
                        .narrow_memory => self.evaluateRangeKernel(
                            .poseidon_narrow,
                            parent_cancellation,
                            range_index,
                            row_start,
                            row_end,
                        ),
                        .universal => self.evaluateRangeKernel(
                            .poseidon_general,
                            parent_cancellation,
                            range_index,
                            row_start,
                            row_end,
                        ),
                    },
                };
            }

            /// Select the immutable component shape once per worker range. Keeping the
            /// dispatch outside the row loop preserves the original narrow-provider
            /// hot kernel while giving general Poseidon its own statically pruned loop.
            fn evaluateRangeKernel(
                self: *@This(),
                comptime kernel: Kernel,
                parent_cancellation: *const prover_task_graph.CancellationToken,
                range_index: usize,
                row_start: usize,
                row_end: usize,
            ) anyerror!bool {
                const component = self.component;
                for (row_start..row_end) |row| {
                    if ((row & (CANCELLATION_POLL_ROWS - 1)) == 0 and
                        (parent_cancellation.isCancelled() or
                            self.failure_boundary.shouldCancel(range_index))) return false;
                    const previous_row = utils.previousBitReversedCircleDomainIndex(
                        row,
                        component.log_size,
                        self.eval_log_size,
                    );
                    const is_first = QM31.fromBase(self.evaluations[0][row]);
                    const row_evaluation = switch (kernel) {
                        .merkle, .merkle_externalized_provider => blk: {
                            const is_active = QM31.fromBase(self.evaluations[1][row]);
                            const main = readMain(
                                merkle_node.N_MAIN_COLUMNS,
                                self.evaluations[self.main_start..][0..merkle_node.N_MAIN_COLUMNS],
                                row,
                            );
                            var sums: [merkle_node.N_SUMS]QM31 = undefined;
                            var previous: [merkle_node.N_SUMS]QM31 = undefined;
                            readInteraction(
                                merkle_node.N_SUMS,
                                self.evaluations,
                                self.interaction_start,
                                row,
                                previous_row,
                                &sums,
                                &previous,
                            );
                            if (kernel == .merkle) {
                                const constraints = merkle_node.evaluate(
                                    main,
                                    is_active,
                                    is_first,
                                    sums,
                                    previous,
                                    component.merkle_claims,
                                    component.relations,
                                );
                                break :blk combineConstraints(
                                    self.column_accumulator.random_coeff_powers,
                                    &constraints,
                                );
                            }
                            const constraints = merkleExternalizedProviderConstraints(
                                main,
                                is_active,
                                is_first,
                                sums,
                                previous,
                                component.merkle_claims,
                                component.relations,
                            );
                            break :blk combineConstraints(
                                self.column_accumulator.random_coeff_powers,
                                &constraints,
                            );
                        },
                        .poseidon_narrow, .poseidon_general => blk: {
                            const main = readMain(
                                poseidon2_air.N_MAIN_COLUMNS,
                                self.evaluations[self.main_start..][0..poseidon2_air.N_MAIN_COLUMNS],
                                row,
                            );
                            var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                            var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                            readInteraction(
                                poseidon2_air.N_SUMS,
                                self.evaluations,
                                self.interaction_start,
                                row,
                                previous_row,
                                &sums,
                                &previous,
                            );
                            if (kernel == .poseidon_narrow) {
                                const constraints = poseidonConstraints(
                                    main,
                                    QM31.fromBase(self.evaluations[1][row]),
                                    is_first,
                                    sums,
                                    previous,
                                    component.poseidon_claims,
                                    component.relations,
                                );
                                break :blk combineConstraints(
                                    self.column_accumulator.random_coeff_powers,
                                    &constraints,
                                );
                            }
                            const constraints = poseidonGeneralConstraints(
                                main,
                                is_first,
                                sums,
                                previous,
                                component.poseidon_claims,
                                component.relations,
                            );
                            break :blk combineConstraints(
                                self.column_accumulator.random_coeff_powers,
                                &constraints,
                            );
                        },
                    };
                    const contribution = row_evaluation.mulM31(
                        self.denominator_inv[row >> @intCast(component.log_size)],
                    );
                    const output = self.column_accumulator.col;
                    if (self.direct_store) {
                        output.set(row, contribution);
                    } else {
                        output.set(row, output.at(row).add(contribution));
                    }
                }
                return true;
            }

            fn finishOutput(self: *@This()) void {
                self.column_accumulator.next_fresh_index = if (self.direct_store) self.eval_size else null;
            }
        };

        pub const PreparedRangeWorker = struct {
            state: *PreparedDomainState,
            parent_cancellation: *const prover_task_graph.CancellationToken,
            range_index: usize,
            row_start: usize,
            row_end: usize,
            is_child: bool,
            completed: bool = false,
            failure: ?anyerror = null,

            fn run(self: *@This()) void {
                defer if (self.is_child) {
                    prepared_parallel_telemetry.recordChildCompletion();
                };
                self.completed = self.state.evaluateRange(
                    self.parent_cancellation,
                    self.range_index,
                    self.row_start,
                    self.row_end,
                ) catch |failure| failed: {
                    self.failure = failure;
                    prepared_parallel_telemetry.recordRangeFailure();
                    if (self.state.failure_boundary.recordFailure(self.range_index)) {
                        prepared_parallel_telemetry.recordLocalCancellation();
                    }
                    break :failed false;
                };
            }
        };

        pub fn serialTaskContext(
            user_context: *anyopaque,
            cancellation: *const prover_task_graph.CancellationToken,
        ) prover_task_graph.TaskContext {
            return .{
                .user_context = user_context,
                .cancellation = cancellation,
                .key = .{
                    .epoch = 0,
                    .stage_rank = 0,
                    .component_registry_index = 0,
                    .shard_or_chunk_index = 0,
                },
                .worker_budget = work_pool.WorkerBudget.serial(),
                .task_class = .leaf,
                .exclusive_lease = null,
                .child_wait_group = null,
            };
        }
    };
}
