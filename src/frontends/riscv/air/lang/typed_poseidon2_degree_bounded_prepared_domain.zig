//! Parallel prepared-domain owner for the degree-six Poseidon2 candidate.
//!
//! Coordinator work materializes immutable quotient-domain views once.  The
//! row kernel then partitions the log-N+3 domain across one bounded
//! pool-exclusive wave.  Discarded PCS coefficients are reconstructed from
//! the committed LDE before extension; retained and recomputed paths therefore
//! feed the exact same row evaluator and composition accumulator.

pub fn Namespace(comptime contract: anytype) type {
    return struct {
        const std = contract.std;
        const M31 = contract.M31;
        const QM31 = contract.QM31;
        const core_constraints = contract.core_constraints;
        const canonic = contract.canonic;
        const utils = contract.utils;
        const prover_air_accumulation = contract.prover_air_accumulation;
        const prover_component = contract.prover_component;
        const prepared_domain = contract.prepared_domain;
        const prover_task_graph = contract.prover_task_graph;
        const work_pool = @import("stwo_prover_engine").work_pool;
        const prover_circle = @import("stwo_prover_engine").poly.circle.poly;
        const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
        const prepared_parallel = @import("../prepared_parallel.zig");
        const Component = contract.Component;
        const MAIN_COLUMNS = contract.MAIN_COLUMNS;
        const INTERACTION_COLUMNS = contract.INTERACTION_COLUMNS;
        const LOGUP_CONSTRAINTS = contract.LOGUP_CONSTRAINTS;
        const CONSTRAINTS = contract.CONSTRAINTS;
        const QUOTIENT_EXPANSION_BITS = contract.QUOTIENT_EXPANSION_BITS;
        const sampling = contract.sampling;

        const PARALLEL_DOMAIN_LOG_SIZE: u32 = 12;
        const CANCELLATION_POLL_ROWS: usize = 4096;
        const WORKER_STACK_BYTES: usize = 256 * 1024;
        const DENOMINATOR_COUNT: usize = 1 << QUOTIENT_EXPANSION_BITS;

        comptime {
            if (MAIN_COLUMNS != 161 or
                INTERACTION_COLUMNS != 8 or
                LOGUP_CONSTRAINTS != 2 or
                CONSTRAINTS != 151 or
                QUOTIENT_EXPANSION_BITS != 3 or
                !std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS))
            {
                @compileError("degree-six prepared-domain geometry drifted");
            }
        }

        pub fn prepare(
            component: *const Component,
            allocator: std.mem.Allocator,
            trace: *const prover_component.Trace,
            accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) !prepared_domain.PreparedDomainEvaluation {
            try component.validate();
            if (trace.polys.items.len < 3) return error.InvalidProofShape;
            const preprocessed = trace.polys.items[0];
            const main = trace.polys.items[1];
            const interaction = trace.polys.items[2];
            const main_end = std.math.add(
                usize,
                component.main_col_offset,
                MAIN_COLUMNS,
            ) catch return error.InvalidProofShape;
            const interaction_end = std.math.add(
                usize,
                component.interaction_col_offset,
                INTERACTION_COLUMNS,
            ) catch return error.InvalidProofShape;
            if (preprocessed.len <= component.is_first_col_idx or
                preprocessed.len <= component.is_active_col_idx or
                main.len < main_end or interaction.len < interaction_end)
            {
                return error.InvalidProofShape;
            }

            const eval_log_size = component.maxConstraintLogDegreeBound();
            const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
            const eval_size = eval_domain.size();
            const source_count = 2 + MAIN_COLUMNS + INTERACTION_COLUMNS;
            const evaluations = try allocator.alloc([]const M31, source_count);
            errdefer allocator.free(evaluations);
            var owned = std.ArrayList([]M31).empty;
            errdefer {
                for (owned.items) |values| allocator.free(values);
                owned.deinit(allocator);
            }
            var retained_extensions = std.ArrayList([]M31).empty;
            defer retained_extensions.deinit(allocator);
            var recomputed_extensions = std.ArrayList([]M31).empty;
            defer recomputed_extensions.deinit(allocator);
            var interpolations = std.ArrayList([]M31).empty;
            defer interpolations.deinit(allocator);
            var interpolation_log_size: ?u32 = null;

            var source: usize = 0;
            evaluations[source] = try evaluationOnDomain(
                allocator,
                preprocessed[component.is_first_col_idx],
                component.log_size,
                eval_log_size,
                eval_size,
                &owned,
                &retained_extensions,
                &recomputed_extensions,
                &interpolations,
                &interpolation_log_size,
            );
            source += 1;
            evaluations[source] = try evaluationOnDomain(
                allocator,
                preprocessed[component.is_active_col_idx],
                component.log_size,
                eval_log_size,
                eval_size,
                &owned,
                &retained_extensions,
                &recomputed_extensions,
                &interpolations,
                &interpolation_log_size,
            );
            source += 1;
            for (main[component.main_col_offset..main_end]) |poly| {
                evaluations[source] = try evaluationOnDomain(
                    allocator,
                    poly,
                    component.log_size,
                    eval_log_size,
                    eval_size,
                    &owned,
                    &retained_extensions,
                    &recomputed_extensions,
                    &interpolations,
                    &interpolation_log_size,
                );
                source += 1;
            }
            for (interaction[component.interaction_col_offset..interaction_end]) |poly| {
                evaluations[source] = try evaluationOnDomain(
                    allocator,
                    poly,
                    component.log_size,
                    eval_log_size,
                    eval_size,
                    &owned,
                    &retained_extensions,
                    &recomputed_extensions,
                    &interpolations,
                    &interpolation_log_size,
                );
                source += 1;
            }
            std.debug.assert(source == source_count);

            if (owned.items.len != 0) {
                var eval_twiddles = try prover_twiddles.precomputeM31(
                    allocator,
                    eval_domain.half_coset,
                );
                defer prover_twiddles.deinitM31(allocator, &eval_twiddles);
                const eval_tree = prover_twiddles.TwiddleTree([]const M31).init(
                    eval_twiddles.root_coset,
                    eval_twiddles.twiddles,
                    eval_twiddles.itwiddles,
                );
                if (interpolations.items.len != 0) {
                    const committed_log_size = interpolation_log_size orelse
                        return error.InvalidProofShape;
                    const committed_domain = canonic.CanonicCoset.new(
                        committed_log_size,
                    ).circleDomain();
                    var committed_twiddles = try prover_twiddles.precomputeM31(
                        allocator,
                        committed_domain.half_coset,
                    );
                    defer prover_twiddles.deinitM31(allocator, &committed_twiddles);
                    try interpolateAndEvaluateBuffersBounded(
                        interpolations.items,
                        recomputed_extensions.items,
                        committed_domain,
                        prover_twiddles.TwiddleTree([]const M31).init(
                            committed_twiddles.root_coset,
                            committed_twiddles.twiddles,
                            committed_twiddles.itwiddles,
                        ),
                        eval_domain,
                        eval_tree,
                    );
                }
                try evaluateBuffersBounded(
                    retained_extensions.items,
                    eval_domain,
                    eval_tree,
                );
            }
            const owned_buffers = try owned.toOwnedSlice(allocator);
            errdefer {
                for (owned_buffers) |values| allocator.free(values);
                allocator.free(owned_buffers);
            }
            const denominators = try quotientDenominators(
                component.log_size,
                eval_log_size,
                eval_domain,
            );
            const accumulators = try accumulator.columns(allocator, &.{.{
                .log_size = eval_log_size,
                .n_cols = CONSTRAINTS,
            }});
            defer allocator.free(accumulators);
            const state = try allocator.create(PreparedDomainState);
            errdefer allocator.destroy(state);
            state.* = .{
                .allocator = allocator,
                .component = component,
                .evaluations = evaluations,
                .owned_buffers = owned_buffers,
                .denominators = denominators,
                .column_accumulator = accumulators[0],
                .direct_store = accumulators[0].next_fresh_index == 0,
                .eval_log_size = eval_log_size,
                .eval_size = eval_size,
            };
            return .{
                .context = state,
                .vtable = &PreparedDomainState.vtable,
                .task_class = if (component.log_size >= PARALLEL_DOMAIN_LOG_SIZE)
                    .pool_exclusive
                else
                    .leaf,
                .resources = try resources(
                    eval_size,
                    source_count,
                    owned_buffers.len,
                ),
            };
        }

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

        const PreparedDomainState = struct {
            allocator: std.mem.Allocator,
            component: *const Component,
            evaluations: [][]const M31,
            owned_buffers: [][]M31,
            denominators: [DENOMINATOR_COUNT]M31,
            column_accumulator: prover_air_accumulation.ColumnAccumulator,
            direct_store: bool,
            eval_log_size: u32,
            eval_size: usize,
            failure_boundary: prepared_parallel.FailureBoundary = .{},
            workers: [work_pool.MAX_WORKERS]RangeWorker = undefined,

            const vtable = prepared_domain.VTable{
                .run = runErased,
                .deinit = deinitErased,
            };

            fn runErased(
                context: *anyopaque,
                task_context: *prover_task_graph.TaskContext,
            ) anyerror!void {
                const self: *PreparedDomainState = @ptrCast(@alignCast(context));
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
                const extra = tile_count % worker_count;
                var next_tile: usize = 0;
                for (self.workers[0..worker_count], 0..) |*worker, index| {
                    const assigned = tiles_per_worker + @intFromBool(index < extra);
                    const end_tile = next_tile + assigned;
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
                for (self.workers[1..worker_count]) |*worker| {
                    try task_context.spawnChild(RangeWorker.run, .{worker});
                }
                self.workers[0].run();
                try task_context.waitForChildren();
                for (self.workers[0..worker_count]) |worker| {
                    if (worker.failure) |failure| return failure;
                }
                for (self.workers[0..worker_count]) |worker| {
                    if (!worker.completed) return;
                }
                self.finishOutput();
            }

            fn deinitErased(context: *anyopaque) void {
                const self: *PreparedDomainState = @ptrCast(@alignCast(context));
                const allocator = self.allocator;
                for (self.owned_buffers) |values| allocator.free(values);
                allocator.free(self.owned_buffers);
                allocator.free(self.evaluations);
                allocator.destroy(self);
            }

            fn evaluateRange(
                self: *PreparedDomainState,
                cancellation: *const prover_task_graph.CancellationToken,
                range_index: usize,
                row_start: usize,
                row_end: usize,
            ) !bool {
                const component = self.component;
                const main_start: usize = 2;
                const interaction_start = main_start + MAIN_COLUMNS;
                const denominator_shift: std.math.Log2Int(usize) =
                    @intCast(component.log_size);
                const powers = self.column_accumulator.random_coeff_powers;
                for (row_start..row_end) |row| {
                    if ((row & (CANCELLATION_POLL_ROWS - 1)) == 0 and
                        (cancellation.isCancelled() or
                            self.failure_boundary.shouldCancel(range_index))) return false;
                    var main: [MAIN_COLUMNS]QM31 = undefined;
                    for (&main, self.evaluations[main_start..][0..MAIN_COLUMNS]) |
                        *value,
                        values,
                    | value.* = QM31.fromBase(values[row]);
                    const previous_row = utils.previousBitReversedCircleDomainIndex(
                        row,
                        component.log_size,
                        self.eval_log_size,
                    );
                    var sums: [LOGUP_CONSTRAINTS]QM31 = undefined;
                    var previous: [LOGUP_CONSTRAINTS]QM31 = undefined;
                    for (0..LOGUP_CONSTRAINTS) |index| {
                        const sources = self.evaluations[interaction_start + 4 * index ..][0..4];
                        sums[index] = sampling.secureAt(sources, row);
                        previous[index] = sampling.secureAt(sources, previous_row);
                    }
                    const evaluated = try component.evaluateConstraints(
                        main,
                        QM31.fromBase(self.evaluations[1][row]),
                        QM31.fromBase(self.evaluations[0][row]),
                        sums,
                        previous,
                    );
                    var folded = QM31.zero();
                    for (evaluated, 0..) |constraint, index| {
                        folded = folded.add(
                            powers[powers.len - 1 - index].mul(constraint),
                        );
                    }
                    const contribution = folded.mulM31(
                        self.denominators[row >> denominator_shift],
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

            fn finishOutput(self: *PreparedDomainState) void {
                self.column_accumulator.next_fresh_index = if (self.direct_store)
                    self.eval_size
                else
                    null;
            }
        };

        const RangeWorker = struct {
            state: *PreparedDomainState,
            parent_cancellation: *const prover_task_graph.CancellationToken,
            range_index: usize,
            row_start: usize,
            row_end: usize,
            is_child: bool,
            completed: bool = false,
            failure: ?anyerror = null,

            fn run(self: *RangeWorker) void {
                _ = self.is_child;
                self.completed = self.state.evaluateRange(
                    self.parent_cancellation,
                    self.range_index,
                    self.row_start,
                    self.row_end,
                ) catch |failure| failed: {
                    self.failure = failure;
                    _ = self.state.failure_boundary.recordFailure(self.range_index);
                    break :failed false;
                };
            }
        };

        fn interpolateBuffersBounded(
            buffers: []const []M31,
            domain: anytype,
            twiddles: anytype,
        ) !void {
            const Job = struct {
                buffers: []const []M31,
                domain: @TypeOf(domain),
                twiddles: @TypeOf(twiddles),
                failure: ?anyerror = null,

                fn run(self: *@This()) void {
                    prover_circle.interpolateBuffersWithTwiddles(
                        self.buffers,
                        self.domain,
                        self.twiddles,
                    ) catch |failure| {
                        self.failure = failure;
                    };
                }
            };
            return runTransformJobs(Job, buffers, domain, twiddles);
        }

        fn evaluateBuffersBounded(
            buffers: []const []M31,
            domain: anytype,
            twiddles: anytype,
        ) !void {
            const Job = struct {
                buffers: []const []M31,
                domain: @TypeOf(domain),
                twiddles: @TypeOf(twiddles),
                failure: ?anyerror = null,

                fn run(self: *@This()) void {
                    prover_circle.evaluateBuffersWithTwiddles(
                        self.buffers,
                        self.domain,
                        self.twiddles,
                    ) catch |failure| {
                        self.failure = failure;
                    };
                }
            };
            return runTransformJobs(Job, buffers, domain, twiddles);
        }

        fn interpolateAndEvaluateBuffersBounded(
            coefficient_buffers: []const []M31,
            extension_buffers: []const []M31,
            committed_domain: anytype,
            committed_twiddles: anytype,
            eval_domain: anytype,
            eval_twiddles: anytype,
        ) !void {
            const Job = struct {
                coefficient_buffers: []const []M31,
                extension_buffers: []const []M31,
                committed_domain: @TypeOf(committed_domain),
                committed_twiddles: @TypeOf(committed_twiddles),
                eval_domain: @TypeOf(eval_domain),
                eval_twiddles: @TypeOf(eval_twiddles),
                failure: ?anyerror = null,

                fn run(self: *@This()) void {
                    prover_circle.interpolateBuffersWithTwiddles(
                        self.coefficient_buffers,
                        self.committed_domain,
                        self.committed_twiddles,
                    ) catch |failure| {
                        self.failure = failure;
                        return;
                    };
                    prover_circle.evaluateBuffersWithTwiddles(
                        self.extension_buffers,
                        self.eval_domain,
                        self.eval_twiddles,
                    ) catch |failure| {
                        self.failure = failure;
                    };
                }
            };
            return runPipelineJobs(
                Job,
                coefficient_buffers,
                extension_buffers,
                committed_domain,
                committed_twiddles,
                eval_domain,
                eval_twiddles,
            );
        }

        fn runTransformJobs(
            comptime Job: type,
            buffers: []const []M31,
            domain: anytype,
            twiddles: anytype,
        ) !void {
            if (buffers.len == 0) return;
            if (domain.logSize() < PARALLEL_DOMAIN_LOG_SIZE) {
                var serial = Job{
                    .buffers = buffers,
                    .domain = domain,
                    .twiddles = twiddles,
                };
                serial.run();
                if (serial.failure) |failure| return failure;
                return;
            }
            const pool = work_pool.getGlobalPool() orelse {
                var serial = Job{
                    .buffers = buffers,
                    .domain = domain,
                    .twiddles = twiddles,
                };
                serial.run();
                if (serial.failure) |failure| return failure;
                return;
            };
            const worker_count = @min(pool.workerCount(), buffers.len);
            if (worker_count == 1) {
                var serial = Job{
                    .buffers = buffers,
                    .domain = domain,
                    .twiddles = twiddles,
                };
                serial.run();
                if (serial.failure) |failure| return failure;
                return;
            }

            var lease = try pool.acquire(try work_pool.WorkerBudget.init(worker_count));
            defer lease.deinit();
            var jobs: [work_pool.MAX_WORKERS]Job = undefined;
            const buffers_per_worker = buffers.len / worker_count;
            const extra = buffers.len % worker_count;
            var next: usize = 0;
            for (jobs[0..worker_count], 0..) |*job, worker_index| {
                const assigned = buffers_per_worker + @intFromBool(worker_index < extra);
                job.* = .{
                    .buffers = buffers[next .. next + assigned],
                    .domain = domain,
                    .twiddles = twiddles,
                };
                next += assigned;
            }
            std.debug.assert(next == buffers.len);

            var wait_group: std.Thread.WaitGroup = .{};
            var wave_active = false;
            defer if (wave_active) {
                wait_group.wait();
                lease.completeWave();
            };
            for (jobs[1..worker_count]) |*job| {
                try lease.spawnWg(&wait_group, Job.run, .{job});
                wave_active = true;
            }
            jobs[0].run();
            wait_group.wait();
            lease.completeWave();
            wave_active = false;
            for (jobs[0..worker_count]) |job| {
                if (job.failure) |failure| return failure;
            }
        }

        fn runPipelineJobs(
            comptime Job: type,
            coefficient_buffers: []const []M31,
            extension_buffers: []const []M31,
            committed_domain: anytype,
            committed_twiddles: anytype,
            eval_domain: anytype,
            eval_twiddles: anytype,
        ) !void {
            if (coefficient_buffers.len == 0) return;
            if (coefficient_buffers.len != extension_buffers.len)
                return error.InvalidProofShape;
            if (eval_domain.logSize() < PARALLEL_DOMAIN_LOG_SIZE) {
                var serial = Job{
                    .coefficient_buffers = coefficient_buffers,
                    .extension_buffers = extension_buffers,
                    .committed_domain = committed_domain,
                    .committed_twiddles = committed_twiddles,
                    .eval_domain = eval_domain,
                    .eval_twiddles = eval_twiddles,
                };
                serial.run();
                if (serial.failure) |failure| return failure;
                return;
            }
            const pool = work_pool.getGlobalPool() orelse {
                var serial = Job{
                    .coefficient_buffers = coefficient_buffers,
                    .extension_buffers = extension_buffers,
                    .committed_domain = committed_domain,
                    .committed_twiddles = committed_twiddles,
                    .eval_domain = eval_domain,
                    .eval_twiddles = eval_twiddles,
                };
                serial.run();
                if (serial.failure) |failure| return failure;
                return;
            };
            const worker_count = @min(pool.workerCount(), coefficient_buffers.len);
            if (worker_count == 1) {
                var serial = Job{
                    .coefficient_buffers = coefficient_buffers,
                    .extension_buffers = extension_buffers,
                    .committed_domain = committed_domain,
                    .committed_twiddles = committed_twiddles,
                    .eval_domain = eval_domain,
                    .eval_twiddles = eval_twiddles,
                };
                serial.run();
                if (serial.failure) |failure| return failure;
                return;
            }

            var lease = try pool.acquire(try work_pool.WorkerBudget.init(worker_count));
            defer lease.deinit();
            var jobs: [work_pool.MAX_WORKERS]Job = undefined;
            const buffers_per_worker = coefficient_buffers.len / worker_count;
            const extra = coefficient_buffers.len % worker_count;
            var next: usize = 0;
            for (jobs[0..worker_count], 0..) |*job, worker_index| {
                const assigned = buffers_per_worker + @intFromBool(worker_index < extra);
                job.* = .{
                    .coefficient_buffers = coefficient_buffers[next .. next + assigned],
                    .extension_buffers = extension_buffers[next .. next + assigned],
                    .committed_domain = committed_domain,
                    .committed_twiddles = committed_twiddles,
                    .eval_domain = eval_domain,
                    .eval_twiddles = eval_twiddles,
                };
                next += assigned;
            }
            std.debug.assert(next == coefficient_buffers.len);

            var wait_group: std.Thread.WaitGroup = .{};
            var wave_active = false;
            defer if (wave_active) {
                wait_group.wait();
                lease.completeWave();
            };
            for (jobs[1..worker_count]) |*job| {
                try lease.spawnWg(&wait_group, Job.run, .{job});
                wave_active = true;
            }
            jobs[0].run();
            wait_group.wait();
            lease.completeWave();
            wave_active = false;
            for (jobs[0..worker_count]) |job| {
                if (job.failure) |failure| return failure;
            }
        }

        fn evaluationOnDomain(
            allocator: std.mem.Allocator,
            poly: prover_component.Poly,
            trace_log_size: u32,
            eval_log_size: u32,
            eval_size: usize,
            owned: *std.ArrayList([]M31),
            retained_extensions: *std.ArrayList([]M31),
            recomputed_extensions: *std.ArrayList([]M31),
            interpolations: *std.ArrayList([]M31),
            interpolation_log_size: *?u32,
        ) ![]const M31 {
            try poly.validate();
            if (poly.log_size == eval_log_size) return poly.values;
            if (poly.log_size > eval_log_size) return error.InvalidProofShape;
            const values = try allocator.alloc(M31, eval_size);
            errdefer allocator.free(values);
            const initialized = if (poly.coefficients) |coefficients| blk: {
                if (coefficients.logSize() != trace_log_size)
                    return error.InvalidProofShape;
                const source = coefficients.coefficients();
                if (source.len > values.len) return error.InvalidProofShape;
                @memcpy(values[0..source.len], source);
                try retained_extensions.append(allocator, values);
                break :blk source.len;
            } else blk: {
                if (poly.log_size < trace_log_size or poly.values.len > values.len)
                    return error.InvalidProofShape;
                if (interpolation_log_size.*) |expected| {
                    if (expected != poly.log_size) return error.InvalidProofShape;
                } else {
                    interpolation_log_size.* = poly.log_size;
                }
                @memcpy(values[0..poly.values.len], poly.values);
                try interpolations.append(allocator, values[0..poly.values.len]);
                try recomputed_extensions.append(allocator, values);
                break :blk poly.values.len;
            };
            @memset(values[initialized..], M31.zero());
            try owned.append(allocator, values);
            return values;
        }

        fn quotientDenominators(
            trace_log_size: u32,
            eval_log_size: u32,
            eval_domain: anytype,
        ) ![DENOMINATOR_COUNT]M31 {
            if (eval_log_size != trace_log_size + QUOTIENT_EXPANSION_BITS)
                return error.InvalidProofShape;
            var result: [DENOMINATOR_COUNT]M31 = undefined;
            const trace_coset = canonic.CanonicCoset.new(trace_log_size).coset();
            for (&result, 0..) |*inverse, index| {
                inverse.* = try core_constraints.cosetVanishing(
                    M31,
                    trace_coset,
                    eval_domain.at(utils.bitReverseIndex(
                        index,
                        QUOTIENT_EXPANSION_BITS,
                    )),
                ).inv();
            }
            return result;
        }

        fn resources(
            eval_size: usize,
            source_count: usize,
            owned_count: usize,
        ) !prover_task_graph.ResourceReservation {
            const final_output_bytes = std.math.mul(
                usize,
                eval_size,
                @sizeOf(QM31),
            ) catch return error.ResourceReservationOverflow;
            var shared = std.math.add(
                usize,
                @sizeOf(PreparedDomainState),
                std.math.mul(usize, source_count, @sizeOf([]const M31)) catch
                    return error.ResourceReservationOverflow,
            ) catch return error.ResourceReservationOverflow;
            shared = std.math.add(
                usize,
                shared,
                std.math.mul(usize, owned_count, @sizeOf([]M31)) catch
                    return error.ResourceReservationOverflow,
            ) catch return error.ResourceReservationOverflow;
            const owned_values = std.math.mul(usize, owned_count, eval_size) catch
                return error.ResourceReservationOverflow;
            shared = std.math.add(
                usize,
                shared,
                std.math.mul(usize, owned_values, @sizeOf(M31)) catch
                    return error.ResourceReservationOverflow,
            ) catch return error.ResourceReservationOverflow;
            return .{
                .final_output_bytes = final_output_bytes,
                .shared_resident_bytes = shared,
                .worker_stack_bytes = WORKER_STACK_BYTES,
            };
        }
    };
}
