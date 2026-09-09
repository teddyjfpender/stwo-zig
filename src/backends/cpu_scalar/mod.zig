//! CPU scalar backend for stwo-zig.
//!
//! This is the default backend. All operations work on plain `[]F` slices
//! with scalar field arithmetic. The type itself is zero-sized — it exists
//! purely to select implementations at compile time.
//!
//! ## Column type
//!
//! `CpuBackend.ColumnType(M31) = []M31` — plain heap-allocated slices.
//!
//! ## Threading
//!
//! Merkle commitment supports optional multi-threaded hashing via
//! `std.Thread.Pool`, configured by environment variables.

const std = @import("std");
const m31_mod = @import("stwo_core").fields.m31;
const cm31_mod = @import("stwo_core").fields.cm31;
const qm31_mod = @import("stwo_core").fields.qm31;
const fields_mod = @import("stwo_core").fields;
const core_fri = @import("stwo_core").fri;
const core_poly = @import("stwo_core").poly;
const prover_impl = @import("stwo_prover_engine");
const work_profile = prover_impl.work_profile;
const lifted_merkle = @import("stwo_prover_engine").vcs_lifted.prover;
const riscv_composition = @import("riscv_composition.zig");
const secure_composition = @import("secure_composition.zig");

const M31 = m31_mod.M31;
const CM31 = cm31_mod.CM31;
const QM31 = qm31_mod.QM31;

/// CPU scalar backend. Zero-sized marker type.
///
/// Satisfies the full `backend.assertBackend` contract by delegating
/// to the existing scalar implementations in `core/` and `prover/`.
pub const CpuBackend = struct {
    pub const capabilities: backend.Capabilities = .{
        .host_batch_inverse = true,
        .fri_folding = true,
        .fri_multi_fold = true,
    };
    pub const combined_commit_min_columns: usize = 65;
    pub const combined_commit_max_columns: usize = 256;
    pub const combined_base_in_place = true;
    pub const reuses_constant_merkle_parents = true;
    pub const lazy_merkle_reuses_constant_parents = false;
    /// The combined CPU LDE elides the degenerate first forward layer only for
    /// an exact 2x extension. This declaration lets cold logical-work
    /// accounting describe the implementation without entering FFT kernels.
    pub fn combinedCircleLdeSkippedForwardLayers(
        base_log_size: u32,
        extended_log_size: u32,
    ) u32 {
        return if (extended_log_size > 2 and
            extended_log_size > base_log_size and
            extended_log_size - base_log_size == 1)
            1
        else
            0;
    }

    pub fn warmup() !void {}

    pub fn computeCompositionEvaluation(
        allocator: std.mem.Allocator,
        components: []const @import("stwo_prover_engine").air.component_prover.ComponentProver,
        random_coeff: QM31,
        trace: *const @import("stwo_prover_engine").air.component_prover.Trace,
        residency_handles: []const ?*anyopaque,
        composition_twiddles: ?@import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const M31),
    ) !?@import("stwo_prover_engine").secure_column.SecureColumnByCoords {
        return computeCompositionEvaluationWithExecution(
            allocator,
            components,
            random_coeff,
            trace,
            residency_handles,
            composition_twiddles,
            try prover_impl.air.composition_execution.Execution.resolve(null),
        );
    }

    pub fn computeCompositionEvaluationWithExecution(
        allocator: std.mem.Allocator,
        components: []const prover_impl.air.component_prover.ComponentProver,
        random_coeff: QM31,
        trace: *const prover_impl.air.component_prover.Trace,
        residency_handles: []const ?*anyopaque,
        composition_twiddles: ?prover_impl.poly.twiddles.TwiddleTree([]const M31),
        execution: prover_impl.air.composition_execution.Execution,
    ) !?prover_impl.secure_column.SecureColumnByCoords {
        _ = residency_handles;
        _ = composition_twiddles;
        // The recurrence fast path owns a direct joined row wave, not a
        // ComponentTaskGraph. Keep it explicitly outside flat task telemetry
        // until that executor has truthful per-task identities and accounting.
        var recurrence_execution = execution;
        recurrence_execution.task_recorder = null;
        if (try secure_composition.evaluateLargeRecurrenceComposition(
            allocator,
            components,
            random_coeff,
            trace,
            recurrence_execution,
        )) |evaluation| return evaluation;
        const adjusted = execution.adjustedForAvailablePool();
        adjusted.validateCapacity() catch |err| {
            prover_impl.engine.EvaluationDiagnostic.recordFirst(
                execution.evaluation_diagnostic,
                .{
                    .stage = .plan,
                    .cause = err,
                    .actual = adjusted.worker_budget.count,
                    .expected = adjusted.poolCapacity(),
                },
            );
            return err;
        };
        return riscv_composition.evaluateWithExecution(
            allocator,
            components,
            random_coeff,
            trace,
            .{
                .worker_budget = adjusted.worker_budget,
                .pool = adjusted.pool,
                .byte_budget = adjusted.host_byte_budget,
                .serial_on_contention = !execution.isStrict(),
                .allow_unprepared_fallback = !execution.isStrict(),
                .requested_worker_count = execution.requestedWorkerCount(),
                .pool_capacity = execution.poolCapacity(),
                .task_recorder = execution.task_recorder,
                .work_capture = execution.composition_work_capture,
                .evaluation_diagnostic = execution.evaluation_diagnostic,
            },
        );
    }

    /// Process-wide structural evidence for the bounded RISC-V CPU composition
    /// path. This is intentionally separate from hybrid-device telemetry.
    pub fn riscvCompositionTelemetrySnapshot() riscv_composition.TelemetrySnapshot {
        return riscv_composition.telemetrySnapshot();
    }

    /// Interpolates the four independent secure-field coordinates in place
    /// on the existing prover pool. The generic path duplicates and transforms
    /// them serially; owned composition evaluations need neither cost.
    pub fn interpolateSecureComposition(
        allocator: std.mem.Allocator,
        values: *prover_impl.secure_column.SecureColumnByCoords,
        domain: core_poly.circle.domain.CircleDomain,
        twiddle_tree: prover_impl.poly.twiddles.TwiddleTree([]const M31),
    ) !work_profile.M31InterpolationBackendResult {
        _ = allocator;
        if (values.representation == .coefficients)
            return .already_coefficients;
        for (values.columns) |coordinate| {
            if (coordinate.len != domain.size()) return .declined;
        }

        const Job = struct {
            values: []M31,
            domain: core_poly.circle.domain.CircleDomain,
            twiddle_tree: prover_impl.poly.twiddles.TwiddleTree([]const M31),
            failure: ?anyerror = null,

            fn run(job: *@This()) void {
                var batch = [_][]M31{job.values};
                prover_impl.poly.circle.poly.interpolateBuffersWithTwiddles(
                    &batch,
                    job.domain,
                    job.twiddle_tree,
                ) catch |err| {
                    job.failure = err;
                };
            }
        };

        var jobs: [qm31_mod.SECURE_EXTENSION_DEGREE]Job = undefined;
        for (values.columns, &jobs) |coordinate, *job| {
            job.* = .{
                .values = coordinate,
                .domain = domain,
                .twiddle_tree = twiddle_tree,
            };
        }

        if (prover_impl.work_pool.getGlobalPool()) |pool| {
            var wait_group: std.Thread.WaitGroup = .{};
            for (jobs[1..]) |*job| pool.spawnWg(&wait_group, Job.run, .{job});
            Job.run(&jobs[0]);
            wait_group.wait();
        } else {
            for (&jobs) |*job| Job.run(job);
        }
        for (jobs) |job| if (job.failure) |err| return err;
        values.representation = .coefficients;
        return .{
            .transformed = .{
                .log_size = domain.logSize(),
                .column_count = qm31_mod.SECURE_EXTENSION_DEGREE,
                // The CPU path runs four independent one-column jobs.
                .batch_count = qm31_mod.SECURE_EXTENSION_DEGREE,
            },
        };
    }

    // ---------------------------------------------------------------
    // ColumnOps
    // ---------------------------------------------------------------

    /// Column storage is a plain slice of field elements.
    pub fn ColumnType(comptime F: type) type {
        return []F;
    }

    // ---------------------------------------------------------------
    // FieldOps
    // ---------------------------------------------------------------

    /// Montgomery batch inverse on a slice of field elements.
    pub fn batchInverse(
        comptime F: type,
        allocator: std.mem.Allocator,
        column: []const F,
    ) ![]F {
        return fields_mod.batchInverse(F, allocator, column);
    }

    /// Retains large CPU commitment columns in the same cache-skewed backing
    /// layout used by the shared-memory Metal path while preserving one FFT
    /// task per column on the global worker pool.
    pub fn interpolateAndEvaluateCircleBuffers(
        allocator: std.mem.Allocator,
        source_values: []const []const M31,
        base_values: []const []M31,
        extended_values: []const []M31,
        transform_buffer: []M31,
        extended_start: usize,
        extended_stride: usize,
        base_domain: anytype,
        base_twiddles: anytype,
        extended_domain: anytype,
        extended_twiddles: anytype,
    ) !work_profile.M31CircleLdeExecution {
        _ = transform_buffer;
        _ = extended_start;
        _ = extended_stride;
        if (source_values.len == 0 or source_values.len != base_values.len or
            base_values.len != extended_values.len)
        {
            return error.InvalidColumns;
        }

        const prover = @import("stwo_prover_engine");
        const BaseDomain = @TypeOf(base_domain);
        const BaseTwiddles = @TypeOf(base_twiddles);
        const ExtendedDomain = @TypeOf(extended_domain);
        const ExtendedTwiddles = @TypeOf(extended_twiddles);
        const Job = struct {
            base: []M31,
            extended: []M31,
            base_domain: BaseDomain,
            base_twiddles: BaseTwiddles,
            extended_domain: ExtendedDomain,
            extended_twiddles: ExtendedTwiddles,
            err: ?anyerror = null,

            fn run(job: *@This()) void {
                var base_batch = [_][]M31{job.base};
                prover.poly.circle.poly.interpolateBuffersWithTwiddles(
                    &base_batch,
                    job.base_domain,
                    job.base_twiddles,
                ) catch |err| {
                    job.err = err;
                    return;
                };
                @memcpy(job.extended[0..job.base.len], job.base);
                var extended_batch = [_][]M31{job.extended};
                const exact_double = job.extended.len % 2 == 0 and
                    job.extended.len / 2 == job.base.len;
                if (exact_double) {
                    prover.poly.circle.poly.evaluateExtensionBuffersWithTwiddles(
                        &extended_batch,
                        job.extended_domain,
                        job.extended_twiddles,
                    ) catch |err| {
                        job.err = err;
                    };
                    return;
                }
                @memset(job.extended[job.base.len..], M31.zero());
                prover.poly.circle.poly.evaluateBuffersWithTwiddles(
                    &extended_batch,
                    job.extended_domain,
                    job.extended_twiddles,
                ) catch |err| {
                    job.err = err;
                };
            }
        };

        const jobs = try allocator.alloc(Job, source_values.len);
        defer allocator.free(jobs);
        for (source_values, base_values, extended_values, jobs) |source, base, extended, *job| {
            if (source.ptr != base.ptr) @memcpy(base, source);
            job.* = .{
                .base = base,
                .extended = extended,
                .base_domain = base_domain,
                .base_twiddles = base_twiddles,
                .extended_domain = extended_domain,
                .extended_twiddles = extended_twiddles,
            };
        }

        if (prover.work_pool.getGlobalPool()) |pool| {
            var wait_group: std.Thread.WaitGroup = .{};
            for (jobs[1..]) |*job| pool.spawnWg(&wait_group, Job.run, .{job});
            Job.run(&jobs[0]);
            wait_group.wait();
        } else {
            for (jobs) |*job| Job.run(job);
        }
        for (jobs) |job| if (job.err) |err| return err;
        return .{
            .interpolation = .{
                .log_size = base_domain.logSize(),
                .column_count = @intCast(source_values.len),
                // Each CPU job interpolates one column independently.
                .batch_count = @intCast(source_values.len),
            },
            .forward = .{
                .log_size = extended_domain.logSize(),
                .column_count = @intCast(source_values.len),
                .skipped_layers = combinedCircleLdeSkippedForwardLayers(
                    base_domain.logSize(),
                    extended_domain.logSize(),
                ),
            },
        };
    }

    // ---------------------------------------------------------------
    // FriOps — delegates to core/fri.zig fold functions
    // ---------------------------------------------------------------

    /// Fold a circle evaluation into a line evaluation.
    pub fn foldCircleIntoLine(
        allocator: std.mem.Allocator,
        dst: []QM31,
        src_columns: [qm31_mod.SECURE_EXTENSION_DEGREE][]const M31,
        src_domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldCircleWorkspace,
    ) !void {
        return core_fri.foldCircleColumnsIntoLineWithWorkspace(
            allocator,
            dst,
            src_columns,
            src_domain,
            alpha,
            workspace,
        );
    }

    pub fn foldCircleIntoLineWithReceipt(
        allocator: std.mem.Allocator,
        dst: []QM31,
        src_columns: [qm31_mod.SECURE_EXTENSION_DEGREE][]const M31,
        src_domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldCircleWorkspace,
        ledger: *work_profile.FriFoldExecutionLedger,
    ) !void {
        try foldCircleIntoLine(
            allocator,
            dst,
            src_columns,
            src_domain,
            alpha,
            workspace,
        );
        const coset = src_domain.half_coset;
        ledger.observe(.{
            .kind = .circle_to_line,
            .initial_count = src_columns[0].len,
            .fold_count = 1,
            .domain_log_size = coset.logSize(),
            .domain_initial_index = @intCast(coset.initial_index.v),
            .domain_step_size = @intCast(coset.step_size.v),
            .inverse_path = .host_batch,
            .alpha_squares = 1,
            .domain_doubles = 0,
        });
    }

    /// Fold a line evaluation to half its size.
    pub fn foldLine(
        allocator: std.mem.Allocator,
        eval: []QM31,
        domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldLineWorkspace,
    ) !core_fri.FoldLineResult {
        return core_fri.foldLineInPlaceWithWorkspace(
            allocator,
            eval,
            domain,
            alpha,
            workspace,
        );
    }

    pub fn foldLineN(
        allocator: std.mem.Allocator,
        eval: []QM31,
        domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldLineWorkspace,
        n_folds: u32,
    ) !core_fri.FoldLineResult {
        return core_fri.foldLineInPlaceNWithWorkspace(
            allocator,
            eval,
            domain,
            alpha,
            workspace,
            n_folds,
        );
    }

    pub fn foldLineNWithReceipt(
        allocator: std.mem.Allocator,
        eval: []QM31,
        domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldLineWorkspace,
        n_folds: u32,
        ledger: *work_profile.FriFoldExecutionLedger,
    ) !core_fri.FoldLineResult {
        const result = try foldLineN(
            allocator,
            eval,
            domain,
            alpha,
            workspace,
            n_folds,
        );
        const coset = domain.coset();
        ledger.observe(.{
            .kind = .line,
            .initial_count = eval.len,
            .fold_count = n_folds,
            .domain_log_size = domain.logSize(),
            .domain_initial_index = @intCast(coset.initial_index.v),
            .domain_step_size = @intCast(coset.step_size.v),
            .inverse_path = .host_batch,
            // The in-place implementation advances alpha after every step,
            // including the final one.
            .alpha_squares = n_folds,
            .domain_doubles = n_folds,
        });
        return result;
    }

    // ---------------------------------------------------------------
    // MerkleOps
    // ---------------------------------------------------------------

    pub fn MerkleTree(comptime H: type) type {
        return lifted_merkle.MerkleProverLifted(H);
    }

    pub fn commitMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        columns: []const []const M31,
    ) !MerkleTree(H) {
        return MerkleTree(H).commit(allocator, columns);
    }

    pub fn commitLazyMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        provider: anytype,
        out_column: anytype,
    ) !MerkleTree(H) {
        return MerkleTree(H).commitWithLazyQuotients(allocator, provider, out_column);
    }
};

// ---------------------------------------------------------------
// Compile-time contract validation
// ---------------------------------------------------------------

const backend = @import("stwo_backend_contracts");

comptime {
    backend.assertBackend(CpuBackend);
}

test "cpu_scalar: CpuBackend satisfies backend contract" {
    comptime backend.assertBackend(CpuBackend);
}

test "cpu_scalar: ColumnType resolves to slices" {
    const ColM31 = CpuBackend.ColumnType(M31);
    const ColQM31 = CpuBackend.ColumnType(QM31);

    // For CPU scalar, columns are plain slices.
    try std.testing.expect(@TypeOf(@as(ColM31, undefined)) == []M31);
    try std.testing.expect(@TypeOf(@as(ColQM31, undefined)) == []QM31);
}

test "cpu_scalar: batchInverse delegates correctly" {
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(M31, &[_]M31{
        M31.fromCanonical(3),
        M31.fromCanonical(7),
        M31.fromCanonical(11),
        M31.fromCanonical(13),
    });
    defer allocator.free(input);

    const result = try CpuBackend.batchInverse(M31, allocator, input);
    defer allocator.free(result);

    // Verify: x * x^-1 == 1
    for (input, result) |x, inv_x| {
        try std.testing.expect(x.mul(inv_x).eql(M31.one()));
    }
}

test "cpu_scalar: FRI fold receipts describe the completed scalar path" {
    const allocator = std.testing.allocator;
    const circle_domain = core_poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const alpha = QM31.fromU32Unchecked(7, 11, 13, 17);
    const source = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
        QM31.fromU32Unchecked(25, 26, 27, 28),
        QM31.fromU32Unchecked(29, 30, 31, 32),
    };
    var coordinates: [qm31_mod.SECURE_EXTENSION_DEGREE][source.len]M31 = undefined;
    for (source, 0..) |value, row| {
        const row_coordinates = value.toM31Array();
        inline for (0..qm31_mod.SECURE_EXTENSION_DEGREE) |coordinate| {
            coordinates[coordinate][row] = row_coordinates[coordinate];
        }
    }
    const source_columns = [_][]const M31{
        coordinates[0][0..],
        coordinates[1][0..],
        coordinates[2][0..],
        coordinates[3][0..],
    };
    var circle_result = [_]QM31{QM31.zero()} ** (source.len / 2);
    var circle_workspace = try core_fri.FoldCircleWorkspace.init(
        allocator,
        circle_result.len,
    );
    defer circle_workspace.deinit(allocator);
    var ledger: work_profile.FriFoldExecutionLedger = .{};

    try CpuBackend.foldCircleIntoLineWithReceipt(
        allocator,
        circle_result[0..],
        source_columns,
        circle_domain,
        alpha,
        &circle_workspace,
        &ledger,
    );

    const line_domain = try core_poly.line.LineDomain.init(
        @import("stwo_core").circle.Coset.halfOdds(2),
    );
    const line_values = try allocator.dupe(QM31, circle_result[0..]);
    var line_workspace = try core_fri.FoldLineWorkspace.init(
        allocator,
        line_values.len / 2,
    );
    defer line_workspace.deinit(allocator);
    const line_result = try CpuBackend.foldLineNWithReceipt(
        allocator,
        line_values,
        line_domain,
        alpha.square(),
        &line_workspace,
        2,
        &ledger,
    );
    defer allocator.free(line_result.values);

    try std.testing.expect(ledger.complete);
    try std.testing.expectEqual(@as(usize, 2), ledger.count);
    try std.testing.expectEqual(work_profile.FriFoldKind.circle_to_line, ledger.executions[0].kind);
    try std.testing.expectEqual(work_profile.FriFoldKind.line, ledger.executions[1].kind);
    try std.testing.expectEqual(@as(u32, 2), ledger.executions[1].fold_count);
    const completed_work = try ledger.exactWork();
    try std.testing.expectEqual(@as(u64, 7), completed_work.fri_folds);
    try std.testing.expectEqual(@as(u64, 3), completed_work.field_inversions);
}

fn expectCombinedCircleLdeMatchesSeparate(
    allocator: std.mem.Allocator,
    base_log_size: u32,
    extended_log_size: u32,
) !void {
    const base_domain = core_poly.circle.canonic.CanonicCoset.new(base_log_size).circleDomain();
    const extended_domain = core_poly.circle.canonic.CanonicCoset.new(extended_log_size).circleDomain();
    var base_twiddles = try prover_impl.poly.twiddles.precomputeM31(
        allocator,
        base_domain.half_coset,
    );
    defer prover_impl.poly.twiddles.deinitM31(allocator, &base_twiddles);
    var extended_twiddles = try prover_impl.poly.twiddles.precomputeM31(
        allocator,
        extended_domain.half_coset,
    );
    defer prover_impl.poly.twiddles.deinitM31(allocator, &extended_twiddles);
    const ConstTwiddleTree = prover_impl.poly.twiddles.TwiddleTree([]const M31);
    const base_twiddle_view = ConstTwiddleTree.init(
        base_twiddles.root_coset,
        base_twiddles.twiddles,
        base_twiddles.itwiddles,
    );
    const extended_twiddle_view = ConstTwiddleTree.init(
        extended_twiddles.root_coset,
        extended_twiddles.twiddles,
        extended_twiddles.itwiddles,
    );

    const source = try allocator.alloc(M31, base_domain.size());
    defer allocator.free(source);
    for (source, 0..) |*value, i| {
        value.* = M31.fromCanonical(@intCast(3 + i * 17));
    }

    const expected_base = try allocator.dupe(M31, source);
    defer allocator.free(expected_base);
    var expected_base_batch = [_][]M31{expected_base};
    try prover_impl.poly.circle.poly.interpolateBuffersWithTwiddles(
        &expected_base_batch,
        base_domain,
        base_twiddle_view,
    );
    const expected_extended = try allocator.alloc(M31, extended_domain.size());
    defer allocator.free(expected_extended);
    @memcpy(expected_extended[0..expected_base.len], expected_base);
    @memset(expected_extended[expected_base.len..], M31.zero());
    var expected_extended_batch = [_][]M31{expected_extended};
    try prover_impl.poly.circle.poly.evaluateBuffersWithTwiddles(
        &expected_extended_batch,
        extended_domain,
        extended_twiddle_view,
    );

    const actual_base_a = try allocator.alloc(M31, base_domain.size());
    defer allocator.free(actual_base_a);
    const actual_base_b = try allocator.alloc(M31, base_domain.size());
    defer allocator.free(actual_base_b);
    const actual_extended_a = try allocator.alloc(M31, extended_domain.size());
    defer allocator.free(actual_extended_a);
    const actual_extended_b = try allocator.alloc(M31, extended_domain.size());
    defer allocator.free(actual_extended_b);
    @memset(actual_extended_a, M31.fromCanonical(0x12_345));
    @memset(actual_extended_b, M31.fromCanonical(0x54_321));

    var source_batch = [_][]const M31{source};
    var actual_base_batch_a = [_][]M31{actual_base_a};
    var actual_base_batch_b = [_][]M31{actual_base_b};
    var actual_extended_batch_a = [_][]M31{actual_extended_a};
    var actual_extended_batch_b = [_][]M31{actual_extended_b};
    var no_transform_buffer: [0]M31 = .{};
    _ = try CpuBackend.interpolateAndEvaluateCircleBuffers(
        allocator,
        &source_batch,
        &actual_base_batch_a,
        &actual_extended_batch_a,
        &no_transform_buffer,
        0,
        extended_domain.size(),
        base_domain,
        base_twiddle_view,
        extended_domain,
        extended_twiddle_view,
    );
    _ = try CpuBackend.interpolateAndEvaluateCircleBuffers(
        allocator,
        &source_batch,
        &actual_base_batch_b,
        &actual_extended_batch_b,
        &no_transform_buffer,
        0,
        extended_domain.size(),
        base_domain,
        base_twiddle_view,
        extended_domain,
        extended_twiddle_view,
    );

    try std.testing.expectEqualSlices(M31, expected_base, actual_base_a);
    try std.testing.expectEqualSlices(M31, expected_base, actual_base_b);
    try std.testing.expectEqualSlices(M31, expected_extended, actual_extended_a);
    try std.testing.expectEqualSlices(M31, expected_extended, actual_extended_b);
}

test "cpu_scalar: combined circle LDE is canonical for 2x and wider extension" {
    const allocator = std.testing.allocator;
    try expectCombinedCircleLdeMatchesSeparate(allocator, 4, 5);
    try expectCombinedCircleLdeMatchesSeparate(allocator, 4, 6);
}

test {
    _ = @import("riscv_composition_test.zig");
    _ = @import("riscv_composition_profile_test.zig");
}
