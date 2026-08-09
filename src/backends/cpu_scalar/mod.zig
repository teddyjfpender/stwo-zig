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
        if (try secure_composition.evaluateLargeRecurrenceComposition(
            allocator,
            components,
            random_coeff,
            trace,
            execution,
        )) |evaluation| return evaluation;
        const adjusted = execution.adjustedForAvailablePool();
        try adjusted.validateCapacity();
        if (execution.host_byte_budget != std.math.maxInt(usize)) {
            // The secure recurrence above has closed accounting. Generic and
            // RISC-V mixed plans reject finite caps before allocating until
            // their coordinator-owned planning storage is accounted too.
            return error.FiniteCompositionByteBudgetUnsupported;
        }
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
    ) !bool {
        _ = allocator;
        for (values.columns) |coordinate| {
            if (coordinate.len != domain.size()) return false;
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
        return true;
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
    ) !void {
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
                prover.poly.circle.poly.evaluateExtensionBuffersWithTwiddles(
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

test {
    _ = @import("riscv_composition_test.zig");
}
