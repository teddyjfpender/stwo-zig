const std = @import("std");
const backend_composition = @import("runtime/backend_composition.zig");
const column_source_materialization = @import("runtime/column_source_materialization.zig");
const commit_policy = @import("commit_policy.zig");
const combined_commit = @import("runtime/combined_commit.zig");
const fold_inverses = @import("runtime/fold_inverses.zig");
const host_primitives = @import("host_primitives.zig");
const merkle = @import("stwo_prover_engine").vcs_lifted.prover;
const metal_merkle = @import("merkle_tree.zig");
const ownership_testing = @import("runtime/ownership_testing.zig");
const quadratic_trace = @import("runtime/quadratic_trace_backend.zig");
const resident_fri_transaction = @import("runtime/resident_fri_transaction.zig");
const shared_runtime = @import("shared_runtime.zig");
const telemetry = @import("telemetry.zig");

pub fn warmup() !void {
    return MetalCommitBackend.warmup();
}

pub fn initializeRuntime(
    allocator: std.mem.Allocator,
    policy: MetalCommitBackend.RuntimeInitializationPolicy,
) !void {
    return MetalCommitBackend.initializeRuntime(allocator, policy);
}

pub fn runtimeLifecycleSnapshot() MetalCommitBackend.RuntimeLifecycleSnapshot {
    return MetalCommitBackend.runtimeLifecycleSnapshot();
}

pub fn shutdown() MetalCommitBackend.ShutdownError!void {
    return MetalCommitBackend.shutdown();
}

pub const MetalCommitBackend = struct {
    pub const capabilities: @import("stwo_backend_contracts").Capabilities = .{
        .host_batch_inverse = true,
        .fri_folding = true,
        .fri_multi_fold = true,
    };
    pub const rawQuotientInputs = true;
    pub const TelemetrySnapshot = telemetry.Snapshot;
    pub const TelemetryDelta = telemetry.Delta;
    pub const TelemetryError = error{RuntimeNotInitialized};
    pub const ShutdownError = shared_runtime.ShutdownError;
    pub const RuntimeLifecycleSnapshot = shared_runtime.LifecycleSnapshot;
    pub const RuntimeInitializationPolicy = shared_runtime.InitializationPolicy;
    pub const preferMonolithicCommit = true;
    // No-copy bind when source == coefficient arena (`circle_legacy.m:227`).
    pub const adopts_source_trace_arena = true;
    pub const lazyFriFoldInverseWorkspace = true;
    pub const prepareAndCommitOwned = combined_commit.prepareAndCommitOwned;
    pub const prepareAndCommitPolys = combined_commit.prepareAndCommitPolys;
    pub const preferContiguousQuadraticRecurrenceTrace = true;
    pub const preferDeferredQuadraticRecurrenceTrace = true;
    pub const admitsDeferredQuadraticRecurrenceTrace = combined_commit.admitsDeferredQuadraticRecurrenceTrace;
    pub const quadratic_recurrence_min_cells = quadratic_trace.min_cells;
    pub const admitsQuadraticRecurrenceTrace = quadratic_trace.admits;
    pub const fillQuadraticRecurrenceTrace = quadratic_trace.fill;
    pub const materializeColumnSource = column_source_materialization.materialize;
    const ResidentFriOps = resident_fri_transaction.Ops(@This());
    pub const commitLazyFriTransaction = ResidentFriOps.commitLazyFriTransaction;
    pub const commitFriCircleLayers = ResidentFriOps.commitFriCircleLayers;

    pub fn warmup() !void {
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
    }

    pub fn initializeRuntime(
        allocator: std.mem.Allocator,
        policy: RuntimeInitializationPolicy,
    ) !void {
        try shared_runtime.initialize(allocator, policy);
    }

    pub const computeCompositionEvaluation = backend_composition.computeCompositionEvaluation;
    pub const interpolateSecureComposition = backend_composition.interpolateSecureComposition;
    pub const armOwnershipTransferFailureForTesting = ownership_testing.arm;
    pub const clearOwnershipTransferFailureForTesting = ownership_testing.clear;
    pub const failAfterOwnershipTransferForTesting = ownership_testing.failAfterTransfer;

    pub fn telemetrySnapshot() TelemetryError!TelemetrySnapshot {
        var lease = try shared_runtime.acquireExisting();
        defer lease.deinit();
        return telemetry.captureWithArchiveStore(
            lease.runtime.pipelineCacheStats(),
            lease.runtime.archiveStoreStats(),
        );
    }

    pub fn runtimeLifecycleSnapshot() RuntimeLifecycleSnapshot {
        return shared_runtime.lifecycleSnapshot();
    }

    pub fn runtimePlatformIdentityAlloc(allocator: std.mem.Allocator) ![]u8 {
        return shared_runtime.platformIdentityAlloc(allocator);
    }

    pub fn shutdown() ShutdownError!void {
        return shared_runtime.shutdown();
    }

    pub const recordSampledValueFallback = commit_policy.recordSampledValueFallback;

    pub fn MerkleTree(comptime H: type) type {
        return metal_merkle.MetalMerkleTree(H);
    }

    fn FriLineCascadeResult(comptime H: type) type {
        return struct {
            columns: []@import("stwo_prover_engine").secure_column.SecureColumnByCoords,
            trees: []MerkleTree(H),
            last_layer_evaluation: @import("stwo_prover_engine").line.LineEvaluation,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                for (self.columns) |*column| column.deinit(allocator);
                allocator.free(self.columns);
                for (self.trees) |*tree| tree.deinit(allocator);
                allocator.free(self.trees);
                self.last_layer_evaluation.deinit(allocator);
                self.* = undefined;
            }
        };
    }

    pub fn allocateSecureColumn(column_len: usize) !@import("stwo_prover_engine").secure_column.SecureColumnByCoords {
        const M31 = @import("stwo_core").fields.m31.M31;
        const DEGREE = @import("stwo_core").fields.qm31.SECURE_EXTENSION_DEGREE;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        var buffer = try lease.runtime.allocateResidentBuffer(column_len * DEGREE * @sizeOf(M31));
        errdefer buffer.deinit();
        const values: [*]M31 = @ptrCast(@alignCast(buffer.contents));
        var columns: [DEGREE][]M31 = undefined;
        for (0..DEGREE) |coordinate| {
            columns[coordinate] = values[coordinate * column_len .. (coordinate + 1) * column_len];
        }
        shared_runtime.retainResidentResource();
        errdefer shared_runtime.releaseResidentResource();
        return @import("stwo_prover_engine").secure_column.SecureColumnByCoords.initResident(
            columns,
            .{
                .handle = buffer.handle,
                .destroyFn = shared_runtime.destroyResidentBuffer,
            },
        );
    }

    pub fn allocateLineEvaluation(
        domain: @import("stwo_core").poly.line.LineDomain,
    ) !@import("stwo_prover_engine").line.LineEvaluation {
        const QM31 = @import("stwo_core").fields.qm31.QM31;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        var buffer = try lease.runtime.allocateResidentBuffer(domain.size() * @sizeOf(QM31));
        errdefer buffer.deinit();
        const values: [*]QM31 = @ptrCast(@alignCast(buffer.contents));
        shared_runtime.retainResidentResource();
        errdefer shared_runtime.releaseResidentResource();
        return @import("stwo_prover_engine").line.LineEvaluation.initResident(
            domain,
            values[0..domain.size()],
            .{
                .handle = buffer.handle,
                .destroyFn = shared_runtime.destroyResidentBuffer,
            },
        );
    }

    pub fn secureColumnFromLine(
        evaluation: @import("stwo_prover_engine").line.LineEvaluation,
    ) !@import("stwo_prover_engine").secure_column.SecureColumnByCoords {
        var column = try allocateSecureColumn(evaluation.len());
        errdefer column.deinit(std.heap.page_allocator);
        const source = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(evaluation.values));
        const destination = std.mem.bytesAsSlice(
            u32,
            std.mem.sliceAsBytes(column.columns[0].ptr[0 .. evaluation.len() * 4]),
        );
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.qm31ToCoordinates(
            source.ptr,
            @intCast(evaluation.len()),
            destination.ptr,
        );
        telemetry.record(.metal_qm31_coordinate_dispatch);
        std.log.debug("Metal QM31 coordinate conversion: {d:.3}ms", .{gpu_ms});
        return column;
    }

    pub fn secureColumnForMerkle(
        allocator: std.mem.Allocator,
        evaluation: @import("stwo_prover_engine").line.LineEvaluation,
    ) !@import("stwo_prover_engine").secure_column.SecureColumnByCoords {
        if (!commit_policy.secureColumnUsesResidentMerkle(evaluation.len())) {
            return @import("stwo_prover_engine").secure_column.SecureColumnByCoords.fromSecureSlice(
                allocator,
                evaluation.values,
            );
        }
        return secureColumnFromLine(evaluation);
    }

    pub fn commitMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        columns: []const []const @import("stwo_core").fields.m31.M31,
    ) !MerkleTree(H) {
        var cells: usize = 0;
        for (columns) |column| cells = try std.math.add(usize, cells, column.len);
        if (cells == 0) {
            const empty_tree = try merkle.MerkleProverLifted(H).commit(allocator, columns);
            return MerkleTree(H).fromHost(empty_tree);
        }
        if (!commit_policy.usesResidentMerkle(cells)) {
            const host_tree = try merkle.MerkleProverLifted(H).commit(allocator, columns);
            telemetry.record(.host_merkle_commit);
            telemetry.record(.cpu_small_merkle_commit);
            return MerkleTree(H).fromHost(host_tree);
        }
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const resident_tree = try MerkleTree(H).commitShared(lease.runtime, allocator, columns);
        telemetry.record(.resident_merkle_commit);
        return resident_tree;
    }

    pub fn commitMerkleWithBacking(
        comptime H: type,
        allocator: std.mem.Allocator,
        columns: []const []const @import("stwo_core").fields.m31.M31,
        backing_buffers: []const []@import("stwo_core").fields.m31.M31,
    ) !MerkleTree(H) {
        var cells: usize = 0;
        for (columns) |column| cells = try std.math.add(usize, cells, column.len);
        if (cells == 0 or !commit_policy.usesResidentMerkle(cells) or backing_buffers.len == 0) {
            return commitMerkle(H, allocator, columns);
        }

        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const resident_tree = try MerkleTree(H).commitSharedBacking(
            lease.runtime,
            allocator,
            columns,
            backing_buffers,
        );
        telemetry.record(.resident_merkle_commit);
        return resident_tree;
    }

    pub fn adoptHostMerkle(
        comptime H: type,
        tree: merkle.MerkleProverLifted(H),
    ) MerkleTree(H) {
        telemetry.record(.host_merkle_commit);
        telemetry.record(.cpu_streaming_merkle_commit);
        return MerkleTree(H).fromHost(tree);
    }

    pub fn quotientResidencyHandle(
        comptime H: type,
        tree: MerkleTree(H),
    ) ?*anyopaque {
        return tree.quotientResidencyHandle();
    }

    pub fn computeLazyQuotients(
        allocator: std.mem.Allocator,
        provider: anytype,
        out: anytype,
    ) !void {
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.computeQuotients(allocator, provider, out);
        telemetry.record(.metal_quotient_dispatch);
        std.log.debug("Metal quotient kernel: {d:.3}ms", .{gpu_ms});
    }

    pub fn commitLazyMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        provider: anytype,
        out: anytype,
    ) !MerkleTree(H) {
        if (!commit_policy.quotientUsesResidentMerkle(provider.lifting_log_size)) {
            try computeLazyQuotients(allocator, provider, out);
            const columns = [_][]const @import("stwo_core").fields.m31.M31{
                out.columns[0],
                out.columns[1],
                out.columns[2],
                out.columns[3],
            };
            return commitMerkle(H, allocator, columns[0..]);
        }
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const result = try lease.runtime.computeQuotientsAndCommit(
            allocator,
            provider,
            out,
            H.leafSeed(),
            H.nodeSeed(),
            H.domainPrefixBytes(),
        );
        telemetry.record(.metal_quotient_dispatch);
        telemetry.record(.resident_merkle_commit);
        std.log.debug("Metal quotient + Merkle epoch: {d:.3}ms", .{result.gpu_ms});
        return MerkleTree(H).fromSharedRuntime(result.tree);
    }

    pub fn evaluateCoefficientPlans(
        allocator: std.mem.Allocator,
        coefficients: anytype,
        tree_values: anytype,
        plans: anytype,
    ) !void {
        if (plans.len == 0) return;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.evaluateCoefficientPlans(
            allocator,
            coefficients,
            tree_values,
            plans,
        );
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug("Metal sampled-value kernel: {d:.3}ms", .{gpu_ms});
    }

    pub fn evaluateCoefficientTreePlans(
        allocator: std.mem.Allocator,
        tree_plans: anytype,
    ) !void {
        if (tree_plans.len == 0) return;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.evaluateCoefficientTreePlans(allocator, tree_plans);
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug("Metal sampled-value batch epoch: {d:.3}ms", .{gpu_ms});
    }

    pub fn interpolateCircleBuffers(
        allocator: std.mem.Allocator,
        values: []const []@import("stwo_core").fields.m31.M31,
        domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        twiddle_tree: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    ) !void {
        if (domain.logSize() < 3) {
            try @import("stwo_prover_engine").poly.circle.poly.interpolateBuffersWithTwiddles(values, domain, twiddle_tree);
            telemetry.record(.cpu_small_circle_interpolation);
            return;
        }
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        _ = try lease.runtime.transformCircle(
            allocator,
            values,
            twiddle_tree.itwiddles,
            domain.logSize(),
            true,
        );
        telemetry.record(.metal_circle_transform_dispatch);
    }

    pub fn evaluateCircleBuffers(
        allocator: std.mem.Allocator,
        values: []const []@import("stwo_core").fields.m31.M31,
        domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        twiddle_tree: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    ) !void {
        if (domain.logSize() < 3) {
            try @import("stwo_prover_engine").poly.circle.poly.evaluateBuffersWithTwiddles(values, domain, twiddle_tree);
            telemetry.record(.cpu_small_circle_evaluation);
            return;
        }
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        _ = try lease.runtime.transformCircle(
            allocator,
            values,
            twiddle_tree.twiddles,
            domain.logSize(),
            false,
        );
        telemetry.record(.metal_circle_transform_dispatch);
    }

    pub fn interpolateAndEvaluateCircleBuffers(
        allocator: std.mem.Allocator,
        source_values: []const []const @import("stwo_core").fields.m31.M31,
        base_values: []const []@import("stwo_core").fields.m31.M31,
        extended_values: []const []@import("stwo_core").fields.m31.M31,
        transform_buffer: []@import("stwo_core").fields.m31.M31,
        extended_start: usize,
        extended_stride: usize,
        base_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        base_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
        extended_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        extended_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    ) !void {
        if (base_domain.logSize() < 3) {
            for (source_values, base_values) |source, base| @memcpy(base, source);
            try @import("stwo_prover_engine").poly.circle.poly.interpolateBuffersWithTwiddles(
                base_values,
                base_domain,
                base_twiddles,
            );
            for (base_values, extended_values) |base, extended| {
                @memcpy(extended[0..base.len], base);
                @memset(extended[base.len..], @import("stwo_core").fields.m31.M31.zero());
            }
            try @import("stwo_prover_engine").poly.circle.poly.evaluateBuffersWithTwiddles(
                extended_values,
                extended_domain,
                extended_twiddles,
            );
            telemetry.record(.cpu_small_circle_lde);
            return;
        }
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.transformCircleLdeInto(
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer,
            extended_start,
            extended_stride,
            base_twiddles.itwiddles,
            extended_twiddles.twiddles,
            base_domain.logSize(),
            extended_domain.logSize(),
        );
        telemetry.record(.metal_circle_lde_dispatch);
        std.log.debug("Metal circle IFFT+RFFT: {d:.3}ms", .{gpu_ms});
    }

    pub const ColumnType = host_primitives.ColumnType;
    pub const batchInverse = host_primitives.batchInverse;
    pub fn foldCircleIntoLine(
        allocator: std.mem.Allocator,
        dst: []@import("stwo_core").fields.qm31.QM31,
        src_columns: [4][]const @import("stwo_core").fields.m31.M31,
        src_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        alpha: @import("stwo_core").fields.qm31.QM31,
        workspace: *@import("stwo_core").fri.FoldCircleWorkspace,
    ) !void {
        const use_resident_inverse = dst.len >= 1 << 13;
        var inverse_words: ?[]const u32 = null;
        if (!use_resident_inverse) {
            try workspace.ensureCapacity(allocator, dst.len);
            const py = workspace.py_values[0..dst.len];
            const inverse_y = workspace.inv_py_values[0..dst.len];
            try fold_inverses.prepare(py, inverse_y, src_domain.half_coset, .y);
            inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_y));
        }
        const alpha_coords = alpha.toM31Array();
        const alpha_words = [4]u32{ alpha_coords[0].v, alpha_coords[1].v, alpha_coords[2].v, alpha_coords[3].v };
        const source_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(src_columns[0].ptr[0 .. src_columns[0].len * 4]));
        const destination_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(dst));
        const fold_coset = src_domain.half_coset;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.foldFriCircle(
            source_words.ptr,
            @intCast(src_columns[0].len),
            inverse_words,
            @intCast(fold_coset.initial_index.v),
            @intCast(fold_coset.step_size.v),
            alpha_words,
            destination_words.ptr,
        );
        telemetry.record(.metal_fri_circle_fold_dispatch);
        std.log.debug("Metal FRI circle fold: {d:.3}ms", .{gpu_ms});
    }

    pub fn foldLineEvaluationN(
        allocator: std.mem.Allocator,
        evaluation: @import("stwo_prover_engine").line.LineEvaluation,
        alpha: @import("stwo_core").fields.qm31.QM31,
        workspace: *@import("stwo_core").fri.FoldLineWorkspace,
        n_folds: u32,
    ) !@import("stwo_prover_engine").line.LineEvaluation {
        var current = evaluation;
        var owns_current = false;
        var current_alpha = alpha;
        errdefer if (owns_current) current.deinit(allocator);
        var step: u32 = 0;
        while (step < n_folds) : (step += 1) {
            const destination_domain = current.domain().double();
            var next = try allocateLineEvaluation(destination_domain);
            errdefer next.deinit(allocator);
            const destination_len = next.len();
            try workspace.ensureCapacity(allocator, destination_len);
            const x = workspace.x_values[0..destination_len];
            const inverse_x = workspace.inv_x_values[0..destination_len];
            try fold_inverses.prepare(x, inverse_x, current.domain().coset(), .x);
            const source_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(current.values));
            const destination_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(@constCast(next.values)));
            const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_x));
            const alpha_coords = current_alpha.toM31Array();
            const alpha_words = [4]u32{ alpha_coords[0].v, alpha_coords[1].v, alpha_coords[2].v, alpha_coords[3].v };
            var lease = try shared_runtime.acquire();
            defer lease.deinit();
            const gpu_ms = try lease.runtime.foldFriLine(
                source_words.ptr,
                @intCast(current.len()),
                inverse_words,
                alpha_words,
                destination_words.ptr,
            );
            telemetry.record(.metal_fri_line_fold_dispatch);
            std.log.debug("Metal FRI line fold: {d:.3}ms", .{gpu_ms});
            if (owns_current) current.deinit(allocator);
            current = next;
            owns_current = true;
            current_alpha = current_alpha.square();
        }
        return current;
    }

    pub fn foldLineAndCommitNext(
        comptime H: type,
        allocator: std.mem.Allocator,
        evaluation: @import("stwo_prover_engine").line.LineEvaluation,
        alpha: @import("stwo_core").fields.qm31.QM31,
        workspace: *@import("stwo_core").fri.FoldLineWorkspace,
        n_folds: u32,
    ) !@import("stwo_backend_contracts").fri_ops.FoldLineAndCommitResult(MerkleTree(H)) {
        const M31 = @import("stwo_core").fields.m31.M31;
        const secure_column = @import("stwo_prover_engine").secure_column;
        if (n_folds == 0 or n_folds >= @bitSizeOf(usize) or
            evaluation.len() >> @intCast(n_folds) == 0)
        {
            return error.InvalidColumns;
        }

        const final_count = evaluation.len() >> @intCast(n_folds);
        const source_storage = evaluation.resident_storage;
        if (source_storage == null or !commit_policy.friFoldCommitUsesResidentMerkle(final_count, n_folds)) {
            const folded = try foldLineEvaluationN(allocator, evaluation, alpha, workspace, n_folds);
            errdefer {
                var owned = folded;
                owned.deinit(allocator);
            }
            var coordinates = if (comptime @hasDecl(@This(), "secureColumnForMerkle"))
                try secureColumnForMerkle(allocator, folded)
            else
                try secure_column.SecureColumnByCoords.fromSecureSlice(allocator, folded.values);
            errdefer coordinates.deinit(allocator);
            const columns = [_][]const M31{
                coordinates.columns[0],
                coordinates.columns[1],
                coordinates.columns[2],
                coordinates.columns[3],
            };
            const tree = try commitMerkle(H, allocator, columns[0..]);
            return .{ .evaluation = folded, .column = coordinates, .tree = tree };
        }

        var final_domain = evaluation.domain();
        var inverse_count: usize = 0;
        var stage_count = evaluation.len();
        for (0..n_folds) |_| {
            stage_count >>= 1;
            inverse_count = try std.math.add(usize, inverse_count, stage_count);
            final_domain = final_domain.double();
        }
        const inverse_values = try allocator.alloc(M31, inverse_count);
        defer allocator.free(inverse_values);
        const alphas = try allocator.alloc([4]u32, n_folds);
        defer allocator.free(alphas);

        var inverse_cursor: usize = 0;
        var current_count = evaluation.len();
        var current_domain = evaluation.domain();
        var current_alpha = alpha;
        for (0..n_folds) |step| {
            const destination_count = current_count >> 1;
            try workspace.ensureCapacity(allocator, destination_count);
            const x = workspace.x_values[0..destination_count];
            const inverse_x = workspace.inv_x_values[0..destination_count];
            try fold_inverses.prepare(x, inverse_x, current_domain.coset(), .x);
            @memcpy(inverse_values[inverse_cursor .. inverse_cursor + destination_count], inverse_x);
            inverse_cursor += destination_count;
            const alpha_coordinates = current_alpha.toM31Array();
            alphas[step] = .{
                alpha_coordinates[0].v,
                alpha_coordinates[1].v,
                alpha_coordinates[2].v,
                alpha_coordinates[3].v,
            };
            current_count = destination_count;
            current_domain = current_domain.double();
            current_alpha = current_alpha.square();
        }

        var folded = try allocateLineEvaluation(final_domain);
        errdefer folded.deinit(allocator);
        var coordinates = try allocateSecureColumn(final_count);
        errdefer coordinates.deinit(allocator);
        const destination_storage = folded.resident_storage orelse return error.InvalidColumns;
        const coordinate_storage = coordinates.resident_storage orelse return error.InvalidColumns;
        const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_values));
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const result = try lease.runtime.foldFriLineAndCommit(
            source_storage.?.handle,
            @intCast(evaluation.len()),
            inverse_words,
            alphas,
            destination_storage.handle,
            coordinate_storage.handle,
            H.leafSeed(),
            H.nodeSeed(),
            H.domainPrefixBytes(),
        );
        const tree = try MerkleTree(H).fromSharedRuntime(result.tree);
        telemetry.record(.metal_fri_fold_commit_epoch);
        telemetry.record(.resident_merkle_commit);
        std.log.debug(
            "Metal FRI fold + Merkle epoch: {d:.3}ms, {} dispatches, {} command buffer, {} wait",
            .{
                result.stats.gpu_milliseconds,
                result.stats.dispatches,
                result.stats.command_buffers,
                result.stats.wait_count,
            },
        );
        return .{ .evaluation = folded, .column = coordinates, .tree = tree };
    }

    pub fn commitFriLineCascade(
        comptime H: type,
        allocator: std.mem.Allocator,
        evaluation: @import("stwo_prover_engine").line.LineEvaluation,
        channel: anytype,
        workspace: *@import("stwo_core").fri.FoldLineWorkspace,
        last_layer_size: usize,
        fold_step: u32,
        circle_source: ?*anyopaque,
        circle_alpha: ?[4]u32,
    ) !?FriLineCascadeResult(H) {
        const channel_blake2s = @import("stwo_core").channel.blake2s;
        const M31 = @import("stwo_core").fields.m31.M31;
        if (comptime @TypeOf(channel.*) != channel_blake2s.Blake2sChannel) return null;
        if (fold_step != 1 or last_layer_size == 0 or
            evaluation.len() <= last_layer_size or evaluation.resident_storage == null or
            !std.math.isPowerOfTwo(evaluation.len()) or !std.math.isPowerOfTwo(last_layer_size) or
            evaluation.len() % last_layer_size != 0)
        {
            return null;
        }
        const layer_count: usize = std.math.log2_int(usize, evaluation.len() / last_layer_size);
        if (layer_count == 0 or layer_count >= 31) return null;
        const inverse_count = evaluation.len() - last_layer_size;
        const use_resident_inverse = evaluation.len() >= 1 << 13;
        var inverse_values: ?[]M31 = null;
        if (!use_resident_inverse) inverse_values = try allocator.alloc(M31, inverse_count);
        defer if (inverse_values) |values| allocator.free(values);
        var current_domain = evaluation.domain();
        var current_count = evaluation.len();
        var inverse_cursor: usize = 0;
        for (0..layer_count) |_| {
            const destination_count = current_count >> 1;
            if (inverse_values) |values| {
                try workspace.ensureCapacity(allocator, destination_count);
                const x = workspace.x_values[0..destination_count];
                const inverse_x = workspace.inv_x_values[0..destination_count];
                try fold_inverses.prepare(x, inverse_x, current_domain.coset(), .x);
                @memcpy(values[inverse_cursor .. inverse_cursor + destination_count], inverse_x);
            }
            inverse_cursor += destination_count;
            current_count = destination_count;
            current_domain = current_domain.double();
        }

        const SecureColumn = @import("stwo_prover_engine").secure_column.SecureColumnByCoords;
        const columns = try allocator.alloc(SecureColumn, layer_count);
        var initialized_columns: usize = 0;
        errdefer {
            for (columns[0..initialized_columns]) |*column| column.deinit(allocator);
            allocator.free(columns);
        }
        const coordinate_handles = try allocator.alloc(*anyopaque, layer_count);
        defer allocator.free(coordinate_handles);
        current_count = evaluation.len();
        for (columns, coordinate_handles) |*column, *handle| {
            column.* = try allocateSecureColumn(current_count);
            initialized_columns += 1;
            handle.* = column.resident_storage.?.handle;
            current_count >>= 1;
        }

        var terminal = try allocateLineEvaluation(current_domain);
        errdefer terminal.deinit(allocator);
        const terminal_storage = terminal.resident_storage orelse return error.InvalidColumns;
        const source_storage = evaluation.resident_storage.?;

        var channel_state = [_]u32{0} ** 10;
        for (0..8) |word| {
            channel_state[word] = std.mem.readInt(
                u32,
                channel.digest[word * 4 ..][0..4],
                .little,
            );
        }
        channel_state[8] = channel.n_draws;
        const inverse_words: ?[]const u32 = if (inverse_values) |values|
            std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(values))
        else
            null;
        const initial_coset = evaluation.domain().coset();

        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        var runtime_result = try lease.runtime.foldFriCircleLineCascade(
            allocator,
            source_storage.handle,
            @intCast(evaluation.len()),
            circle_source,
            circle_alpha,
            inverse_words,
            @intCast(initial_coset.initial_index.v),
            @intCast(initial_coset.step_size.v),
            coordinate_handles,
            terminal_storage.handle,
            H.leafSeed(),
            H.nodeSeed(),
            H.domainPrefixBytes(),
            &channel_state,
        );
        defer allocator.free(runtime_result.trees);

        var consumed_runtime_trees: usize = 0;
        errdefer {
            for (runtime_result.trees[consumed_runtime_trees..]) |*tree| tree.deinit();
        }
        const trees = try allocator.alloc(MerkleTree(H), layer_count);
        var initialized_trees: usize = 0;
        errdefer {
            for (trees[0..initialized_trees]) |*tree| tree.deinit(allocator);
            allocator.free(trees);
        }
        for (runtime_result.trees, trees) |runtime_tree, *tree| {
            consumed_runtime_trees += 1;
            tree.* = try MerkleTree(H).fromSharedRuntime(runtime_tree);
            initialized_trees += 1;
        }

        for (0..8) |word| {
            std.mem.writeInt(u32, channel.digest[word * 4 ..][0..4], channel_state[word], .little);
        }
        channel.n_draws = channel_state[8];
        telemetry.record(.metal_fri_fold_commit_epoch);
        for (0..layer_count) |_| telemetry.record(.resident_merkle_commit);
        std.log.debug(
            "Metal FRI line cascade: {d:.3}ms, {} layers, {} dispatches, {} command buffer, {} wait",
            .{
                runtime_result.stats.gpu_milliseconds,
                layer_count,
                runtime_result.stats.dispatches,
                runtime_result.stats.command_buffers,
                runtime_result.stats.wait_count,
            },
        );
        return .{
            .columns = columns,
            .trees = trees,
            .last_layer_evaluation = terminal,
        };
    }

    pub fn commitFriLayers(
        comptime H: type,
        comptime InnerLayerProver: type,
        comptime InnerCommitResult: type,
        allocator: std.mem.Allocator,
        evaluation: @import("stwo_prover_engine").line.LineEvaluation,
        channel: anytype,
        workspace: *@import("stwo_core").fri.FoldLineWorkspace,
        config: @import("stwo_core").fri.FriConfig,
    ) !?InnerCommitResult {
        var cascade = (try commitFriLineCascade(
            H,
            allocator,
            evaluation,
            channel,
            workspace,
            config.lastLayerDomainSize(),
            config.fold_step,
            null,
            null,
        )) orelse return null;
        std.debug.assert(cascade.columns.len == cascade.trees.len);
        const ready_layers = allocator.alloc(InnerLayerProver, cascade.columns.len) catch |err| {
            cascade.deinit(allocator);
            return err;
        };
        var layer_domain = evaluation.domain();
        for (ready_layers, cascade.columns, cascade.trees) |*layer, column, tree| {
            layer.* = .{
                .domain = layer_domain,
                .column = column,
                .merkle_tree = tree,
                .fold_step = 1,
            };
            layer_domain = layer_domain.double();
        }
        const terminal_evaluation = cascade.last_layer_evaluation;
        allocator.free(cascade.columns);
        allocator.free(cascade.trees);
        var consumed_evaluation = evaluation;
        consumed_evaluation.deinit(allocator);
        return .{
            .inner_layers = ready_layers,
            .last_layer_evaluation = terminal_evaluation,
        };
    }

    pub const foldLine = host_primitives.foldLine;
    pub const foldLineN = host_primitives.foldLineN;
};

test "Metal commit backend exposes telemetry without constructing a runtime" {
    _ = MetalCommitBackend.TelemetrySnapshot;
    _ = MetalCommitBackend.TelemetryDelta;
    _ = MetalCommitBackend.RuntimeLifecycleSnapshot;
    _ = MetalCommitBackend.ShutdownError;
    comptime {
        _ = @TypeOf(MetalCommitBackend.telemetrySnapshot);
        _ = @TypeOf(MetalCommitBackend.recordSampledValueFallback);
        _ = @TypeOf(MetalCommitBackend.runtimeLifecycleSnapshot);
        _ = @TypeOf(MetalCommitBackend.shutdown);
    }

    const lifecycle = MetalCommitBackend.runtimeLifecycleSnapshot();
    try std.testing.expect(lifecycle.initialization_count >= lifecycle.shutdown_count);
    try std.testing.expectEqual(
        lifecycle.initialized,
        lifecycle.initialization_count > lifecycle.shutdown_count,
    );
}
