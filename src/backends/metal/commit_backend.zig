const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;
const backend_composition = @import("runtime/backend_composition.zig");
const base_polynomial_composition = @import("runtime/base_polynomial_composition.zig");
const column_source_materialization = @import("runtime/column_source_materialization.zig");
const circle_lde_output_parity = @import("circle_lde_output_parity.zig");
const commit_policy = @import("commit_policy.zig");
const combined_commit = @import("runtime/combined_commit.zig");
const fold_inverses = @import("runtime/fold_inverses.zig");
const heterogeneous_commit = @import("runtime/heterogeneous_commit.zig");
const hash_domain = @import("hash_domain.zig");
const host_primitives = @import("host_primitives.zig");
const merkle = @import("stwo_prover_engine").vcs_lifted.prover;
const metal_merkle = @import("merkle_tree.zig");
const metal_runtime = @import("runtime.zig");
const ownership_testing = @import("runtime/ownership_testing.zig");
const quotient_output_parity = @import("quotient_output_parity.zig");
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
    // Resident composition addresses each component as a tightly packed run
    // of columns.  Keeping the LDE arena compact also lets the Merkle tree and
    // every later polynomial batch share that one proof-owned Metal view.
    pub const requires_contiguous_resident_columns = true;
    // Apple-silicon pages are 16 KiB; this is also a multiple of Intel macOS's
    // 4 KiB pages, so `newBufferWithBytesNoCopy` can bind either target.
    pub const resident_column_arena_alignment = std.mem.Alignment.fromByteUnits(16 * 1024);

    /// Holds the shared runtime lease and one command containing every direct
    /// circle-LDE group for a generic commitment. The prover explicitly
    /// finishes this owner before consuming transformed columns; unfinished
    /// error-path destruction releases the uncommitted command before borrowed
    /// host arenas unwind.
    pub const CircleLdeBatch = struct {
        lease: shared_runtime.CallLease,
        runtime_batch: metal_runtime.CircleLdeBatch,
        parity_groups: std.ArrayList(circle_lde_output_parity.GroupCaptureV1) = .empty,
        parity_allocator: ?std.mem.Allocator = null,

        pub fn init() !CircleLdeBatch {
            var lease = try shared_runtime.acquire();
            errdefer lease.deinit();
            const runtime_batch = try lease.runtime.beginCircleLdeBatch();
            return .{ .lease = lease, .runtime_batch = runtime_batch };
        }

        pub fn deinit(self: *CircleLdeBatch) void {
            if (self.parity_allocator) |allocator| {
                for (self.parity_groups.items) |*group| group.deinit(allocator);
                self.parity_groups.deinit(allocator);
            }
            self.lease.runtime.destroyCircleLdeBatch(&self.runtime_batch);
            self.lease.deinit();
            self.* = undefined;
        }

        pub fn finish(self: *CircleLdeBatch) !void {
            const stats = try self.lease.runtime.finishCircleLdeBatch(&self.runtime_batch);
            if (circle_lde_output_parity.enabled()) {
                const allocator = self.parity_allocator orelse
                    return error.MetalCircleLdeParityMissingRoute;
                const result = try circle_lde_output_parity.compareBatch(
                    allocator,
                    self.parity_groups.items,
                );
                switch (result) {
                    .exact => |receipt| std.debug.print(
                        "METAL_RETAINED_LDE_PARITY=exact groups={} rebased_groups={} dispatches={} selected_columns={} coefficient_values={} extended_values={} sha256={x}\n",
                        .{
                            receipt.group_count,
                            receipt.rebased_group_count,
                            receipt.dispatch_count,
                            receipt.selected_column_count,
                            receipt.coefficient_values,
                            receipt.extended_values,
                            receipt.actual_sha256,
                        },
                    ),
                    .mismatch => |mismatch| {
                        std.debug.print(
                            "METAL_RETAINED_LDE_PARITY=mismatch group={} column={} phase={s} row={} expected={} actual={}\n",
                            .{
                                mismatch.group_index,
                                mismatch.group_column_index,
                                @tagName(mismatch.phase),
                                mismatch.row,
                                mismatch.expected.v,
                                mismatch.actual.v,
                            },
                        );
                        return error.MetalCircleLdeOutputParityMismatch;
                    },
                }
            }
            std.log.debug(
                "Metal circle LDE batch: {} direct groups, {d:.3}ms GPU",
                .{ stats.encoded_operations, stats.gpu_milliseconds },
            );
        }

        fn captureParityGroup(
            self: *CircleLdeBatch,
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
            if (!circle_lde_output_parity.enabled()) return;
            if (self.parity_allocator) |prior| {
                if (prior.ptr != allocator.ptr or prior.vtable != allocator.vtable)
                    return error.MetalCircleLdeParityAllocatorMismatch;
            } else {
                self.parity_allocator = allocator;
            }
            var capture = try circle_lde_output_parity.GroupCaptureV1.init(
                allocator,
                source_values,
                base_values,
                extended_values,
                transform_buffer.len,
                extended_start,
                extended_stride,
                base_domain,
                base_twiddles,
                extended_domain,
                extended_twiddles,
            );
            errdefer capture.deinit(allocator);
            try self.parity_groups.append(allocator, capture);
        }
    };
    pub const lazyFriFoldInverseWorkspace = true;
    // Every resident parent-chain route dispatches the complete binary-tree
    // cardinality at each level.  This is deliberately distinct from the host
    // backend's constant-column fast path: lifecycle_and_tree.m,
    // circle_commit_epoch.m, merkle_epochs.m, and fri_fold_commit.m all encode
    // `leaf_count >> level` parents without data-dependent elision.  Keep the
    // three declarations separate so a future route-specific optimization
    // cannot silently change the work receipt for the other two routes.
    pub const reuses_constant_merkle_parents = false;
    pub const lazy_merkle_reuses_constant_parents = false;
    pub const fri_fused_merkle_reuses_constant_parents = false;
    /// Resident queried-value gathering rejects byte-equal columns at a new
    /// pointer.  Multi-fold FRI therefore keeps the exact packed host columns
    /// alive until decommitment instead of recreating or host-falling back.
    pub const retainFriPackedOpeningColumns = true;

    pub const prepareAndCommitOwned = heterogeneous_commit.prepareAndCommitOwned;
    pub const prepareAndCommitOwnedWithWorkRecorder =
        heterogeneous_commit.prepareAndCommitOwnedWithWorkRecorder;
    pub const prepareAndCommitPolys = combined_commit.prepareAndCommitPolys;
    pub const prepareAndCommitPolysWithWorkRecorder =
        combined_commit.prepareAndCommitPolysWithWorkRecorder;
    pub const preferContiguousQuadraticRecurrenceTrace = true;
    pub const preferDeferredQuadraticRecurrenceTrace = true;
    pub const admitsDeferredQuadraticRecurrenceTrace = combined_commit.admitsDeferredQuadraticRecurrenceTrace;
    pub const quadratic_recurrence_min_cells = quadratic_trace.min_cells;
    pub const admitsQuadraticRecurrenceTrace = quadratic_trace.admits;
    pub const fillQuadraticRecurrenceTrace = quadratic_trace.fill;
    pub const materializeColumnSource = column_source_materialization.materialize;
    const ResidentFriOps = resident_fri_transaction.Ops(@This());
    pub const commitLazyFriTransaction = ResidentFriOps.commitLazyFriTransaction;
    pub const commitLazyFriTransactionWithReceipt = ResidentFriOps.commitLazyFriTransactionWithReceipt;
    pub const commitFriCircleLayers = ResidentFriOps.commitFriCircleLayers;
    pub const commitFriCircleLayersWithReceipt = ResidentFriOps.commitFriCircleLayersWithReceipt;

    pub fn warmup() !void {
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
    }

    /// Searches the exact BLAKE2s nonce space on the authenticated Metal
    /// runtime. The generic PCS layer revalidates the returned nonce against
    /// its transcript before publication.
    pub fn grindBlake2sProofOfWork(prefix: [32]u8, pow_bits: u32) !u64 {
        var prefix_words: [8]u32 = undefined;
        for (&prefix_words, 0..) |*word, index| {
            word.* = std.mem.readInt(u32, prefix[index * 4 ..][0..4], .little);
        }
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        return (try lease.runtime.grindBlake2sProofOfWork(&prefix_words, pow_bits)).nonce;
    }

    /// Device search for the Poseidon2-M31 recursion channel; the generic
    /// prover re-verifies the nonce on the host channel before use.
    pub fn grindPoseidon2ChannelProofOfWork(prefix_state: [16]u32, pow_bits: u32) !u64 {
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        return (try lease.runtime.grindPoseidon2ChannelProofOfWork(&prefix_state, pow_bits)).nonce;
    }

    pub fn initializeRuntime(
        allocator: std.mem.Allocator,
        policy: RuntimeInitializationPolicy,
    ) !void {
        try shared_runtime.initialize(allocator, policy);
    }

    pub const computeCompositionEvaluation = backend_composition.computeCompositionEvaluation;
    pub const computeCompositionEvaluationWithExecution =
        backend_composition.computeCompositionEvaluationWithExecution;
    pub const computeCompositionEvaluationWithWorkCapture =
        backend_composition.computeCompositionEvaluationWithWorkCapture;
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
        // Pooled composition-domain scratch buffers belong to the live runtime;
        // release them before the runtime itself can be torn down.
        base_polynomial_composition.releasePooledCompositionScratch();
        return shared_runtime.shutdown();
    }

    pub const recordSampledValueFallback = commit_policy.recordSampledValueFallback;

    pub fn MerkleTree(comptime H: type) type {
        return metal_merkle.MetalMerkleTree(H);
    }

    pub fn FriLineCascadeResult(comptime H: type) type {
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
        const resident_hash_supported = comptime hash_domain.parameters(H) != null;
        if (cells == 0) {
            const empty_tree = try merkle.MerkleProverLifted(H).commit(allocator, columns);
            return MerkleTree(H).fromHost(empty_tree);
        }
        if (!commit_policy.usesResidentMerkle(cells) or !resident_hash_supported) {
            const host_tree = try merkle.MerkleProverLifted(H).commit(allocator, columns);
            telemetry.record(.host_merkle_commit);
            telemetry.record(if (commit_policy.usesResidentMerkle(cells))
                .cpu_streaming_merkle_commit
            else
                .cpu_small_merkle_commit);
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
        const resident_hash_supported = comptime hash_domain.parameters(H) != null;
        if (cells == 0 or !commit_policy.usesResidentMerkle(cells) or
            backing_buffers.len == 0 or !resident_hash_supported)
        {
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
        const gpu_ms = if (provider.rowWorkProfileEnabled()) blk: {
            const result = try lease.runtime.computeQuotientsWithReceipt(
                allocator,
                provider,
                out,
            );
            try provider.completeMetalRowExecution(result.execution);
            break :blk result.gpu_ms;
        } else try lease.runtime.computeQuotients(allocator, provider, out);
        try validateQuotientOutputParity(allocator, provider, out);
        telemetry.record(.metal_quotient_dispatch);
        std.log.debug("Metal quotient kernel: {d:.3}ms", .{gpu_ms});
    }

    pub fn commitLazyMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        provider: anytype,
        out: anytype,
    ) !MerkleTree(H) {
        const maybe_domain = comptime hash_domain.parameters(H);
        if (comptime maybe_domain == null) {
            try computeLazyQuotients(allocator, provider, out);
            const columns = [_][]const @import("stwo_core").fields.m31.M31{
                out.columns[0],
                out.columns[1],
                out.columns[2],
                out.columns[3],
            };
            return commitMerkle(H, allocator, columns[0..]);
        }
        const domain = maybe_domain.?;
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
        const result: @import("runtime.zig").QuotientCommitResult = if (provider.rowWorkProfileEnabled()) blk: {
            const profiled = try lease.runtime.computeQuotientsAndCommitWithReceiptForHash(
                allocator,
                provider,
                out,
                domain.leaf_seed,
                domain.node_seed,
                domain.domain_prefix_bytes,
                @intFromEnum(domain.family),
            );
            try provider.completeMetalRowExecution(profiled.execution);
            break :blk .{ .gpu_ms = profiled.gpu_ms, .tree = profiled.tree };
        } else try lease.runtime.computeQuotientsAndCommitForHash(
            allocator,
            provider,
            out,
            domain.leaf_seed,
            domain.node_seed,
            domain.domain_prefix_bytes,
            @intFromEnum(domain.family),
        );
        var tree = try MerkleTree(H).fromSharedRuntime(result.tree);
        errdefer tree.deinit(allocator);
        try validateQuotientOutputParity(allocator, provider, out);
        telemetry.record(.metal_quotient_dispatch);
        telemetry.record(.resident_merkle_commit);
        std.log.debug("Metal quotient + Merkle epoch: {d:.3}ms", .{result.gpu_ms});
        return tree;
    }

    fn validateQuotientOutputParity(
        allocator: std.mem.Allocator,
        provider: anytype,
        out: anytype,
    ) !void {
        if (!quotient_output_parity.enabled()) return;
        const result = try quotient_output_parity.compareRawProviderAgainstCpu(
            allocator,
            provider,
            out,
        );
        switch (result) {
            .exact => |receipt| std.debug.print(
                "METAL_QUOTIENT_PARITY=exact log={} rows={} values={} sha256={x}\n",
                .{
                    receipt.lifting_log_size,
                    receipt.row_count,
                    receipt.compared_values,
                    receipt.actual_sha256,
                },
            ),
            .mismatch => |mismatch| {
                std.debug.print(
                    "METAL_QUOTIENT_PARITY=mismatch row={} coordinate={} expected={} actual={}\n",
                    .{
                        mismatch.row,
                        mismatch.coordinate,
                        mismatch.expected.v,
                        mismatch.actual.v,
                    },
                );
                return error.MetalQuotientOutputParityMismatch;
            },
        }
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
        const gpu_ms = try lease.runtime.evaluateCoefficientPlansUnprofiled(
            allocator,
            coefficients,
            tree_values,
            plans,
        );
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug("Metal sampled-value kernel: {d:.3}ms", .{gpu_ms});
    }

    pub fn evaluateCoefficientPlansWithReceipt(
        allocator: std.mem.Allocator,
        coefficients: anytype,
        tree_values: anytype,
        plans: anytype,
    ) !work_profile.SampledCoefficientExecution {
        if (plans.len == 0) return emptySampledCoefficientExecution();
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const result = try lease.runtime.evaluateCoefficientPlans(
            allocator,
            coefficients,
            tree_values,
            plans,
        );
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug("Metal sampled-value kernel: {d:.3}ms", .{result.gpu_ms});
        return result.execution;
    }

    pub fn evaluateCoefficientTreePlans(
        allocator: std.mem.Allocator,
        tree_plans: anytype,
    ) !void {
        if (tree_plans.len == 0) return;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const gpu_ms = try lease.runtime.evaluateCoefficientTreePlansUnprofiled(
            allocator,
            tree_plans,
        );
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug("Metal sampled-value batch epoch: {d:.3}ms", .{gpu_ms});
    }

    pub fn evaluateCoefficientTreePlansWithReceipt(
        allocator: std.mem.Allocator,
        tree_plans: anytype,
    ) !work_profile.SampledCoefficientExecution {
        if (tree_plans.len == 0) return emptySampledCoefficientExecution();
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const result = try lease.runtime.evaluateCoefficientTreePlans(allocator, tree_plans);
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug("Metal sampled-value batch epoch: {d:.3}ms", .{result.gpu_ms});
        return result.execution;
    }

    pub fn evaluateBarycentricTreePlans(
        allocator: std.mem.Allocator,
        tree_plans: anytype,
    ) !void {
        if (tree_plans.len == 0) return;
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const result = try lease.runtime.evaluateBarycentricTreePlans(
            allocator,
            tree_plans,
        );
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug(
            "Metal sampled-value barycentric epoch: {d:.3}ms",
            .{result.gpu_ms},
        );
    }

    pub fn evaluateBarycentricTreePlansWithReceipt(
        allocator: std.mem.Allocator,
        tree_plans: anytype,
    ) !work_profile.SampledBarycentricExecution {
        if (tree_plans.len == 0) return emptySampledBarycentricExecution();
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        const result = try lease.runtime.evaluateBarycentricTreePlans(
            allocator,
            tree_plans,
        );
        telemetry.record(.metal_sampled_value_dispatch);
        std.log.debug(
            "Metal sampled-value barycentric epoch: {d:.3}ms",
            .{result.gpu_ms},
        );
        return result.execution;
    }

    fn emptySampledBarycentricExecution() work_profile.SampledBarycentricExecution {
        return .{
            .point_plan_count = 0,
            .domain_plan_count = 0,
            .evaluation_task_count = 0,
            .weight_value_count = 0,
            .dot_product_terms = 0,
            .domain_circle_multiplications = 0,
            .scale_double_count = 0,
            .inverse_tree_block_count = 0,
            .direct_inversion_count = 0,
            .reduction_addition_count = 0,
            .constant_addition_count = 0,
            .constant_multiplication_count = 0,
            .constant_inversion_count = 0,
        };
    }

    fn emptySampledCoefficientExecution() work_profile.SampledCoefficientExecution {
        return .{
            .plan_count = 0,
            .basis_task_count = 0,
            .evaluation_task_count = 0,
            .evaluation_coefficient_terms = 0,
            .basis_multiplications = 0,
            .basis_threadgroup_width = 0,
            .evaluation_threadgroup_width = 0,
        };
    }

    pub fn interpolateCircleBuffers(
        allocator: std.mem.Allocator,
        values: []const []@import("stwo_core").fields.m31.M31,
        domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        twiddle_tree: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    ) !work_profile.M31InterpolationExecution {
        if (values.len == 0) return error.InvalidColumns;
        if (domain.logSize() < 3) {
            try @import("stwo_prover_engine").poly.circle.poly.interpolateBuffersWithTwiddles(values, domain, twiddle_tree);
            telemetry.record(.cpu_small_circle_interpolation);
            const execution = work_profile.M31InterpolationExecution{
                .log_size = domain.logSize(),
                .column_count = @intCast(values.len),
                // One host fallback call shares its normalization inverse.
                .batch_count = 1,
            };
            try execution.validate();
            return execution;
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
        const execution = work_profile.M31InterpolationExecution{
            .log_size = domain.logSize(),
            .column_count = @intCast(values.len),
            // The device dispatch shares one scale factor across every column.
            .batch_count = 1,
        };
        try execution.validate();
        return execution;
    }

    pub fn evaluateCircleBuffers(
        allocator: std.mem.Allocator,
        values: []const []@import("stwo_core").fields.m31.M31,
        domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        twiddle_tree: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    ) !work_profile.M31ForwardFftExecution {
        if (values.len == 0) return error.InvalidColumns;
        if (domain.logSize() < 3) {
            try @import("stwo_prover_engine").poly.circle.poly.evaluateBuffersWithTwiddles(values, domain, twiddle_tree);
            telemetry.record(.cpu_small_circle_evaluation);
            const execution = work_profile.M31ForwardFftExecution{
                .log_size = domain.logSize(),
                .column_count = @intCast(values.len),
            };
            try execution.validate();
            return execution;
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
        const execution = work_profile.M31ForwardFftExecution{
            .log_size = domain.logSize(),
            .column_count = @intCast(values.len),
            // Standalone evaluation materializes every layer on device.
            .skipped_layers = 0,
        };
        try execution.validate();
        return execution;
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
    ) !work_profile.M31CircleLdeExecution {
        return interpolateAndEvaluateCircleBuffersImpl(
            null,
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer,
            extended_start,
            extended_stride,
            base_domain,
            base_twiddles,
            extended_domain,
            extended_twiddles,
        );
    }

    pub fn interpolateAndEvaluateCircleBuffersBatched(
        batch: *CircleLdeBatch,
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
    ) !work_profile.M31CircleLdeExecution {
        return interpolateAndEvaluateCircleBuffersImpl(
            batch,
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer,
            extended_start,
            extended_stride,
            base_domain,
            base_twiddles,
            extended_domain,
            extended_twiddles,
        );
    }

    fn interpolateAndEvaluateCircleBuffersImpl(
        batch: ?*CircleLdeBatch,
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
    ) !work_profile.M31CircleLdeExecution {
        if (source_values.len == 0 or source_values.len != base_values.len or
            base_values.len != extended_values.len)
        {
            return error.InvalidColumns;
        }
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
            return .{
                .interpolation = .{
                    .log_size = base_domain.logSize(),
                    .column_count = @intCast(source_values.len),
                    // The host fallback submits every column as one batch.
                    .batch_count = 1,
                },
                .forward = .{
                    .log_size = extended_domain.logSize(),
                    .column_count = @intCast(source_values.len),
                },
            };
        }
        if (batch) |active| try active.captureParityGroup(
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer,
            extended_start,
            extended_stride,
            base_domain,
            base_twiddles,
            extended_domain,
            extended_twiddles,
        );
        const result = if (batch) |active|
            try active.lease.runtime.transformCircleLdeIntoBatch(
                &active.runtime_batch,
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
            )
        else blk: {
            var lease = try shared_runtime.acquire();
            defer lease.deinit();
            break :blk try lease.runtime.transformCircleLdeInto(
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
        };
        telemetry.record(.metal_circle_lde_dispatch);
        std.log.debug("Metal circle IFFT+RFFT: {d:.3}ms", .{result.gpu_milliseconds});
        return result.execution;
    }

    pub const ColumnType = host_primitives.ColumnType;
    pub const batchInverse = host_primitives.batchInverse;
    const FriOps = @import("commit_backend_fri.zig").Ops(@This());
    pub const foldCircleIntoLine = FriOps.foldCircleIntoLine;
    pub const foldCircleIntoLineWithReceipt = FriOps.foldCircleIntoLineWithReceipt;
    pub const foldLineEvaluationN = FriOps.foldLineEvaluationN;
    pub const foldLineEvaluationNWithReceipt = FriOps.foldLineEvaluationNWithReceipt;
    pub const foldLineAndCommitNext = FriOps.foldLineAndCommitNext;
    pub const foldLineAndCommitNextWithReceipt = FriOps.foldLineAndCommitNextWithReceipt;
    pub const commitFriLineCascade = FriOps.commitFriLineCascade;
    pub const commitFriLineCascadeWithReceipt = FriOps.commitFriLineCascadeWithReceipt;
    pub const commitFriLayers = FriOps.commitFriLayers;
    pub const commitFriLayersWithReceipt = FriOps.commitFriLayersWithReceipt;

    pub const foldLine = host_primitives.foldLine;
    pub const foldLineN = host_primitives.foldLineN;
};

test "metal proof of work returns the protocol lowest nonce" {
    const core = @import("stwo_core");
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Hasher = core.crypto.blake2s_backend.Blake2sHasher;

    try MetalCommitBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer MetalCommitBackend.shutdown() catch unreachable;

    var channel = Channel{};
    channel.mixU32s(&.{ 0x1234_5678, 0x9abc_def0 });
    const pow_bits: u32 = 12;
    var prefix_input: [52]u8 = [_]u8{0} ** 52;
    std.mem.writeInt(u32, prefix_input[0..4], Channel.POW_PREFIX, .little);
    @memcpy(prefix_input[16..48], channel.digestBytes()[0..]);
    std.mem.writeInt(u32, prefix_input[48..52], pow_bits, .little);
    const prefix = Hasher.hashFixedSingleBlock(prefix_input.len, &prefix_input);

    const expected = channel.grind(pow_bits);
    const actual = try MetalCommitBackend.grindBlake2sProofOfWork(prefix, pow_bits);
    try std.testing.expectEqual(expected, actual);
    try std.testing.expect(channel.verifyPowNonce(pow_bits, actual));
}

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
