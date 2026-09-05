const std = @import("std");
const circle = @import("stwo_core").circle;
const core_fri = @import("stwo_core").fri;
const backend_fri = @import("stwo_backend_contracts").fri_ops;
const backend_merkle = @import("stwo_backend_contracts").merkle_ops;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const circle_domain = @import("stwo_core").poly.circle.domain;
const queries_mod = @import("stwo_core").queries;
const vcs_lifted_verifier = @import("stwo_core").vcs_lifted.verifier;
const fri_lazy_commit = @import("pcs/fri_lazy_commit.zig");
const prover_line = @import("line.zig");
const quotient_ops = @import("pcs/quotient_ops.zig");
const shell_work_profile = @import("pcs/shell_work_profile.zig");
const secure_column = @import("secure_column.zig");
const fri_packing = @import("fri_packing.zig");
const fri_decommit = @import("fri_decommit.zig");
const work_profile = @import("stwo_prover_api").work_profile;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const WorkRecorder = work_profile.Recorder(true);
const PACKED_LEAF_SIZE: usize = @as(usize, 1) << @intCast(core_fri.LOG_PACKED_LEAF_SIZE);
const PACKED_COLUMN_COUNT: usize = PACKED_LEAF_SIZE * qm31.SECURE_EXTENSION_DEGREE;
pub const PackedSecureColumns = fri_packing.PackedSecureColumns;
const shouldPack = fri_packing.shouldPack;
const packedQueryPositions = fri_packing.packedQueryPositions;
pub const FriDecommitError = fri_decommit.FriDecommitError;
pub const FriProverError = error{ NotCanonicDomain, ShapeMismatch, InvalidLastLayerSize, InvalidLastLayerDegree, InvalidColumnSize };
pub const FoldLineAndCommitResult = backend_fri.FoldLineAndCommitResult;
pub const ValueEntry = fri_decommit.ValueEntry;
pub const DecommitmentPositionsResult = fri_decommit.DecommitmentPositionsResult;
const MAX_FRI_MERKLE_LAYERS: usize = @bitSizeOf(usize) + 1;

/// Execution-path evidence accumulated only when exact work capture is armed.
/// A fixed-size ledger keeps the ordinary prover allocation-free and makes an
/// over-wide or partially described backend transaction fail closed.
pub const FriProtocolWorkAudit = struct {
    const MerklePath = enum(u2) {
        generic,
        lazy,
        fused,
    };

    merkle_paths: [MAX_FRI_MERKLE_LAYERS]MerklePath = undefined,
    merkle_path_count: usize = 0,
    fold_executions: work_profile.FriFoldExecutionLedger = .{},
    terminal_interpolation: ?work_profile.FriLineInterpolationExecution = null,
    standalone_field_work: work_profile.Counters = .{},
    complete: bool = true,

    fn observe(self: *FriProtocolWorkAudit, path: MerklePath, count: usize) void {
        if (!self.complete) return;
        if (self.merkle_path_count > self.merkle_paths.len or
            count > self.merkle_paths.len - self.merkle_path_count)
        {
            self.complete = false;
            return;
        }
        for (self.merkle_paths[self.merkle_path_count..][0..count]) |*slot| {
            slot.* = path;
        }
        self.merkle_path_count += count;
    }

    pub fn observeGenericMerkle(self: *FriProtocolWorkAudit) void {
        self.observe(.generic, 1);
    }

    pub fn observeLazyMerkle(self: *FriProtocolWorkAudit) void {
        self.observe(.lazy, 1);
    }

    pub fn observeFusedMerkle(self: *FriProtocolWorkAudit, count: usize) void {
        self.observe(.fused, count);
    }

    pub fn observeAlphaSquare(self: *FriProtocolWorkAudit) void {
        if (!self.complete) return;
        self.standalone_field_work.field_multiplications = std.math.add(
            u64,
            self.standalone_field_work.field_multiplications,
            1,
        ) catch {
            self.complete = false;
            return;
        };
    }

    pub fn observeTerminalInterpolation(
        self: *FriProtocolWorkAudit,
        execution: work_profile.FriLineInterpolationExecution,
    ) void {
        if (!self.complete or self.terminal_interpolation != null) {
            self.complete = false;
            return;
        }
        execution.validate() catch {
            self.complete = false;
            return;
        };
        self.terminal_interpolation = execution;
    }

    /// Closes custody for the exact root-mix observations accumulated at the
    /// generic/lazy call sites or after a receipt-bearing fused transaction.
    /// Returned root bytes and path selection are bound in transcript order.
    pub fn rootMixReceipt(
        self: *const FriProtocolWorkAudit,
        prover: anytype,
    ) !shell_work_profile.FriRootMixReceipt {
        const expected = std.math.add(
            usize,
            prover.inner_layers.len,
            1,
        ) catch return error.CounterOverflow;
        if (!self.complete or self.merkle_path_count != expected)
            return error.InvalidCounterGroup;

        var generic_count: usize = 0;
        var lazy_count: usize = 0;
        var fused_count: usize = 0;
        var authority = std.crypto.hash.sha2.Sha256.init(.{});
        authority.update(shell_work_profile.FRI_ROOT_MIX_DOMAIN);
        hashFriRoot(&authority, 0, self.merkle_paths[0], prover.first_layer.merkle_tree.root());
        for (prover.inner_layers, 0..) |layer, index| {
            hashFriRoot(
                &authority,
                index + 1,
                self.merkle_paths[index + 1],
                layer.merkle_tree.root(),
            );
        }
        for (self.merkle_paths[0..self.merkle_path_count]) |path| switch (path) {
            .generic => generic_count += 1,
            .lazy => lazy_count += 1,
            .fused => fused_count += 1,
        };
        return shell_work_profile.FriRootMixReceipt.init(
            expected,
            generic_count,
            lazy_count,
            fused_count,
            authority.finalResult(),
        );
    }

    fn hashFriRoot(
        hash: *std.crypto.hash.sha2.Sha256,
        ordinal: usize,
        path: MerklePath,
        root: anytype,
    ) void {
        var ordinal_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &ordinal_bytes, @intCast(ordinal), .little);
        hash.update(&ordinal_bytes);
        hash.update(&.{@intFromEnum(path)});
        hash.update(std.mem.asBytes(&root));
    }
};

const FriFoldWork = struct {
    circle_folds: u64,
    line_folds: u64,
    final_ifft_butterflies: u64,

    pub fn totalFolds(self: FriFoldWork) !u64 {
        return std.math.add(u64, self.circle_folds, self.line_folds) catch
            error.CounterOverflow;
    }
};

fn checkedFoldedSize(size: usize, fold_count: u32) !usize {
    if (size == 0 or !std.math.isPowerOfTwo(size))
        return error.InvalidCounterGroup;
    const log_size: u32 = @intCast(std.math.log2_int(usize, size));
    if (fold_count == 0 or fold_count > log_size)
        return error.InvalidCounterGroup;
    return size >> @intCast(fold_count);
}

/// Replays the exact successful FRI shape transition, using the returned
/// layer domains rather than assuming that an optional backend hook followed
/// the requested schedule. One logical fold is one completed pair reduction.
fn deriveFriFoldWork(
    prover: anytype,
    config: core_fri.FriConfig,
    initial_size: usize,
) !FriFoldWork {
    if (initial_size < 2 or !std.math.isPowerOfTwo(initial_size) or
        prover.first_layer.domain.size() != initial_size or
        prover.first_layer.column.len() != initial_size)
    {
        return error.InvalidCounterGroup;
    }

    const last_log_size = std.math.add(
        u32,
        config.log_last_layer_degree_bound,
        config.log_blowup_factor,
    ) catch return error.CounterOverflow;
    if (last_log_size >= @bitSizeOf(usize)) return error.CounterOverflow;
    const last_size = @as(usize, 1) << @intCast(last_log_size);
    if (last_size == 0 or last_size > initial_size)
        return error.InvalidCounterGroup;

    const after_circle = initial_size >> 1;
    var current_size = try checkedFoldedSize(initial_size, config.fold_step);
    var line_folds = std.math.cast(u64, after_circle - current_size) orelse
        return error.CounterOverflow;

    for (prover.inner_layers) |layer| {
        if (layer.domain.size() != current_size or
            layer.column.len() != current_size)
        {
            return error.InvalidCounterGroup;
        }
        const next_size = try checkedFoldedSize(current_size, layer.fold_step);
        line_folds = std.math.add(
            u64,
            line_folds,
            std.math.cast(u64, current_size - next_size) orelse
                return error.CounterOverflow,
        ) catch return error.CounterOverflow;
        current_size = next_size;
    }
    if (current_size != last_size) return error.InvalidCounterGroup;

    return .{
        .circle_folds = std.math.cast(u64, after_circle) orelse
            return error.CounterOverflow,
        .line_folds = line_folds,
        .final_ifft_butterflies = try work_profile.logicalFftButterflies(
            last_log_size,
            0,
        ),
    };
}

fn backendMerkleReuse(
    comptime B: type,
    path: FriProtocolWorkAudit.MerklePath,
) !bool {
    return switch (path) {
        .generic => if (comptime @hasDecl(B, "reuses_constant_merkle_parents"))
            B.reuses_constant_merkle_parents
        else
            error.InvalidCounterGroup,
        .lazy => if (comptime @hasDecl(B, "lazy_merkle_reuses_constant_parents"))
            B.lazy_merkle_reuses_constant_parents
        else
            error.InvalidCounterGroup,
        .fused => if (comptime @hasDecl(B, "fri_fused_merkle_reuses_constant_parents"))
            B.fri_fused_merkle_reuses_constant_parents
        else
            error.InvalidCounterGroup,
    };
}

fn friColumnIsMerkleConstant(column: anytype, uses_packed_leaves: bool) bool {
    const leaf_count = if (uses_packed_leaves)
        column.len() / PACKED_LEAF_SIZE
    else
        column.len();
    if (leaf_count == 0) return false;

    for (column.columns) |coordinate| {
        const values_per_leaf = if (uses_packed_leaves) PACKED_LEAF_SIZE else 1;
        for (0..values_per_leaf) |offset| {
            const first = coordinate[offset];
            for (1..leaf_count) |leaf| {
                if (!coordinate[leaf * values_per_leaf + offset].eql(first))
                    return false;
            }
        }
    }
    return true;
}

fn friLayerMerkleCompressions(
    column: anytype,
    uses_packed_leaves: bool,
    reuses_constant_parents: bool,
) !u64 {
    const column_len = column.len();
    if (column_len == 0 or !std.math.isPowerOfTwo(column_len))
        return error.InvalidCounterGroup;
    for (column.columns) |coordinate| {
        if (coordinate.len != column_len) return error.InvalidCounterGroup;
    }
    const leaf_count = if (uses_packed_leaves)
        column_len / PACKED_LEAF_SIZE
    else
        column_len;
    const encoded_leaf_count = std.math.cast(u64, leaf_count) orelse
        return error.CounterOverflow;
    return work_profile.logicalMerkleCompressions(
        encoded_leaf_count,
        reuses_constant_parents and
            friColumnIsMerkleConstant(column, uses_packed_leaves),
    );
}

fn deriveFriMerkleWork(
    comptime B: type,
    audit: *const FriProtocolWorkAudit,
    prover: anytype,
    config: core_fri.FriConfig,
) !u64 {
    const expected_path_count = std.math.add(
        usize,
        prover.inner_layers.len,
        1,
    ) catch return error.CounterOverflow;
    if (!audit.complete or audit.merkle_path_count != expected_path_count) {
        return error.InvalidCounterGroup;
    }

    var total = try friLayerMerkleCompressions(
        prover.first_layer.column,
        shouldPack(prover.first_layer.column.len(), config.fold_step),
        try backendMerkleReuse(B, audit.merkle_paths[0]),
    );
    for (prover.inner_layers, 0..) |layer, index| {
        total = std.math.add(
            u64,
            total,
            try friLayerMerkleCompressions(
                layer.column,
                shouldPack(layer.column.len(), layer.fold_step),
                try backendMerkleReuse(B, audit.merkle_paths[index + 1]),
            ),
        ) catch return error.CounterOverflow;
    }
    return total;
}

fn recordFriProtocolWork(
    comptime B: type,
    recorder: ?*WorkRecorder,
    audit: *const FriProtocolWorkAudit,
    prover: anytype,
    config: core_fri.FriConfig,
    initial_size: usize,
) void {
    const active = recorder orelse return;
    const fold_work = deriveFriFoldWork(prover, config, initial_size) catch
        return active.markIncomplete();
    if (!audit.complete or !audit.fold_executions.complete)
        return active.markIncomplete();
    const executed_folds = audit.fold_executions.exactWork() catch
        return active.markIncomplete();
    var executed_circle_folds: u64 = 0;
    var executed_line_folds: u64 = 0;
    for (audit.fold_executions.executions[0..audit.fold_executions.count]) |execution| {
        const execution_work = execution.exactWork() catch
            return active.markIncomplete();
        switch (execution.kind) {
            .circle_to_line => executed_circle_folds = std.math.add(
                u64,
                executed_circle_folds,
                execution_work.fri_folds,
            ) catch return active.markIncomplete(),
            .line => executed_line_folds = std.math.add(
                u64,
                executed_line_folds,
                execution_work.fri_folds,
            ) catch return active.markIncomplete(),
        }
    }
    if (executed_circle_folds != fold_work.circle_folds or
        executed_line_folds != fold_work.line_folds)
    {
        return active.markIncomplete();
    }
    const terminal_execution = audit.terminal_interpolation orelse
        return active.markIncomplete();
    const terminal_work = terminal_execution.exactWork() catch
        return active.markIncomplete();
    if (terminal_work.fft_butterflies != fold_work.final_ifft_butterflies)
        return active.markIncomplete();
    var protocol_work = executed_folds.add(terminal_work) catch
        return active.markIncomplete();
    protocol_work = protocol_work.add(audit.standalone_field_work) catch
        return active.markIncomplete();
    const merkle_compressions = deriveFriMerkleWork(
        B,
        audit,
        prover,
        config,
    ) catch return active.markIncomplete();
    active.recordCompletedDelta(.{
        .site = .fri_protocol,
        .producer = .fri_protocol,
        .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
            work_profile.SourceMask.one(.field_multiplications).bits |
            work_profile.SourceMask.one(.field_inversions).bits |
            work_profile.SourceMask.one(.fft_butterflies).bits |
            work_profile.SourceMask.one(.fri_folds).bits |
            work_profile.SourceMask.one(.merkle_compressions).bits },
        .counters = .{
            .field_additions = protocol_work.field_additions,
            .field_multiplications = protocol_work.field_multiplications,
            .field_inversions = protocol_work.field_inversions,
            .fft_butterflies = protocol_work.fft_butterflies,
            .fri_folds = protocol_work.fri_folds,
            .merkle_compressions = merkle_compressions,
        },
    }) catch active.markIncomplete();
    // work-profile-complete:fri-protocol
}

/// Owns the STWO FRI leaf layout used whenever a layer folds more than one
/// level: four adjacent QM31 evaluations become sixteen M31 columns, ordered
/// first by evaluation offset and then by extension-field coordinate.
pub const LayerDecommitResult = fri_decommit.LayerDecommitResult;
pub const FriDecommitResult = fri_decommit.FriDecommitResult;
pub fn FriProver(comptime B: type, comptime H: type, comptime MC: type) type {
    comptime backend_merkle.assertMerkleOps(B, H);
    return struct {
        config: core_fri.FriConfig,
        first_layer: FirstLayerProver,
        inner_layers: []InnerLayerProver,
        last_layer_poly: line.LinePoly,

        const Self = @This();
        const lazy_inverse_workspace = if (@hasDecl(B, "lazyFriFoldInverseWorkspace")) B.lazyFriFoldInverseWorkspace else false;
        pub const ProtocolWorkAudit = FriProtocolWorkAudit;
        pub const RootMixCapture = shell_work_profile.FriRootMixCapture;

        pub fn completeProtocolWork(
            recorder: ?*WorkRecorder,
            audit: *const ProtocolWorkAudit,
            prover: *const Self,
            config: core_fri.FriConfig,
            initial_size: usize,
        ) void {
            recordFriProtocolWork(B, recorder, audit, prover, config, initial_size);
        }

        pub fn completeRootMixCapture(
            recorder: ?*WorkRecorder,
            capture: ?*RootMixCapture,
            audit: *const ProtocolWorkAudit,
            prover: *const Self,
        ) void {
            const active_capture = capture orelse return;
            const receipt = audit.rootMixReceipt(prover) catch {
                if (recorder) |active| active.markIncomplete();
                return;
            };
            active_capture.publish(receipt) catch {
                if (recorder) |active| active.markIncomplete();
            };
        }

        pub const FirstLayerProver = struct {
            domain: circle_domain.CircleDomain,
            column: secure_column.SecureColumnByCoords,
            merkle_tree: B.MerkleTree(H),
            /// Present only for a backend whose resident queried-value map
            /// authenticates the exact packed host-column pointers committed
            /// for a multi-fold layer.  This process-local owner is never
            /// serialized and is consumed with the prover.
            retained_packing: ?PackedSecureColumns = null,

            pub fn deinit(self: *FirstLayerProver, allocator: std.mem.Allocator) void {
                self.merkle_tree.deinit(allocator);
                if (self.retained_packing) |*packing| packing.deinit(allocator);
                self.column.deinit(allocator);
                self.* = undefined;
            }
        };

        pub const InnerLayerProver = struct {
            domain: line.LineDomain,
            column: secure_column.SecureColumnByCoords,
            merkle_tree: B.MerkleTree(H),
            /// Same live pointer-custody owner as `FirstLayerProver`.
            retained_packing: ?PackedSecureColumns = null,
            /// Number of folds this layer performs (normally FOLD_STEP, may
            /// be smaller for the last inner layer).
            fold_step: u32 = core_fri.FOLD_STEP,

            pub fn deinit(self: *InnerLayerProver, allocator: std.mem.Allocator) void {
                self.merkle_tree.deinit(allocator);
                if (self.retained_packing) |*packing| packing.deinit(allocator);
                self.column.deinit(allocator);
                self.* = undefined;
            }
        };

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.first_layer.deinit(allocator);
            for (self.inner_layers) |*layer| layer.deinit(allocator);
            allocator.free(self.inner_layers);
            self.last_layer_poly.deinit(allocator);
            self.* = undefined;
        }

        pub fn commit(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            column_domain: circle_domain.CircleDomain,
            column: secure_column.SecureColumnByCoords,
        ) !Self {
            if (!column_domain.isCanonic()) {
                var owned_column = column;
                owned_column.deinit(allocator);
                return FriProverError.NotCanonicDomain;
            }
            if (column.len() != column_domain.size()) {
                var owned_column = column;
                owned_column.deinit(allocator);
                return FriProverError.ShapeMismatch;
            }

            var first_layer = try commitFirstLayer(
                allocator,
                channel,
                column_domain,
                column,
                config.fold_step,
            );
            errdefer first_layer.deinit(allocator);

            var inner_commit = try commitInnerLayers(
                allocator,
                channel,
                config,
                first_layer,
                null,
            );
            defer inner_commit.last_layer_evaluation.deinit(allocator);
            errdefer {
                for (inner_commit.inner_layers) |*layer| layer.deinit(allocator);
                allocator.free(inner_commit.inner_layers);
            }

            var last_layer_poly = try commitLastLayer(
                allocator,
                channel,
                config,
                &inner_commit.last_layer_evaluation,
                null,
            );
            errdefer last_layer_poly.deinit(allocator);

            return .{
                .config = config,
                .first_layer = first_layer,
                .inner_layers = inner_commit.inner_layers,
                .last_layer_poly = last_layer_poly,
            };
        }

        /// Fused commit: computes FRI quotients lazily and builds the Merkle
        /// tree at the same time, avoiding a separate full-column
        /// materialization before hashing.
        ///
        /// The resulting `SecureColumnByCoords` in `first_layer.column` is
        /// bit-identical to what `computeFriQuotients` would have produced.
        pub fn commitLazy(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            column_domain: circle_domain.CircleDomain,
            provider: *quotient_ops.LazyQuotientProvider,
        ) !Self {
            return commitLazyWithWorkRecorder(
                allocator,
                channel,
                config,
                column_domain,
                provider,
                null,
            );
        }

        pub fn commitLazyWithWorkRecorder(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            column_domain: circle_domain.CircleDomain,
            provider: *quotient_ops.LazyQuotientProvider,
            work_recorder: ?*WorkRecorder,
        ) !Self {
            return commitLazyWithWorkRecorderAndRootMixCapture(
                allocator,
                channel,
                config,
                column_domain,
                provider,
                work_recorder,
                null,
            );
        }

        pub fn commitLazyWithWorkRecorderAndRootMixCapture(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            column_domain: circle_domain.CircleDomain,
            provider: *quotient_ops.LazyQuotientProvider,
            work_recorder: ?*WorkRecorder,
            root_mix_capture: ?*RootMixCapture,
        ) !Self {
            return fri_lazy_commit.commitLazy(
                Self,
                B,
                H,
                allocator,
                channel,
                config,
                column_domain,
                provider,
                work_recorder,
                root_mix_capture,
            );
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            channel: anytype,
        ) (std.mem.Allocator.Error || FriDecommitError || FriProverError)!FriDecommitResult(H) {
            const first_layer_log_size = self.first_layer.domain.logSize();
            const unsorted_query_locations = try queries_mod.drawQueries(
                channel,
                allocator,
                first_layer_log_size,
                self.config.n_queries,
            );
            errdefer allocator.free(unsorted_query_locations);

            var queries = try queries_mod.Queries.init(
                allocator,
                unsorted_query_locations,
                first_layer_log_size,
            );
            defer queries.deinit(allocator);

            var fri_proof = try decommitOnQueries(self, allocator, queries);
            errdefer fri_proof.deinit(allocator);

            return .{
                .fri_proof = fri_proof,
                .query_positions = try allocator.dupe(usize, queries.positions),
                .unsorted_query_locations = unsorted_query_locations,
            };
        }

        pub fn decommitOnQueries(
            self: Self,
            allocator: std.mem.Allocator,
            queries: queries_mod.Queries,
        ) (std.mem.Allocator.Error || FriDecommitError || FriProverError)!core_fri.ExtendedFriProof(H) {
            var first_layer = self.first_layer;
            const inner_layers = self.inner_layers;
            var last_layer_poly = self.last_layer_poly;
            errdefer last_layer_poly.deinit(allocator);
            defer {
                first_layer.deinit(allocator);
                for (inner_layers) |*layer| layer.deinit(allocator);
                allocator.free(inner_layers);
            }

            if (queries.log_domain_size != first_layer.domain.logSize()) {
                return FriProverError.ShapeMismatch;
            }

            var first_layer_proof = try fri_decommit.decommitLayerExtendedWithRetainedPacking(
                H,
                allocator,
                first_layer.merkle_tree,
                first_layer.column,
                queries.positions,
                self.config.fold_step,
                if (first_layer.retained_packing) |*packing| packing else null,
            );
            errdefer first_layer_proof.deinit(allocator);

            var layer_queries = try queries.fold(allocator, self.config.fold_step);
            defer layer_queries.deinit(allocator);

            var inner_layer_proofs = std.ArrayList(core_fri.ExtendedFriLayerProof(H)).empty;
            defer inner_layer_proofs.deinit(allocator);
            errdefer {
                for (inner_layer_proofs.items) |*proof| proof.deinit(allocator);
            }

            for (inner_layers) |*layer| {
                var inner_proof = try fri_decommit.decommitLayerExtendedWithRetainedPacking(
                    H,
                    allocator,
                    layer.merkle_tree,
                    layer.column,
                    layer_queries.positions,
                    layer.fold_step,
                    if (layer.retained_packing) |*packing| packing else null,
                );
                errdefer inner_proof.deinit(allocator);
                try inner_layer_proofs.append(allocator, inner_proof);

                const next_queries = try layer_queries.fold(allocator, layer.fold_step);
                layer_queries.deinit(allocator);
                layer_queries = next_queries;
            }

            const inner_extended = try inner_layer_proofs.toOwnedSlice(allocator);
            defer allocator.free(inner_extended);

            const inner_proofs = try allocator.alloc(core_fri.FriLayerProof(H), inner_extended.len);
            errdefer allocator.free(inner_proofs);
            const inner_aux = try allocator.alloc(core_fri.FriLayerProofAux(H), inner_extended.len);
            errdefer allocator.free(inner_aux);
            for (inner_extended, 0..) |proof, i| {
                inner_proofs[i] = proof.proof;
                inner_aux[i] = proof.aux;
            }

            return .{
                .proof = .{
                    .first_layer = first_layer_proof.proof,
                    .inner_layers = inner_proofs,
                    .last_layer_poly = last_layer_poly,
                },
                .aux = .{
                    .first_layer = first_layer_proof.aux,
                    .inner_layers = inner_aux,
                },
            };
        }

        const CommitOps = @import("fri_commit_ops.zig").CommitOps(B, H, MC, Self);
        const commitFirstLayer = CommitOps.commitFirstLayer;
        pub const commitFirstLayerLazy = CommitOps.commitFirstLayerLazy;
        pub const InnerCommitResult = CommitOps.InnerCommitResult;
        pub const LazyFriCommitResult = CommitOps.LazyFriCommitResult;
        pub const commitInnerLayers = CommitOps.commitInnerLayers;
        pub const commitLastLayer = CommitOps.commitLastLayer;
    };
}

/// Produces an extended FRI layer proof (proof + aux) for one layer decommitment.
pub const decommitLayerExtended = fri_decommit.decommitLayerExtended;
pub const decommitLayerExtendedWithRetainedPacking =
    fri_decommit.decommitLayerExtendedWithRetainedPacking;
pub const computeDecommitmentPositionsAndWitnessEvals =
    fri_decommit.computeDecommitmentPositionsAndWitnessEvals;
pub const decommitLayer = fri_decommit.decommitLayer;
const Root = @This();

pub const testing = if (@import("builtin").is_test) struct {
    pub const deriveFriFoldWork = Root.deriveFriFoldWork;
    pub const recordFriProtocolWork = Root.recordFriProtocolWork;
} else struct {};
