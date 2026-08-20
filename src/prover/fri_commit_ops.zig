//! FRI layer commitment routes and backend-authenticated fold custody.

const std = @import("std");
const circle = @import("stwo_core").circle;
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const circle_domain = @import("stwo_core").poly.circle.domain;
const fri_lazy_commit = @import("pcs/fri_lazy_commit.zig");
const prover_line = @import("line.zig");
const quotient_ops = @import("pcs/quotient_ops.zig");
const secure_column = @import("secure_column.zig");
const work_profile = @import("stwo_prover_api").work_profile;
const packing = @import("fri_packing.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const PackedSecureColumns = packing.PackedSecureColumns;
const shouldPack = packing.shouldPack;
const FriProverError = error{ NotCanonicDomain, ShapeMismatch, InvalidLastLayerSize, InvalidLastLayerDegree, InvalidColumnSize };

pub fn CommitOps(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    comptime Owner: type,
) type {
    return struct {
        const Self = Owner;
        const ProtocolWorkAudit = Owner.ProtocolWorkAudit;
        const FriProtocolWorkAudit = Owner.ProtocolWorkAudit;
        const FirstLayerProver = Owner.FirstLayerProver;
        const InnerLayerProver = Owner.InnerLayerProver;
        const lazy_inverse_workspace =
            if (@hasDecl(B, "lazyFriFoldInverseWorkspace")) B.lazyFriFoldInverseWorkspace else false;

        fn observeHostCircleFold(
            audit: *FriProtocolWorkAudit,
            source_count: usize,
            domain: circle_domain.CircleDomain,
        ) void {
            const coset = domain.half_coset;
            audit.fold_executions.observe(.{
                .kind = .circle_to_line,
                .initial_count = std.math.cast(u64, source_count) orelse {
                    audit.complete = false;
                    return;
                },
                .fold_count = 1,
                .domain_log_size = coset.logSize(),
                .domain_initial_index = std.math.cast(u32, coset.initial_index.v) orelse {
                    audit.complete = false;
                    return;
                },
                .domain_step_size = std.math.cast(u32, coset.step_size.v) orelse {
                    audit.complete = false;
                    return;
                },
                .inverse_path = .host_batch,
                .alpha_squares = 1,
                .domain_doubles = 0,
            });
        }

        fn observeHostLineFolds(
            audit: *FriProtocolWorkAudit,
            initial_count: usize,
            domain: line.LineDomain,
            fold_count: u32,
        ) void {
            const coset = domain.coset();
            audit.fold_executions.observe(.{
                .kind = .line,
                .initial_count = std.math.cast(u64, initial_count) orelse {
                    audit.complete = false;
                    return;
                },
                .fold_count = fold_count,
                .domain_log_size = domain.logSize(),
                .domain_initial_index = std.math.cast(u32, coset.initial_index.v) orelse {
                    audit.complete = false;
                    return;
                },
                .domain_step_size = std.math.cast(u32, coset.step_size.v) orelse {
                    audit.complete = false;
                    return;
                },
                .inverse_path = .host_batch,
                // The in-place generic implementation advances alpha after every
                // completed fold, including the final step.
                .alpha_squares = fold_count,
                .domain_doubles = fold_count,
            });
        }

        pub fn commitFirstLayer(
            allocator: std.mem.Allocator,
            channel: anytype,
            domain: circle_domain.CircleDomain,
            column: secure_column.SecureColumnByCoords,
            fold_step: u32,
        ) !FirstLayerProver {
            var merkle_tree = try commitSecureColumnForFold(
                allocator,
                column,
                fold_step,
            );
            MC.mixRoot(channel, merkle_tree.root());
            return .{
                .domain = domain,
                .column = column,
                .merkle_tree = merkle_tree,
            };
        }

        pub fn commitFirstLayerLazy(
            allocator: std.mem.Allocator,
            channel: anytype,
            domain: circle_domain.CircleDomain,
            provider: *quotient_ops.LazyQuotientProvider,
            fold_step: u32,
            work_audit: ?*ProtocolWorkAudit,
        ) !FirstLayerProver {
            var column = if (comptime @hasDecl(B, "allocateSecureColumn"))
                try B.allocateSecureColumn(provider.domain_size)
            else
                try SecureColumnByCoords.uninitialized(allocator, provider.domain_size);
            errdefer column.deinit(allocator);

            var merkle_tree = if (comptime @hasDecl(B, "commitLazyMerkle")) blk: {
                if (!shouldPack(column.len(), fold_step)) {
                    break :blk try B.commitLazyMerkle(H, allocator, provider, &column);
                }
                if (comptime @hasDecl(B, "computeLazyQuotients")) {
                    try B.computeLazyQuotients(allocator, provider, &column);
                } else {
                    try provider.computeAll(allocator, &column);
                }
                break :blk try commitSecureColumnForFold(
                    allocator,
                    column,
                    fold_step,
                );
            } else blk: {
                if (comptime @hasDecl(B, "computeLazyQuotients")) {
                    try B.computeLazyQuotients(allocator, provider, &column);
                } else {
                    try provider.computeAll(allocator, &column);
                }
                break :blk try commitSecureColumnForFold(
                    allocator,
                    column,
                    fold_step,
                );
            };
            MC.mixRoot(channel, merkle_tree.root());
            if (work_audit) |audit| {
                const used_lazy_merkle = @hasDecl(B, "commitLazyMerkle") and
                    !shouldPack(column.len(), fold_step);
                if (used_lazy_merkle)
                    audit.observeLazyMerkle()
                else
                    audit.observeGenericMerkle();
            }

            return .{
                .domain = domain,
                .column = column,
                .merkle_tree = merkle_tree,
            };
        }

        pub const InnerCommitResult = struct {
            inner_layers: []InnerLayerProver,
            last_layer_evaluation: prover_line.LineEvaluation,
        };

        pub const LazyFriCommitResult = struct {
            first_layer: FirstLayerProver,
            inner_commit: InnerCommitResult,
        };

        pub fn commitInnerLayers(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            first_layer: FirstLayerProver,
            work_audit: ?*ProtocolWorkAudit,
        ) !InnerCommitResult {
            if (config.fold_step == 0 or config.fold_step > first_layer.domain.logSize())
                return core_fri.FriVerificationError.InvalidNumFriLayers;
            const circle_fold_log_size = first_layer.domain.logSize() - 1;
            const circle_fold_domain = try line.LineDomain.init(
                circle.Coset.halfOdds(circle_fold_log_size),
            );
            if (comptime @hasDecl(B, "commitFriCircleLayers")) {
                const fused_result = if (work_audit) |audit| blk: {
                    if (comptime @hasDecl(B, "commitFriCircleLayersWithReceipt")) {
                        break :blk try B.commitFriCircleLayersWithReceipt(
                            H,
                            InnerLayerProver,
                            InnerCommitResult,
                            allocator,
                            first_layer.column,
                            first_layer.domain,
                            circle_fold_domain,
                            channel,
                            config,
                            &audit.fold_executions,
                        );
                    }
                    const result = try B.commitFriCircleLayers(
                        H,
                        InnerLayerProver,
                        InnerCommitResult,
                        allocator,
                        first_layer.column,
                        first_layer.domain,
                        circle_fold_domain,
                        channel,
                        config,
                    );
                    if (result != null) audit.complete = false;
                    break :blk result;
                } else try B.commitFriCircleLayers(
                    H,
                    InnerLayerProver,
                    InnerCommitResult,
                    allocator,
                    first_layer.column,
                    first_layer.domain,
                    circle_fold_domain,
                    channel,
                    config,
                );
                if (fused_result) |result| {
                    if (work_audit) |audit|
                        audit.observeFusedMerkle(result.inner_layers.len);
                    return result;
                }
            }

            var layer_evaluation = if (comptime @hasDecl(B, "allocateLineEvaluation"))
                try B.allocateLineEvaluation(circle_fold_domain)
            else
                try prover_line.LineEvaluation.newZero(allocator, circle_fold_domain);
            errdefer layer_evaluation.deinit(allocator);

            var fold_circle_workspace = try core_fri.FoldCircleWorkspace.init(
                allocator,
                if (lazy_inverse_workspace) 0 else layer_evaluation.len(),
            );
            defer fold_circle_workspace.deinit(allocator);
            const folding_alpha = channel.drawSecureFelt();
            const first_layer_columns = [_][]const M31{
                first_layer.column.columns[0],
                first_layer.column.columns[1],
                first_layer.column.columns[2],
                first_layer.column.columns[3],
            };
            if (work_audit) |audit| {
                if (comptime @hasDecl(B, "foldCircleIntoLineWithReceipt")) {
                    try B.foldCircleIntoLineWithReceipt(
                        allocator,
                        @constCast(layer_evaluation.values),
                        first_layer_columns,
                        first_layer.domain,
                        folding_alpha,
                        &fold_circle_workspace,
                        &audit.fold_executions,
                    );
                } else if (comptime @hasDecl(B, "foldCircleIntoLine")) {
                    try B.foldCircleIntoLine(
                        allocator,
                        @constCast(layer_evaluation.values),
                        first_layer_columns,
                        first_layer.domain,
                        folding_alpha,
                        &fold_circle_workspace,
                    );
                    // An optimized backend without an execution receipt is
                    // not assumed to share the scalar operation schedule.
                    audit.complete = false;
                } else {
                    try core_fri.foldCircleColumnsIntoLineWithWorkspace(
                        allocator,
                        @constCast(layer_evaluation.values),
                        first_layer_columns,
                        first_layer.domain,
                        folding_alpha,
                        &fold_circle_workspace,
                    );
                    observeHostCircleFold(
                        audit,
                        first_layer_columns[0].len,
                        first_layer.domain,
                    );
                }
            } else if (comptime @hasDecl(B, "foldCircleIntoLine")) {
                try B.foldCircleIntoLine(
                    allocator,
                    @constCast(layer_evaluation.values),
                    first_layer_columns,
                    first_layer.domain,
                    folding_alpha,
                    &fold_circle_workspace,
                );
            } else {
                try core_fri.foldCircleColumnsIntoLineWithWorkspace(
                    allocator,
                    @constCast(layer_evaluation.values),
                    first_layer_columns,
                    first_layer.domain,
                    folding_alpha,
                    &fold_circle_workspace,
                );
            }

            if (config.fold_step > 1) {
                var first_line_workspace = try core_fri.FoldLineWorkspace.init(
                    allocator,
                    if (lazy_inverse_workspace) 0 else layer_evaluation.len() / 2,
                );
                defer first_line_workspace.deinit(allocator);
                const first_line_alpha = folding_alpha.square();
                if (comptime @hasDecl(B, "foldLineEvaluationN")) {
                    const folded = if (work_audit) |audit| blk: {
                        if (comptime @hasDecl(B, "foldLineEvaluationNWithReceipt")) {
                            break :blk try B.foldLineEvaluationNWithReceipt(
                                allocator,
                                layer_evaluation,
                                first_line_alpha,
                                &first_line_workspace,
                                config.fold_step - 1,
                                &audit.fold_executions,
                            );
                        }
                        const result = try B.foldLineEvaluationN(
                            allocator,
                            layer_evaluation,
                            first_line_alpha,
                            &first_line_workspace,
                            config.fold_step - 1,
                        );
                        audit.complete = false;
                        break :blk result;
                    } else try B.foldLineEvaluationN(
                        allocator,
                        layer_evaluation,
                        first_line_alpha,
                        &first_line_workspace,
                        config.fold_step - 1,
                    );
                    layer_evaluation.deinit(allocator);
                    layer_evaluation = folded;
                } else {
                    const original_len = layer_evaluation.len();
                    const original_domain = layer_evaluation.domain();
                    const folded = if (work_audit) |audit| blk: {
                        if (comptime @hasDecl(B, "foldLineNWithReceipt")) {
                            break :blk try B.foldLineNWithReceipt(
                                allocator,
                                @constCast(layer_evaluation.values),
                                original_domain,
                                first_line_alpha,
                                &first_line_workspace,
                                config.fold_step - 1,
                                &audit.fold_executions,
                            );
                        }
                        if (comptime @hasDecl(B, "foldLineN")) {
                            const result = try B.foldLineN(
                                allocator,
                                @constCast(layer_evaluation.values),
                                original_domain,
                                first_line_alpha,
                                &first_line_workspace,
                                config.fold_step - 1,
                            );
                            audit.complete = false;
                            break :blk result;
                        }
                        const result = try core_fri.foldLineInPlaceNWithWorkspace(
                            allocator,
                            @constCast(layer_evaluation.values),
                            original_domain,
                            first_line_alpha,
                            &first_line_workspace,
                            config.fold_step - 1,
                        );
                        observeHostLineFolds(
                            audit,
                            original_len,
                            original_domain,
                            config.fold_step - 1,
                        );
                        break :blk result;
                    } else if (comptime @hasDecl(B, "foldLineN"))
                        try B.foldLineN(
                            allocator,
                            @constCast(layer_evaluation.values),
                            original_domain,
                            first_line_alpha,
                            &first_line_workspace,
                            config.fold_step - 1,
                        )
                    else
                        try core_fri.foldLineInPlaceNWithWorkspace(
                            allocator,
                            @constCast(layer_evaluation.values),
                            original_domain,
                            first_line_alpha,
                            &first_line_workspace,
                            config.fold_step - 1,
                        );
                    layer_evaluation.domain_value = folded.domain;
                    layer_evaluation.values = folded.values;
                    layer_evaluation.owns_values = true;
                }
                if (work_audit) |audit| audit.observeAlphaSquare();
            }

            var layers = std.ArrayList(InnerLayerProver).empty;
            defer layers.deinit(allocator);
            errdefer {
                for (layers.items) |*layer| layer.deinit(allocator);
            }
            var fold_workspace = try core_fri.FoldLineWorkspace.init(
                allocator,
                if (lazy_inverse_workspace) 0 else layer_evaluation.len() / 2,
            );
            defer fold_workspace.deinit(allocator);
            const last_layer_log_size = std.math.log2_int(usize, config.lastLayerDomainSize());
            // Existing fused backend transactions commit one coordinate per
            // column. Multi-fold FRI commits packed leaves and must use the
            // protocol-correct generic path until a backend advertises that
            // exact layout explicitly.
            if (config.fold_step == 1 and comptime @hasDecl(B, "commitFriLayers")) {
                const fused_result = if (work_audit) |audit| blk: {
                    if (comptime @hasDecl(B, "commitFriLayersWithReceipt")) {
                        break :blk try B.commitFriLayersWithReceipt(
                            H,
                            InnerLayerProver,
                            InnerCommitResult,
                            allocator,
                            layer_evaluation,
                            channel,
                            &fold_workspace,
                            config,
                            &audit.fold_executions,
                        );
                    }
                    const result = try B.commitFriLayers(
                        H,
                        InnerLayerProver,
                        InnerCommitResult,
                        allocator,
                        layer_evaluation,
                        channel,
                        &fold_workspace,
                        config,
                    );
                    if (result != null) audit.complete = false;
                    break :blk result;
                } else try B.commitFriLayers(
                    H,
                    InnerLayerProver,
                    InnerCommitResult,
                    allocator,
                    layer_evaluation,
                    channel,
                    &fold_workspace,
                    config,
                );
                if (fused_result) |result| {
                    if (work_audit) |audit|
                        audit.observeFusedMerkle(result.inner_layers.len);
                    return result;
                }
            }
            var pending_tree: ?B.MerkleTree(H) = null;
            var pending_column: ?SecureColumnByCoords = null;
            errdefer if (pending_tree) |*tree| tree.deinit(allocator);
            errdefer if (pending_column) |*column| column.deinit(allocator);
            while (layer_evaluation.len() > config.lastLayerDomainSize()) {
                var secure_values = pending_column orelse if (comptime @hasDecl(B, "secureColumnForMerkle"))
                    try B.secureColumnForMerkle(allocator, layer_evaluation)
                else if (comptime @hasDecl(B, "secureColumnFromLine"))
                    try B.secureColumnFromLine(layer_evaluation)
                else
                    try secure_column.SecureColumnByCoords.fromSecureSlice(
                        allocator,
                        layer_evaluation.values,
                    );
                pending_column = null;
                var layer_appended = false;
                errdefer if (!layer_appended) secure_values.deinit(allocator);

                const current_log_size = std.math.log2_int(usize, layer_evaluation.len());
                const remaining_folds = current_log_size - last_layer_log_size;
                const this_fold_step: u32 = @intCast(@min(config.fold_step, remaining_folds));
                const used_pending_fused_tree = pending_tree != null;

                var merkle_tree = pending_tree orelse
                    try commitSecureColumnForFold(
                        allocator,
                        secure_values,
                        this_fold_step,
                    );
                pending_tree = null;
                errdefer if (!layer_appended) merkle_tree.deinit(allocator);

                MC.mixRoot(channel, merkle_tree.root());
                const fold_alpha = channel.drawSecureFelt();

                const layer = InnerLayerProver{
                    .domain = layer_evaluation.domain(),
                    .column = secure_values,
                    .merkle_tree = merkle_tree,
                    .fold_step = this_fold_step,
                };
                try layers.append(allocator, layer);
                layer_appended = true;
                if (work_audit) |audit| {
                    if (used_pending_fused_tree)
                        audit.observeFusedMerkle(1)
                    else
                        audit.observeGenericMerkle();
                }
                if (config.fold_step == 1 and comptime @hasDecl(B, "foldLineAndCommitNext")) {
                    if (remaining_folds > this_fold_step) {
                        const folded = if (work_audit) |audit| blk: {
                            if (comptime @hasDecl(B, "foldLineAndCommitNextWithReceipt")) {
                                break :blk try B.foldLineAndCommitNextWithReceipt(
                                    H,
                                    allocator,
                                    layer_evaluation,
                                    fold_alpha,
                                    &fold_workspace,
                                    this_fold_step,
                                    &audit.fold_executions,
                                );
                            }
                            const result = try B.foldLineAndCommitNext(
                                H,
                                allocator,
                                layer_evaluation,
                                fold_alpha,
                                &fold_workspace,
                                this_fold_step,
                            );
                            audit.complete = false;
                            break :blk result;
                        } else try B.foldLineAndCommitNext(
                            H,
                            allocator,
                            layer_evaluation,
                            fold_alpha,
                            &fold_workspace,
                            this_fold_step,
                        );
                        layer_evaluation.deinit(allocator);
                        layer_evaluation = folded.evaluation;
                        pending_tree = folded.tree;
                        pending_column = folded.column;
                        continue;
                    }
                }
                if (comptime @hasDecl(B, "foldLineEvaluationN")) {
                    const folded_evaluation = if (work_audit) |audit| blk: {
                        if (comptime @hasDecl(B, "foldLineEvaluationNWithReceipt")) {
                            break :blk try B.foldLineEvaluationNWithReceipt(
                                allocator,
                                layer_evaluation,
                                fold_alpha,
                                &fold_workspace,
                                this_fold_step,
                                &audit.fold_executions,
                            );
                        }
                        const result = try B.foldLineEvaluationN(
                            allocator,
                            layer_evaluation,
                            fold_alpha,
                            &fold_workspace,
                            this_fold_step,
                        );
                        audit.complete = false;
                        break :blk result;
                    } else try B.foldLineEvaluationN(
                        allocator,
                        layer_evaluation,
                        fold_alpha,
                        &fold_workspace,
                        this_fold_step,
                    );
                    layer_evaluation.deinit(allocator);
                    layer_evaluation = folded_evaluation;
                } else {
                    const original_len = layer_evaluation.len();
                    const original_domain = layer_evaluation.domain();
                    const folded = if (work_audit) |audit| blk: {
                        if (comptime @hasDecl(B, "foldLineNWithReceipt")) {
                            break :blk try B.foldLineNWithReceipt(
                                allocator,
                                @constCast(layer_evaluation.values),
                                original_domain,
                                fold_alpha,
                                &fold_workspace,
                                this_fold_step,
                                &audit.fold_executions,
                            );
                        }
                        if (comptime @hasDecl(B, "foldLineN")) {
                            const result = try B.foldLineN(
                                allocator,
                                @constCast(layer_evaluation.values),
                                original_domain,
                                fold_alpha,
                                &fold_workspace,
                                this_fold_step,
                            );
                            audit.complete = false;
                            break :blk result;
                        }
                        const result = try core_fri.foldLineInPlaceNWithWorkspace(
                            allocator,
                            @constCast(layer_evaluation.values),
                            original_domain,
                            fold_alpha,
                            &fold_workspace,
                            this_fold_step,
                        );
                        observeHostLineFolds(
                            audit,
                            original_len,
                            original_domain,
                            this_fold_step,
                        );
                        break :blk result;
                    } else if (comptime @hasDecl(B, "foldLineN"))
                        try B.foldLineN(
                            allocator,
                            @constCast(layer_evaluation.values),
                            original_domain,
                            fold_alpha,
                            &fold_workspace,
                            this_fold_step,
                        )
                    else
                        try core_fri.foldLineInPlaceNWithWorkspace(
                            allocator,
                            @constCast(layer_evaluation.values),
                            original_domain,
                            fold_alpha,
                            &fold_workspace,
                            this_fold_step,
                        );
                    layer_evaluation.domain_value = folded.domain;
                    layer_evaluation.values = folded.values;
                    layer_evaluation.owns_values = true;
                }
            }

            return .{
                .inner_layers = try layers.toOwnedSlice(allocator),
                .last_layer_evaluation = layer_evaluation,
            };
        }

        pub fn commitLastLayer(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            evaluation: *prover_line.LineEvaluation,
            work_audit: ?*ProtocolWorkAudit,
        ) (std.mem.Allocator.Error || FriProverError || prover_line.LineEvaluation.Error)!line.LinePoly {
            if (evaluation.len() != config.lastLayerDomainSize()) {
                return FriProverError.InvalidLastLayerSize;
            }

            const interpolation_log_size = evaluation.domain().logSize();
            var poly = try evaluation.interpolate(allocator);
            if (work_audit) |audit| {
                const execution = work_profile.FriLineInterpolationExecution{
                    .log_size = interpolation_log_size,
                };
                execution.validate() catch unreachable;
                // Publish only after interpolation completes, preserving the
                // same failure-atomic boundary without coupling backend
                // contracts to the prover-api receipt schema.
                audit.observeTerminalInterpolation(execution);
            }
            errdefer poly.deinit(allocator);

            const ordered_coeffs = poly.intoOrderedCoefficients();
            const degree_bound = @as(usize, 1) << @intCast(config.log_last_layer_degree_bound);
            if (degree_bound > ordered_coeffs.len) return FriProverError.InvalidLastLayerDegree;
            for (ordered_coeffs[degree_bound..]) |coeff| {
                if (!coeff.isZero()) return FriProverError.InvalidLastLayerDegree;
            }

            const truncated = try allocator.dupe(QM31, ordered_coeffs[0..degree_bound]);
            poly.deinit(allocator);
            var last_layer_poly = line.LinePoly.fromOrderedCoefficients(truncated);
            channel.mixFelts(last_layer_poly.coefficients());
            return last_layer_poly;
        }

        fn commitSecureColumnForFold(
            allocator: std.mem.Allocator,
            column: secure_column.SecureColumnByCoords,
            fold_step: u32,
        ) !B.MerkleTree(H) {
            if (!shouldPack(column.len(), fold_step)) {
                const column_refs = [_][]const M31{
                    column.columns[0],
                    column.columns[1],
                    column.columns[2],
                    column.columns[3],
                };
                return B.commitMerkle(H, allocator, &column_refs);
            }

            var packed_columns = try PackedSecureColumns.init(allocator, column);
            defer packed_columns.deinit(allocator);
            const refs = packed_columns.refs();
            return B.commitMerkle(H, allocator, &refs);
        }
    };
}
