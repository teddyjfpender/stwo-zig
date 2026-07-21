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
const secure_column = @import("secure_column.zig");
const M31 = m31.M31;
const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
pub const FriDecommitError = error{ QueryOutOfRange, FoldStepTooLarge };
pub const FriProverError = error{ NotCanonicDomain, ShapeMismatch, InvalidLastLayerSize, InvalidLastLayerDegree, InvalidColumnSize };
pub const FoldLineAndCommitResult = backend_fri.FoldLineAndCommitResult;
pub const ValueEntry = struct { position: usize, value: QM31 };
pub const DecommitmentPositionsResult = struct {
    decommitment_positions: []usize,
    witness_evals: []QM31,
    value_map: []ValueEntry,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.decommitment_positions);
        allocator.free(self.witness_evals);
        allocator.free(self.value_map);
        self.* = undefined;
    }
};

pub fn LayerDecommitResult(comptime H: type) type {
    return struct {
        decommitment_positions: []usize,
        proof: core_fri.FriLayerProof(H),
        value_map: []ValueEntry,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.decommitment_positions);
            self.proof.deinit(allocator);
            allocator.free(self.value_map);
            self.* = undefined;
        }
    };
}

pub fn FriDecommitResult(comptime H: type) type {
    return struct {
        fri_proof: core_fri.ExtendedFriProof(H),
        query_positions: []usize,
        unsorted_query_locations: []usize,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.fri_proof.deinit(allocator);
            allocator.free(self.query_positions);
            allocator.free(self.unsorted_query_locations);
            self.* = undefined;
        }
    };
}

pub fn FriProver(comptime B: type, comptime H: type, comptime MC: type) type {
    comptime backend_merkle.assertMerkleOps(B, H);
    return struct {
        config: core_fri.FriConfig,
        first_layer: FirstLayerProver,
        inner_layers: []InnerLayerProver,
        last_layer_poly: line.LinePoly,

        const Self = @This();
        const lazy_inverse_workspace = if (@hasDecl(B, "lazyFriFoldInverseWorkspace")) B.lazyFriFoldInverseWorkspace else false;

        pub const FirstLayerProver = struct {
            domain: circle_domain.CircleDomain,
            column: secure_column.SecureColumnByCoords,
            merkle_tree: B.MerkleTree(H),

            pub fn deinit(self: *FirstLayerProver, allocator: std.mem.Allocator) void {
                self.column.deinit(allocator);
                self.merkle_tree.deinit(allocator);
                self.* = undefined;
            }
        };

        pub const InnerLayerProver = struct {
            domain: line.LineDomain,
            column: secure_column.SecureColumnByCoords,
            merkle_tree: B.MerkleTree(H),
            /// Number of folds this layer performs (normally FOLD_STEP, may
            /// be smaller for the last inner layer).
            fold_step: u32 = core_fri.FOLD_STEP,

            pub fn deinit(self: *InnerLayerProver, allocator: std.mem.Allocator) void {
                self.column.deinit(allocator);
                self.merkle_tree.deinit(allocator);
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

            var first_layer = try commitFirstLayer(allocator, channel, column_domain, column);
            errdefer first_layer.deinit(allocator);
            var inner_commit = try commitInnerLayers(allocator, channel, config, first_layer, null);
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
            fold_itwiddles: ?[]const M31,
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
                fold_itwiddles,
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

            var first_layer_proof = try decommitLayerExtended(
                H,
                allocator,
                first_layer.merkle_tree,
                first_layer.column,
                queries.positions,
                self.config.fold_step,
            );
            errdefer first_layer_proof.deinit(allocator);

            var layer_queries = try queries.fold(allocator, self.config.fold_step);
            defer layer_queries.deinit(allocator);

            var inner_layer_proofs = std.ArrayList(core_fri.ExtendedFriLayerProof(H)).empty;
            defer inner_layer_proofs.deinit(allocator);
            errdefer {
                for (inner_layer_proofs.items) |*proof| proof.deinit(allocator);
            }

            for (inner_layers) |layer| {
                var inner_proof = try decommitLayerExtended(
                    H,
                    allocator,
                    layer.merkle_tree,
                    layer.column,
                    layer_queries.positions,
                    layer.fold_step,
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

        fn commitFirstLayer(
            allocator: std.mem.Allocator,
            channel: anytype,
            domain: circle_domain.CircleDomain,
            column: secure_column.SecureColumnByCoords,
        ) !FirstLayerProver {
            const column_refs = [_][]const M31{
                column.columns[0],
                column.columns[1],
                column.columns[2],
                column.columns[3],
            };
            var merkle_tree = try B.commitMerkle(H, allocator, column_refs[0..]);
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
        ) !FirstLayerProver {
            var column = if (comptime @hasDecl(B, "allocateSecureColumn"))
                try B.allocateSecureColumn(provider.domain_size)
            else
                try SecureColumnByCoords.uninitialized(allocator, provider.domain_size);
            errdefer column.deinit(allocator);

            var merkle_tree = if (comptime @hasDecl(B, "commitLazyMerkle"))
                try B.commitLazyMerkle(H, allocator, provider, &column)
            else blk: {
                if (comptime @hasDecl(B, "computeLazyQuotients")) {
                    try B.computeLazyQuotients(allocator, provider, &column);
                } else {
                    try provider.computeAll(allocator, &column);
                }
                const column_refs = [_][]const M31{
                    column.columns[0],
                    column.columns[1],
                    column.columns[2],
                    column.columns[3],
                };
                break :blk try B.commitMerkle(H, allocator, column_refs[0..]);
            };
            MC.mixRoot(channel, merkle_tree.root());

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
            fold_itwiddles: ?[]const M31,
        ) !InnerCommitResult {
            if (config.fold_step == 0 or config.fold_step > first_layer.domain.logSize())
                return core_fri.FriVerificationError.InvalidNumFriLayers;
            const circle_fold_log_size = first_layer.domain.logSize() - 1;
            const circle_fold_domain = try line.LineDomain.init(
                circle.Coset.halfOdds(circle_fold_log_size),
            );
            if (comptime @hasDecl(B, "commitFriCircleLayers")) {
                if (try B.commitFriCircleLayers(
                    H,
                    InnerLayerProver,
                    InnerCommitResult,
                    allocator,
                    first_layer.column,
                    first_layer.domain,
                    circle_fold_domain,
                    channel,
                    config,
                )) |result| return result;
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
            if (comptime @hasDecl(B, "foldCircleIntoLine")) {
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
                if (comptime @hasDecl(B, "foldLineEvaluationN")) {
                    const folded = try B.foldLineEvaluationN(
                        allocator,
                        layer_evaluation,
                        folding_alpha.square(),
                        &first_line_workspace,
                        config.fold_step - 1,
                    );
                    layer_evaluation.deinit(allocator);
                    layer_evaluation = folded;
                } else {
                    const folded = if (comptime @hasDecl(B, "foldLineN"))
                        try B.foldLineN(
                            allocator,
                            @constCast(layer_evaluation.values),
                            layer_evaluation.domain(),
                            folding_alpha.square(),
                            &first_line_workspace,
                            config.fold_step - 1,
                        )
                    else
                        try core_fri.foldLineInPlaceNWithWorkspace(
                            allocator,
                            @constCast(layer_evaluation.values),
                            layer_evaluation.domain(),
                            folding_alpha.square(),
                            &first_line_workspace,
                            config.fold_step - 1,
                        );
                    layer_evaluation.domain_value = folded.domain;
                    layer_evaluation.values = folded.values;
                    layer_evaluation.owns_values = true;
                }
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
            fold_workspace.preset_itwiddles = fold_itwiddles;
            defer fold_workspace.deinit(allocator);
            const last_layer_log_size = std.math.log2_int(usize, config.lastLayerDomainSize());
            if (comptime @hasDecl(B, "commitFriLayers")) {
                if (try B.commitFriLayers(
                    H,
                    InnerLayerProver,
                    InnerCommitResult,
                    allocator,
                    layer_evaluation,
                    channel,
                    &fold_workspace,
                    config,
                )) |result| return result;
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

                const coord_refs = [_][]const M31{
                    secure_values.columns[0],
                    secure_values.columns[1],
                    secure_values.columns[2],
                    secure_values.columns[3],
                };
                var merkle_tree = pending_tree orelse
                    try B.commitMerkle(H, allocator, coord_refs[0..]);
                pending_tree = null;
                errdefer if (!layer_appended) merkle_tree.deinit(allocator);

                MC.mixRoot(channel, merkle_tree.root());
                const fold_alpha = channel.drawSecureFelt();

                const current_log_size = std.math.log2_int(usize, layer_evaluation.len());
                const remaining_folds = current_log_size - last_layer_log_size;
                const this_fold_step: u32 = @intCast(@min(config.fold_step, remaining_folds));

                const layer = InnerLayerProver{
                    .domain = layer_evaluation.domain(),
                    .column = secure_values,
                    .merkle_tree = merkle_tree,
                    .fold_step = this_fold_step,
                };
                try layers.append(allocator, layer);
                layer_appended = true;
                if (comptime @hasDecl(B, "foldLineAndCommitNext")) {
                    if (remaining_folds > this_fold_step) {
                        const folded = try B.foldLineAndCommitNext(
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
                    const folded_evaluation = try B.foldLineEvaluationN(
                        allocator,
                        layer_evaluation,
                        fold_alpha,
                        &fold_workspace,
                        this_fold_step,
                    );
                    layer_evaluation.deinit(allocator);
                    layer_evaluation = folded_evaluation;
                } else {
                    const folded = if (comptime @hasDecl(B, "foldLineN"))
                        try B.foldLineN(
                            allocator,
                            @constCast(layer_evaluation.values),
                            layer_evaluation.domain(),
                            fold_alpha,
                            &fold_workspace,
                            this_fold_step,
                        )
                    else
                        try core_fri.foldLineInPlaceNWithWorkspace(
                            allocator,
                            @constCast(layer_evaluation.values),
                            layer_evaluation.domain(),
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
        ) (std.mem.Allocator.Error || FriProverError || prover_line.LineEvaluation.Error)!line.LinePoly {
            if (evaluation.len() != config.lastLayerDomainSize()) {
                return FriProverError.InvalidLastLayerSize;
            }

            var poly = try evaluation.interpolate(allocator);
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
    };
}

/// Produces an extended FRI layer proof (proof + aux) for one layer decommitment.
pub fn decommitLayerExtended(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: anytype,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) !core_fri.ExtendedFriLayerProof(H) {
    const helper = try computeDecommitmentPositionsAndWitnessEvalsFromCoords(
        allocator,
        column,
        query_positions,
        fold_step,
    );
    errdefer {
        allocator.free(helper.decommitment_positions);
        allocator.free(helper.witness_evals);
        allocator.free(helper.value_map);
    }

    const IndexedValue = core_fri.FriLayerProofAux(H).IndexedValue;
    const indexed_values = try allocator.alloc(IndexedValue, helper.value_map.len);
    errdefer allocator.free(indexed_values);
    for (helper.value_map, 0..) |entry, i| {
        indexed_values[i] = .{
            .index = entry.position,
            .value = entry.value,
        };
    }
    const all_values = try allocator.alloc([]IndexedValue, 1);
    errdefer {
        allocator.free(indexed_values);
        allocator.free(all_values);
    }
    all_values[0] = indexed_values;

    const column_refs = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    const merkle_decommit = try merkle_tree.decommit(
        allocator,
        helper.decommitment_positions,
        column_refs[0..],
    );
    defer {
        for (merkle_decommit.queried_values) |col| allocator.free(col);
        allocator.free(merkle_decommit.queried_values);
    }

    allocator.free(helper.decommitment_positions);
    allocator.free(helper.value_map);
    return .{
        .proof = .{
            .fri_witness = helper.witness_evals,
            .decommitment = merkle_decommit.decommitment.decommitment,
            .commitment = merkle_tree.root(),
        },
        .aux = .{
            .all_values = all_values,
            .decommitment = merkle_decommit.decommitment.aux,
        },
    };
}

/// Returns Merkle decommitment positions and witness evals needed for one FRI layer decommitment.
///
/// `query_positions` are expected in sorted ascending order.
pub fn computeDecommitmentPositionsAndWitnessEvals(
    allocator: std.mem.Allocator,
    column: []const QM31,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!DecommitmentPositionsResult {
    if (fold_step >= @bitSizeOf(usize)) return FriDecommitError.FoldStepTooLarge;

    var decommitment_positions = std.ArrayList(usize).empty;
    defer decommitment_positions.deinit(allocator);
    var witness_evals = std.ArrayList(QM31).empty;
    defer witness_evals.deinit(allocator);
    var value_map = std.ArrayList(ValueEntry).empty;
    defer value_map.deinit(allocator);

    const subset_len = @as(usize, 1) << @intCast(fold_step);

    var subset_start_idx: usize = 0;
    while (subset_start_idx < query_positions.len) {
        const subset_key = query_positions[subset_start_idx] >> @intCast(fold_step);
        var subset_end_idx = subset_start_idx + 1;
        while (subset_end_idx < query_positions.len and
            (query_positions[subset_end_idx] >> @intCast(fold_step)) == subset_key)
        {
            subset_end_idx += 1;
        }

        const subset_queries = query_positions[subset_start_idx..subset_end_idx];
        const subset_start = subset_key << @intCast(fold_step);
        var subset_query_at: usize = 0;

        var position = subset_start;
        while (position < subset_start + subset_len) : (position += 1) {
            if (position >= column.len) return FriDecommitError.QueryOutOfRange;

            try decommitment_positions.append(allocator, position);
            const eval = column[position];
            try value_map.append(allocator, .{
                .position = position,
                .value = eval,
            });

            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(allocator, eval);
            }
        }

        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(allocator),
        .witness_evals = try witness_evals.toOwnedSlice(allocator),
        .value_map = try value_map.toOwnedSlice(allocator),
    };
}

fn computeDecommitmentPositionsAndWitnessEvalsFromCoords(
    allocator: std.mem.Allocator,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!DecommitmentPositionsResult {
    if (fold_step >= @bitSizeOf(usize)) return FriDecommitError.FoldStepTooLarge;

    var decommitment_positions = std.ArrayList(usize).empty;
    defer decommitment_positions.deinit(allocator);
    var witness_evals = std.ArrayList(QM31).empty;
    defer witness_evals.deinit(allocator);
    var value_map = std.ArrayList(ValueEntry).empty;
    defer value_map.deinit(allocator);

    const subset_len = @as(usize, 1) << @intCast(fold_step);
    var subset_start_idx: usize = 0;
    while (subset_start_idx < query_positions.len) {
        const subset_key = query_positions[subset_start_idx] >> @intCast(fold_step);
        var subset_end_idx = subset_start_idx + 1;
        while (subset_end_idx < query_positions.len and
            (query_positions[subset_end_idx] >> @intCast(fold_step)) == subset_key)
        {
            subset_end_idx += 1;
        }

        const subset_queries = query_positions[subset_start_idx..subset_end_idx];
        const subset_start = subset_key << @intCast(fold_step);
        var subset_query_at: usize = 0;
        for (subset_start..subset_start + subset_len) |position| {
            if (position >= column.len()) return FriDecommitError.QueryOutOfRange;
            const eval = column.at(position);
            try decommitment_positions.append(allocator, position);
            try value_map.append(allocator, .{ .position = position, .value = eval });
            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(allocator, eval);
            }
        }
        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(allocator),
        .witness_evals = try witness_evals.toOwnedSlice(allocator),
        .value_map = try value_map.toOwnedSlice(allocator),
    };
}

/// Produces a FRI layer decommitment proof for `query_positions`.
pub fn decommitLayer(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: anytype,
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) !LayerDecommitResult(H) {
    const helper = try computeDecommitmentPositionsAndWitnessEvalsFromCoords(
        allocator,
        column,
        query_positions,
        fold_step,
    );
    errdefer {
        allocator.free(helper.decommitment_positions);
        allocator.free(helper.witness_evals);
        allocator.free(helper.value_map);
    }

    const column_refs = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle_decommit = try merkle_tree.decommit(
        allocator,
        helper.decommitment_positions,
        column_refs[0..],
    );
    defer {
        for (merkle_decommit.queried_values) |col| allocator.free(col);
        allocator.free(merkle_decommit.queried_values);
        merkle_decommit.decommitment.aux.deinit(allocator);
    }

    return .{
        .decommitment_positions = helper.decommitment_positions,
        .proof = .{
            .fri_witness = helper.witness_evals,
            .decommitment = merkle_decommit.decommitment.decommitment,
            .commitment = merkle_tree.root(),
        },
        .value_map = helper.value_map,
    };
}
