const std = @import("std");
const circle = @import("circle.zig");
const fft = @import("fft.zig");
const fields = @import("fields/mod.zig");
const m31 = @import("fields/m31.zig");
const qm31 = @import("fields/qm31.zig");
const line = @import("poly/line.zig");
const canonic = @import("poly/circle/canonic.zig");
const circle_domain = @import("poly/circle/domain.zig");
const queries_mod = @import("queries.zig");
const core_utils = @import("utils.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const buildMerkleVerificationInputs = merkle_queries.build;
const findSubsetIndex = merkle_queries.findSubsetIndex;
const findPosition = merkle_queries.findPosition;

const config_mod = @import("fri/config.zig");
const folding = @import("fri/folding.zig");
const merkle_queries = @import("fri/merkle_queries.zig");
const query_capture = @import("fri/query_capture.zig");

pub const geometry = @import("fri/geometry.zig");

pub const FriConfig = config_mod.FriConfig;
pub const FOLD_STEP = config_mod.FOLD_STEP;
pub const CIRCLE_TO_LINE_FOLD_STEP = config_mod.CIRCLE_TO_LINE_FOLD_STEP;
pub const LOG_PACKED_LEAF_SIZE = config_mod.LOG_PACKED_LEAF_SIZE;
pub const FriVerificationError = config_mod.FriVerificationError;
pub const CirclePolyDegreeBound = config_mod.CirclePolyDegreeBound;
pub const LinePolyDegreeBound = config_mod.LinePolyDegreeBound;

pub const SparseEvaluation = folding.SparseEvaluation;
pub const ComputeDecommitmentResult = folding.ComputeDecommitmentResult;

pub const SampledQueryPositions = query_capture.SampledQueryPositions;
pub const FriLayerQueryCapture = query_capture.FriLayerQueryCapture;
pub const FriQueryCapture = query_capture.FriQueryCapture;

pub fn FriVerifier(comptime H: type, comptime MC: type) type {
    return struct {
        config: FriConfig,
        first_layer: FriFirstLayerVerifier(H),
        inner_layers: []FriInnerLayerVerifier(H),
        last_layer_domain: line.LineDomain,
        last_layer_poly: line.LinePoly,
        queries: ?queries_mod.Queries = null,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.first_layer.deinit(allocator);
            for (self.inner_layers) |*layer| layer.deinit(allocator);
            allocator.free(self.inner_layers);
            self.last_layer_poly.deinit(allocator);
            if (self.queries) |*queries| queries.deinit(allocator);
            self.* = undefined;
        }

        pub fn commit(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: FriConfig,
            proof_in: FriProof(H),
            column_bound: CirclePolyDegreeBound,
        ) (std.mem.Allocator.Error || FriVerificationError)!Self {
            MC.mixRoot(channel, proof_in.first_layer.commitment);

            const column_commitment_domain = canonic.CanonicCoset
                .new(column_bound.logDegreeBound() + config.log_blowup_factor)
                .circleDomain();
            var first_layer = FriFirstLayerVerifier(H){
                .column_commitment_domain = column_commitment_domain,
                .folding_alpha = channel.drawSecureFelt(),
                .proof = try cloneLayerProof(H, allocator, proof_in.first_layer),
                .pack_leaves = column_commitment_domain.logSize() >= LOG_PACKED_LEAF_SIZE and
                    config.fold_step > 1,
            };
            errdefer first_layer.deinit(allocator);

            var layer_bound = column_bound.foldToLineWithStep(config.fold_step);
            var layer_domain = line.LineDomain.init(
                circle.Coset.halfOdds(layer_bound.logDegreeBound() + config.log_blowup_factor),
            ) catch return FriVerificationError.InvalidNumFriLayers;

            const inner_layers = try allocator.alloc(FriInnerLayerVerifier(H), proof_in.inner_layers.len);
            errdefer allocator.free(inner_layers);
            var initialized: usize = 0;
            errdefer {
                for (inner_layers[0..initialized]) |*layer| layer.deinit(allocator);
            }

            for (proof_in.inner_layers, 0..) |inner_proof, i| {
                MC.mixRoot(channel, inner_proof.commitment);

                // Determine fold count: normally FOLD_STEP, clamped to the
                // remaining degree so we don't overshoot.
                const remaining = layer_bound.logDegreeBound() - config.log_last_layer_degree_bound;
                const this_fold_step: u32 = @min(config.fold_step, remaining);

                inner_layers[i] = .{
                    .domain = layer_domain,
                    .folding_alpha = channel.drawSecureFelt(),
                    .layer_index = i,
                    .proof = try cloneLayerProof(H, allocator, inner_proof),
                    .fold_step = this_fold_step,
                    .pack_leaves = layer_domain.logSize() >= LOG_PACKED_LEAF_SIZE and
                        this_fold_step > 1,
                };
                initialized += 1;

                layer_bound = layer_bound.fold(this_fold_step) orelse return FriVerificationError.InvalidNumFriLayers;
                // Advance domain by this_fold_step halvings.
                {
                    var step: u32 = 0;
                    while (step < this_fold_step) : (step += 1) {
                        layer_domain = layer_domain.double();
                    }
                }
            }

            if (layer_bound.logDegreeBound() != config.log_last_layer_degree_bound) {
                return FriVerificationError.InvalidNumFriLayers;
            }
            var last_layer_poly = line.LinePoly.initOwned(
                try allocator.dupe(QM31, proof_in.last_layer_poly.coefficients()),
            );
            errdefer last_layer_poly.deinit(allocator);
            if (last_layer_poly.len() > (@as(usize, 1) << @intCast(config.log_last_layer_degree_bound))) {
                return FriVerificationError.LastLayerDegreeInvalid;
            }

            channel.mixFelts(last_layer_poly.coefficients());

            return .{
                .config = config,
                .first_layer = first_layer,
                .inner_layers = inner_layers,
                .last_layer_domain = layer_domain,
                .last_layer_poly = last_layer_poly,
                .queries = null,
            };
        }

        pub fn sampleQueryPositions(
            self: *Self,
            allocator: std.mem.Allocator,
            channel: anytype,
        ) ![]usize {
            const sampled = try self.sampleQueryPositionsWithRaw(
                allocator,
                channel,
            );
            allocator.free(sampled.raw);
            return sampled.unique;
        }

        /// Samples once and retains the exact raw draw alongside the unique
        /// Merkle-verifier set. Publication is failure-atomic: neither slice
        /// escapes unless query normalization and the returned duplicate both
        /// succeed.
        pub fn sampleQueryPositionsWithRaw(
            self: *Self,
            allocator: std.mem.Allocator,
            channel: anytype,
        ) !SampledQueryPositions {
            const first_layer_log_size = self.first_layer.column_commitment_domain.logSize();
            const raw = try queries_mod.drawQueries(
                channel,
                allocator,
                first_layer_log_size,
                self.config.n_queries,
            );
            errdefer allocator.free(raw);

            if (self.queries) |*queries| queries.deinit(allocator);
            self.queries = try queries_mod.Queries.init(
                allocator,
                raw,
                first_layer_log_size,
            );
            return .{
                .raw = raw,
                .unique = try allocator.dupe(usize, self.queries.?.positions),
            };
        }

        pub fn decommit(
            self: *Self,
            allocator: std.mem.Allocator,
            first_layer_query_evals: []const QM31,
        ) !void {
            return self.decommitImpl(
                allocator,
                first_layer_query_evals,
                null,
                null,
            );
        }

        /// Completes FRI verification and publishes raw-query values and full
        /// authentication paths only after the terminal polynomial check.
        pub fn decommitWithQueryCapture(
            self: *Self,
            allocator: std.mem.Allocator,
            first_layer_query_evals: []const QM31,
            raw_query_positions: []const usize,
            capture: *FriQueryCapture(H),
        ) !void {
            return self.decommitImpl(
                allocator,
                first_layer_query_evals,
                raw_query_positions,
                capture,
            );
        }

        fn decommitImpl(
            self: *Self,
            allocator: std.mem.Allocator,
            first_layer_query_evals: []const QM31,
            raw_query_positions: ?[]const usize,
            capture_out: ?*FriQueryCapture(H),
        ) !void {
            if ((raw_query_positions == null) != (capture_out == null))
                return FriVerificationError.FirstLayerEvaluationsInvalid;
            const queries = self.queries orelse return FriVerificationError.FirstLayerEvaluationsInvalid;
            const capture_layers = if (capture_out != null)
                try allocator.alloc(
                    FriLayerQueryCapture(H),
                    1 + self.inner_layers.len,
                )
            else
                null;
            var initialized_layers: usize = 0;
            errdefer if (capture_layers) |layers| {
                for (layers[0..initialized_layers]) |*layer| layer.deinit(allocator);
                allocator.free(layers);
            };

            const raw_positions = if (raw_query_positions) |positions|
                try allocator.dupe(usize, positions)
            else
                null;
            defer if (raw_positions) |positions| allocator.free(positions);

            var first_layer_capture: FriLayerQueryCapture(H) = undefined;
            var first_layer_sparse_eval = try self.first_layer.verifyImpl(
                allocator,
                queries,
                first_layer_query_evals,
                self.config.fold_step,
                raw_positions,
                if (capture_out != null) &first_layer_capture else null,
            );
            defer first_layer_sparse_eval.deinit(allocator);
            if (capture_layers) |layers| {
                layers[0] = first_layer_capture;
                initialized_layers = 1;
            }

            var layer_queries = try queries.fold(allocator, self.config.fold_step);
            defer layer_queries.deinit(allocator);
            var layer_query_evals = try first_layer_sparse_eval.foldCircleSubsets(
                allocator,
                self.first_layer.folding_alpha,
                self.first_layer.column_commitment_domain,
                self.config.fold_step,
            );
            defer allocator.free(layer_query_evals);

            if (raw_positions) |positions| {
                for (positions) |*position| position.* >>= @intCast(self.config.fold_step);
            }

            for (self.inner_layers, 0..) |layer, layer_index| {
                var layer_capture: FriLayerQueryCapture(H) = undefined;
                const folded = try layer.verifyAndFoldImpl(
                    allocator,
                    layer_queries,
                    layer_query_evals,
                    raw_positions,
                    if (capture_out != null) &layer_capture else null,
                );
                if (capture_layers) |layers| {
                    layers[layer_index + 1] = layer_capture;
                    initialized_layers += 1;
                }

                layer_queries.deinit(allocator);
                allocator.free(layer_query_evals);
                layer_queries = folded.queries;
                layer_query_evals = folded.evals;

                if (raw_positions) |positions| {
                    for (positions) |*position| position.* >>= @intCast(layer.fold_step);
                }
            }

            try self.decommitLastLayer(allocator, layer_queries, layer_query_evals);
            if (capture_out) |destination| {
                destination.* = .{ .layers = capture_layers.? };
            }
        }

        fn decommitLastLayer(
            self: Self,
            allocator: std.mem.Allocator,
            queries: queries_mod.Queries,
            query_evals: []const QM31,
        ) !void {
            if (queries.positions.len != query_evals.len) {
                return FriVerificationError.LastLayerEvaluationsInvalid;
            }

            for (queries.positions, query_evals) |query, query_eval| {
                const x = self.last_layer_domain.at(core_utils.bitReverseIndex(
                    query,
                    self.last_layer_domain.logSize(),
                ));
                const expected = try self.last_layer_poly.evalAtPoint(allocator, QM31.fromBase(x));
                if (!query_eval.eql(expected)) {
                    return FriVerificationError.LastLayerEvaluationsInvalid;
                }
            }
        }
    };
}

fn cloneLayerProof(
    comptime H: type,
    allocator: std.mem.Allocator,
    proof: FriLayerProof(H),
) !FriLayerProof(H) {
    const fri_witness = try allocator.dupe(QM31, proof.fri_witness);
    errdefer allocator.free(fri_witness);

    return .{
        .fri_witness = fri_witness,
        .decommitment = .{
            .hash_witness = try allocator.dupe(H.Hash, proof.decommitment.hash_witness),
        },
        .commitment = proof.commitment,
    };
}

pub fn FriLayerProof(comptime H: type) type {
    return struct {
        fri_witness: []QM31,
        decommitment: vcs_verifier.MerkleDecommitmentLifted(H),
        commitment: H.Hash,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.fri_witness);
            self.decommitment.deinit(allocator);
            self.* = undefined;
        }
    };
}

fn FriFirstLayerVerifier(comptime H: type) type {
    return struct {
        column_commitment_domain: circle_domain.CircleDomain,
        folding_alpha: QM31,
        proof: FriLayerProof(H),
        pack_leaves: bool,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        fn verify(
            self: Self,
            allocator: std.mem.Allocator,
            queries: queries_mod.Queries,
            column_query_evals: []const QM31,
            fold_step: u32,
        ) !SparseEvaluation {
            return self.verifyImpl(
                allocator,
                queries,
                column_query_evals,
                fold_step,
                null,
                null,
            );
        }

        fn verifyImpl(
            self: Self,
            allocator: std.mem.Allocator,
            queries: queries_mod.Queries,
            column_query_evals: []const QM31,
            fold_step: u32,
            raw_query_positions: ?[]const usize,
            capture_out: ?*FriLayerQueryCapture(H),
        ) !SparseEvaluation {
            if ((raw_query_positions == null) != (capture_out == null))
                return FriVerificationError.FirstLayerEvaluationsInvalid;
            if (queries.log_domain_size != self.column_commitment_domain.logSize()) {
                return FriVerificationError.FirstLayerEvaluationsInvalid;
            }

            var rebuilt = computeDecommitmentPositionsAndRebuildEvals(
                allocator,
                queries,
                column_query_evals,
                self.proof.fri_witness,
                fold_step,
            ) catch return FriVerificationError.FirstLayerEvaluationsInvalid;
            errdefer rebuilt.deinit(allocator);

            if (rebuilt.consumed_witness != self.proof.fri_witness.len) {
                return FriVerificationError.FirstLayerEvaluationsInvalid;
            }

            const leaf_log_size: u32 = if (self.pack_leaves) LOG_PACKED_LEAF_SIZE else 0;
            var merkle_inputs = try buildMerkleVerificationInputs(
                allocator,
                rebuilt.decommitment_positions,
                rebuilt.sparse_evaluation,
                leaf_log_size,
            );
            defer merkle_inputs.deinit(allocator);
            const repeated_sizes = try allocator.alloc(u32, merkle_inputs.columns.len);
            defer allocator.free(repeated_sizes);
            @memset(repeated_sizes, self.column_commitment_domain.logSize() - leaf_log_size);
            var merkle_verifier = try vcs_verifier.MerkleVerifierLifted(H).init(
                allocator,
                self.proof.commitment,
                repeated_sizes,
            );
            defer merkle_verifier.deinit(allocator);

            if (capture_out) |destination| {
                var merkle_capture: vcs_verifier.MerklePathCapture(H) = undefined;
                merkle_verifier.verifyWithPathCapture(
                    allocator,
                    merkle_inputs.positions,
                    merkle_inputs.columns,
                    self.proof.decommitment,
                    &merkle_capture,
                ) catch return FriVerificationError.FirstLayerCommitmentInvalid;
                defer merkle_capture.deinit(allocator);

                destination.* = try buildFriLayerQueryCapture(
                    H,
                    allocator,
                    self.proof.commitment,
                    self.folding_alpha,
                    self.column_commitment_domain.logSize(),
                    fold_step,
                    leaf_log_size,
                    raw_query_positions.?,
                    rebuilt.decommitment_positions,
                    rebuilt.sparse_evaluation,
                    merkle_capture,
                );
            } else {
                merkle_verifier.verify(
                    allocator,
                    merkle_inputs.positions,
                    merkle_inputs.columns,
                    self.proof.decommitment,
                ) catch return FriVerificationError.FirstLayerCommitmentInvalid;
            }

            allocator.free(rebuilt.decommitment_positions);
            return rebuilt.sparse_evaluation;
        }
    };
}

fn FriInnerLayerVerifier(comptime H: type) type {
    return struct {
        domain: line.LineDomain,
        folding_alpha: QM31,
        layer_index: usize,
        proof: FriLayerProof(H),
        /// Number of folds this layer performs (normally FOLD_STEP, may be
        /// smaller for the last inner layer when the remaining degree is not
        /// evenly divisible by FOLD_STEP).
        fold_step: u32 = FOLD_STEP,
        pack_leaves: bool,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        fn verifyAndFold(
            self: Self,
            allocator: std.mem.Allocator,
            queries: queries_mod.Queries,
            evals_at_queries: []const QM31,
        ) !FoldedLayerState {
            return self.verifyAndFoldImpl(
                allocator,
                queries,
                evals_at_queries,
                null,
                null,
            );
        }

        fn verifyAndFoldImpl(
            self: Self,
            allocator: std.mem.Allocator,
            queries: queries_mod.Queries,
            evals_at_queries: []const QM31,
            raw_query_positions: ?[]const usize,
            capture_out: ?*FriLayerQueryCapture(H),
        ) !FoldedLayerState {
            if ((raw_query_positions == null) != (capture_out == null))
                return FriVerificationError.InnerLayerEvaluationsInvalid;
            if (queries.log_domain_size != self.domain.logSize()) {
                return FriVerificationError.InnerLayerEvaluationsInvalid;
            }

            var rebuilt = computeDecommitmentPositionsAndRebuildEvals(
                allocator,
                queries,
                evals_at_queries,
                self.proof.fri_witness,
                self.fold_step,
            ) catch return FriVerificationError.InnerLayerEvaluationsInvalid;
            errdefer rebuilt.deinit(allocator);

            if (rebuilt.consumed_witness != self.proof.fri_witness.len) {
                return FriVerificationError.InnerLayerEvaluationsInvalid;
            }

            const leaf_log_size: u32 = if (self.pack_leaves) LOG_PACKED_LEAF_SIZE else 0;
            var merkle_inputs = try buildMerkleVerificationInputs(
                allocator,
                rebuilt.decommitment_positions,
                rebuilt.sparse_evaluation,
                leaf_log_size,
            );
            defer merkle_inputs.deinit(allocator);
            const repeated_sizes = try allocator.alloc(u32, merkle_inputs.columns.len);
            defer allocator.free(repeated_sizes);
            @memset(repeated_sizes, self.domain.logSize() - leaf_log_size);
            var merkle_verifier = try vcs_verifier.MerkleVerifierLifted(H).init(
                allocator,
                self.proof.commitment,
                repeated_sizes,
            );
            defer merkle_verifier.deinit(allocator);

            if (capture_out) |destination| {
                var merkle_capture: vcs_verifier.MerklePathCapture(H) = undefined;
                merkle_verifier.verifyWithPathCapture(
                    allocator,
                    merkle_inputs.positions,
                    merkle_inputs.columns,
                    self.proof.decommitment,
                    &merkle_capture,
                ) catch return FriVerificationError.InnerLayerCommitmentInvalid;
                defer merkle_capture.deinit(allocator);

                destination.* = try buildFriLayerQueryCapture(
                    H,
                    allocator,
                    self.proof.commitment,
                    self.folding_alpha,
                    self.domain.logSize(),
                    self.fold_step,
                    leaf_log_size,
                    raw_query_positions.?,
                    rebuilt.decommitment_positions,
                    rebuilt.sparse_evaluation,
                    merkle_capture,
                );
            } else {
                merkle_verifier.verify(
                    allocator,
                    merkle_inputs.positions,
                    merkle_inputs.columns,
                    self.proof.decommitment,
                ) catch return FriVerificationError.InnerLayerCommitmentInvalid;
            }

            var folded_queries = try queries.fold(allocator, self.fold_step);
            errdefer folded_queries.deinit(allocator);
            const folded_evals = try rebuilt.sparse_evaluation.foldLineSubsetsN(
                allocator,
                self.folding_alpha,
                self.domain,
                self.fold_step,
            );

            allocator.free(rebuilt.decommitment_positions);
            rebuilt.sparse_evaluation.deinit(allocator);
            return .{
                .queries = folded_queries,
                .evals = folded_evals,
            };
        }
    };
}

const FoldedLayerState = struct {
    queries: queries_mod.Queries,
    evals: []QM31,

    fn deinit(self: *FoldedLayerState, allocator: std.mem.Allocator) void {
        self.queries.deinit(allocator);
        allocator.free(self.evals);
        self.* = undefined;
    }
};

fn buildFriLayerQueryCapture(
    comptime H: type,
    allocator: std.mem.Allocator,
    commitment: H.Hash,
    folding_alpha: QM31,
    evaluation_log_size: u32,
    fold_step: u32,
    leaf_log_size: u32,
    raw_query_positions: []const usize,
    decommitment_positions: []const usize,
    sparse: SparseEvaluation,
    merkle_capture: vcs_verifier.MerklePathCapture(H),
) !FriLayerQueryCapture(H) {
    if (fold_step == 0 or fold_step >= @bitSizeOf(usize) or
        leaf_log_size > fold_step or leaf_log_size >= @bitSizeOf(usize))
    {
        return error.ShapeMismatch;
    }
    const fold_width: usize = @as(usize, 1) << @intCast(fold_step);
    const leaf_width: usize = @as(usize, 1) << @intCast(leaf_log_size);
    const authenticated_subtree_height = fold_step - leaf_log_size;
    if (merkle_capture.path_depth < authenticated_subtree_height)
        return error.ShapeMismatch;
    const authentication_path_depth =
        merkle_capture.path_depth - authenticated_subtree_height;
    const subset_count = sparse.subset_evals.len;
    if (subset_count != sparse.subset_domain_initial_indexes.len or
        decommitment_positions.len != subset_count * fold_width or
        merkle_capture.positions.len != decommitment_positions.len / leaf_width)
    {
        return error.ShapeMismatch;
    }
    for (sparse.subset_evals) |subset| {
        if (subset.len != fold_width) return error.ShapeMismatch;
    }

    const captured_positions = try allocator.dupe(usize, raw_query_positions);
    errdefer allocator.free(captured_positions);
    const captured_values = try allocator.alloc(
        QM31,
        raw_query_positions.len * fold_width,
    );
    errdefer allocator.free(captured_values);
    var capture = FriLayerQueryCapture(H){
        .commitment = commitment,
        .folding_alpha = folding_alpha,
        .fold_step = fold_step,
        .fold_width = @intCast(fold_width),
        .path_depth = authentication_path_depth,
        .query_count = raw_query_positions.len,
        .positions = captured_positions,
        .values = captured_values,
        .siblings = undefined,
    };
    capture.siblings = try allocator.alloc(
        H.Hash,
        raw_query_positions.len * @as(usize, @intCast(capture.path_depth)),
    );
    errdefer allocator.free(capture.siblings);

    for (raw_query_positions, 0..) |position, raw_index| {
        const subset_start = (position >> @intCast(fold_step)) << @intCast(fold_step);
        const subset_index = findSubsetIndex(
            decommitment_positions,
            fold_width,
            subset_start,
        ) orelse return error.ShapeMismatch;
        @memcpy(
            capture.values[raw_index * fold_width ..][0..fold_width],
            sparse.subset_evals[subset_index],
        );

        const leaf_position = subset_start >> @intCast(leaf_log_size);
        const merkle_index = findPosition(
            merkle_capture.positions,
            leaf_position,
        ) orelse return error.ShapeMismatch;
        const source_path = merkle_capture.path(merkle_index)[authenticated_subtree_height..];
        const path_depth: usize = @intCast(capture.path_depth);
        @memcpy(
            capture.siblings[raw_index * path_depth ..][0..path_depth],
            source_path,
        );
    }

    const expected_path_depth = evaluation_log_size - fold_step;
    if (capture.path_depth != expected_path_depth) return error.ShapeMismatch;
    return capture;
}

pub fn FriLayerProofAux(comptime H: type) type {
    return struct {
        all_values: [][]IndexedValue,
        decommitment: vcs_verifier.MerkleDecommitmentLiftedAux(H),

        pub const IndexedValue = struct {
            index: usize,
            value: QM31,
        };

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.all_values) |layer_values| allocator.free(layer_values);
            allocator.free(self.all_values);
            self.decommitment.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn ExtendedFriLayerProof(comptime H: type) type {
    return struct {
        proof: FriLayerProof(H),
        aux: FriLayerProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn FriProof(comptime H: type) type {
    return struct {
        first_layer: FriLayerProof(H),
        inner_layers: []FriLayerProof(H),
        last_layer_poly: line.LinePoly,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.first_layer.deinit(allocator);
            for (self.inner_layers) |*layer_proof| layer_proof.deinit(allocator);
            allocator.free(self.inner_layers);
            self.last_layer_poly.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn FriProofAux(comptime H: type) type {
    return struct {
        first_layer: FriLayerProofAux(H),
        inner_layers: []FriLayerProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.first_layer.deinit(allocator);
            for (self.inner_layers) |*layer_aux| layer_aux.deinit(allocator);
            allocator.free(self.inner_layers);
            self.* = undefined;
        }
    };
}

pub fn ExtendedFriProof(comptime H: type) type {
    return struct {
        proof: FriProof(H),
        aux: FriProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub const computeDecommitmentPositionsAndRebuildEvals = folding.computeDecommitmentPositionsAndRebuildEvals;
pub const FoldLineResult = folding.FoldLineResult;
pub const FoldLineWorkspace = folding.FoldLineWorkspace;
pub const FoldCircleWorkspace = folding.FoldCircleWorkspace;
pub const foldLine = folding.foldLine;
pub const foldLineSingleStep = folding.foldLineSingleStep;
pub const foldLineNWithWorkspace = folding.foldLineNWithWorkspace;
pub const foldLineWithWorkspace = folding.foldLineWithWorkspace;
pub const foldLineInPlaceNWithWorkspace = folding.foldLineInPlaceNWithWorkspace;
pub const foldLineInPlaceWithWorkspace = folding.foldLineInPlaceWithWorkspace;
pub const foldCircleIntoLine = folding.foldCircleIntoLine;
pub const foldCircleIntoLineWithWorkspace = folding.foldCircleIntoLineWithWorkspace;
pub const foldCircleColumnsIntoLineWithWorkspace = folding.foldCircleColumnsIntoLineWithWorkspace;
pub const accumulateLine = folding.accumulateLine;
