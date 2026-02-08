const std = @import("std");
const circle = @import("circle.zig");
const fft = @import("fft.zig");
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

/// FRI proof configuration.
pub const FriConfig = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,

    pub const Error = error{
        InvalidLastLayerDegreeBound,
        InvalidBlowupFactor,
    };

    pub const LOG_MIN_LAST_LAYER_DEGREE_BOUND: u32 = 0;
    pub const LOG_MAX_LAST_LAYER_DEGREE_BOUND: u32 = 10;
    pub const LOG_MIN_BLOWUP_FACTOR: u32 = 1;
    pub const LOG_MAX_BLOWUP_FACTOR: u32 = 16;

    pub fn init(
        log_last_layer_degree_bound: u32,
        log_blowup_factor: u32,
        n_queries: usize,
    ) Error!FriConfig {
        if (log_last_layer_degree_bound < LOG_MIN_LAST_LAYER_DEGREE_BOUND or
            log_last_layer_degree_bound > LOG_MAX_LAST_LAYER_DEGREE_BOUND)
        {
            return Error.InvalidLastLayerDegreeBound;
        }
        if (log_blowup_factor < LOG_MIN_BLOWUP_FACTOR or
            log_blowup_factor > LOG_MAX_BLOWUP_FACTOR)
        {
            return Error.InvalidBlowupFactor;
        }
        return .{
            .log_blowup_factor = log_blowup_factor,
            .log_last_layer_degree_bound = log_last_layer_degree_bound,
            .n_queries = n_queries,
        };
    }

    pub inline fn lastLayerDomainSize(self: FriConfig) usize {
        return @as(usize, 1) << @intCast(self.log_last_layer_degree_bound + self.log_blowup_factor);
    }

    pub inline fn securityBits(self: FriConfig) u32 {
        return self.log_blowup_factor * @as(u32, @intCast(self.n_queries));
    }

    pub fn default() FriConfig {
        return FriConfig.init(0, 1, 3) catch unreachable;
    }
};

/// Number of folds for univariate polynomials.
pub const FOLD_STEP: u32 = 1;

/// Number of folds when reducing circle to line polynomial.
pub const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;

pub const FriVerificationError = error{
    InvalidNumFriLayers,
    FirstLayerEvaluationsInvalid,
    FirstLayerCommitmentInvalid,
    InnerLayerCommitmentInvalid,
    InnerLayerEvaluationsInvalid,
    LastLayerDegreeInvalid,
    LastLayerEvaluationsInvalid,
};

pub const CirclePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub inline fn init(log_degree_bound: u32) CirclePolyDegreeBound {
        return .{ .log_degree_bound = log_degree_bound };
    }

    pub inline fn logDegreeBound(self: CirclePolyDegreeBound) u32 {
        return self.log_degree_bound;
    }

    pub inline fn foldToLine(self: CirclePolyDegreeBound) LinePolyDegreeBound {
        return .{ .log_degree_bound = self.log_degree_bound - CIRCLE_TO_LINE_FOLD_STEP };
    }
};

pub const LinePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub inline fn logDegreeBound(self: LinePolyDegreeBound) u32 {
        return self.log_degree_bound;
    }

    pub fn fold(self: LinePolyDegreeBound, n_folds: u32) ?LinePolyDegreeBound {
        if (self.log_degree_bound < n_folds) return null;
        return .{ .log_degree_bound = self.log_degree_bound - n_folds };
    }
};

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
            var proof = proof_in;
            defer allocator.free(proof.inner_layers);
            errdefer proof.last_layer_poly.deinit(allocator);

            MC.mixRoot(channel, proof.first_layer.commitment);

            const column_commitment_domain = canonic.CanonicCoset
                .new(column_bound.logDegreeBound() + config.log_blowup_factor)
                .circleDomain();
            var first_layer = FriFirstLayerVerifier(H){
                .column_commitment_domain = column_commitment_domain,
                .folding_alpha = channel.drawSecureFelt(),
                .proof = proof.first_layer,
            };
            errdefer first_layer.deinit(allocator);

            var layer_bound = column_bound.foldToLine();
            var layer_domain = line.LineDomain.init(
                circle.Coset.halfOdds(layer_bound.logDegreeBound() + config.log_blowup_factor),
            ) catch return FriVerificationError.InvalidNumFriLayers;

            const inner_layers = try allocator.alloc(FriInnerLayerVerifier(H), proof.inner_layers.len);
            errdefer allocator.free(inner_layers);
            var initialized: usize = 0;
            errdefer {
                for (inner_layers[0..initialized]) |*layer| layer.deinit(allocator);
            }

            for (proof.inner_layers, 0..) |inner_proof, i| {
                MC.mixRoot(channel, inner_proof.commitment);
                inner_layers[i] = .{
                    .domain = layer_domain,
                    .folding_alpha = channel.drawSecureFelt(),
                    .layer_index = i,
                    .proof = inner_proof,
                };
                initialized += 1;

                layer_bound = layer_bound.fold(FOLD_STEP) orelse return FriVerificationError.InvalidNumFriLayers;
                layer_domain = layer_domain.double();
            }

            if (layer_bound.logDegreeBound() != config.log_last_layer_degree_bound) {
                return FriVerificationError.InvalidNumFriLayers;
            }
            if (proof.last_layer_poly.len() > (@as(usize, 1) << @intCast(config.log_last_layer_degree_bound))) {
                return FriVerificationError.LastLayerDegreeInvalid;
            }

            channel.mixFelts(proof.last_layer_poly.coefficients());

            return .{
                .config = config,
                .first_layer = first_layer,
                .inner_layers = inner_layers,
                .last_layer_domain = layer_domain,
                .last_layer_poly = proof.last_layer_poly,
                .queries = null,
            };
        }

        pub fn sampleQueryPositions(
            self: *Self,
            allocator: std.mem.Allocator,
            channel: anytype,
        ) ![]usize {
            const first_layer_log_size = self.first_layer.column_commitment_domain.logSize();
            const unsorted = try queries_mod.drawQueries(
                channel,
                allocator,
                first_layer_log_size,
                self.config.n_queries,
            );
            defer allocator.free(unsorted);

            if (self.queries) |*queries| queries.deinit(allocator);
            self.queries = try queries_mod.Queries.init(allocator, unsorted, first_layer_log_size);
            return allocator.dupe(usize, self.queries.?.positions);
        }

        pub fn decommit(
            self: *Self,
            allocator: std.mem.Allocator,
            first_layer_query_evals: []const QM31,
        ) !void {
            const queries = self.queries orelse return FriVerificationError.FirstLayerEvaluationsInvalid;
            var first_layer_sparse_eval = try self.first_layer.verify(
                allocator,
                queries,
                first_layer_query_evals,
            );
            defer first_layer_sparse_eval.deinit(allocator);

            var layer_queries = try queries.fold(allocator, CIRCLE_TO_LINE_FOLD_STEP);
            defer layer_queries.deinit(allocator);
            var layer_query_evals = try first_layer_sparse_eval.foldCircleSubsets(
                allocator,
                self.first_layer.folding_alpha,
                self.first_layer.column_commitment_domain,
            );
            defer allocator.free(layer_query_evals);

            for (self.inner_layers) |layer| {
                const folded = try layer.verifyAndFold(allocator, layer_queries, layer_query_evals);

                layer_queries.deinit(allocator);
                allocator.free(layer_query_evals);
                layer_queries = folded.queries;
                layer_query_evals = folded.evals;
            }

            try self.decommitLastLayer(allocator, layer_queries, layer_query_evals);
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
        ) !SparseEvaluation {
            if (queries.log_domain_size != self.column_commitment_domain.logSize()) {
                return FriVerificationError.FirstLayerEvaluationsInvalid;
            }

            var rebuilt = computeDecommitmentPositionsAndRebuildEvals(
                allocator,
                queries,
                column_query_evals,
                self.proof.fri_witness,
                CIRCLE_TO_LINE_FOLD_STEP,
            ) catch return FriVerificationError.FirstLayerEvaluationsInvalid;
            errdefer rebuilt.deinit(allocator);

            if (rebuilt.consumed_witness != self.proof.fri_witness.len) {
                return FriVerificationError.FirstLayerEvaluationsInvalid;
            }

            const decommitmented_values = try sparseToBaseColumns(allocator, rebuilt.sparse_evaluation);
            defer freeBaseColumns(allocator, decommitmented_values);
            const repeated_sizes = [_]u32{
                self.column_commitment_domain.logSize(),
                self.column_commitment_domain.logSize(),
                self.column_commitment_domain.logSize(),
                self.column_commitment_domain.logSize(),
            };
            var merkle_verifier = try vcs_verifier.MerkleVerifierLifted(H).init(
                allocator,
                self.proof.commitment,
                repeated_sizes[0..],
            );
            defer merkle_verifier.deinit(allocator);

            merkle_verifier.verify(
                allocator,
                rebuilt.decommitment_positions,
                decommitmented_values,
                self.proof.decommitment,
            ) catch return FriVerificationError.FirstLayerCommitmentInvalid;

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
            if (queries.log_domain_size != self.domain.logSize()) {
                return FriVerificationError.InnerLayerEvaluationsInvalid;
            }

            var rebuilt = computeDecommitmentPositionsAndRebuildEvals(
                allocator,
                queries,
                evals_at_queries,
                self.proof.fri_witness,
                FOLD_STEP,
            ) catch return FriVerificationError.InnerLayerEvaluationsInvalid;
            errdefer rebuilt.deinit(allocator);

            if (rebuilt.consumed_witness != self.proof.fri_witness.len) {
                return FriVerificationError.InnerLayerEvaluationsInvalid;
            }

            const decommitmented_values = try sparseToBaseColumns(allocator, rebuilt.sparse_evaluation);
            defer freeBaseColumns(allocator, decommitmented_values);
            const repeated_sizes = [_]u32{
                self.domain.logSize(),
                self.domain.logSize(),
                self.domain.logSize(),
                self.domain.logSize(),
            };
            var merkle_verifier = try vcs_verifier.MerkleVerifierLifted(H).init(
                allocator,
                self.proof.commitment,
                repeated_sizes[0..],
            );
            defer merkle_verifier.deinit(allocator);

            merkle_verifier.verify(
                allocator,
                rebuilt.decommitment_positions,
                decommitmented_values,
                self.proof.decommitment,
            ) catch return FriVerificationError.InnerLayerCommitmentInvalid;

            var folded_queries = try queries.fold(allocator, FOLD_STEP);
            errdefer folded_queries.deinit(allocator);
            const folded_evals = try rebuilt.sparse_evaluation.foldLineSubsets(
                allocator,
                self.folding_alpha,
                self.domain,
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

fn sparseToBaseColumns(allocator: std.mem.Allocator, sparse: SparseEvaluation) ![][]M31 {
    var columns = [_]std.ArrayList(M31){
        .empty,
        .empty,
        .empty,
        .empty,
    };
    defer {
        for (&columns) |*column| column.deinit(allocator);
    }

    for (sparse.subset_evals) |subset| {
        for (subset) |value| {
            const arr = value.toM31Array();
            inline for (arr, 0..) |coord, i| {
                try columns[i].append(allocator, coord);
            }
        }
    }

    const out = try allocator.alloc([]M31, qm31.SECURE_EXTENSION_DEGREE);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = try columns[i].toOwnedSlice(allocator);
    }
    return out;
}

fn freeBaseColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
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

pub const SparseEvaluation = struct {
    subset_evals: [][]QM31,
    subset_domain_initial_indexes: []usize,

    pub const Error = error{
        InvalidSubsetSize,
        ShapeMismatch,
    };

    pub fn initOwned(
        subset_evals: [][]QM31,
        subset_domain_initial_indexes: []usize,
    ) Error!SparseEvaluation {
        const fold_factor = @as(usize, 1) << @intCast(FOLD_STEP);
        for (subset_evals) |subset| {
            if (subset.len != fold_factor) return Error.InvalidSubsetSize;
        }
        if (subset_evals.len != subset_domain_initial_indexes.len) return Error.ShapeMismatch;
        return .{
            .subset_evals = subset_evals,
            .subset_domain_initial_indexes = subset_domain_initial_indexes,
        };
    }

    pub fn deinit(self: *SparseEvaluation, allocator: std.mem.Allocator) void {
        for (self.subset_evals) |subset| allocator.free(subset);
        allocator.free(self.subset_evals);
        allocator.free(self.subset_domain_initial_indexes);
        self.* = undefined;
    }

    pub fn foldLineSubsets(
        self: SparseEvaluation,
        allocator: std.mem.Allocator,
        fold_alpha: QM31,
        source_domain: line.LineDomain,
    ) ![]QM31 {
        const out = try allocator.alloc(QM31, self.subset_evals.len);
        var i: usize = 0;
        while (i < self.subset_evals.len) : (i += 1) {
            const domain_initial_index = self.subset_domain_initial_indexes[i];
            const fold_domain_initial = source_domain.coset().indexAt(domain_initial_index);
            const fold_domain = try line.LineDomain.init(circle.Coset.new(fold_domain_initial, FOLD_STEP));
            const folded = try foldLine(allocator, self.subset_evals[i], fold_domain, fold_alpha);
            defer allocator.free(folded.values);
            out[i] = folded.values[0];
        }
        return out;
    }

    pub fn foldCircleSubsets(
        self: SparseEvaluation,
        allocator: std.mem.Allocator,
        fold_alpha: QM31,
        source_domain: circle_domain.CircleDomain,
    ) ![]QM31 {
        const out = try allocator.alloc(QM31, self.subset_evals.len);
        var i: usize = 0;
        while (i < self.subset_evals.len) : (i += 1) {
            const domain_initial_index = self.subset_domain_initial_indexes[i];
            const fold_domain_initial = source_domain.indexAt(domain_initial_index);
            const fold_domain = circle_domain.CircleDomain.new(
                circle.Coset.new(fold_domain_initial, CIRCLE_TO_LINE_FOLD_STEP - 1),
            );
            const buffer = try allocator.alloc(QM31, fold_domain.half_coset.size());
            defer allocator.free(buffer);
            @memset(buffer, QM31.zero());
            try foldCircleIntoLine(buffer, self.subset_evals[i], fold_domain, fold_alpha);
            out[i] = buffer[0];
        }
        return out;
    }
};

pub const ComputeDecommitmentResult = struct {
    decommitment_positions: []usize,
    sparse_evaluation: SparseEvaluation,
    consumed_witness: usize,

    pub fn deinit(self: *ComputeDecommitmentResult, allocator: std.mem.Allocator) void {
        allocator.free(self.decommitment_positions);
        self.sparse_evaluation.deinit(allocator);
        self.* = undefined;
    }
};

pub fn computeDecommitmentPositionsAndRebuildEvals(
    allocator: std.mem.Allocator,
    queries: queries_mod.Queries,
    query_evals: []const QM31,
    witness_evals: []const QM31,
    fold_step: u32,
) !ComputeDecommitmentResult {
    if (query_evals.len != queries.positions.len) return error.ShapeMismatch;

    var decommitment_positions = std.ArrayList(usize).empty;
    defer decommitment_positions.deinit(allocator);
    var subset_evals = std.ArrayList([]QM31).empty;
    defer subset_evals.deinit(allocator);
    errdefer {
        for (subset_evals.items) |subset| allocator.free(subset);
    }
    var subset_domain_initial_indexes = std.ArrayList(usize).empty;
    defer subset_domain_initial_indexes.deinit(allocator);

    const subset_size: usize = @as(usize, 1) << @intCast(fold_step);

    var query_idx: usize = 0;
    var witness_idx: usize = 0;
    while (query_idx < queries.positions.len) {
        const subset_group = queries.positions[query_idx] >> @intCast(fold_step);
        const subset_start = subset_group << @intCast(fold_step);

        var subset_end_idx = query_idx;
        while (subset_end_idx < queries.positions.len and
            (queries.positions[subset_end_idx] >> @intCast(fold_step)) == subset_group)
        {
            subset_end_idx += 1;
        }

        var pos: usize = subset_start;
        while (pos < subset_start + subset_size) : (pos += 1) {
            try decommitment_positions.append(allocator, pos);
        }

        const subset = try allocator.alloc(QM31, subset_size);
        errdefer allocator.free(subset);

        var subset_query_idx = query_idx;
        var subset_pos: usize = 0;
        while (subset_pos < subset_size) : (subset_pos += 1) {
            const absolute_pos = subset_start + subset_pos;
            if (subset_query_idx < subset_end_idx and queries.positions[subset_query_idx] == absolute_pos) {
                subset[subset_pos] = query_evals[subset_query_idx];
                subset_query_idx += 1;
            } else {
                if (witness_idx >= witness_evals.len) return error.InsufficientWitness;
                subset[subset_pos] = witness_evals[witness_idx];
                witness_idx += 1;
            }
        }

        try subset_evals.append(allocator, subset);
        try subset_domain_initial_indexes.append(
            allocator,
            core_utils.bitReverseIndex(subset_start, queries.log_domain_size),
        );
        query_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(allocator),
        .sparse_evaluation = try SparseEvaluation.initOwned(
            try subset_evals.toOwnedSlice(allocator),
            try subset_domain_initial_indexes.toOwnedSlice(allocator),
        ),
        .consumed_witness = witness_idx,
    };
}

pub const FoldLineResult = struct {
    domain: line.LineDomain,
    values: []QM31,
};

pub fn foldLine(
    allocator: std.mem.Allocator,
    eval: []const QM31,
    domain: line.LineDomain,
    alpha: QM31,
) !FoldLineResult {
    if (eval.len < 2 or (eval.len & 1) != 0) return error.InvalidEvaluationLength;

    const folded_values = try allocator.alloc(QM31, eval.len / 2);
    var i: usize = 0;
    while (i < folded_values.len) : (i += 1) {
        const x = domain.at(core_utils.bitReverseIndex(i << @intCast(FOLD_STEP), domain.logSize()));
        const inv_x = try x.inv();
        var f0 = eval[i * 2];
        var f1 = eval[i * 2 + 1];
        fft.ibutterfly(QM31, &f0, &f1, inv_x);
        folded_values[i] = f0.add(alpha.mul(f1));
    }

    return .{
        .domain = domain.double(),
        .values = folded_values,
    };
}

pub fn foldCircleIntoLine(
    dst: []QM31,
    src: []const QM31,
    src_domain: circle_domain.CircleDomain,
    alpha: QM31,
) !void {
    if ((src.len >> @intCast(CIRCLE_TO_LINE_FOLD_STEP)) != dst.len) {
        return error.ShapeMismatch;
    }

    const alpha_sq = alpha.square();
    var i: usize = 0;
    while (i < dst.len) : (i += 1) {
        const p = src_domain.at(core_utils.bitReverseIndex(
            i << @intCast(CIRCLE_TO_LINE_FOLD_STEP),
            src_domain.logSize(),
        ));
        const inv_py = try p.y.inv();
        var f0_px = src[i * 2];
        var f1_px = src[i * 2 + 1];
        fft.ibutterfly(QM31, &f0_px, &f1_px, inv_py);
        const f_prime = alpha.mul(f1_px).add(f0_px);
        dst[i] = dst[i].mul(alpha_sq).add(f_prime);
    }
}

pub fn accumulateLine(layer_query_evals: []QM31, column_query_evals: []const QM31, folding_alpha: QM31) void {
    std.debug.assert(layer_query_evals.len == column_query_evals.len);
    const alpha_sq = folding_alpha.square();
    for (layer_query_evals, 0..) |*curr, i| {
        curr.* = curr.*.mul(alpha_sq).add(column_query_evals[i]);
    }
}

test "fri config: security bits" {
    const config = try FriConfig.init(10, 10, 70);
    try std.testing.expectEqual(@as(u32, 700), config.securityBits());
}

test "fri config: default values" {
    const cfg = FriConfig.default();
    try std.testing.expectEqual(@as(u32, 0), cfg.log_last_layer_degree_bound);
    try std.testing.expectEqual(@as(u32, 1), cfg.log_blowup_factor);
    try std.testing.expectEqual(@as(usize, 3), cfg.n_queries);
}

test "fri config: bounds checks" {
    try std.testing.expectError(FriConfig.Error.InvalidLastLayerDegreeBound, FriConfig.init(11, 1, 1));
    try std.testing.expectError(FriConfig.Error.InvalidBlowupFactor, FriConfig.init(0, 0, 1));
}

test "fri: degree bound folding" {
    const circle_bound = CirclePolyDegreeBound.init(7);
    const line_bound = circle_bound.foldToLine();
    try std.testing.expectEqual(@as(u32, 6), line_bound.log_degree_bound);
    try std.testing.expectEqual(@as(u32, 5), (line_bound.fold(1) orelse unreachable).log_degree_bound);
    try std.testing.expect((line_bound.fold(7)) == null);
}

test "fri: accumulate line" {
    var layer = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    };
    const folded = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const alpha = QM31.fromU32Unchecked(5, 0, 0, 0);
    accumulateLine(layer[0..], folded[0..], alpha);

    const alpha_sq = alpha.square();
    try std.testing.expect(layer[0].eql(QM31.fromU32Unchecked(1, 0, 0, 0).mul(alpha_sq).add(folded[0])));
    try std.testing.expect(layer[1].eql(QM31.fromU32Unchecked(2, 0, 0, 0).mul(alpha_sq).add(folded[1])));
}

test "fri: compute decommitment positions and rebuild evals" {
    const alloc = std.testing.allocator;
    const raw_queries = [_]usize{ 1, 2, 5 };
    var queries = try queries_mod.Queries.init(alloc, raw_queries[0..], 3);
    defer queries.deinit(alloc);

    const q1 = QM31.fromU32Unchecked(11, 0, 0, 0);
    const q2 = QM31.fromU32Unchecked(22, 0, 0, 0);
    const q5 = QM31.fromU32Unchecked(55, 0, 0, 0);
    const query_evals = [_]QM31{ q1, q2, q5 };
    const witness = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var result = try computeDecommitmentPositionsAndRebuildEvals(
        alloc,
        queries,
        query_evals[0..],
        witness[0..],
        1,
    );
    defer result.deinit(alloc);

    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3, 4, 5 }, result.decommitment_positions);
    try std.testing.expectEqual(@as(usize, 3), result.sparse_evaluation.subset_evals.len);
    try std.testing.expectEqual(@as(usize, 3), result.consumed_witness);
    try std.testing.expect(result.sparse_evaluation.subset_evals[0][0].eql(witness[0]));
    try std.testing.expect(result.sparse_evaluation.subset_evals[0][1].eql(q1));
    try std.testing.expect(result.sparse_evaluation.subset_evals[1][0].eql(q2));
    try std.testing.expect(result.sparse_evaluation.subset_evals[1][1].eql(witness[1]));
    try std.testing.expect(result.sparse_evaluation.subset_evals[2][0].eql(witness[2]));
    try std.testing.expect(result.sparse_evaluation.subset_evals[2][1].eql(q5));
}

test "fri: compute decommitment fails on insufficient witness" {
    const alloc = std.testing.allocator;
    const raw_queries = [_]usize{ 1, 2, 5 };
    var queries = try queries_mod.Queries.init(alloc, raw_queries[0..], 3);
    defer queries.deinit(alloc);

    const query_evals = [_]QM31{
        QM31.fromU32Unchecked(11, 0, 0, 0),
        QM31.fromU32Unchecked(22, 0, 0, 0),
        QM31.fromU32Unchecked(55, 0, 0, 0),
    };
    const short_witness = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
    };

    try std.testing.expectError(
        error.InsufficientWitness,
        computeDecommitmentPositionsAndRebuildEvals(
            alloc,
            queries,
            query_evals[0..],
            short_witness[0..],
            1,
        ),
    );
}

test "fri: fold line matches pairwise butterfly formula" {
    const alloc = std.testing.allocator;
    const domain = try line.LineDomain.init(circle.Coset.halfOdds(2));
    const alpha = QM31.fromU32Unchecked(9, 0, 0, 0);
    const eval = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 0, 0),
        QM31.fromU32Unchecked(3, 4, 0, 0),
        QM31.fromU32Unchecked(5, 6, 0, 0),
        QM31.fromU32Unchecked(7, 8, 0, 0),
    };

    const folded = try foldLine(alloc, eval[0..], domain, alpha);
    defer alloc.free(folded.values);

    try std.testing.expectEqual(@as(u32, domain.logSize() - 1), folded.domain.logSize());
    try std.testing.expectEqual(@as(usize, 2), folded.values.len);

    var expected0_f0 = eval[0];
    var expected0_f1 = eval[1];
    fft.ibutterfly(QM31, &expected0_f0, &expected0_f1, try domain.at(core_utils.bitReverseIndex(0, domain.logSize())).inv());
    const expected0 = expected0_f0.add(alpha.mul(expected0_f1));

    var expected1_f0 = eval[2];
    var expected1_f1 = eval[3];
    fft.ibutterfly(QM31, &expected1_f0, &expected1_f1, try domain.at(core_utils.bitReverseIndex(2, domain.logSize())).inv());
    const expected1 = expected1_f0.add(alpha.mul(expected1_f1));

    try std.testing.expect(folded.values[0].eql(expected0));
    try std.testing.expect(folded.values[1].eql(expected1));
}

test "fri: fold circle into line accumulates correctly" {
    const src_domain = canonic.CanonicCoset.new(2).circleDomain();
    const alpha = QM31.fromU32Unchecked(7, 0, 0, 0);
    const src = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var dst = [_]QM31{ QM31.zero(), QM31.zero() };

    try foldCircleIntoLine(dst[0..], src[0..], src_domain, alpha);

    var expected = [_]QM31{ QM31.zero(), QM31.zero() };
    const alpha_sq = alpha.square();
    var i: usize = 0;
    while (i < expected.len) : (i += 1) {
        const p = src_domain.at(core_utils.bitReverseIndex(i << @intCast(CIRCLE_TO_LINE_FOLD_STEP), src_domain.logSize()));
        var f0 = src[i * 2];
        var f1 = src[i * 2 + 1];
        fft.ibutterfly(QM31, &f0, &f1, try p.y.inv());
        const f_prime = alpha.mul(f1).add(f0);
        expected[i] = expected[i].mul(alpha_sq).add(f_prime);
    }

    try std.testing.expect(dst[0].eql(expected[0]));
    try std.testing.expect(dst[1].eql(expected[1]));
}

test "fri verifier: commit and sample query positions" {
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("channel/blake2s.zig").Blake2sChannel;
    const Verifier = FriVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var channel = Channel{};
    const config = try FriConfig.init(2, 1, 4);
    var verifier = try Verifier.commit(
        alloc,
        &channel,
        config,
        .{
            .first_layer = .{
                .fri_witness = try alloc.alloc(QM31, 0),
                .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                .commitment = [_]u8{2} ** 32,
            },
            .inner_layers = try alloc.alloc(FriLayerProof(Hasher), 0),
            .last_layer_poly = line.LinePoly.initOwned(
                try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
            ),
        },
        CirclePolyDegreeBound.init(3),
    );
    defer verifier.deinit(alloc);

    const positions = try verifier.sampleQueryPositions(alloc, &channel);
    defer alloc.free(positions);
    try std.testing.expect(positions.len <= config.n_queries);
    for (positions) |pos| {
        try std.testing.expect(pos < (@as(usize, 1) << @intCast(3 + config.log_blowup_factor)));
    }
}

test "fri verifier: invalid layer count fails commit" {
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("channel/blake2s.zig").Blake2sChannel;
    const Verifier = FriVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    var channel = Channel{};
    const config = try FriConfig.init(1, 1, 2);
    try std.testing.expectError(
        FriVerificationError.InvalidNumFriLayers,
        Verifier.commit(
            alloc,
            &channel,
            config,
            .{
                .first_layer = .{
                    .fri_witness = try alloc.alloc(QM31, 0),
                    .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                    .commitment = [_]u8{9} ** 32,
                },
                .inner_layers = try alloc.alloc(FriLayerProof(Hasher), 0),
                .last_layer_poly = line.LinePoly.initOwned(
                    try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                ),
            },
            CirclePolyDegreeBound.init(3),
        ),
    );
}

test "fri proof containers: deinit owned buffers" {
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LayerProof = FriLayerProof(Hasher);
    const LayerProofAux = FriLayerProofAux(Hasher);
    const Proof = FriProof(Hasher);
    const ProofAux = FriProofAux(Hasher);
    const Extended = ExtendedFriProof(Hasher);
    const MerkleAux = vcs_verifier.MerkleDecommitmentLiftedAux(Hasher);

    const alloc = std.testing.allocator;

    const first_witness = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    });
    const first_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
    };
    const first_layer = LayerProof{
        .fri_witness = first_witness,
        .decommitment = first_decommitment,
        .commitment = [_]u8{0} ** 32,
    };

    const inner_witness = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
    });
    const inner_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
    };
    const inner_layers = try alloc.alloc(LayerProof, 1);
    inner_layers[0] = .{
        .fri_witness = inner_witness,
        .decommitment = inner_decommitment,
        .commitment = [_]u8{1} ** 32,
    };

    const poly_coeffs = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(5, 0, 0, 0),
    });
    const proof = Proof{
        .first_layer = first_layer,
        .inner_layers = inner_layers,
        .last_layer_poly = line.LinePoly.initOwned(poly_coeffs),
    };

    const first_aux = LayerProofAux{
        .all_values = try alloc.alloc([]LayerProofAux.IndexedValue, 0),
        .decommitment = MerkleAux{
            .all_node_values = try alloc.alloc([]MerkleAux.NodeValue, 0),
        },
    };
    const inner_aux_layers = try alloc.alloc(LayerProofAux, 0);
    const proof_aux = ProofAux{
        .first_layer = first_aux,
        .inner_layers = inner_aux_layers,
    };

    var extended = Extended{
        .proof = proof,
        .aux = proof_aux,
    };
    extended.deinit(alloc);
}
