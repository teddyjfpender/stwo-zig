const std = @import("std");
const circle = @import("../core/circle.zig");
const core_fri = @import("../core/fri.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const line = @import("../core/poly/line.zig");
const circle_domain = @import("../core/poly/circle/domain.zig");
const queries_mod = @import("../core/queries.zig");
const vcs_lifted_verifier = @import("../core/vcs_lifted/verifier.zig");
const prover_line = @import("line.zig");
const secure_column = @import("secure_column.zig");
const vcs_lifted_prover = @import("vcs_lifted/prover.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const FriDecommitError = error{
    QueryOutOfRange,
    FoldStepTooLarge,
};

pub const FriProverError = error{
    NotCanonicDomain,
    ShapeMismatch,
    InvalidLastLayerSize,
    InvalidLastLayerDegree,
};

pub const ValueEntry = struct {
    position: usize,
    value: QM31,
};

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

pub fn FriProver(comptime H: type, comptime MC: type) type {
    return struct {
        config: core_fri.FriConfig,
        first_layer: FirstLayerProver,
        inner_layers: []InnerLayerProver,
        last_layer_poly: line.LinePoly,

        const Self = @This();

        const FirstLayerProver = struct {
            domain: circle_domain.CircleDomain,
            column: secure_column.SecureColumnByCoords,
            merkle_tree: vcs_lifted_prover.MerkleProverLifted(H),

            fn deinit(self: *FirstLayerProver, allocator: std.mem.Allocator) void {
                self.column.deinit(allocator);
                self.merkle_tree.deinit(allocator);
                self.* = undefined;
            }
        };

        const InnerLayerProver = struct {
            domain: line.LineDomain,
            column: secure_column.SecureColumnByCoords,
            merkle_tree: vcs_lifted_prover.MerkleProverLifted(H),

            fn deinit(self: *InnerLayerProver, allocator: std.mem.Allocator) void {
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

            var inner_commit = try commitInnerLayers(allocator, channel, config, first_layer);
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
                core_fri.CIRCLE_TO_LINE_FOLD_STEP,
            );
            errdefer first_layer_proof.deinit(allocator);

            var layer_queries = try queries.fold(allocator, core_fri.CIRCLE_TO_LINE_FOLD_STEP);
            defer layer_queries.deinit(allocator);

            var inner_layer_proofs = std.ArrayList(core_fri.ExtendedFriLayerProof(H)).init(allocator);
            defer inner_layer_proofs.deinit();
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
                    core_fri.FOLD_STEP,
                );
                errdefer inner_proof.deinit(allocator);
                try inner_layer_proofs.append(inner_proof);

                const next_queries = try layer_queries.fold(allocator, core_fri.FOLD_STEP);
                layer_queries.deinit(allocator);
                layer_queries = next_queries;
            }

            const inner_extended = try inner_layer_proofs.toOwnedSlice();
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
            var merkle_tree = try vcs_lifted_prover.MerkleProverLifted(H).commit(
                allocator,
                column_refs[0..],
            );
            MC.mixRoot(channel, merkle_tree.root());
            return .{
                .domain = domain,
                .column = column,
                .merkle_tree = merkle_tree,
            };
        }

        const InnerCommitResult = struct {
            inner_layers: []InnerLayerProver,
            last_layer_evaluation: prover_line.LineEvaluation,
        };

        fn commitInnerLayers(
            allocator: std.mem.Allocator,
            channel: anytype,
            config: core_fri.FriConfig,
            first_layer: FirstLayerProver,
        ) !InnerCommitResult {
            const first_inner_layer_log_size = first_layer.domain.logSize() - core_fri.CIRCLE_TO_LINE_FOLD_STEP;
            const first_inner_layer_domain = try line.LineDomain.init(
                circle.Coset.halfOdds(first_inner_layer_log_size),
            );

            var layer_evaluation = try prover_line.LineEvaluation.newZero(
                allocator,
                first_inner_layer_domain,
            );
            errdefer layer_evaluation.deinit(allocator);

            const folding_alpha = channel.drawSecureFelt();
            const first_layer_values = try first_layer.column.toVec(allocator);
            defer allocator.free(first_layer_values);
            try core_fri.foldCircleIntoLine(
                layer_evaluation.values,
                first_layer_values,
                first_layer.domain,
                folding_alpha,
            );

            var layers = std.ArrayList(InnerLayerProver).init(allocator);
            defer layers.deinit();
            errdefer {
                for (layers.items) |*layer| layer.deinit(allocator);
            }

            while (layer_evaluation.len() > config.lastLayerDomainSize()) {
                var secure_values = try secure_column.SecureColumnByCoords.fromSecureSlice(
                    allocator,
                    layer_evaluation.values,
                );
                errdefer secure_values.deinit(allocator);

                const coord_refs = [_][]const M31{
                    secure_values.columns[0],
                    secure_values.columns[1],
                    secure_values.columns[2],
                    secure_values.columns[3],
                };
                var merkle_tree = try vcs_lifted_prover.MerkleProverLifted(H).commit(
                    allocator,
                    coord_refs[0..],
                );
                errdefer merkle_tree.deinit(allocator);

                MC.mixRoot(channel, merkle_tree.root());
                const fold_alpha = channel.drawSecureFelt();
                const folded = try core_fri.foldLine(
                    allocator,
                    layer_evaluation.values,
                    layer_evaluation.domain(),
                    fold_alpha,
                );

                const layer = InnerLayerProver{
                    .domain = layer_evaluation.domain(),
                    .column = secure_values,
                    .merkle_tree = merkle_tree,
                };
                try layers.append(layer);

                layer_evaluation.deinit(allocator);
                layer_evaluation = try prover_line.LineEvaluation.initOwned(
                    folded.domain,
                    folded.values,
                );
            }

            return .{
                .inner_layers = try layers.toOwnedSlice(),
                .last_layer_evaluation = layer_evaluation,
            };
        }

        fn commitLastLayer(
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
    merkle_tree: vcs_lifted_prover.MerkleProverLifted(H),
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!core_fri.ExtendedFriLayerProof(H) {
    const column_values = try column.toVec(allocator);
    defer allocator.free(column_values);

    const helper = try computeDecommitmentPositionsAndWitnessEvals(
        allocator,
        column_values,
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

    var decommitment_positions = std.ArrayList(usize).init(allocator);
    defer decommitment_positions.deinit();
    var witness_evals = std.ArrayList(QM31).init(allocator);
    defer witness_evals.deinit();
    var value_map = std.ArrayList(ValueEntry).init(allocator);
    defer value_map.deinit();

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

            try decommitment_positions.append(position);
            const eval = column[position];
            try value_map.append(.{
                .position = position,
                .value = eval,
            });

            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(eval);
            }
        }

        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(),
        .witness_evals = try witness_evals.toOwnedSlice(),
        .value_map = try value_map.toOwnedSlice(),
    };
}

/// Produces a FRI layer decommitment proof for `query_positions`.
pub fn decommitLayer(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: vcs_lifted_prover.MerkleProverLifted(H),
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!LayerDecommitResult(H) {
    const column_values = try column.toVec(allocator);
    defer allocator.free(column_values);

    const helper = try computeDecommitmentPositionsAndWitnessEvals(
        allocator,
        column_values,
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

test "prover fri: decommitment positions and witness evals" {
    const alloc = std.testing.allocator;

    const column = [_]QM31{
        QM31.fromBase(.fromCanonical(1)),
        QM31.fromBase(.fromCanonical(2)),
        QM31.fromBase(.fromCanonical(3)),
        QM31.fromBase(.fromCanonical(4)),
        QM31.fromBase(.fromCanonical(5)),
        QM31.fromBase(.fromCanonical(6)),
        QM31.fromBase(.fromCanonical(7)),
        QM31.fromBase(.fromCanonical(8)),
    };
    const queries = [_]usize{ 1, 3, 6 };

    var result = try computeDecommitmentPositionsAndWitnessEvals(
        alloc,
        column[0..],
        queries[0..],
        1,
    );
    defer result.deinit(alloc);

    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3, 6, 7 }, result.decommitment_positions);
    try std.testing.expectEqual(@as(usize, 3), result.witness_evals.len);
    try std.testing.expect(result.witness_evals[0].eql(column[0]));
    try std.testing.expect(result.witness_evals[1].eql(column[2]));
    try std.testing.expect(result.witness_evals[2].eql(column[7]));

    try std.testing.expectEqual(@as(usize, 6), result.value_map.len);
    for (result.value_map, 0..) |entry, i| {
        try std.testing.expectEqual(result.decommitment_positions[i], entry.position);
        try std.testing.expect(entry.value.eql(column[entry.position]));
    }
}

test "prover fri: query out of range fails" {
    const column = [_]QM31{
        QM31.fromBase(.fromCanonical(1)),
        QM31.fromBase(.fromCanonical(2)),
        QM31.fromBase(.fromCanonical(3)),
        QM31.fromBase(.fromCanonical(4)),
    };
    const queries = [_]usize{7};
    try std.testing.expectError(
        FriDecommitError.QueryOutOfRange,
        computeDecommitmentPositionsAndWitnessEvals(
            std.testing.allocator,
            column[0..],
            queries[0..],
            0,
        ),
    );
}

test "prover fri: fold step too large fails" {
    const column = [_]QM31{QM31.fromBase(.fromCanonical(1))};
    const queries = [_]usize{0};
    try std.testing.expectError(
        FriDecommitError.FoldStepTooLarge,
        computeDecommitmentPositionsAndWitnessEvals(
            std.testing.allocator,
            column[0..],
            queries[0..],
            @bitSizeOf(usize),
        ),
    );
}

test "prover fri: layer decommit extended contains proof and aux values" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{1};
    var extended = try decommitLayerExtended(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        1,
    );
    defer extended.deinit(alloc);

    try std.testing.expect(std.mem.eql(
        u8,
        std.mem.asBytes(&extended.proof.commitment),
        std.mem.asBytes(&merkle.root()),
    ));
    try std.testing.expectEqual(@as(usize, 1), extended.aux.all_values.len);
    try std.testing.expectEqual(@as(usize, 2), extended.aux.all_values[0].len);
    try std.testing.expectEqual(@as(usize, 0), extended.aux.all_values[0][0].index);
    try std.testing.expect(extended.aux.all_values[0][0].value.eql(values[0]));
    try std.testing.expectEqual(@as(usize, 1), extended.aux.all_values[0][1].index);
    try std.testing.expect(extended.aux.all_values[0][1].value.eql(values[1]));
}

test "prover fri: layer decommit extended query out of range fails" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{7};
    try std.testing.expectError(
        FriDecommitError.QueryOutOfRange,
        decommitLayerExtended(
            Hasher,
            alloc,
            merkle,
            column,
            query_positions[0..],
            1,
        ),
    );
}

test "prover fri: layer decommit verifies with lifted merkle verifier" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const LiftedVerifier = vcs_lifted_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
        QM31.fromU32Unchecked(25, 26, 27, 28),
        QM31.fromU32Unchecked(29, 30, 31, 32),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{ 1, 3, 6 };
    var decommit = try decommitLayer(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        1,
    );
    defer decommit.deinit(alloc);

    const queried_values = try alloc.alloc([]const M31, qm31.SECURE_EXTENSION_DEGREE);
    defer alloc.free(queried_values);
    const queried_values_owned = try alloc.alloc([]M31, qm31.SECURE_EXTENSION_DEGREE);
    defer {
        for (queried_values_owned) |col_vals| alloc.free(col_vals);
        alloc.free(queried_values_owned);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        queried_values_owned[coord] = try alloc.alloc(M31, decommit.value_map.len);
        for (decommit.value_map, 0..) |entry, i| {
            const coords = entry.value.toM31Array();
            queried_values_owned[coord][i] = coords[coord];
        }
        queried_values[coord] = queried_values_owned[coord];
    }

    const log_size = @as(u32, @intCast(std.math.log2_int(usize, values.len)));
    const repeated_sizes = [_]u32{ log_size, log_size, log_size, log_size };
    var verifier = try LiftedVerifier.init(alloc, merkle.root(), repeated_sizes[0..]);
    defer verifier.deinit(alloc);
    try verifier.verify(
        alloc,
        decommit.decommitment_positions,
        queried_values,
        decommit.proof.decommitment,
    );
}

test "prover fri: layer decommit corrupted witness fails" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const LiftedVerifier = vcs_lifted_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{1};
    var decommit = try decommitLayer(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        1,
    );
    defer decommit.deinit(alloc);

    decommit.proof.decommitment.hash_witness[0][0] ^= 1;

    const queried_values = try alloc.alloc([]const M31, qm31.SECURE_EXTENSION_DEGREE);
    defer alloc.free(queried_values);
    const queried_values_owned = try alloc.alloc([]M31, qm31.SECURE_EXTENSION_DEGREE);
    defer {
        for (queried_values_owned) |col_vals| alloc.free(col_vals);
        alloc.free(queried_values_owned);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        queried_values_owned[coord] = try alloc.alloc(M31, decommit.value_map.len);
        for (decommit.value_map, 0..) |entry, i| {
            const coords = entry.value.toM31Array();
            queried_values_owned[coord][i] = coords[coord];
        }
        queried_values[coord] = queried_values_owned[coord];
    }

    const log_size = @as(u32, @intCast(std.math.log2_int(usize, values.len)));
    const repeated_sizes = [_]u32{ log_size, log_size, log_size, log_size };
    var verifier = try LiftedVerifier.init(alloc, merkle.root(), repeated_sizes[0..]);
    defer verifier.deinit(alloc);

    try std.testing.expectError(
        vcs_lifted_verifier.MerkleVerificationError.RootMismatch,
        verifier.verify(
            alloc,
            decommit.decommitment_positions,
            queried_values,
            decommit.proof.decommitment,
        ),
    );
}

test "prover fri: commit and decommit roundtrip with verifier" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Prover = FriProver(Hasher, MerkleChannel);
    const Verifier = core_fri.FriVerifier(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = try core_fri.FriConfig.init(0, 1, 4);
    const column_log_size: u32 = 3;
    const domain = @import("../core/poly/circle/canonic.zig").CanonicCoset
        .new(column_log_size)
        .circleDomain();

    const constant_value = QM31.fromU32Unchecked(7, 0, 0, 0);
    const values = try alloc.alloc(QM31, domain.size());
    defer alloc.free(values);
    @memset(values, constant_value);

    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values);

    var prover_channel = Channel{};
    var prover = try Prover.commit(
        alloc,
        &prover_channel,
        config,
        domain,
        column,
    );
    var decommit_result = try prover.decommit(alloc, &prover_channel);
    defer decommit_result.deinit(alloc);

    var verifier_channel = Channel{};
    const bound = core_fri.CirclePolyDegreeBound.init(column_log_size - config.log_blowup_factor);
    var verifier = try Verifier.commit(
        alloc,
        &verifier_channel,
        config,
        decommit_result.fri_proof.proof,
        bound,
    );
    defer verifier.deinit(alloc);

    const query_positions = try verifier.sampleQueryPositions(alloc, &verifier_channel);
    defer alloc.free(query_positions);
    try std.testing.expectEqualSlices(usize, decommit_result.query_positions, query_positions);

    const first_layer_answers = try alloc.alloc(QM31, query_positions.len);
    defer alloc.free(first_layer_answers);
    @memset(first_layer_answers, constant_value);
    try verifier.decommit(alloc, first_layer_answers);
}

test "prover fri: commit rejects non-canonic domain" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Prover = FriProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const invalid_domain = circle_domain.CircleDomain.new(
        circle.Coset.new(circle.CirclePointIndex.generator(), 3),
    );
    try std.testing.expect(!invalid_domain.isCanonic());

    const values = try alloc.alloc(QM31, invalid_domain.size());
    defer alloc.free(values);
    @memset(values, QM31.one());

    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values);
    var channel = Channel{};
    try std.testing.expectError(
        FriProverError.NotCanonicDomain,
        Prover.commit(
            alloc,
            &channel,
            try core_fri.FriConfig.init(0, 1, 3),
            invalid_domain,
            column,
        ),
    );
}

test "prover fri: commit rejects high-degree last layer" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MerkleChannel = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../core/channel/blake2s.zig").Blake2sChannel;
    const Prover = FriProver(Hasher, MerkleChannel);
    const alloc = std.testing.allocator;

    const config = try core_fri.FriConfig.init(0, 1, 3);
    const domain = @import("../core/poly/circle/canonic.zig").CanonicCoset
        .new(3)
        .circleDomain();

    const values = try alloc.alloc(QM31, domain.size());
    defer alloc.free(values);
    for (values, 0..) |*v, i| {
        v.* = QM31.fromBase(M31.fromCanonical(@intCast(i + 1)));
    }

    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values);
    var channel = Channel{};
    try std.testing.expectError(
        FriProverError.InvalidLastLayerDegree,
        Prover.commit(alloc, &channel, config, domain, column),
    );
}
