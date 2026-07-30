const std = @import("std");
const circle = @import("circle.zig");
const m31 = @import("fields/m31.zig");
const qm31 = @import("fields/qm31.zig");
const fri = @import("fri.zig");
const pcs = @import("pcs/mod.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");
const verifier_types = @import("verifier_types.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const StarkProofSizeBreakdown = struct {
    oods_samples: usize,
    queries_values: usize,
    fri_samples: usize,
    fri_decommitments: usize,
    trace_decommitments: usize,
};

pub fn StarkProof(comptime H: type) type {
    return struct {
        commitment_scheme_proof: pcs.CommitmentSchemeProof(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.commitment_scheme_proof.deinit(allocator);
            self.* = undefined;
        }

        /// Extracts the composition OODS evaluation from the sampled-values layout.
        ///
        /// Returns `null` if the sampled-values structure does not match the expected
        /// shape: the last tree must contain `2 * SECURE_EXTENSION_DEGREE` columns, each
        /// with exactly one value.
        pub fn extractCompositionOodsEval(
            self: Self,
            oods_point: CirclePointQM31,
            composition_log_size: u32,
        ) ?QM31 {
            return self.extractCompositionOodsEvalWithSplit(
                oods_point,
                composition_log_size,
                1,
            );
        }

        pub fn extractCompositionOodsEvalWithSplit(
            self: Self,
            oods_point: CirclePointQM31,
            composition_log_size: u32,
            split_depth: u32,
        ) ?QM31 {
            if (split_depth == 0 or
                split_depth > verifier_types.MAX_COMPOSITION_LOG_SPLIT or
                composition_log_size <= split_depth)
            {
                return null;
            }
            if (self.commitment_scheme_proof.sampled_values.items.len == 0) return null;

            const masks = self.commitment_scheme_proof.sampled_values.items[
                self.commitment_scheme_proof.sampled_values.items.len - 1
            ];
            const chunk_count = verifier_types.compositionChunkCount(split_depth) orelse
                return null;
            const expected_cols = verifier_types.compositionColumnCount(
                split_depth,
                qm31.SECURE_EXTENSION_DEGREE,
            ) orelse return null;
            if (masks.len != expected_cols) return null;

            var chunk_evals: [@as(usize, 1) << verifier_types.MAX_COMPOSITION_LOG_SPLIT]QM31 =
                undefined;
            for (chunk_evals[0..chunk_count], 0..) |*chunk_eval, chunk_index| {
                var coordinates: [qm31.SECURE_EXTENSION_DEGREE]QM31 = undefined;
                for (&coordinates, 0..) |*coordinate, coordinate_index| {
                    const column = masks[
                        chunk_index * qm31.SECURE_EXTENSION_DEGREE + coordinate_index
                    ];
                    if (column.len != 1) return null;
                    coordinate.* = column[0];
                }
                chunk_eval.* = QM31.fromPartialEvals(coordinates);
            }

            return reconstructCompositionChunkEvals(
                chunk_evals[0..chunk_count],
                oods_point,
                composition_log_size,
                split_depth,
            );
        }

        pub fn sizeEstimate(self: Self) usize {
            const proof = self.commitment_scheme_proof;
            return estimateHashSlice(H, proof.commitments.items) +
                estimateTreeQm31(proof.sampled_values) +
                estimateMerkleDecommitments(H, proof.decommitments.items) +
                estimateTreeM31(proof.queried_values) +
                @sizeOf(@TypeOf(proof.proof_of_work)) +
                estimateFriProof(H, proof.fri_proof) +
                @sizeOf(@TypeOf(proof.config));
        }

        pub fn sizeBreakdownEstimate(self: Self) StarkProofSizeBreakdown {
            const proof = self.commitment_scheme_proof;

            var inner_samples: usize = 0;
            var inner_hashes: usize = 0;
            for (proof.fri_proof.inner_layers) |layer| {
                inner_samples += estimateQm31Slice(layer.fri_witness);
                inner_hashes += estimateMerkleDecommitment(H, layer.decommitment) + @sizeOf(H.Hash);
            }

            return .{
                .oods_samples = estimateTreeQm31(proof.sampled_values),
                .queries_values = estimateTreeM31(proof.queried_values),
                .fri_samples = estimateQm31Slice(proof.fri_proof.last_layer_poly.coefficients()) +
                    inner_samples +
                    estimateQm31Slice(proof.fri_proof.first_layer.fri_witness),
                .fri_decommitments = inner_hashes +
                    estimateMerkleDecommitment(H, proof.fri_proof.first_layer.decommitment) +
                    @sizeOf(H.Hash),
                .trace_decommitments = estimateHashSlice(H, proof.commitments.items) +
                    estimateMerkleDecommitments(H, proof.decommitments.items),
            };
        }
    };
}

/// Reconstructs one secure composition evaluation from recursively ordered
/// coefficient-chunk evaluations.
pub fn reconstructCompositionChunkEvals(
    chunk_evals_in: []const QM31,
    point: CirclePointQM31,
    composition_log_size: u32,
    split_depth: u32,
) ?QM31 {
    const chunk_count = verifier_types.compositionChunkCount(split_depth) orelse
        return null;
    if (composition_log_size <= split_depth or chunk_evals_in.len != chunk_count) {
        return null;
    }

    var chunk_evals: [@as(usize, 1) << verifier_types.MAX_COMPOSITION_LOG_SPLIT]QM31 =
        undefined;
    @memcpy(chunk_evals[0..chunk_count], chunk_evals_in);

    var active = chunk_count;
    var parent_log = composition_log_size - split_depth + 1;
    while (active > 1) {
        const factor = point.repeatedDouble(parent_log - 2).x;
        var out_index: usize = 0;
        var input_index: usize = 0;
        while (input_index < active) : (input_index += 2) {
            chunk_evals[out_index] = chunk_evals[input_index].add(
                factor.mul(chunk_evals[input_index + 1]),
            );
            out_index += 1;
        }
        active /= 2;
        parent_log += 1;
    }
    return chunk_evals[0];
}

pub fn ExtendedStarkProof(comptime H: type) type {
    return struct {
        proof: StarkProof(H),
        aux: pcs.CommitmentSchemeProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

fn estimateQm31Slice(values: []const QM31) usize {
    return values.len * @sizeOf(QM31);
}

fn estimateHashSlice(comptime H: type, values: []const H.Hash) usize {
    return values.len * @sizeOf(H.Hash);
}

fn estimateMerkleDecommitment(
    comptime H: type,
    decommitment: vcs_verifier.MerkleDecommitmentLifted(H),
) usize {
    return estimateHashSlice(H, decommitment.hash_witness);
}

fn estimateMerkleDecommitments(
    comptime H: type,
    decommitments: []const vcs_verifier.MerkleDecommitmentLifted(H),
) usize {
    var total: usize = 0;
    for (decommitments) |decommitment| {
        total += estimateMerkleDecommitment(H, decommitment);
    }
    return total;
}

fn estimateTreeQm31(tree: pcs.TreeVec([][]QM31)) usize {
    var total: usize = 0;
    for (tree.items) |cols| {
        for (cols) |col| total += estimateQm31Slice(col);
    }
    return total;
}

fn estimateTreeM31(tree: pcs.TreeVec([][]M31)) usize {
    var total: usize = 0;
    for (tree.items) |cols| {
        for (cols) |col| total += col.len * @sizeOf(M31);
    }
    return total;
}

fn estimateFriProof(comptime H: type, fri_proof: fri.FriProof(H)) usize {
    var total = estimateQm31Slice(fri_proof.first_layer.fri_witness) +
        estimateMerkleDecommitment(H, fri_proof.first_layer.decommitment) +
        @sizeOf(H.Hash) +
        estimateQm31Slice(fri_proof.last_layer_poly.coefficients());

    for (fri_proof.inner_layers) |layer| {
        total += estimateQm31Slice(layer.fri_witness);
        total += estimateMerkleDecommitment(H, layer.decommitment);
        total += @sizeOf(H.Hash);
    }
    return total;
}

test "stark proof: extract composition oods eval" {
    const alloc = std.testing.allocator;
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;

    const left = [_]QM31{
        QM31.fromBase(M31.fromCanonical(1)),
        QM31.fromBase(M31.fromCanonical(2)),
        QM31.fromBase(M31.fromCanonical(3)),
        QM31.fromBase(M31.fromCanonical(4)),
    };
    const right = [_]QM31{
        QM31.fromBase(M31.fromCanonical(5)),
        QM31.fromBase(M31.fromCanonical(6)),
        QM31.fromBase(M31.fromCanonical(7)),
        QM31.fromBase(M31.fromCanonical(8)),
    };

    const composition_cols = try alloc.alloc([]QM31, 2 * qm31.SECURE_EXTENSION_DEGREE);
    var initialized: usize = 0;
    errdefer {
        for (composition_cols[0..initialized]) |col| alloc.free(col);
        alloc.free(composition_cols);
    }
    var i: usize = 0;
    while (i < composition_cols.len) : (i += 1) {
        composition_cols[i] = try alloc.alloc(QM31, 1);
        composition_cols[i][0] = if (i < qm31.SECURE_EXTENSION_DEGREE) left[i] else right[i - qm31.SECURE_EXTENSION_DEGREE];
        initialized += 1;
    }

    const sampled_values = pcs.TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{composition_cols}),
    );
    var proof = StarkProof(Hasher){
        .commitment_scheme_proof = .{
            .config = pcs.PcsConfig.default(),
            .commitments = pcs.TreeVec(Hasher.Hash).initOwned(try alloc.alloc(Hasher.Hash, 0)),
            .sampled_values = sampled_values,
            .decommitments = pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(
                try alloc.alloc(vcs_verifier.MerkleDecommitmentLifted(Hasher), 0),
            ),
            .queried_values = pcs.TreeVec([][]M31).initOwned(
                try alloc.alloc([][]M31, 0),
            ),
            .proof_of_work = 0,
            .fri_proof = .{
                .first_layer = .{
                    .fri_witness = try alloc.alloc(QM31, 0),
                    .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                    .commitment = [_]u8{0} ** 32,
                },
                .inner_layers = try alloc.alloc(fri.FriLayerProof(Hasher), 0),
                .last_layer_poly = @import("poly/line.zig").LinePoly.initOwned(
                    try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                ),
            },
        },
    };
    defer proof.deinit(alloc);

    const composition_log_size: u32 = 6;
    const oods_point = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const extracted = proof.extractCompositionOodsEval(oods_point, composition_log_size) orelse unreachable;
    const expected = QM31.fromPartialEvals(left).add(
        oods_point.repeatedDouble(composition_log_size - 2).x.mul(QM31.fromPartialEvals(right)),
    );
    try std.testing.expect(extracted.eql(expected));
}

test "stark proof: extract composition oods eval rejects invalid shape" {
    const alloc = std.testing.allocator;
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;

    const bad_cols = try alloc.alloc([]QM31, 2 * qm31.SECURE_EXTENSION_DEGREE - 1);
    var initialized: usize = 0;
    errdefer {
        for (bad_cols[0..initialized]) |col| alloc.free(col);
        alloc.free(bad_cols);
    }
    var i: usize = 0;
    while (i < bad_cols.len) : (i += 1) {
        bad_cols[i] = try alloc.alloc(QM31, 1);
        bad_cols[i][0] = QM31.one();
        initialized += 1;
    }

    const sampled_values = pcs.TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{bad_cols}),
    );
    var proof = StarkProof(Hasher){
        .commitment_scheme_proof = .{
            .config = pcs.PcsConfig.default(),
            .commitments = pcs.TreeVec(Hasher.Hash).initOwned(try alloc.alloc(Hasher.Hash, 0)),
            .sampled_values = sampled_values,
            .decommitments = pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(
                try alloc.alloc(vcs_verifier.MerkleDecommitmentLifted(Hasher), 0),
            ),
            .queried_values = pcs.TreeVec([][]M31).initOwned(
                try alloc.alloc([][]M31, 0),
            ),
            .proof_of_work = 0,
            .fri_proof = .{
                .first_layer = .{
                    .fri_witness = try alloc.alloc(QM31, 0),
                    .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                    .commitment = [_]u8{0} ** 32,
                },
                .inner_layers = try alloc.alloc(fri.FriLayerProof(Hasher), 0),
                .last_layer_poly = @import("poly/line.zig").LinePoly.initOwned(
                    try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                ),
            },
        },
    };
    defer proof.deinit(alloc);

    try std.testing.expect(proof.extractCompositionOodsEval(circle.SECURE_FIELD_CIRCLE_GEN, 4) == null);
}
