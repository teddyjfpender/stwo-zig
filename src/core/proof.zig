const std = @import("std");
const circle = @import("circle.zig");
const m31 = @import("fields/m31.zig");
const qm31 = @import("fields/qm31.zig");
const fri = @import("fri.zig");
const pcs = @import("pcs/mod.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

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
            if (composition_log_size < 2) return null;
            if (self.commitment_scheme_proof.sampled_values.items.len == 0) return null;

            const masks = self.commitment_scheme_proof.sampled_values.items[
                self.commitment_scheme_proof.sampled_values.items.len - 1
            ];
            const expected_cols = 2 * qm31.SECURE_EXTENSION_DEGREE;
            if (masks.len != expected_cols) return null;

            var left_coords: [qm31.SECURE_EXTENSION_DEGREE]QM31 = undefined;
            var right_coords: [qm31.SECURE_EXTENSION_DEGREE]QM31 = undefined;

            var i: usize = 0;
            while (i < expected_cols) : (i += 1) {
                const col = masks[i];
                if (col.len != 1) return null;
                if (i < qm31.SECURE_EXTENSION_DEGREE) {
                    left_coords[i] = col[0];
                } else {
                    right_coords[i - qm31.SECURE_EXTENSION_DEGREE] = col[0];
                }
            }

            const left_eval = QM31.fromPartialEvals(left_coords);
            const right_eval = QM31.fromPartialEvals(right_coords);
            const x = oods_point.repeatedDouble(composition_log_size - 2).x;
            return left_eval.add(x.mul(right_eval));
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
