const std = @import("std");
const circle = @import("../circle.zig");
const fri = @import("../fri.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const verifier = @import("../verifier.zig");
const mod_pcs = @import("mod.zig");
const quotients = @import("quotients.zig");
const pcs_utils = @import("utils.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const PcsConfig = mod_pcs.PcsConfig;
const TreeVec = mod_pcs.TreeVec;

/// Verifier-side state of the PCS commitment phase.
pub fn CommitmentSchemeVerifier(comptime H: type, comptime MC: type) type {
    return struct {
        trees: TreeVec(vcs_verifier.MerkleVerifierLifted(H)),
        config: PcsConfig,

        const Self = @This();
        const MerkleVerifier = vcs_verifier.MerkleVerifierLifted(H);
        const FriVerifier = fri.FriVerifier(H, MC);
        const CommitmentSchemeProof = mod_pcs.CommitmentSchemeProof(H);

        pub fn init(allocator: std.mem.Allocator, config: PcsConfig) !Self {
            return .{
                .trees = TreeVec(MerkleVerifier).initOwned(try allocator.alloc(MerkleVerifier, 0)),
                .config = config,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.trees.items) |*tree| tree.deinit(allocator);
            self.trees.deinit(allocator);
            self.* = undefined;
        }

        pub fn columnLogSizes(self: Self, allocator: std.mem.Allocator) !TreeVec([]u32) {
            const out = try allocator.alloc([]u32, self.trees.items.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |tree_sizes| allocator.free(tree_sizes);
            }

            for (self.trees.items, 0..) |tree, i| {
                out[i] = try allocator.dupe(u32, tree.column_log_sizes);
                initialized += 1;
            }
            return TreeVec([]u32).initOwned(out);
        }

        /// Reads a commitment from the prover and extends log sizes by FRI blowup.
        pub fn commit(
            self: *Self,
            allocator: std.mem.Allocator,
            commitment: H.Hash,
            log_sizes: []const u32,
            channel: anytype,
        ) !void {
            MC.mixRoot(channel, commitment);

            const extended_log_sizes = try allocator.alloc(u32, log_sizes.len);
            defer allocator.free(extended_log_sizes);
            for (log_sizes, 0..) |log_size, i| {
                extended_log_sizes[i] = log_size + self.config.fri_config.log_blowup_factor;
            }

            const merkle_verifier = try MerkleVerifier.init(allocator, commitment, extended_log_sizes);
            try appendTree(self, allocator, merkle_verifier);
        }

        /// Verifies PCS openings and decommitments end-to-end.
        pub fn verifyValues(
            self: *const Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            proof_in: CommitmentSchemeProof,
            channel: anytype,
        ) (std.mem.Allocator.Error || verifier.VerificationError)!void {
            var sampled_points_owned = sampled_points;
            defer sampled_points_owned.deinitDeep(allocator);

            var proof = proof_in;
            defer cleanupProofWithoutFri(&proof, allocator);

            if (self.trees.items.len == 0) return verifier.VerificationError.EmptyTrees;
            if (proof.decommitments.items.len != self.trees.items.len) return verifier.VerificationError.ShapeMismatch;
            if (proof.queried_values.items.len != self.trees.items.len) return verifier.VerificationError.ShapeMismatch;

            const sampled_values_flat = try flattenSampledValues(allocator, proof.sampled_values);
            defer allocator.free(sampled_values_flat);
            channel.mixFelts(sampled_values_flat);
            const random_coeff = channel.drawSecureFelt();

            var column_log_sizes = try self.columnLogSizes(allocator);
            defer column_log_sizes.deinitDeep(allocator);

            const lifting_log_size = try computeLiftingLogSize(column_log_sizes, sampled_points_owned);
            if (lifting_log_size < self.config.fri_config.log_blowup_factor) {
                return verifier.VerificationError.ShapeMismatch;
            }
            const bound = fri.CirclePolyDegreeBound.init(lifting_log_size - self.config.fri_config.log_blowup_factor);
            var fri_verifier = try FriVerifier.commit(
                allocator,
                channel,
                self.config.fri_config,
                proof.fri_proof,
                bound,
            );
            defer fri_verifier.deinit(allocator);

            if (!channel.verifyPowNonce(self.config.pow_bits, proof.proof_of_work)) {
                return verifier.VerificationError.ProofOfWork;
            }
            channel.mixU64(proof.proof_of_work);

            const query_positions = try fri_verifier.sampleQueryPositions(allocator, channel);
            defer allocator.free(query_positions);

            const pp_max_log_size = if (column_log_sizes.items.len > verifier.PREPROCESSED_TRACE_IDX)
                maxOrDefault(column_log_sizes.items[verifier.PREPROCESSED_TRACE_IDX], 0)
            else
                0;

            const preprocessed_query_positions = try pcs_utils.preparePreprocessedQueryPositions(
                allocator,
                query_positions,
                lifting_log_size,
                pp_max_log_size,
            );
            defer allocator.free(preprocessed_query_positions);

            const query_positions_tree = try allocator.alloc([]const usize, self.trees.items.len);
            defer allocator.free(query_positions_tree);
            for (query_positions_tree, 0..) |*positions, i| {
                positions.* = if (i == verifier.PREPROCESSED_TRACE_IDX)
                    preprocessed_query_positions
                else
                    query_positions;
            }

            for (self.trees.items, 0..) |tree, i| {
                try tree.verify(
                    allocator,
                    query_positions_tree[i],
                    proof.queried_values.items[i],
                    proof.decommitments.items[i],
                );
            }

            var samples = try buildPointSamples(allocator, sampled_points_owned, proof.sampled_values);
            defer samples.deinitDeep(allocator);

            const fri_answers = try quotients.friAnswers(
                allocator,
                column_log_sizes,
                samples,
                random_coeff,
                query_positions,
                proof.queried_values,
                lifting_log_size,
            );
            defer allocator.free(fri_answers);

            try fri_verifier.decommit(allocator, fri_answers);
        }

        fn appendTree(self: *Self, allocator: std.mem.Allocator, tree: MerkleVerifier) !void {
            const old_len = self.trees.items.len;
            const next = try allocator.alloc(MerkleVerifier, old_len + 1);
            errdefer allocator.free(next);
            @memcpy(next[0..old_len], self.trees.items);
            next[old_len] = tree;
            allocator.free(self.trees.items);
            self.trees.items = next;
        }

        fn cleanupProofWithoutFri(proof: *CommitmentSchemeProof, allocator: std.mem.Allocator) void {
            proof.commitments.deinit(allocator);
            proof.sampled_values.deinitDeep(allocator);
            for (proof.decommitments.items) |*decommitment| decommitment.deinit(allocator);
            proof.decommitments.deinit(allocator);
            proof.queried_values.deinitDeep(allocator);
            proof.* = undefined;
        }
    };
}

fn maxOrDefault(values: []const u32, default: u32) u32 {
    var out = default;
    for (values) |value| out = @max(out, value);
    return out;
}

fn flattenSampledValues(
    allocator: std.mem.Allocator,
    sampled_values: TreeVec([][]QM31),
) ![]QM31 {
    var total: usize = 0;
    for (sampled_values.items) |tree| {
        for (tree) |column| total += column.len;
    }

    const out = try allocator.alloc(QM31, total);
    var at: usize = 0;
    for (sampled_values.items) |tree| {
        for (tree) |column| {
            @memcpy(out[at .. at + column.len], column);
            at += column.len;
        }
    }
    return out;
}

fn computeLiftingLogSize(
    column_log_sizes: TreeVec([]u32),
    sampled_points: TreeVec([][]CirclePointQM31),
) verifier.VerificationError!u32 {
    if (column_log_sizes.items.len != sampled_points.items.len) return verifier.VerificationError.ShapeMismatch;

    var max_log_size: ?u32 = null;
    for (column_log_sizes.items, sampled_points.items) |sizes_per_tree, points_per_tree| {
        if (sizes_per_tree.len != points_per_tree.len) return verifier.VerificationError.ShapeMismatch;
        for (sizes_per_tree, points_per_tree) |log_size, points| {
            if (points.len == 0) continue;
            max_log_size = if (max_log_size) |cur| @max(cur, log_size) else log_size;
        }
    }
    return max_log_size orelse verifier.VerificationError.EmptySampledSet;
}

fn buildPointSamples(
    allocator: std.mem.Allocator,
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
) (std.mem.Allocator.Error || verifier.VerificationError)!TreeVec([][]quotients.PointSample) {
    if (sampled_points.items.len != sampled_values.items.len) return verifier.VerificationError.ShapeMismatch;

    var trees_builder = std.ArrayList([][]quotients.PointSample).init(allocator);
    defer trees_builder.deinit();
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        }
    }

    for (sampled_points.items, sampled_values.items) |points_per_tree, values_per_tree| {
        if (points_per_tree.len != values_per_tree.len) return verifier.VerificationError.ShapeMismatch;
        var cols_builder = std.ArrayList([]quotients.PointSample).init(allocator);
        defer cols_builder.deinit();
        errdefer {
            for (cols_builder.items) |column| allocator.free(column);
        }

        for (points_per_tree, values_per_tree) |points_col, values_col| {
            if (points_col.len != values_col.len) return verifier.VerificationError.ShapeMismatch;
            const out_col = try allocator.alloc(quotients.PointSample, points_col.len);
            errdefer allocator.free(out_col);
            for (points_col, values_col, 0..) |point, value, i| {
                out_col[i] = .{ .point = point, .value = value };
            }
            try cols_builder.append(out_col);
        }
        try trees_builder.append(try cols_builder.toOwnedSlice());
    }

    return TreeVec([][]quotients.PointSample).initOwned(try trees_builder.toOwnedSlice());
}

test "pcs verifier: commit stores extended log sizes and mixes root" {
    const alloc = std.testing.allocator;
    const H = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MC = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../channel/blake2s.zig").Blake2sChannel;
    const Verifier = CommitmentSchemeVerifier(H, MC);

    var channel = Channel{};
    const before = channel.digestBytes();

    var verifier_instance = try Verifier.init(alloc, .{
        .pow_bits = 10,
        .fri_config = try fri.FriConfig.init(0, 2, 3),
    });
    defer verifier_instance.deinit(alloc);

    const root = [_]u8{7} ** 32;
    try verifier_instance.commit(alloc, root, &[_]u32{ 3, 5 }, &channel);

    try std.testing.expect(!std.mem.eql(u8, before[0..], channel.digestBytes()[0..]));
    try std.testing.expectEqual(@as(usize, 1), verifier_instance.trees.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 5, 7 }, verifier_instance.trees.items[0].column_log_sizes);

    var sizes = try verifier_instance.columnLogSizes(alloc);
    defer sizes.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 1), sizes.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 5, 7 }, sizes.items[0]);
}

test "pcs verifier: verify_values fails on invalid proof-of-work" {
    const alloc = std.testing.allocator;
    const H = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MC = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../channel/blake2s.zig").Blake2sChannel;
    const Verifier = CommitmentSchemeVerifier(H, MC);
    const Proof = mod_pcs.CommitmentSchemeProof(H);

    var verifier_instance = try Verifier.init(alloc, .{
        .pow_bits = 129,
        .fri_config = try fri.FriConfig.init(0, 1, 2),
    });
    defer verifier_instance.deinit(alloc);

    var commit_channel = Channel{};
    try verifier_instance.commit(alloc, [_]u8{1} ** 32, &[_]u32{1}, &commit_channel);

    const sampled_points_col = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
    });
    const sampled_points_tree = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{sampled_points_col});
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{sampled_points_tree}),
    );

    const sampled_values_col = try alloc.dupe(QM31, &[_]QM31{QM31.fromU32Unchecked(1, 2, 3, 4)});
    const sampled_values_tree = try alloc.dupe([]QM31, &[_][]QM31{sampled_values_col});
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{sampled_values_tree}),
    );

    const queried_values_col = try alloc.dupe(M31, &[_]M31{M31.fromCanonical(5)});
    const queried_values_tree = try alloc.dupe([]M31, &[_][]M31{queried_values_col});
    const queried_values = TreeVec([][]M31).initOwned(
        try alloc.dupe([][]M31, &[_][][]M31{queried_values_tree}),
    );

    const decommitments = TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)).initOwned(
        try alloc.dupe(vcs_verifier.MerkleDecommitmentLifted(H), &[_]vcs_verifier.MerkleDecommitmentLifted(H){
            .{ .hash_witness = try alloc.alloc(H.Hash, 0) },
        }),
    );

    const commitments = TreeVec(H.Hash).initOwned(try alloc.dupe(H.Hash, &[_]H.Hash{
        [_]u8{1} ** 32,
    }));

    var channel = Channel{};
    try std.testing.expectError(
        verifier.VerificationError.ProofOfWork,
        verifier_instance.verifyValues(
            alloc,
            sampled_points,
            Proof{
                .config = verifier_instance.config,
                .commitments = commitments,
                .sampled_values = sampled_values,
                .decommitments = decommitments,
                .queried_values = queried_values,
                .proof_of_work = 0,
                .fri_proof = .{
                    .first_layer = .{
                        .fri_witness = try alloc.alloc(QM31, 0),
                        .decommitment = .{ .hash_witness = try alloc.alloc(H.Hash, 0) },
                        .commitment = [_]u8{3} ** 32,
                    },
                    .inner_layers = try alloc.alloc(fri.FriLayerProof(H), 0),
                    .last_layer_poly = @import("../poly/line.zig").LinePoly.initOwned(
                        try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                    ),
                },
            },
            &channel,
        ),
    );
}
