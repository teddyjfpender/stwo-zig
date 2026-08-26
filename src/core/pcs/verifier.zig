const std = @import("std");
const circle = @import("../circle.zig");
const fri = @import("../fri.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const verifier_types = @import("../verifier_types.zig");
const mod_pcs = @import("mod.zig");
const quotients = @import("quotients.zig");
const pcs_utils = @import("utils.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const PcsConfig = mod_pcs.PcsConfig;
const TreeVec = mod_pcs.TreeVec;

pub const QueryCapture = fri.SampledQueryPositions;

/// Transcript challenges drawn before PCS opening verification and retained
/// only for a successful fixed-recursion capture. The PCS verifier adds its
/// own DEEP randomness draw to the published capture.
pub const ProofCaptureChallenges = struct {
    composition_randomness: QM31,
    oods_seed: QM31,
};

/// Canonical proof material reconstructed by successful native verification.
/// Dynamic multiproofs are expanded to one queried-value and Merkle-path slot
/// per raw transcript query, ready for a fixed recursive witness adapter.
pub fn VerifiedProofCapture(comptime H: type) type {
    return struct {
        queries: QueryCapture,
        commitments: []H.Hash,
        /// Verifier-owned, FRI-extended column logs in commitment-tree order.
        column_log_sizes: [][]u32,
        /// Exact verifier-generated OODS mask points in tree/column/sample
        /// order. These are retained as profile evidence for recursive DEEP
        /// circuit construction; they are never decoded from proof bytes.
        sampled_points: [][][]CirclePointQM31,
        sampled_values: []QM31,
        queried_values: []M31,
        /// DEEP answers in raw transcript-query order, including duplicates.
        deep_answers: []QM31,
        trace_paths: []vcs_verifier.MerklePathCapture(H),
        fri: fri.FriQueryCapture(H),
        last_layer_coefficients: []QM31,
        proof_of_work: u64,
        composition_randomness: QM31,
        oods_seed: QM31,
        deep_randomness: QM31,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.queries.deinit(allocator);
            allocator.free(self.commitments);
            for (self.column_log_sizes) |logs| allocator.free(logs);
            allocator.free(self.column_log_sizes);
            freeSampledPoints(allocator, self.sampled_points);
            allocator.free(self.sampled_values);
            allocator.free(self.queried_values);
            allocator.free(self.deep_answers);
            for (self.trace_paths) |*path| path.deinit(allocator);
            allocator.free(self.trace_paths);
            self.fri.deinit(allocator);
            allocator.free(self.last_layer_coefficients);
            self.* = undefined;
        }
    };
}

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

            var merkle_verifier = try MerkleVerifier.init(allocator, commitment, extended_log_sizes);
            errdefer merkle_verifier.deinit(allocator);
            try appendTree(self, allocator, merkle_verifier);
        }

        /// Verifies PCS openings and decommitments end-to-end.
        pub fn verifyValues(
            self: *const Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            proof_in: CommitmentSchemeProof,
            channel: anytype,
        ) (std.mem.Allocator.Error || verifier_types.VerificationError)!void {
            return self.verifyValuesImpl(
                allocator,
                sampled_points,
                proof_in,
                channel,
                null,
                null,
                null,
            );
        }

        /// Verifies the complete PCS proof and, only on success, publishes the
        /// exact raw and unique query positions sampled by the verifier.
        pub fn verifyValuesWithQueryCapture(
            self: *const Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            proof_in: CommitmentSchemeProof,
            channel: anytype,
            capture: *QueryCapture,
        ) (std.mem.Allocator.Error || verifier_types.VerificationError)!void {
            return self.verifyValuesImpl(
                allocator,
                sampled_points,
                proof_in,
                channel,
                capture,
                null,
                null,
            );
        }

        /// Verifies the complete PCS proof and transactionally publishes all
        /// material needed by a fixed-width recursive witness.
        pub fn verifyValuesWithProofCapture(
            self: *const Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            proof_in: CommitmentSchemeProof,
            channel: anytype,
            challenges: ProofCaptureChallenges,
            capture: *VerifiedProofCapture(H),
        ) (std.mem.Allocator.Error || verifier_types.VerificationError)!void {
            return self.verifyValuesImpl(
                allocator,
                sampled_points,
                proof_in,
                channel,
                null,
                capture,
                challenges,
            );
        }

        fn verifyValuesImpl(
            self: *const Self,
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            proof_in: CommitmentSchemeProof,
            channel: anytype,
            capture_out: ?*QueryCapture,
            proof_capture_out: ?*VerifiedProofCapture(H),
            proof_capture_challenges: ?ProofCaptureChallenges,
        ) (std.mem.Allocator.Error || verifier_types.VerificationError)!void {
            var sampled_points_owned = sampled_points;
            defer sampled_points_owned.deinitDeep(allocator);

            var proof = proof_in;
            defer cleanupProof(&proof, allocator);

            if (self.trees.items.len == 0) return verifier_types.VerificationError.EmptyTrees;
            if (proof.decommitments.items.len != self.trees.items.len) return verifier_types.VerificationError.ShapeMismatch;
            if (proof.queried_values.items.len != self.trees.items.len) return verifier_types.VerificationError.ShapeMismatch;
            if (capture_out != null and proof_capture_out != null)
                return verifier_types.VerificationError.InvalidStructure;
            if ((proof_capture_out == null) != (proof_capture_challenges == null))
                return verifier_types.VerificationError.InvalidStructure;

            const sampled_values_flat = try flattenSampledValues(allocator, proof.sampled_values);
            defer allocator.free(sampled_values_flat);
            channel.mixFelts(sampled_values_flat);
            const deep_randomness = channel.drawSecureFelt();

            var column_log_sizes = try self.columnLogSizes(allocator);
            defer column_log_sizes.deinitDeep(allocator);

            const lifting_log_size = try computeLiftingLogSize(column_log_sizes, sampled_points_owned);
            if (lifting_log_size < self.config.fri_config.log_blowup_factor) {
                return verifier_types.VerificationError.ShapeMismatch;
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
                return verifier_types.VerificationError.ProofOfWork;
            }
            channel.mixU64(proof.proof_of_work);

            var query_capture = try fri_verifier.sampleQueryPositionsWithRaw(
                allocator,
                channel,
            );
            var query_capture_owned = true;
            defer if (query_capture_owned) query_capture.deinit(allocator);
            const query_positions = query_capture.unique;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_VERIFIER_DECOMMIT"))
                std.debug.print("verifier_sampled_queries={any}\n", .{query_positions});

            const query_positions_tree = try allocator.alloc([]const usize, self.trees.items.len);
            var query_trees_initialized: usize = 0;
            defer {
                for (query_positions_tree[0..query_trees_initialized]) |positions| {
                    allocator.free(positions);
                }
                allocator.free(query_positions_tree);
            }
            for (query_positions_tree, 0..) |*positions, i| {
                const tree_log_size: ?u32 =
                    if (column_log_sizes.items[i].len == 0)
                        null
                    else
                        maxOrDefault(column_log_sizes.items[i], 0);
                positions.* = try pcs_utils.prepareTreeQueryPositions(
                    allocator,
                    query_positions,
                    lifting_log_size,
                    tree_log_size,
                );
                query_trees_initialized += 1;
            }

            const trace_paths = if (proof_capture_out != null)
                try allocator.alloc(
                    vcs_verifier.MerklePathCapture(H),
                    self.trees.items.len,
                )
            else
                null;
            var trace_paths_initialized: usize = 0;
            var trace_paths_owned = trace_paths != null;
            defer if (trace_paths_owned) if (trace_paths) |paths| {
                for (paths[0..trace_paths_initialized]) |*path| path.deinit(allocator);
                allocator.free(paths);
            };

            var expanded_queried_values = std.ArrayList(M31).empty;
            defer expanded_queried_values.deinit(allocator);

            for (self.trees.items, 0..) |tree, i| {
                if (proof_capture_out != null) {
                    const tree_log_size: ?u32 =
                        if (column_log_sizes.items[i].len == 0)
                            null
                        else
                            maxOrDefault(column_log_sizes.items[i], 0);
                    const raw_tree_positions = try pcs_utils.prepareTreeQueryPositions(
                        allocator,
                        query_capture.raw,
                        lifting_log_size,
                        tree_log_size,
                    );
                    defer allocator.free(raw_tree_positions);
                    var raw_columns = try expandQueriedColumns(
                        allocator,
                        proof.queried_values.items[i],
                        query_capture.raw,
                        query_capture.unique,
                    );
                    defer raw_columns.deinitDeep(allocator);

                    tree.verifyWithPathCapture(
                        allocator,
                        raw_tree_positions,
                        raw_columns.items,
                        proof.decommitments.items[i],
                        &trace_paths.?[i],
                    ) catch |err| {
                        std.log.err("PCS Merkle verification failed for tree {d}: {s}", .{ i, @errorName(err) });
                        return err;
                    };
                    trace_paths_initialized += 1;
                    for (raw_columns.items) |column| {
                        try expanded_queried_values.appendSlice(allocator, column);
                    }
                } else {
                    tree.verify(
                        allocator,
                        query_positions_tree[i],
                        proof.queried_values.items[i],
                        proof.decommitments.items[i],
                    ) catch |err| {
                        std.log.err("PCS Merkle verification failed for tree {d}: {s}", .{ i, @errorName(err) });
                        return err;
                    };
                }
            }

            const fri_answers = try quotients.friAnswers(
                allocator,
                column_log_sizes,
                sampled_points_owned,
                proof.sampled_values,
                deep_randomness,
                query_positions,
                proof.queried_values,
                lifting_log_size,
            );
            defer allocator.free(fri_answers);

            var fri_capture: fri.FriQueryCapture(H) = undefined;
            var fri_capture_owned = false;
            defer if (fri_capture_owned) fri_capture.deinit(allocator);
            if (proof_capture_out != null) {
                fri_verifier.decommitWithQueryCapture(
                    allocator,
                    fri_answers,
                    query_capture.raw,
                    &fri_capture,
                ) catch |err| {
                    std.log.err("FRI verification failed: {s}", .{@errorName(err)});
                    return err;
                };
                fri_capture_owned = true;
            } else {
                fri_verifier.decommit(allocator, fri_answers) catch |err| {
                    std.log.err("FRI verification failed: {s}", .{@errorName(err)});
                    return err;
                };
            }

            if (capture_out) |capture| {
                capture.* = query_capture;
                query_capture_owned = false;
            }
            if (proof_capture_out) |destination| {
                const commitments = try allocator.dupe(
                    H.Hash,
                    proof.commitments.items,
                );
                errdefer allocator.free(commitments);
                const captured_column_log_sizes = try duplicateColumnLogSizes(
                    allocator,
                    column_log_sizes.items,
                );
                errdefer freeColumnLogSizes(allocator, captured_column_log_sizes);
                const captured_sampled_points = try duplicateSampledPoints(
                    allocator,
                    sampled_points_owned.items,
                );
                errdefer freeSampledPoints(allocator, captured_sampled_points);
                const sampled_values = try allocator.dupe(
                    QM31,
                    sampled_values_flat,
                );
                errdefer allocator.free(sampled_values);
                const queried_values = try expanded_queried_values.toOwnedSlice(
                    allocator,
                );
                errdefer allocator.free(queried_values);
                const deep_answers = try expandQueryValues(
                    allocator,
                    fri_answers,
                    query_capture.raw,
                    query_capture.unique,
                );
                errdefer allocator.free(deep_answers);
                const last_layer_coefficients = try allocator.dupe(
                    QM31,
                    proof.fri_proof.last_layer_poly.coefficients(),
                );
                errdefer allocator.free(last_layer_coefficients);

                destination.* = .{
                    .queries = query_capture,
                    .commitments = commitments,
                    .column_log_sizes = captured_column_log_sizes,
                    .sampled_points = captured_sampled_points,
                    .sampled_values = sampled_values,
                    .queried_values = queried_values,
                    .deep_answers = deep_answers,
                    .trace_paths = trace_paths.?,
                    .fri = fri_capture,
                    .last_layer_coefficients = last_layer_coefficients,
                    .proof_of_work = proof.proof_of_work,
                    .composition_randomness = proof_capture_challenges.?.composition_randomness,
                    .oods_seed = proof_capture_challenges.?.oods_seed,
                    .deep_randomness = deep_randomness,
                };
                query_capture_owned = false;
                trace_paths_owned = false;
                fri_capture_owned = false;
            }
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

        fn cleanupProof(proof: *CommitmentSchemeProof, allocator: std.mem.Allocator) void {
            proof.commitments.deinit(allocator);
            proof.sampled_values.deinitDeep(allocator);
            for (proof.decommitments.items) |*decommitment| decommitment.deinit(allocator);
            proof.decommitments.deinit(allocator);
            proof.queried_values.deinitDeep(allocator);
            proof.fri_proof.deinit(allocator);
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

fn duplicateColumnLogSizes(
    allocator: std.mem.Allocator,
    source: []const []u32,
) ![][]u32 {
    const result = try allocator.alloc([]u32, source.len);
    errdefer allocator.free(result);
    var initialized: usize = 0;
    errdefer for (result[0..initialized]) |logs| allocator.free(logs);
    for (source, result) |logs, *destination| {
        destination.* = try allocator.dupe(u32, logs);
        initialized += 1;
    }
    return result;
}

fn freeColumnLogSizes(allocator: std.mem.Allocator, values: [][]u32) void {
    for (values) |logs| allocator.free(logs);
    allocator.free(values);
}

fn duplicateSampledPoints(
    allocator: std.mem.Allocator,
    source: []const [][]CirclePointQM31,
) ![][][]CirclePointQM31 {
    const trees = try allocator.alloc([][]CirclePointQM31, source.len);
    errdefer allocator.free(trees);
    var tree_count: usize = 0;
    errdefer {
        for (trees[0..tree_count]) |columns| {
            for (columns) |points| allocator.free(points);
            allocator.free(columns);
        }
    }
    for (source, trees) |source_columns, *destination_columns| {
        destination_columns.* = try allocator.alloc(
            []CirclePointQM31,
            source_columns.len,
        );
        var column_count: usize = 0;
        errdefer {
            for (destination_columns.*[0..column_count]) |points|
                allocator.free(points);
            allocator.free(destination_columns.*);
        }
        for (source_columns, destination_columns.*) |points, *destination| {
            destination.* = try allocator.dupe(CirclePointQM31, points);
            column_count += 1;
        }
        tree_count += 1;
    }
    return trees;
}

fn freeSampledPoints(
    allocator: std.mem.Allocator,
    values: [][][]CirclePointQM31,
) void {
    for (values) |columns| {
        for (columns) |points| allocator.free(points);
        allocator.free(columns);
    }
    allocator.free(values);
}

fn expandQueriedColumns(
    allocator: std.mem.Allocator,
    unique_columns: []const []M31,
    raw_positions: []const usize,
    unique_positions: []const usize,
) (std.mem.Allocator.Error || verifier_types.VerificationError)!TreeVec([]M31) {
    const columns = try allocator.alloc([]M31, unique_columns.len);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }

    for (unique_columns, 0..) |unique_column, column_index| {
        if (unique_column.len != unique_positions.len)
            return verifier_types.VerificationError.ShapeMismatch;
        columns[column_index] = try allocator.alloc(M31, raw_positions.len);
        initialized += 1;
        for (raw_positions, 0..) |position, raw_index| {
            const unique_index = findSortedPosition(unique_positions, position) orelse
                return verifier_types.VerificationError.ShapeMismatch;
            columns[column_index][raw_index] = unique_column[unique_index];
        }
    }
    return TreeVec([]M31).initOwned(columns);
}

fn expandQueryValues(
    allocator: std.mem.Allocator,
    unique_values: []const QM31,
    raw_positions: []const usize,
    unique_positions: []const usize,
) (std.mem.Allocator.Error || verifier_types.VerificationError)![]QM31 {
    if (unique_values.len != unique_positions.len)
        return verifier_types.VerificationError.ShapeMismatch;
    const result = try allocator.alloc(QM31, raw_positions.len);
    errdefer allocator.free(result);
    for (raw_positions, 0..) |position, raw_index| {
        const unique_index = findSortedPosition(unique_positions, position) orelse
            return verifier_types.VerificationError.ShapeMismatch;
        result[raw_index] = unique_values[unique_index];
    }
    return result;
}

fn findSortedPosition(positions: []const usize, target: usize) ?usize {
    var left: usize = 0;
    var right: usize = positions.len;
    while (left < right) {
        const middle = left + (right - left) / 2;
        if (positions[middle] < target) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left < positions.len and positions[left] == target) return left;
    return null;
}

fn computeLiftingLogSize(
    column_log_sizes: TreeVec([]u32),
    sampled_points: TreeVec([][]CirclePointQM31),
) verifier_types.VerificationError!u32 {
    if (column_log_sizes.items.len != sampled_points.items.len) return verifier_types.VerificationError.ShapeMismatch;

    var max_log_size: ?u32 = null;
    for (column_log_sizes.items, sampled_points.items) |sizes_per_tree, points_per_tree| {
        if (sizes_per_tree.len != points_per_tree.len) return verifier_types.VerificationError.ShapeMismatch;
        for (sizes_per_tree, points_per_tree) |log_size, points| {
            if (points.len == 0) continue;
            max_log_size = if (max_log_size) |cur| @max(cur, log_size) else log_size;
        }
    }
    return max_log_size orelse verifier_types.VerificationError.EmptySampledSet;
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

fn exerciseCommitAllocationFailures(allocator: std.mem.Allocator) !void {
    const H = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MC = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../channel/blake2s.zig").Blake2sChannel;
    const Verifier = CommitmentSchemeVerifier(H, MC);

    var verifier_instance = try Verifier.init(allocator, .{
        .pow_bits = 10,
        .fri_config = try fri.FriConfig.init(0, 2, 3),
    });
    defer verifier_instance.deinit(allocator);

    var channel = Channel{};
    try verifier_instance.commit(
        allocator,
        [_]u8{7} ** 32,
        &[_]u32{ 3, 5 },
        &channel,
    );
}

test "pcs verifier: commit releases the unappended tree on every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseCommitAllocationFailures,
        .{},
    );
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
        verifier_types.VerificationError.ProofOfWork,
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
