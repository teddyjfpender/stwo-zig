//! PCS configuration of the `proving_5a7c5ed` protocol revision.
//!
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 vendors stwo `7b211ed` plus a
//! PcsConfig refactor that changes the transcript:
//!
//! - proof-of-work bits live in the FRI config (`core/fri.rs::FriConfig`);
//! - the FRI config always mixes two felts,
//!   `[(pow_bits, log_blowup, n_queries, log_last_layer), (fold_step, 0, 0, 0)]`;
//! - `PcsConfig` carries two explicit lifting heights, one for the
//!   preprocessed tree and one for every other tree, and is itself never
//!   mixed (`core/pcs/mod.rs`).
//!
//! The existing `pcs.PcsConfig` and its transcript stay untouched; lanes pick
//! this type through `protocol_revision.Revision.proving_5a7c5ed`.

const std = @import("std");
const fri_config = @import("../fri/config.zig");
const qm31 = @import("../fields/qm31.zig");

const QM31 = qm31.QM31;
const LegacyFriConfig = fri_config.FriConfig;

/// Index of the preprocessed tree (`PREPROCESSED_TRACE_IDX`).
pub const preprocessed_tree_index: usize = 0;

pub const FriConfigV2 = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    fold_step: u32,

    pub const Error = LegacyFriConfig.Error || error{InvalidFoldStep};

    /// `FriConfig::new`, with upstream's range assertions returned as errors.
    pub fn init(
        pow_bits: u32,
        log_last_layer_degree_bound: u32,
        log_blowup_factor: u32,
        n_queries: u32,
        fold_step: u32,
    ) Error!FriConfigV2 {
        _ = try LegacyFriConfig.init(log_last_layer_degree_bound, log_blowup_factor, n_queries);
        if (fold_step == 0) return error.InvalidFoldStep;
        return .{
            .pow_bits = pow_bits,
            .log_blowup_factor = log_blowup_factor,
            .log_last_layer_degree_bound = log_last_layer_degree_bound,
            .n_queries = n_queries,
            .fold_step = fold_step,
        };
    }

    /// Always two felts, independent of `fold_step`.
    pub fn mixInto(self: FriConfigV2, channel: anytype) void {
        channel.mixFelts(&[_]QM31{
            QM31.fromU32Unchecked(self.pow_bits, self.log_blowup_factor, self.n_queries, self.log_last_layer_degree_bound),
            QM31.fromU32Unchecked(self.fold_step, 0, 0, 0),
        });
    }

    pub fn securityBits(self: FriConfigV2) u32 {
        return self.pow_bits + self.log_blowup_factor * self.n_queries;
    }

    /// The folding parameters without proof of work, for the FRI prover and
    /// verifier, which take PoW bits from the PCS layer.
    pub fn folding(self: FriConfigV2) LegacyFriConfig {
        return .{
            .log_blowup_factor = self.log_blowup_factor,
            .log_last_layer_degree_bound = self.log_last_layer_degree_bound,
            .n_queries = self.n_queries,
            .fold_step = self.fold_step,
        };
    }
};

pub const PcsConfigV2 = struct {
    fri_config: FriConfigV2,
    /// Height of every committed tree except the preprocessed one. It already
    /// includes `log_blowup_factor`.
    trace_lifting_log_size: u32,
    /// Height of tree `preprocessed_tree_index`.
    preprocessed_lifting_log_size: u32,

    pub const Error = error{ InvalidTreeHeight, InvalidLiftingLogSize };

    /// Every tree, the preprocessed one included, lifted to the trace's
    /// extended domain (`from_fri_and_trace_size`).
    pub fn fromFriAndTraceSize(config: FriConfigV2, trace_log_size: u32) PcsConfigV2 {
        return fromFriAndLiftingSize(config, trace_log_size + config.log_blowup_factor);
    }

    /// Every tree lifted to `lifting_log_size`, which already includes the
    /// blowup (`from_fri_and_lifting_size`).
    pub fn fromFriAndLiftingSize(config: FriConfigV2, lifting_log_size: u32) PcsConfigV2 {
        return .{
            .fri_config = config,
            .trace_lifting_log_size = lifting_log_size,
            .preprocessed_lifting_log_size = lifting_log_size,
        };
    }

    /// The height the `tree_index`-th committed tree is lifted to.
    pub fn liftingLogSize(self: PcsConfigV2, tree_index: usize) u32 {
        if (tree_index == preprocessed_tree_index) return self.preprocessed_lifting_log_size;
        return self.trace_lifting_log_size;
    }

    /// Merkle height of the `tree_index`-th tree given its extended column
    /// log sizes: always the configured lifting height. Upstream commits and
    /// verifies every tree at `lifting_log_size(tree_index)`
    /// (`CommitmentSchemeProver::commit` and `CommitmentSchemeVerifier::commit`
    /// in `crates/stwo/src/{prover,core}/pcs`), and `MerkleProverLifted::commit`
    /// and `MerkleVerifierLifted::new` assert that the height dominates every
    /// column and is 0 when there are none. An empty tree is therefore valid
    /// only under a zero lifting height, as in the upstream examples that set
    /// `preprocessed_lifting_log_size: 0` without preprocessed columns; any
    /// other height is `error.InvalidTreeHeight`, never a silent 0.
    pub fn treeHeight(self: PcsConfigV2, tree_index: usize, extended_log_sizes: []const u32) Error!u32 {
        const height = self.liftingLogSize(tree_index);
        if (extended_log_sizes.len == 0 and height != 0) return error.InvalidTreeHeight;
        for (extended_log_sizes) |log_size| {
            if (log_size > height) return error.InvalidTreeHeight;
        }
        return height;
    }

    /// Lifting height of the FRI input (`verify_ex` in `core/verifier.rs`).
    ///
    /// With `include_all_preprocessed_columns` the trace height may not be
    /// below the committed preprocessed height. The composition tree is a
    /// trace tree, so `max` with its split degree bound is a no-op for every
    /// supported AIR; it is kept because upstream keeps it.
    pub fn finalLiftingLogSize(
        self: PcsConfigV2,
        preprocessed_tree_height: u32,
        include_all_preprocessed_columns: bool,
        split_composition_log_degree_bound: u32,
    ) Error!u32 {
        if (include_all_preprocessed_columns and self.trace_lifting_log_size < preprocessed_tree_height)
            return error.InvalidLiftingLogSize;
        return @max(
            self.trace_lifting_log_size,
            split_composition_log_degree_bound + self.fri_config.log_blowup_factor,
        );
    }
};

const channel_blake2s = @import("../channel/blake2s.zig");

fn expectDigestHex(expected: *const [64]u8, digest: [32]u8) !void {
    try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(digest, .lower));
}

test "pcs config v2: FRI mix matches proving@5a7c5ed on both Blake2s channels" {
    // Oracle: `FriConfig::new(26, 0, 1, 70, 4).mix_into(&mut C::default())`,
    // proving@5a7c5ed crates/stwo (the production circuit FRI config).
    const config = try FriConfigV2.init(26, 0, 1, 70, 4);
    var plain = channel_blake2s.Blake2sChannel{};
    config.mixInto(&plain);
    try expectDigestHex("54eb2c5200f192007d8034e03112037a8dc2438073d5fe0c16ca7422a8cfb3d6", plain.digestBytes());
    var reduced = channel_blake2s.Blake2sM31Channel{};
    config.mixInto(&reduced);
    try expectDigestHex("54eb2c5200f192007e8034603112037a8ec2430073d5fe0c16ca7422a9cfb356", reduced.digestBytes());
}

test "pcs config v2: fold step one still mixes two felts" {
    // The legacy PcsConfig mixes one felt for fold_step 1 without lifting;
    // this revision never does.
    const config = try FriConfigV2.init(10, 0, 1, 3, 1);
    var actual = channel_blake2s.Blake2sChannel{};
    config.mixInto(&actual);
    var expected = channel_blake2s.Blake2sChannel{};
    expected.mixFelts(&.{ QM31.fromU32Unchecked(10, 1, 3, 0), QM31.fromU32Unchecked(1, 0, 0, 0) });
    try std.testing.expectEqualSlices(u8, &expected.digestBytes(), &actual.digestBytes());
}

test "pcs config v2: constructor validates like FriConfig::new" {
    try std.testing.expectError(error.InvalidLastLayerDegreeBound, FriConfigV2.init(0, 11, 1, 3, 1));
    try std.testing.expectError(error.InvalidBlowupFactor, FriConfigV2.init(0, 0, 0, 3, 1));
    try std.testing.expectError(error.InvalidBlowupFactor, FriConfigV2.init(0, 0, 17, 3, 1));
    try std.testing.expectError(error.InvalidFoldStep, FriConfigV2.init(0, 0, 1, 3, 0));
    // `config_tests::test_security_bits`.
    try std.testing.expectEqual(@as(u32, 10 * 70 + 42), (try FriConfigV2.init(42, 10, 10, 70, 1)).securityBits());
}

test "pcs config v2: an empty tree needs a zero lifting height" {
    // `MerkleProverLifted::commit` and `MerkleVerifierLifted::new` assert
    // `lifting_log_size == 0` when no columns are committed; the PCS passes
    // `lifting_log_size(tree_index)` unchanged, so an empty tree under a
    // nonzero configured height is rejected upstream, not given height 0.
    const fri = try FriConfigV2.init(26, 0, 1, 70, 4);
    const no_preprocessed = PcsConfigV2{ .fri_config = fri, .trace_lifting_log_size = 24, .preprocessed_lifting_log_size = 0 };
    try std.testing.expectEqual(@as(u32, 0), try no_preprocessed.treeHeight(0, &.{}));
    try std.testing.expectError(error.InvalidTreeHeight, no_preprocessed.treeHeight(0, &.{1}));
    try std.testing.expectError(error.InvalidTreeHeight, no_preprocessed.treeHeight(2, &.{}));
    const uniform = PcsConfigV2.fromFriAndTraceSize(fri, 20);
    try std.testing.expectError(error.InvalidTreeHeight, uniform.treeHeight(0, &.{}));
}

test "pcs config v2: per-tree heights and the final lifting rule" {
    const fri = try FriConfigV2.init(26, 0, 1, 70, 4);
    const uniform = PcsConfigV2.fromFriAndTraceSize(fri, 20);
    try std.testing.expectEqual(@as(u32, 21), uniform.liftingLogSize(0));
    try std.testing.expectEqual(@as(u32, 21), uniform.liftingLogSize(3));

    const split = PcsConfigV2{ .fri_config = fri, .trace_lifting_log_size = 24, .preprocessed_lifting_log_size = 21 };
    try std.testing.expectEqual(@as(u32, 21), try split.treeHeight(0, &.{ 5, 21 }));
    try std.testing.expectEqual(@as(u32, 24), try split.treeHeight(1, &.{ 5, 9 }));
    try std.testing.expectError(error.InvalidTreeHeight, split.treeHeight(0, &.{22}));

    try std.testing.expectEqual(@as(u32, 24), try split.finalLiftingLogSize(21, true, 23));
    try std.testing.expectEqual(@as(u32, 26), try split.finalLiftingLogSize(21, false, 25));
    const short = PcsConfigV2{ .fri_config = fri, .trace_lifting_log_size = 20, .preprocessed_lifting_log_size = 21 };
    try std.testing.expectError(error.InvalidLiftingLogSize, short.finalLiftingLogSize(21, true, 19));
    try std.testing.expectEqual(@as(u32, 20), try short.finalLiftingLogSize(21, false, 19));
}
