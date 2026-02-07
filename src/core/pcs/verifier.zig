const std = @import("std");
const mod_pcs = @import("mod.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");

const PcsConfig = mod_pcs.PcsConfig;
const TreeVec = mod_pcs.TreeVec;

/// Verifier-side state of the PCS commitment phase.
pub fn CommitmentSchemeVerifier(comptime H: type, comptime MC: type) type {
    return struct {
        trees: TreeVec(vcs_verifier.MerkleVerifierLifted(H)),
        config: PcsConfig,

        const Self = @This();
        const MerkleVerifier = vcs_verifier.MerkleVerifierLifted(H);

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

            const verifier = try MerkleVerifier.init(allocator, commitment, extended_log_sizes);
            try appendTree(self, allocator, verifier);
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
    };
}

test "pcs verifier: commit stores extended log sizes and mixes root" {
    const alloc = std.testing.allocator;
    const H = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MC = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    const Channel = @import("../channel/blake2s.zig").Blake2sChannel;
    const Verifier = CommitmentSchemeVerifier(H, MC);

    var channel = Channel{};
    const before = channel.digestBytes();

    var verifier = try Verifier.init(alloc, .{
        .pow_bits = 10,
        .fri_config = try @import("../fri.zig").FriConfig.init(0, 2, 3),
    });
    defer verifier.deinit(alloc);

    const root = [_]u8{7} ** 32;
    try verifier.commit(alloc, root, &[_]u32{ 3, 5 }, &channel);

    try std.testing.expect(!std.mem.eql(u8, before[0..], channel.digestBytes()[0..]));
    try std.testing.expectEqual(@as(usize, 1), verifier.trees.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 5, 7 }, verifier.trees.items[0].column_log_sizes);

    var sizes = try verifier.columnLogSizes(alloc);
    defer sizes.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 1), sizes.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 5, 7 }, sizes.items[0]);
}
