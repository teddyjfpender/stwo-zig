//! Fixed-capacity digest frontier for the isolated aggregation reference.
//! A frontier consumes leaves in canonical order and uses O(log n) storage.

const std = @import("std");
const hash = @import("hash.zig");
const types = @import("types.zig");

pub const MAX_TREE_HEIGHT: usize = 10;

pub const DigestFrontier = struct {
    node_domain: []const u8,
    levels: [MAX_TREE_HEIGHT + 1]?hash.Digest =
        .{null} ** (MAX_TREE_HEIGHT + 1),
    leaf_count: usize = 0,

    pub fn init(node_domain: []const u8) DigestFrontier {
        return .{ .node_domain = node_domain };
    }

    pub fn push(self: *DigestFrontier, leaf: hash.Digest) !void {
        if (self.leaf_count == types.MAX_LEAVES) return error.TooManyLeaves;

        var carry = leaf;
        var occupied = self.leaf_count;
        var level: usize = 0;
        while ((occupied & 1) != 0) : ({
            occupied >>= 1;
            level += 1;
        }) {
            const left = self.levels[level] orelse
                return error.CorruptDigestFrontier;
            carry = hash.hashPair(self.node_domain, left, carry);
            self.levels[level] = null;
        }
        self.levels[level] = carry;
        self.leaf_count += 1;
    }

    pub fn finish(self: *const DigestFrontier) !hash.Digest {
        if (self.leaf_count == 0 or
            !std.math.isPowerOfTwo(self.leaf_count))
        {
            return error.IncompleteDigestTree;
        }
        const root_level: usize = @intCast(@ctz(self.leaf_count));
        const root = self.levels[root_level] orelse
            return error.CorruptDigestFrontier;
        for (self.levels, 0..) |entry, level| {
            if (level != root_level and entry != null) {
                return error.CorruptDigestFrontier;
            }
        }
        return root;
    }
};
