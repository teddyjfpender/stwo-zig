//! Independently trusted leaf topology admission, never derived from leaf JSON.
const std = @import("std");
pub const MAX_LEAVES = 64;
pub const MAX_NODES = 2 * MAX_LEAVES - 1;
pub const MAX_DEPTH = 64;
pub const MAX_PACKED_JSON_BYTES = 64 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES = 64 * 1024;
pub const MAX_LEAF_JSON_BYTES = 4 * 1024 * 1024;
pub const MAX_STATEMENT_WORDS = 65536;
pub const SCHEMA = "rv64-recursion-leaf-topologies-v1";
pub const layoutDigest = @import("layout_digest.zig").digest;
pub const Topology = struct {
    circuit_hash: [8]u32,
    layout_digest: [32]u8,
    pub fn checkLayout(self: Topology, actual: [32]u8) !void {
        if (!std.mem.eql(u8, &self.layout_digest, &actual)) return error.LeafLayoutMismatch;
    }
};
pub const TrustedTopologies = struct {
    schema: []const u8,
    leaves: []const Topology,
    pub fn validate(self: TrustedTopologies, count: usize) !void {
        try validateCount(count);
        if (!std.mem.eql(u8, self.schema, SCHEMA) or self.leaves.len != count) return error.InvalidTrustedLeafTopologies;
    }
};
pub const Leaf = struct { circuit_hash: [8]u32, statement_digest: [8]u32 };
pub fn validateCount(count: usize) !void {
    if (count == 0 or count > MAX_LEAVES) return error.InvalidRecursionLeafCount;
}
pub fn checkLeaf(expected: Leaf, circuit_hash: [8]u32, statement_digest: [8]u32) !void {
    if (!std.mem.eql(u32, &expected.circuit_hash, &circuit_hash)) return error.LeafCircuitHashMismatch;
    if (!std.mem.eql(u32, &expected.statement_digest, &statement_digest)) return error.LeafStatementDigestMismatch;
}
