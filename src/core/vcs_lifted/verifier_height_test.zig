//! Explicit-height lifted Merkle verification against the pinned Rust oracle.

const std = @import("std");
const M31 = @import("../fields/m31.zig").M31;
const verifier = @import("verifier.zig");
const vectors = @import("testdata/lifted_height_vectors.zig");
const Hasher = @import("blake2_merkle.zig").Blake2sPlainMerkleHasher;

const Verifier = verifier.MerkleVerifierLifted(Hasher);

const OracleDecommitment = struct {
    values: [][]const M31,
    witness: []Hasher.Hash,

    fn init(alloc: std.mem.Allocator, case: vectors.Case) !OracleDecommitment {
        const values = try alloc.alloc([]const M31, case.values.len);
        var filled: usize = 0;
        errdefer {
            for (values[0..filled]) |column| alloc.free(column);
            alloc.free(values);
        }
        for (values, case.values) |*column, raw| {
            const owned = try alloc.alloc(M31, raw.len);
            for (owned, raw) |*value, word| value.* = M31.fromCanonical(word);
            column.* = owned;
            filled += 1;
        }
        const witness = try alloc.alloc(Hasher.Hash, case.witness.len);
        for (witness, case.witness) |*hash, hex| hash.* = vectors.digest(hex);
        return .{ .values = values, .witness = witness };
    }

    fn deinit(self: *OracleDecommitment, alloc: std.mem.Allocator) void {
        for (self.values) |column| alloc.free(column);
        alloc.free(self.values);
        alloc.free(self.witness);
    }
};

test "vcs_lifted verifier: explicit heights accept proving@5a7c5ed oracle decommitments" {
    const alloc = std.testing.allocator;
    for (vectors.cases) |case| {
        var oracle = try OracleDecommitment.init(alloc, case);
        defer oracle.deinit(alloc);
        const root = vectors.digest(case.root);

        var tree = try Verifier.initWithHeight(alloc, root, &vectors.column_log_sizes, case.height);
        defer tree.deinit(alloc);
        var capture: verifier.MerklePathCapture(Hasher) = undefined;
        try tree.verifyWithPathCapture(alloc, case.positions, oracle.values, .{ .hash_witness = oracle.witness }, &capture);
        defer capture.deinit(alloc);
        try std.testing.expectEqual(case.height, capture.path_depth);

        // One layer short of the committed height cannot reach the root (at the
        // largest-column height it is not even a valid tree).
        const short_height = case.height - 1;
        if (short_height < std.mem.max(u32, &vectors.column_log_sizes)) {
            try std.testing.expectError(
                error.InvalidTreeHeight,
                Verifier.initWithHeight(alloc, root, &vectors.column_log_sizes, short_height),
            );
            continue;
        }
        var short = try Verifier.initWithHeight(alloc, root, &vectors.column_log_sizes, short_height);
        defer short.deinit(alloc);
        if (short.verify(alloc, case.positions, oracle.values, .{ .hash_witness = oracle.witness })) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "vcs_lifted verifier: the largest-column rule is the height of the largest column" {
    const alloc = std.testing.allocator;
    const case = vectors.cases[0];
    try std.testing.expectEqual(@as(u32, 3), case.height);
    var oracle = try OracleDecommitment.init(alloc, case);
    defer oracle.deinit(alloc);

    var tree = try Verifier.init(alloc, vectors.digest(case.root), &vectors.column_log_sizes);
    defer tree.deinit(alloc);
    try std.testing.expectEqual(case.height, tree.height);
    try tree.verify(alloc, case.positions, oracle.values, .{ .hash_witness = oracle.witness });
}

test "vcs_lifted verifier: explicit heights must dominate columns and be zero when empty" {
    const alloc = std.testing.allocator;
    const root = [_]u8{0} ** 32;
    try std.testing.expectError(error.InvalidTreeHeight, Verifier.initWithHeight(alloc, root, &.{ 3, 5 }, 4));
    try std.testing.expectError(error.InvalidTreeHeight, Verifier.initWithHeight(alloc, root, &.{}, 1));
    var empty = try Verifier.initWithHeight(alloc, root, &.{}, 0);
    defer empty.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 0), empty.height);
    try empty.verify(alloc, &.{ 0, 1 }, &.{}, .{ .hash_witness = &.{} });
}
