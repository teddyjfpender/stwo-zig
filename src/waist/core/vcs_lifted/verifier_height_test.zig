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

test "properties Merkle: CM31 seeded permutations and mutations of frozen Rust witnesses" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x012d_3293_6102_268b);
    const rng = prng.random();
    for (vectors.cases) |case| {
        var oracle = try OracleDecommitment.init(a, case);
        defer oracle.deinit(a);
        const positions = try a.dupe(usize, case.positions);
        defer a.free(positions);
        const root = vectors.digest(case.root);
        var tree = try Verifier.initWithHeight(a, root, &vectors.column_log_sizes, case.height);
        defer tree.deinit(a);
        for (0..8) |_| {
            const left = rng.uintLessThan(usize, positions.len);
            const right = rng.uintLessThan(usize, positions.len);
            std.mem.swap(usize, &positions[left], &positions[right]);
            for (oracle.values) |column| {
                const mutable = @constCast(column);
                std.mem.swap(M31, &mutable[left], &mutable[right]);
            }
            try tree.verify(a, positions, oracle.values, .{ .hash_witness = oracle.witness });
            {
                // Change every queried value of one column, retaining all
                // duplicate-query equalities: this must reach root rejection.
                const column = @constCast(oracle.values[rng.uintLessThan(usize, oracle.values.len)]);
                const delta = M31.fromCanonical(1 + rng.uintLessThan(u32, 1024));
                for (column) |*x| x.* = x.add(delta);
                defer {
                    for (column) |*x| x.* = x.sub(delta);
                }
                try std.testing.expectError(error.RootMismatch, tree.verify(a, positions, oracle.values, .{ .hash_witness = oracle.witness }));
            }
            {
                const hash = &oracle.witness[rng.uintLessThan(usize, oracle.witness.len)];
                const byte = rng.uintLessThan(usize, hash.len);
                hash[byte] ^= 1;
                defer hash[byte] ^= 1;
                try std.testing.expectError(error.RootMismatch, tree.verify(a, positions, oracle.values, .{ .hash_witness = oracle.witness }));
            }
            {
                tree.root[rng.uintLessThan(usize, tree.root.len)] ^= 1;
                defer tree.root = root;
                try std.testing.expectError(error.RootMismatch, tree.verify(a, positions, oracle.values, .{ .hash_witness = oracle.witness }));
            }
        }
    }
}
