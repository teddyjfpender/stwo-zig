const std = @import("std");
const m31 = @import("../fields/m31.zig");
const lifted_verifier = @import("verifier.zig");
const lifted_prover = @import("../../prover/vcs_lifted/prover.zig");

const M31 = m31.M31;

pub fn TestData(comptime H: type) type {
    return struct {
        query_positions: []usize,
        decommitment: lifted_verifier.MerkleDecommitmentLifted(H),
        queried_values: [][]M31,
        verifier: lifted_verifier.MerkleVerifierLifted(H),

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.query_positions);
            self.decommitment.deinit(allocator);
            for (self.queried_values) |col| allocator.free(col);
            allocator.free(self.queried_values);
            self.verifier.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn prepareMerkle(
    comptime H: type,
    allocator: std.mem.Allocator,
    seed: u64,
) !TestData(H) {
    const Prover = lifted_prover.MerkleProverLifted(H);
    const n_cols = 10;
    const max_queries = 4;
    const min_log_size: u32 = 3;
    const max_log_size_exclusive: u32 = 5;

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    const log_sizes = try allocator.alloc(u32, n_cols);
    defer allocator.free(log_sizes);

    const columns_const = try allocator.alloc([]const M31, n_cols);
    defer allocator.free(columns_const);

    const columns_owned = try allocator.alloc([]M31, n_cols);
    defer {
        for (columns_owned) |column| allocator.free(column);
        allocator.free(columns_owned);
    }

    var max_log_size: u32 = 0;
    for (0..n_cols) |i| {
        const log_size = random.intRangeLessThan(u32, min_log_size, max_log_size_exclusive);
        log_sizes[i] = log_size;
        max_log_size = @max(max_log_size, log_size);

        const len = @as(usize, 1) << @intCast(log_size);
        columns_owned[i] = try allocator.alloc(M31, len);
        for (columns_owned[i]) |*value| {
            value.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, 1 << 30));
        }
        columns_const[i] = columns_owned[i];
    }

    var prover = try Prover.commit(allocator, columns_const);
    defer prover.deinit(allocator);

    var query_positions_builder = std.ArrayList(usize).empty;
    defer query_positions_builder.deinit(allocator);
    const query_domain_size = @as(usize, 1) << @intCast(max_log_size);
    const n_queries = random.intRangeAtMost(usize, 1, @min(max_queries, query_domain_size));
    while (query_positions_builder.items.len < n_queries) {
        const q = random.intRangeLessThan(usize, 0, query_domain_size);
        if (std.mem.indexOfScalar(usize, query_positions_builder.items, q) == null) {
            try query_positions_builder.append(allocator, q);
        }
    }
    std.sort.heap(usize, query_positions_builder.items, {}, std.sort.asc(usize));
    const query_positions = try query_positions_builder.toOwnedSlice(allocator);
    errdefer allocator.free(query_positions);

    var decommitment_result = try prover.decommit(allocator, query_positions, columns_const);
    errdefer decommitment_result.deinit(allocator);

    var verifier = try lifted_verifier.MerkleVerifierLifted(H).init(
        allocator,
        prover.root(),
        log_sizes,
    );
    errdefer verifier.deinit(allocator);

    const out = TestData(H){
        .query_positions = query_positions,
        .decommitment = decommitment_result.decommitment.decommitment,
        .queried_values = decommitment_result.queried_values,
        .verifier = verifier,
    };
    decommitment_result.decommitment.aux.deinit(allocator);
    return out;
}

test "vcs_lifted test utils: prepare merkle verifies" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    const alloc = std.testing.allocator;

    var data = try prepareMerkle(Hasher, alloc, 0);
    defer data.deinit(alloc);

    const queried_values = try alloc.alloc([]const M31, data.queried_values.len);
    defer alloc.free(queried_values);
    for (data.queried_values, 0..) |column, i| queried_values[i] = column;

    try data.verifier.verify(
        alloc,
        data.query_positions,
        queried_values,
        data.decommitment,
    );
}
