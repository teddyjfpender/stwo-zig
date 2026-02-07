const std = @import("std");
const m31 = @import("../fields/m31.zig");
const vcs_verifier = @import("verifier.zig");
const vcs_prover = @import("../../prover/vcs/prover.zig");

const M31 = m31.M31;

pub fn TestData(comptime H: type) type {
    return struct {
        queries: []vcs_verifier.LogSizeQueries,
        decommitment: vcs_verifier.MerkleDecommitment(H),
        queried_values: []M31,
        verifier: vcs_verifier.MerkleVerifier(H),

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.queries) |entry| allocator.free(entry.queries);
            allocator.free(self.queries);
            self.decommitment.deinit(allocator);
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
    const Prover = vcs_prover.MerkleProver(H);
    const n_cols = 10;
    const n_queries = 3;
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

    for (0..n_cols) |i| {
        const log_size = random.intRangeLessThan(u32, min_log_size, max_log_size_exclusive);
        log_sizes[i] = log_size;
        const len = @as(usize, 1) << @intCast(log_size);
        columns_owned[i] = try allocator.alloc(M31, len);
        for (columns_owned[i]) |*value| {
            value.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, 1 << 30));
        }
        columns_const[i] = columns_owned[i];
    }

    var prover = try Prover.commit(allocator, columns_const);
    defer prover.deinit(allocator);

    const n_layers = max_log_size_exclusive - min_log_size;
    const queries = try allocator.alloc(vcs_verifier.LogSizeQueries, n_layers);
    var q_index: usize = 0;
    errdefer {
        for (queries[0..q_index]) |entry| allocator.free(entry.queries);
        allocator.free(queries);
    }

    var layer_log_size: i32 = @intCast(max_log_size_exclusive - 1);
    while (layer_log_size >= @as(i32, @intCast(min_log_size))) : (layer_log_size -= 1) {
        const log_size: u32 = @intCast(layer_log_size);
        var layer_queries = std.ArrayList(usize).init(allocator);
        defer layer_queries.deinit();

        while (layer_queries.items.len < n_queries) {
            const q = random.intRangeLessThan(usize, 0, @as(usize, 1) << @intCast(log_size));
            if (std.mem.indexOfScalar(usize, layer_queries.items, q) == null) {
                try layer_queries.append(q);
            }
        }
        std.sort.heap(usize, layer_queries.items, {}, std.sort.asc(usize));

        queries[q_index] = .{
            .log_size = log_size,
            .queries = try layer_queries.toOwnedSlice(),
        };
        q_index += 1;
    }

    var decommitment_result = try prover.decommit(allocator, queries, columns_const);
    errdefer decommitment_result.deinit(allocator);

    var verifier = try vcs_verifier.MerkleVerifier(H).init(allocator, prover.root(), log_sizes);
    errdefer verifier.deinit(allocator);

    const out = TestData(H){
        .queries = queries,
        .decommitment = decommitment_result.decommitment.decommitment,
        .queried_values = decommitment_result.queried_values,
        .verifier = verifier,
    };
    decommitment_result.decommitment.aux.deinit(allocator);
    return out;
}

test "vcs test utils: prepare merkle verifies" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    const alloc = std.testing.allocator;

    var data = try prepareMerkle(Hasher, alloc, 0);
    defer data.deinit(alloc);

    try data.verifier.verify(alloc, data.queries, data.queried_values, data.decommitment);
}
