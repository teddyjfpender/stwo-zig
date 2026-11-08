const std = @import("std");
const m31 = @import("../fields/m31.zig");
const lifted_verifier = @import("verifier.zig");

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
