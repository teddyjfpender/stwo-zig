const std = @import("std");
const m31 = @import("../fields/m31.zig");
const vcs_verifier = @import("verifier.zig");

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
