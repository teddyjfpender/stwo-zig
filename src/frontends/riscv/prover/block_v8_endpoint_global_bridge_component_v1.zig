//! Narrow late bridge over EXACTLY the endpoint main tree authenticated by a
//! local execution proof. This component proves only a global transition sum.
//! It deliberately repeats neither execution nor endpoint range constraints.
//! A receiver MUST verify the local proof/root binding and the sorted-memory
//! provider before the resulting claim confers any execution authority.
const R = @import("block_v7_memory_relations_v1.zig");
const K = @import("block_v8_ram_endpoint_kernel_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const std = @import("std");
pub const Spec = struct {
    pub const FIXED_COUNT = 1;
    pub const MAIN_COUNT = K.COLUMN_COUNT;
    pub const INTERACTION_COUNT = 4;
    pub const CONSTRAINT_COUNT = 1;
    pub const DEGREE = 2;
    pub const EXPANSION_BITS = 1;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
    policy: K.Policy,
    challenge: R.Relation(R.Q, 11),
    sums: [1]R.Q,
    pub const Domain = struct {
        policy: K.Policy,
        challenge: R.Relation(R.Q, 11),
        packed_challenge: R.Relation(R.P, 11),
        normalized: [1]R.Q,
        pub fn evaluate(self: Domain, f: [1]R.Q, row: [MAIN_COUNT]R.Q, previous: [MAIN_COUNT]R.Q, current: [4]R.Q, before: [4]R.Q, size: u32) ![1]R.Q {
            _ = previous;
            _ = size;
            return equations(R.Q, self.policy, self.challenge, f[0], row, current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, f: [1]R.P, row: [MAIN_COUNT]R.P, previous: [MAIN_COUNT]R.P, current: [4]R.P, before: [4]R.P) [1]R.P {
            _ = previous;
            return equations(R.P, self.policy, self.packed_challenge, f[0], row, current, before, .{R.P.splat(self.normalized[0])});
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        try self.policy.validate();
        return .{ .policy = self.policy, .challenge = self.challenge, .packed_challenge = .from(.{ .z = self.challenge.z, .alpha = self.challenge.powers[1], .alpha_powers = self.challenge.powers }), .normalized = try R.normalize(1, self.sums, size) };
    }
    pub fn evaluate(self: Spec, f: [1]R.Q, row: [MAIN_COUNT]R.Q, previous: [MAIN_COUNT]R.Q, current: [4]R.Q, before: [4]R.Q, size: u32) ![1]R.Q {
        return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
    }
};
pub fn term(comptime S: type, policy: K.Policy, challenge: R.Relation(S, 11), active: S, row: [K.COLUMN_COUNT]S) R.Term(S) {
    return .{ .left = challenge.combineSecure(K.globalTuple(S, row, policy) catch unreachable), .wl = active };
}
pub fn equations(comptime S: type, policy: K.Policy, challenge: R.Relation(S, 11), active: S, row: [K.COLUMN_COUNT]S, current: [4]S, before: [4]S, normalized: [1]S) [1]S {
    return R.interactionConstraints(S, 1, .{term(S, policy, challenge, active, row)}, current, before, normalized);
}
pub const InteractionContext = struct {
    policy: K.Policy,
    challenge: R.Relation(R.Q, 11),
    pub fn termsAt(self: InteractionContext, matrix: T.Matrix, logical: usize) ![1]R.Term(R.Q) {
        // The original endpoint matrix has two fixed columns; the bridge uses
        // only active-prefix, retaining the identical 23-column main tree.
        return .{term(R.Q, self.policy, self.challenge, R.Q.fromBase(matrix.get(0, logical)), matrix.row(K.COLUMN_COUNT, 2, logical))};
    }
};
/// The fixed prefix is independent of the producer's row values. Its size and
/// active count come from the locally verified statement, never a new claim.
pub fn prefix(a: std.mem.Allocator, count: u32, log: u32, max_bytes: usize) !T.Matrix {
    if (count == 0 or log < 4 or log > 24 or log != @max(@as(u32, 4), std.math.log2_int_ceil(u32, count))) return error.InvalidEndpointBridgeGeometry;
    var result = try T.Matrix.init(a, log, 1, max_bytes);
    errdefer result.deinit();
    for (0..count) |i| result.set(0, i, R.M.one());
    return result;
}
