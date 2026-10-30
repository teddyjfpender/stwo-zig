//! Experimental endpoint AIR with the complete local, global and range-plane
//! equations. All eleven physical claims must be transcript-bound. Local and
//! global relations remain OPEN until execution and sorted RAM close them;
//! range16 and byte-pair providers must also close their exact request sums.
const core = @import("stwo_core");
const K = @import("block_v8_ram_endpoint_kernel_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const U = @import("../recursion/air/universal_challenges.zig");
const Q = R.Q;
const P = R.P;
pub const PLANES = 11;
pub fn Challenges(comptime S: type) type {
    return struct {
        native: R.Relation(S, 7),
        transition: R.Relation(S, 11),
        range16: R.Relation(S, 1),
        bytes: R.Relation(S, 2),
        pub fn from(q: Challenges(Q)) @This() {
            var result: @This() = undefined;
            inline for (.{ "native", "transition", "range16", "bytes" }) |name| {
                @field(result, name).z = R.lift(S, @field(q, name).z);
                for (&@field(result, name).powers, @field(q, name).powers) |*v, source| v.* = R.lift(S, source);
            }
            return result;
        }
    };
}
pub fn fromEpoch(drawn: @import("block_v7_execution_epoch_v1.zig").Drawn) Challenges(Q) {
    const native = drawn.word.universal_prefix.get(.memory_access);
    const bytes = drawn.word.universal_prefix.get(.range_check_8_8);
    return .{ .native = .{ .z = native.z, .powers = native.alpha_powers[0..7].* }, .transition = .from(drawn.word.transition), .range16 = .from(drawn.word.range16), .bytes = .{ .z = bytes.z, .powers = bytes.alpha_powers[0..2].* } };
}
pub fn terms(comptime S: type, policy: K.Policy, ch: Challenges(S), active: S, row: [K.COLUMN_COUNT]S) [PLANES]R.Term(S) {
    @setEvalBranchQuota(20000);
    var out: [PLANES]R.Term(S) = undefined;
    out[0] = .{ .left = ch.native.combineSecure(K.localTuple(S, row, false)), .right = ch.native.combineSecure(K.localTuple(S, row, true)), .wl = active, .wr = active.neg() };
    out[1] = .{ .left = ch.transition.combineSecure(K.globalTuple(S, row, policy) catch unreachable), .wl = active };
    var ranges: [13]S = undefined;
    for (K.range16_columns, ranges[0..12]) |column, *value| value.* = row[column];
    ranges[12] = K.derivedRange16(S, row)[0];
    for (0..7) |index| {
        const offset = 2 * index;
        out[2 + index] = .{ .left = ch.range16.combineSecure(.{ranges[offset]}), .wl = active.neg() };
        if (offset + 1 < ranges.len) {
            out[2 + index].right = ch.range16.combineSecure(.{ranges[offset + 1]});
            out[2 + index].wr = active.neg();
        }
    }
    for (0..2) |index| {
        const left = K.byte_pairs[2 * index];
        const right = K.byte_pairs[2 * index + 1];
        out[9 + index] = .{ .left = ch.bytes.combineSecure(.{ row[left[0]], row[left[1]] }), .right = ch.bytes.combineSecure(.{ row[right[0]], row[right[1]] }), .wl = active.neg(), .wr = active.neg() };
    }
    return out;
}
pub const Spec = struct {
    pub const FIXED_COUNT = 2; // active prefix, first logical row
    pub const MAIN_COUNT = K.COLUMN_COUNT;
    pub const INTERACTION_COUNT = PLANES * 4;
    pub const CONSTRAINT_COUNT = K.CONSTRAINT_COUNT + PLANES;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = blk: {
        var mask: [MAIN_COUNT]bool = @splat(false);
        mask[0] = true;
        mask[1] = true;
        break :blk mask;
    };
    policy: K.Policy,
    challenges: Challenges(Q),
    sums: [PLANES]Q,
    pub const Domain = struct {
        policy: K.Policy,
        challenges: Challenges(Q),
        packed_challenges: Challenges(P),
        normalized: [PLANES]Q,
        pub fn evaluate(self: Domain, f: [2]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            _ = size;
            return equations(Q, self.policy, self.challenges, f, row, previous, current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, f: [2]P, row: [MAIN_COUNT]P, previous: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, before: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
            var norm: [PLANES]P = undefined;
            for (&norm, self.normalized) |*v, value| v.* = P.splat(value);
            return equations(P, self.policy, self.packed_challenges, f, row, previous, current, before, norm);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        try self.policy.validate();
        return .{ .policy = self.policy, .challenges = self.challenges, .packed_challenges = .from(self.challenges), .normalized = try R.normalize(PLANES, self.sums, size) };
    }
    pub fn evaluate(self: Spec, f: [2]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
    }
};
pub fn equations(comptime S: type, policy: K.Policy, ch: Challenges(S), f: [2]S, row: [K.COLUMN_COUNT]S, previous: [K.COLUMN_COUNT]S, current: [PLANES * 4]S, before: [PLANES * 4]S, normalized: [PLANES]S) [Spec.CONSTRAINT_COUNT]S {
    @setEvalBranchQuota(20000);
    return K.constraintsPrevious(S, row, previous, f[0], f[0], f[1], R.base(S, policy.max_local_clock)) ++ R.interactionConstraints(S, PLANES, terms(S, policy, ch, f[0], row), current, before, normalized);
}
