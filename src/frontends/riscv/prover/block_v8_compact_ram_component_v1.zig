//! Compact sorted-RAM equations and independent initial/final lookup planes.
//! The whole-source verifier must authenticate local roots, late bridges and
//! receiver-derived boundary/range provider keys before using these claims.
const R = @import("block_v7_memory_relations_v1.zig");
const K = @import("block_v8_compact_ram_kernel_v1.zig");
pub const PLANES = 6;
pub fn Challenges(comptime S: type) type {
    return struct {
        transition: R.Relation(S, 11),
        boundary: R.Relation(S, 5),
        range16: R.Relation(S, 1),
        pub fn from(q: Challenges(R.Q)) @This() {
            var out: @This() = undefined;
            inline for (.{ "transition", "boundary", "range16" }) |name| {
                @field(out, name).z = R.lift(S, @field(q, name).z);
                for (&@field(out, name).powers, @field(q, name).powers) |*value, power| value.* = R.lift(S, power);
            }
            return out;
        }
    };
}
pub fn fromEpoch(drawn: @import("block_v7_execution_epoch_v1.zig").Drawn) Challenges(R.Q) {
    return .{ .transition = drawn.memory.transition, .boundary = .from(drawn.word.initial), .range16 = drawn.memory.range16 };
}
pub fn terms(comptime S: type, ch: Challenges(S), f: [3]S, row: [K.COLUMN_COUNT]S, previous: [K.COLUMN_COUNT]S) [PLANES]R.Term(S) {
    @setEvalBranchQuota(20000);
    const fresh = K.newAddress(S, f, row);
    const first_key = f[0].sub(row[K.Col.same]);
    return .{
        .{ .left = ch.transition.combineSecure(K.transitionTuple(S, row)), .wl = f[0].neg() },
        .{ .left = ch.boundary.combineSecure(K.initialTuple(S, row)), .wl = first_key },
        .{ .left = ch.boundary.combineSecure(K.finalTuple(S, previous)), .wl = fresh, .right = ch.boundary.combineSecure(K.finalTuple(S, row)), .wr = f[2] },
        .{ .left = ch.range16.combineSecure(.{row[K.Col.gap_low]}), .wl = fresh.neg(), .right = ch.range16.combineSecure(.{row[K.Col.gap_high]}), .wr = fresh.neg() },
        .{ .left = ch.range16.combineSecure(.{row[K.Col.gap_high].mul(K.c(S, 16))}), .wl = fresh.neg(), .right = ch.range16.combineSecure(.{row[K.Col.clock_gap]}), .wr = row[K.Col.same].neg() },
        .{ .constant = fresh.mul(K.c(S, 3)).add(row[K.Col.same]) },
    };
}
pub const Spec = struct {
    pub const FIXED_COUNT = 3;
    pub const MAIN_COUNT = K.COLUMN_COUNT;
    pub const INTERACTION_COUNT = 4 * PLANES;
    pub const CONSTRAINT_COUNT = K.DIRECT_COUNT + PLANES;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = .{ true, true, true, false, false, true, true, false, false, false, false, false };
    challenges: Challenges(R.Q),
    sums: [PLANES]R.Q,
    pub const Domain = struct {
        ch: Challenges(R.Q),
        packed_challenges: Challenges(R.P),
        normalized: [PLANES]R.Q,
        pub fn evaluate(self: Domain, f: [3]R.Q, row: [MAIN_COUNT]R.Q, previous: [MAIN_COUNT]R.Q, current: [INTERACTION_COUNT]R.Q, before: [INTERACTION_COUNT]R.Q, size: u32) ![CONSTRAINT_COUNT]R.Q {
            _ = size;
            return equations(R.Q, self.ch, f, row, previous, current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, f: [3]R.P, row: [MAIN_COUNT]R.P, previous: [MAIN_COUNT]R.P, current: [INTERACTION_COUNT]R.P, before: [INTERACTION_COUNT]R.P) [CONSTRAINT_COUNT]R.P {
            var normalized: [PLANES]R.P = undefined;
            for (&normalized, self.normalized) |*v, q| v.* = R.P.splat(q);
            return equations(R.P, self.packed_challenges, f, row, previous, current, before, normalized);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        return .{ .ch = self.challenges, .packed_challenges = .from(self.challenges), .normalized = try R.normalize(PLANES, self.sums, size) };
    }
    pub fn evaluate(self: Spec, f: [3]R.Q, row: [MAIN_COUNT]R.Q, previous: [MAIN_COUNT]R.Q, current: [INTERACTION_COUNT]R.Q, before: [INTERACTION_COUNT]R.Q, size: u32) ![CONSTRAINT_COUNT]R.Q {
        return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
    }
};
pub fn equations(comptime S: type, ch: Challenges(S), f: [3]S, row: [K.COLUMN_COUNT]S, previous: [K.COLUMN_COUNT]S, current: [4 * PLANES]S, before: [4 * PLANES]S, normalized: [PLANES]S) [Spec.CONSTRAINT_COUNT]S {
    @setEvalBranchQuota(20000);
    return K.constraints(S, f, row, previous) ++ R.interactionConstraints(S, PLANES, terms(S, ch, f, row, previous), current, before, normalized);
}
pub const BoundarySpec = struct {
    // active,address2,incoming2,outgoing2,changed. All fixed values are freshly
    // derived from complete external snapshots and a checked address selection.
    pub const FIXED_COUNT = 8;
    pub const MAIN_COUNT = 1;
    pub const INTERACTION_COUNT = 8;
    pub const CONSTRAINT_COUNT = 5;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [1]bool = .{false};
    challenge: R.Relation(R.Q, 5),
    sums: [2]R.Q,
    pub fn termsFor(comptime S: type, relation: R.Relation(S, 5), f: [8]S, row: [1]S) [2]R.Term(S) {
        return .{ .{ .left = relation.combineSecure(.{ S.one(), f[1], f[2], f[3], f[4] }), .wl = row[0].neg() }, .{ .left = relation.combineSecure(.{ S.one(), f[1], f[2], f[5], f[6] }), .wl = row[0].neg() } };
    }
    pub const Domain = struct {
        challenge: R.Relation(R.Q, 5),
        packed_challenges: R.Relation(R.P, 5),
        normalized: [2]R.Q,
        pub fn evaluate(self: Domain, f: [8]R.Q, row: [1]R.Q, previous: [1]R.Q, current: [8]R.Q, before: [8]R.Q, size: u32) ![5]R.Q {
            _ = previous;
            _ = size;
            return equationsFor(R.Q, self.challenge, f, row, current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, f: [8]R.P, row: [1]R.P, previous: [1]R.P, current: [8]R.P, before: [8]R.P) [5]R.P {
            _ = previous;
            return equationsFor(R.P, self.packed_challenges, f, row, current, before, .{ R.P.splat(self.normalized[0]), R.P.splat(self.normalized[1]) });
        }
    };
    pub fn prepareDomain(self: BoundarySpec, size: u32) !Domain {
        var packed_challenges: R.Relation(R.P, 5) = undefined;
        packed_challenges.z = R.P.splat(self.challenge.z);
        for (&packed_challenges.powers, self.challenge.powers) |*v, q| v.* = R.P.splat(q);
        return .{ .challenge = self.challenge, .packed_challenges = packed_challenges, .normalized = try R.normalize(2, self.sums, size) };
    }
    pub fn evaluate(self: BoundarySpec, f: [8]R.Q, row: [1]R.Q, previous: [1]R.Q, current: [8]R.Q, before: [8]R.Q, size: u32) ![5]R.Q {
        return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
    }
    pub fn equationsFor(comptime S: type, relation: R.Relation(S, 5), f: [8]S, row: [1]S, current: [8]S, before: [8]S, normalized: [2]S) [5]S {
        @setEvalBranchQuota(20000);
        return [3]S{ row[0].mul(row[0].sub(S.one())), S.one().sub(f[0]).mul(row[0]), f[7].mul(S.one().sub(row[0])) } ++ R.interactionConstraints(S, 2, termsFor(S, relation, f, row), current, before, normalized);
    }
};
