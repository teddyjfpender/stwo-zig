//! One degree-three authority for the independently sized frontier and DAG
//! components. Classic local closure is the qualification reference; the same
//! source expressions can later feed local GKR without replacing the algebra.
const E = @import("../../evaluation.zig");
const S = @import("narrow_source.zig");
const M = @import("micro.zig");
const D = @import("dag.zig");
const WireFor = @import("../curves/equations.zig").WireFor;
pub fn ChallengesFor(comptime C: type) type {
    return struct { bytes: C, carries: C, ssa: WireFor(C), wire: WireFor(C) };
}
pub const Challenges = ChallengesFor(E.Q);
pub fn ClaimsFor(comptime C: type) type {
    return struct { ssa: C, wire: C };
}
pub const Claims = ClaimsFor(E.Q);
pub fn Layout(comptime role: S.Role) type {
    return struct {
        pub const ROLE = role;
        pub const MAIN = S.mainWidth(role) + if (role == .arithmetic) @as(usize, 2) else 0;
        pub const BYTE_MULT = S.BYTE_MULT;
        pub const CARRY_MULT = S.CARRY_MULT;
        pub const RANGE_FRACTIONS = if (role == .arithmetic) M.RANGE_QUERIES + 2 else 0;
        pub const RANGE_BATCHES = (RANGE_FRACTIONS + 1) / 2;
        pub const SSA_FRACTIONS = if (role == .arithmetic) 8 else 1;
        pub const SSA_BATCHES = (SSA_FRACTIONS + 1) / 2;
        pub const RANGE_FIRST = 0;
        pub const RANGE_LAST = if (RANGE_BATCHES != 0) 4 * (RANGE_BATCHES - 1) else 0;
        pub const SSA_FIRST = 4 * RANGE_BATCHES;
        pub const SSA_LAST = SSA_FIRST + 4 * (SSA_BATCHES - 1);
        pub const WIRE_FIRST = SSA_FIRST + 4 * SSA_BATCHES;
        pub const WIRE_LAST = WIRE_FIRST;
        pub const INTERACTION = WIRE_FIRST + 4;
        pub const MAIN_CONSTRAINTS = (if (role == .arithmetic) 1 + 7 * 32 + M.G.groups + 15 + 16 else 1) + 4;
        pub const CONSTRAINTS = MAIN_CONSTRAINTS + RANGE_BATCHES + SSA_BATCHES + 1;
        pub const LOG_EXTENSION = 1;
        pub const DEGREE = 3;
        pub const ACTIVE = 0;
        pub fn widths() [3]usize {
            return .{ S.FIXED, MAIN, INTERACTION };
        }
        pub fn validateGeometry(calls: u32, first: u32, log: u32) !void {
            try S.validate(role, .{ .calls = calls, .first_id = first }, log);
            if (role == .arithmetic and log < M.G.carry_bits) return error.TowerGeometry;
        }
    };
}
pub fn Equations(comptime role: S.Role) type {
    return struct {
        pub const L = Layout(role);
        fn secure(comptime F: type, v: anytype, start: usize, previous: bool) E.SecureFor(F) {
            const degree = comptime E.extensionDegree(E.ConstFor(F));
            const at = start / 4 * degree;
            var values: [degree]F = undefined;
            for (&values, 0..) |*value, index| value.* = if (previous) v.previousInteraction(at + index) else v.interaction(at + index);
            return E.secureFromCoordinatesForField(E.ConstFor(F), F, values);
        }
        pub const Family = enum { range, ssa, wire };
        pub fn fraction(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), comptime family: Family, index: usize) struct { F, E.SecureFor(F) } {
            const active = v.main(0);
            switch (family) {
                .range => {
                    if (role == .frontier) return .{ F.zero(), E.SecureFor(F).one() };
                    if (index < M.BYTE_QUERIES) {
                        const column = if (index < 32) M.RESULT + index else if (index < 32 + M.G.q_bytes) M.QUOTIENT + index - 32 else M.DISTANCE + index - 32 - M.G.q_bytes;
                        return .{ active, E.splatFor(F, ch.bytes).sub(E.liftFor(F, v.main(column))) };
                    }
                    if (index == M.BYTE_QUERIES) return .{ v.main(L.BYTE_MULT).neg(), E.splatFor(F, ch.bytes).sub(E.liftFor(F, v.fixed(S.BYTE_VALUE))) };
                    const carry = index - M.BYTE_QUERIES - 1;
                    if (carry < M.G.carries) return .{ active, E.splatFor(F, ch.carries).sub(E.liftFor(F, v.main(M.CARRY + carry))) };
                    if (carry == M.G.carries) return .{ v.main(L.CARRY_MULT).neg(), E.splatFor(F, ch.carries).sub(E.liftFor(F, v.fixed(S.CARRY_VALUE))) };
                },
                .ssa => {
                    if (index < L.SSA_FRACTIONS) {
                        var id: F = undefined;
                        var start: usize = undefined;
                        var numerator: F = undefined;
                        if (role == .arithmetic and index < 7) {
                            id = v.fixed(S.READ_ID + index);
                            start = M.OPERANDS + 32 * index;
                            numerator = active.mul(v.fixed(S.READ_WEIGHT + index)).neg();
                        } else {
                            id = v.fixed(S.WRITER_ID);
                            start = if (role == .arithmetic) M.RESULT else S.FRONTIER_VALUE;
                            numerator = active.mul(v.fixed(S.WRITER_WEIGHT));
                        }
                        const tuple = S.tuple(F, v, public, id, start);
                        return .{ numerator, E.denominatorFor(F, ch.ssa.offset, &ch.ssa.coefficients, &tuple, true) };
                    }
                },
                .wire => if (index == 0) {
                    const f = S.globalFraction(role, F, v, public);
                    return .{ f.weight, E.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &f.tuple, true) };
                },
            }
            return .{ F.zero(), E.SecureFor(F).one() };
        }
        fn batch(comptime F: type, delta: E.SecureFor(F), a: struct { F, E.SecureFor(F) }, b: struct { F, E.SecureFor(F) }, sink: *E.SinkFor(F)) void {
            sink.emit(delta.mul(a[1]).mul(b[1]).sub(E.mulBaseFor(F, b[1], a[0])).sub(E.mulBaseFor(F, a[1], b[0])));
        }
        pub fn emitMain(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
            S.emitMain(role, F, v, public, sink);
        }
        pub fn emit(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), claims: ClaimsFor(E.ConstFor(F)), ch: ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
            emitMain(F, v, public, sink);
            inline for (.{ Family.range, Family.ssa, Family.wire }) |family| {
                const first = switch (family) {
                    .range => L.RANGE_FIRST,
                    .ssa => L.SSA_FIRST,
                    .wire => L.WIRE_FIRST,
                };
                const last = switch (family) {
                    .range => L.RANGE_LAST,
                    .ssa => L.SSA_LAST,
                    .wire => L.WIRE_LAST,
                };
                const count = switch (family) {
                    .range => L.RANGE_BATCHES,
                    .ssa => L.SSA_BATCHES,
                    .wire => 1,
                };
                const claim = switch (family) {
                    .range => E.ConstFor(F).zero(),
                    .ssa => claims.ssa,
                    .wire => claims.wire,
                };
                for (0..count) |index| {
                    const at = first + 4 * index;
                    const current = secure(F, v, at, false);
                    const prior = if (index > 0) secure(F, v, at - 4, false) else secure(F, v, last, true).sub(E.mulBaseFor(F, E.splatFor(F, claim), v.fixed(S.FIRST)));
                    batch(F, current.sub(prior), fraction(F, v, public, ch, family, 2 * index), fraction(F, v, public, ch, family, 2 * index + 1), sink);
                }
            }
        }
    };
}
