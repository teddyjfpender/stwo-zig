//! Original proofs for fixed interval/range providers and terminal transitions.
const R = @import("block_v7_memory_relations_v1.zig");
const Q = R.Q;
const P = R.P;
const Terminal = @import("block_v7_terminal_algebra_v1.zig");
pub const Kind = enum { interval, range16, terminal };
pub fn For(comptime kind: Kind) type {
    return struct {
        const Self = @This();
        pub const FIXED_COUNT = if (kind == .terminal) 10 else if (kind == .interval) 7 else 2;
        pub const MAIN_COUNT = if (kind == .terminal) 19 else 1;
        pub const PLANES = if (kind == .terminal) 1 else 2;
        pub const INTERACTION_COUNT = 4 * PLANES;
        pub const CONSTRAINT_COUNT = if (kind == .terminal) 28 else 3;
        pub const DEGREE = 4;
        pub const EXPANSION_BITS = 2;
        pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
        challenges: R.Challenges(Q),
        sums: [PLANES]Q,
        pub fn fixedTerminal(comptime S: type, f: [10]S) Terminal.Algebra(S).Fixed {
            return .{ .active = f[0], .tail = f[1], .address = f[2..4].*, .clock = f[4..8].*, .value = f[8..10].* };
        }
        pub fn terms(comptime S: type, ch: R.Challenges(S), f: [FIXED_COUNT]S, row: [MAIN_COUNT]S) [PLANES]R.Term(S) {
            if (kind == .terminal) return .{.{ .left = ch.transition.combineSecure(row[0..11].*), .wl = f[0] }};
            return .{ .{ .left = if (kind == .interval) ch.interval.combineSecure(f[1..7].*) else ch.range16.combineSecure(.{f[1]}), .wl = row[0] }, .{ .wl = row[0] } };
        }
        pub fn equations(comptime S: type, f: [FIXED_COUNT]S, row: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, before: [INTERACTION_COUNT]S, ch: R.Challenges(S), norm: [PLANES]S) [CONSTRAINT_COUNT]S {
            const direct = if (kind == .terminal) Terminal.Algebra(S).constraints(fixedTerminal(S, f), row) else [1]S{S.one().sub(f[0]).mul(row[0])};
            return direct ++ R.interactionConstraints(S, PLANES, terms(S, ch, f, row), current, before, norm);
        }
        pub const Domain = struct {
            ch: R.Challenges(Q),
            packed_challenges: R.Challenges(P),
            normalized: [PLANES]Q,
            pub fn evaluate(self: Domain, f: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
                _ = previous;
                _ = size;
                return self.eval(Q, f, row, current, before, self.ch, self.normalized);
            }
            pub fn evaluatePacked(self: *const Domain, f: [FIXED_COUNT]P, row: [MAIN_COUNT]P, previous: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, before: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
                _ = previous;
                var norm: [PLANES]P = undefined;
                for (&norm, self.normalized) |*v, x| v.* = P.splat(x);
                return self.eval(P, f, row, current, before, self.packed_challenges, norm);
            }
            fn eval(_: Domain, comptime S: type, f: [FIXED_COUNT]S, row: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, before: [INTERACTION_COUNT]S, ch: R.Challenges(S), norm: [PLANES]S) [CONSTRAINT_COUNT]S {
                return Self.equations(S, f, row, current, before, ch, norm);
            }
        };
        pub fn prepareDomain(self: Self, size: u32) !Domain {
            return .{ .ch = self.challenges, .packed_challenges = .from(self.challenges), .normalized = try R.normalize(PLANES, self.sums, size) };
        }
        pub fn evaluate(self: Self, f: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
        }
    };
}
