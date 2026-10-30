//! Original AIR for a standalone same-ROM macro theorem. Local value and byte
//! providers close here. Program/state/register and external RAM projections
//! remain explicitly OPEN for the enclosing VM to authenticate and close.
const core = @import("stwo_core");
const K = @import("../air/guest_precompile/bulk_memcpy_byte_loop_kernel_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const U = @import("../recursion/air/universal_challenges.zig");
const Endpoint = @import("block_v8_ram_endpoint_kernel_v1.zig");
const E = @import("../air/relation_challenges.zig");
const Q = R.Q;
const P = R.P;
pub const Kind = enum { destination, source, bytes, boundary };
pub fn Challenges(comptime S: type) type {
    return struct {
        value: R.Relation(S, 5),
        bytes: R.Relation(S, 1),
        ram: R.Relation(S, 7),
        program: R.Relation(S, 5),
        state: R.Relation(S, 2),
        transition: R.Relation(S, 11),
        range16: R.Relation(S, 1),
        pub fn from(q: Challenges(Q)) @This() {
            if (S == Q) return q;
            var out: @This() = undefined;
            inline for (.{ "value", "bytes", "ram", "program", "state", "transition", "range16" }) |name| {
                @field(out, name).z = R.lift(S, @field(q, name).z);
                for (&@field(out, name).powers, @field(q, name).powers) |*v, value| v.* = R.lift(S, value);
            }
            return out;
        }
    };
}
pub const Drawn = struct { universal: U.UniversalRelations, memory: R.Challenges(Q), challenges: Challenges(Q) };
pub fn draw(a: @import("std").mem.Allocator, channel: anytype) !Drawn {
    const universal = try U.UniversalRelations.draw(a, channel);
    const memory = R.draw(channel);
    channel.mixU32s(&.{ 0x42384d42, 1, 5, 1 });
    const value = E.RelationElements(5).init(channel.drawSecureFelt(), channel.drawSecureFelt());
    const bytes = E.RelationElements(1).init(channel.drawSecureFelt(), channel.drawSecureFelt());
    return .{ .universal = universal, .memory = memory, .challenges = .{ .value = .from(value), .bytes = .from(bytes), .ram = .{ .z = universal.get(.memory_access).z, .powers = universal.get(.memory_access).alpha_powers[0..7].* }, .program = .{ .z = universal.get(.program_access).z, .powers = universal.get(.program_access).alpha_powers[0..5].* }, .state = .{ .z = universal.get(.registers_state).z, .powers = universal.get(.registers_state).alpha_powers[0..2].* }, .transition = memory.transition, .range16 = memory.range16 } };
}
fn ramTuple(comptime S: type, address: S, clock: S, bytes: [4]S) [7]S {
    return .{ S.one(), address, clock, bytes[0], bytes[1], bytes[2], bytes[3] };
}
pub fn Spec(comptime kind: Kind) type {
    return struct {
        const Self = @This();
        pub const FIXED_COUNT = switch (kind) {
            .destination => 21,
            .source => 4,
            .bytes => 2,
            .boundary => 11,
        };
        pub const MAIN_COUNT = switch (kind) {
            .destination => K.COLUMN_COUNT,
            .source => 5,
            .bytes, .boundary => 1,
        };
        pub const PLANES = switch (kind) {
            .destination => 6,
            .source => 5,
            .bytes => 2,
            .boundary => 3,
        };
        pub const DIRECT_COUNT = switch (kind) {
            .destination => K.CONSTRAINT_COUNT + 14,
            .source => 5,
            .bytes => 0,
            .boundary => 1,
        };
        pub const INTERACTION_COUNT = 4 * PLANES;
        pub const CONSTRAINT_COUNT = DIRECT_COUNT + PLANES;
        pub const DEGREE = 4;
        pub const EXPANSION_BITS = 2;
        pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
        challenges: Challenges(Q),
        sums: [PLANES]Q,
        last_byte: u8 = 0,
        pub fn terms(comptime S: type, ch: Challenges(S), f: [FIXED_COUNT]S, row: [MAIN_COUNT]S) [PLANES]R.Term(S) {
            @setEvalBranchQuota(30000);
            if (kind == .destination) {
                var out: [PLANES]R.Term(S) = undefined;
                out[0] = .{ .left = ch.value.combineSecure(.{ f[15], row[1], row[2], row[3], row[4] }), .wl = f[17].neg(), .right = ch.value.combineSecure(.{ f[16], row[5], row[6], row[7], row[8] }), .wr = f[18].neg() };
                out[1] = .{ .left = ch.ram.combineSecure(ramTuple(S, f[14], f[19], row[9..13].*)), .wl = f[0].neg(), .right = ch.ram.combineSecure(ramTuple(S, f[14], f[20], row[13..17].*)), .wr = f[0] };
                for (0..4) |i| out[2 + i] = .{ .left = ch.bytes.combineSecure(.{row[9 + 2 * i]}), .wl = f[0].neg(), .right = ch.bytes.combineSecure(.{row[10 + 2 * i]}), .wr = f[0].neg() };
                return out;
            }
            if (kind == .source) return .{
                .{ .left = ch.value.combineSecure(.{ f[1], row[0], row[1], row[2], row[3] }), .wl = row[4] },
                .{ .left = ch.ram.combineSecure(ramTuple(S, f[1], f[2], row[0..4].*)), .wl = f[0].neg(), .right = ch.ram.combineSecure(ramTuple(S, f[1], f[3], row[0..4].*)), .wr = f[0] },
                .{ .left = ch.bytes.combineSecure(.{row[0]}), .wl = f[0].neg(), .right = ch.bytes.combineSecure(.{row[1]}), .wr = f[0].neg() },
                .{ .left = ch.bytes.combineSecure(.{row[2]}), .wl = f[0].neg(), .right = ch.bytes.combineSecure(.{row[3]}), .wr = f[0].neg() },
                .{ .wl = row[4] },
            };
            if (kind == .bytes) return .{ .{ .left = ch.bytes.combineSecure(.{f[1]}), .wl = row[0] }, .{ .wl = row[0] } };
            if (kind == .boundary) return .{
                .{ .left = ch.program.combineSecure(f[4..9].*), .wl = row[0].mul(f[0]) },
                .{ .left = ch.state.combineSecure(f[4..6].*), .wl = row[0].mul(f[1]) },
                .{ .left = ch.ram.combineSecure(f[4..11].*), .wl = row[0].mul(f[2]) },
            };
        }
        pub fn equations(comptime S: type, ch: Challenges(S), last_byte: u8, f: [FIXED_COUNT]S, row: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, before: [INTERACTION_COUNT]S, normalized: [PLANES]S) [CONSTRAINT_COUNT]S {
            @setEvalBranchQuota(30000);
            var direct: [DIRECT_COUNT]S = undefined;
            if (kind == .destination) {
                @memcpy(direct[0..K.CONSTRAINT_COUNT], &K.constraints(S, row));
                direct[K.CONSTRAINT_COUNT] = row[K.Layout.active].sub(f[0]);
                for (0..12) |i| direct[K.CONSTRAINT_COUNT + 1 + i] = row[K.Layout.start + i].sub(f[2 + i]);
                direct[K.CONSTRAINT_COUNT + 13] = f[1].mul(K.lastCopiedByte(S, row).sub(R.base(S, last_byte)));
            }
            if (kind == .source) for (row, 0..) |value, i| {
                direct[i] = S.one().sub(f[0]).mul(value);
            };
            if (kind == .boundary) direct[0] = row[0].sub(f[3]);
            return direct ++ R.interactionConstraints(S, PLANES, terms(S, ch, f, row), current, before, normalized);
        }
        pub const Domain = struct {
            ch: Challenges(Q),
            packed_challenges: Challenges(P),
            normalized: [PLANES]Q,
            last_byte: u8,
            pub fn evaluate(self: Domain, f: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
                _ = previous;
                _ = size;
                return Self.equations(Q, self.ch, self.last_byte, f, row, current, before, self.normalized);
            }
            pub fn evaluatePacked(self: *const Domain, f: [FIXED_COUNT]P, row: [MAIN_COUNT]P, previous: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, before: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
                _ = previous;
                var norm: [PLANES]P = undefined;
                for (&norm, self.normalized) |*v, q| v.* = P.splat(q);
                return Self.equations(P, self.packed_challenges, self.last_byte, f, row, current, before, norm);
            }
        };
        pub fn prepareDomain(self: Self, size: u32) !Domain {
            return .{ .ch = self.challenges, .packed_challenges = .from(self.challenges), .normalized = try R.normalize(PLANES, self.sums, size), .last_byte = self.last_byte };
        }
        pub fn evaluate(self: Self, f: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
        }
    };
}

/// Complete ordered endpoint cohort for this public macro's address inventory.
/// Unlike the V2 window-only endpoint, its independently fixed before-clock
/// is the actual external predecessor supplied by the public statement.
pub const EndpointSpec = struct {
    pub const FIXED_COUNT = 5; // active, first, before clock, word low16/high12
    pub const MAIN_COUNT = Endpoint.COLUMN_COUNT;
    pub const PLANES = 13;
    pub const INTERACTION_COUNT = 4 * PLANES;
    pub const CONSTRAINT_COUNT = Endpoint.CONSTRAINT_COUNT + 2 + PLANES;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = blk: {
        var out: [MAIN_COUNT]bool = @splat(false);
        out[0] = true;
        out[1] = true;
        break :blk out;
    };
    policy: Endpoint.Policy,
    challenges: Challenges(Q),
    sums: [PLANES]Q,
    pub fn terms(comptime S: type, policy: Endpoint.Policy, ch: Challenges(S), f: [FIXED_COUNT]S, row: [MAIN_COUNT]S) [PLANES]R.Term(S) {
        @setEvalBranchQuota(30000);
        var initial = Endpoint.localTuple(S, row, false);
        initial[2] = f[2];
        var out: [PLANES]R.Term(S) = undefined;
        out[0] = .{ .left = ch.ram.combineSecure(initial), .wl = f[0], .right = ch.ram.combineSecure(Endpoint.localTuple(S, row, true)), .wr = f[0].neg() };
        out[1] = .{ .left = ch.transition.combineSecure(Endpoint.globalTuple(S, row, policy) catch unreachable), .wl = f[0] };
        var ranges: [13]S = undefined;
        for (Endpoint.range16_columns, ranges[0..12]) |column, *value| value.* = row[column];
        ranges[12] = Endpoint.derivedRange16(S, row)[0];
        for (0..7) |i| {
            out[2 + i] = .{ .left = ch.range16.combineSecure(.{ranges[2 * i]}), .wl = f[0].neg() };
            if (2 * i + 1 < ranges.len) {
                out[2 + i].right = ch.range16.combineSecure(.{ranges[2 * i + 1]});
                out[2 + i].wr = f[0].neg();
            }
        }
        for (0..4) |i| out[9 + i] = .{ .left = ch.bytes.combineSecure(.{row[3 + 2 * i]}), .wl = f[0].neg(), .right = ch.bytes.combineSecure(.{row[4 + 2 * i]}), .wr = f[0].neg() };
        return out;
    }
    pub fn equations(comptime S: type, policy: Endpoint.Policy, ch: Challenges(S), f: [FIXED_COUNT]S, row: [MAIN_COUNT]S, previous: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, before: [INTERACTION_COUNT]S, norm: [PLANES]S) [CONSTRAINT_COUNT]S {
        @setEvalBranchQuota(30000);
        const direct = Endpoint.constraintsPrevious(S, row, previous, f[0], f[0], f[1], R.base(S, policy.max_local_clock));
        const address = [2]S{ row[0].sub(f[3]), row[1].sub(f[4]) };
        return direct ++ address ++ R.interactionConstraints(S, PLANES, terms(S, policy, ch, f, row), current, before, norm);
    }
    pub const Domain = struct {
        policy: Endpoint.Policy,
        ch: Challenges(Q),
        packed_challenges: Challenges(P),
        normalized: [PLANES]Q,
        pub fn evaluate(self: Domain, f: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            _ = size;
            return EndpointSpec.equations(Q, self.policy, self.ch, f, row, previous, current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, f: [FIXED_COUNT]P, row: [MAIN_COUNT]P, previous: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, before: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
            var norm: [PLANES]P = undefined;
            for (&norm, self.normalized) |*v, q| v.* = P.splat(q);
            return EndpointSpec.equations(P, self.policy, self.packed_challenges, f, row, previous, current, before, norm);
        }
    };
    pub fn prepareDomain(self: EndpointSpec, size: u32) !Domain {
        try self.policy.validate();
        return .{ .policy = self.policy, .ch = self.challenges, .packed_challenges = .from(self.challenges), .normalized = try R.normalize(PLANES, self.sums, size) };
    }
    pub fn evaluate(self: EndpointSpec, f: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        return (try self.prepareDomain(size)).evaluate(f, row, previous, current, before, size);
    }
};
pub const RangeSpec = @import("block_v7_provider_component_v1.zig").For(.range16);
