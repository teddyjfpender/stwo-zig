//! First-halt semantics for sorted RAM. Every active halt-address event with a
//! nonzero after-word must occur in the final guest instruction or its unique
//! terminal read. Initial halt memory must independently be fixed zero.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
pub const COLUMN_COUNT = 6;
pub const CONSTRAINT_COUNT = 12;
pub const DEGREE = 4;
pub const PUBLIC_COUNT = 18;
pub fn Constants(comptime S: type) type {
    return struct { address: [2]S, clocks: [4][4]S };
}
pub fn derive(policy: Terminal.Policy) !Constants(Q) {
    try policy.validate();
    var out: Constants(Q) = undefined;
    for (&out.address, 0..) |*v, i| v.* = Q.fromBase(M.fromCanonical(@truncate((policy.halt_address >> @as(u5, @intCast(16 * i))) & 65535)));
    const base = try std.math.mul(u64, 4, policy.final_cycle);
    for (&out.clocks, [4]u64{ base - 3, base - 2, base - 1, base + 1 }) |*row, clock| {
        for (row, 0..) |*v, i| v.* = Q.fromBase(M.fromCanonical(@intCast((clock >> @as(u6, @intCast(16 * i))) & 65535)));
    }
    return out;
}
pub fn lift(comptime S: type, value: Constants(Q)) Constants(S) {
    var out: Constants(S) = undefined;
    for (&out.address, value.address) |*v, q| v.* = @import("block_v7_memory_relations_v1.zig").lift(S, q);
    for (&out.clocks, value.clocks) |*row, values| {
        for (row, values) |*v, q| v.* = @import("block_v7_memory_relations_v1.zig").lift(S, q);
    }
    return out;
}
/// Host witness generation deliberately does NOT reject an early halt: hostile
/// traces must fail the real equations/prover, not merely a source filter.
pub fn witness(active: bool, address: u32, clock: u64, after: u32, policy: Terminal.Policy) ![COLUMN_COUNT]M {
    return witnessWithConstants(active, address, clock, after, try derive(policy));
}
pub fn witnessWithConstants(active: bool, address: u32, clock: u64, after: u32, constants: Constants(Q)) ![COLUMN_COUNT]M {
    if (!active) return @splat(M.zero());
    const delta0 = M.fromCanonical(address & 65535).sub(constants.address[0].tryIntoM31() catch unreachable);
    const delta1 = M.fromCanonical(address >> 16).sub(constants.address[1].tryIntoM31() catch unreachable);
    const delta = delta0.mul(delta0).add(delta1.mul(delta1));
    const sum = M.fromCanonical(after & 65535).add(M.fromCanonical(after >> 16));
    var choice: u32 = 0;
    for (constants.clocks, 0..) |limbs, i| {
        var candidate: u64 = 0;
        for (limbs, 0..) |v, j| candidate |= @as(u64, (v.tryIntoM31() catch unreachable).toU32()) << @as(u6, @intCast(16 * j));
        if (clock == candidate) choice = @intCast(i);
    }
    return .{ M.fromCanonical(@intFromBool(delta.isZero())), if (delta.isZero()) M.zero() else try delta.inv(), M.fromCanonical(@intFromBool(!sum.isZero())), if (sum.isZero()) M.zero() else try sum.inv(), M.fromCanonical(choice & 1), M.fromCanonical(choice >> 1) };
}
pub fn Algebra(comptime S: type) type {
    return struct {
        pub const Row = [COLUMN_COUNT]S;
        pub fn constraints(active: S, address: [2]S, clock: [4]S, after: [2]S, constants: Constants(S), row: Row) [CONSTRAINT_COUNT]S {
            @setEvalBranchQuota(20000);
            const dx = address[0].sub(constants.address[0]);
            const dy = address[1].sub(constants.address[1]);
            // Over the base field M31, -1 is nonsquare (p = 3 mod 4), so
            // dx²+dy²=0 iff both differences vanish. Range16 makes each
            // difference an exact address-limb equality, without mod alias.
            const delta = dx.mul(dx).add(dy.mul(dy));
            const sum = after[0].add(after[1]); // bounded by 131070 < p
            const match = row[0];
            const nonzero = row[2];
            const u = row[4];
            const v = row[5];
            const uv = u.mul(v);
            const gate = match.mul(nonzero); // no extra active: degree <= 4
            var out: [CONSTRAINT_COUNT]S = undefined;
            out[0] = match.mul(match.sub(active));
            out[1] = delta.mul(match);
            out[2] = delta.mul(row[1]).sub(active).add(match);
            out[3] = nonzero.mul(nonzero.sub(active));
            out[4] = sum.mul(row[3]).sub(nonzero);
            out[5] = sum.mul(active.sub(nonzero));
            out[6] = u.mul(u.sub(active));
            out[7] = v.mul(v.sub(active));
            for (clock, 0..) |limb, i| {
                const c0 = constants.clocks[0][i];
                const c1 = constants.clocks[1][i];
                const c2 = constants.clocks[2][i];
                const c3 = constants.clocks[3][i];
                const selected = c0.add(c1.sub(c0).mul(u)).add(c2.sub(c0).mul(v)).add(c3.sub(c2).sub(c1).add(c0).mul(uv));
                out[8 + i] = gate.mul(limb.sub(selected));
            }
            return out;
        }
    };
}
