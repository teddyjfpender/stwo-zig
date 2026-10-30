//! Experimental native-RAM endpoint kernel. The product does not select this
//! protocol. Range providers, original native/caller closure and recursive
//! admission must be integrated before these equations confer proof authority.
//! Every source has its own local MemoryAccess sum; source identity must never
//! be dropped by adding unrelated per-source sums before closing them.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const COLUMN_COUNT: usize = 23;
pub const CONSTRAINT_COUNT: usize = 38;
pub const range16_columns = [_]usize{ 0, 1, 2, 11, 12, 13, 14, 15, 16, 18, 19, 20 };
pub const byte_pairs = [_][2]usize{ .{ 3, 4 }, .{ 5, 6 }, .{ 7, 8 }, .{ 9, 10 } };
// Columns: address word low16/high12/high-slack; initial bytes4; final bytes4;
// final local clock low16/high11/high-slack; remaining clock same; inverse;
// next-address gap-minus-one low16/high12/high-slack; byte-address carry bits2.
// All bounds are proved by
// the listed range16/byte-pair requests, not by witness construction checks.
pub const Policy = struct {
    source_ordinal: u32,
    max_local_clock: u32,
    pub fn validate(self: Policy) !void {
        if (self.source_ordinal >= 1 << 20 or self.max_local_clock == 0 or self.max_local_clock >= 1 << 27) return error.InvalidRamEndpointPolicy;
    }
    /// Coarse ordered-cohort time, separate from instruction-clock semantics.
    /// Native and caller effects close TOGETHER in this cohort's local bus.
    /// The low phase is nonzero, so the existing sorted-WORD integer clock
    /// representation can be reused under the new endpoint protocol domain.
    pub fn globalClock(self: Policy) !u64 {
        try self.validate();
        return std.math.add(u64, try std.math.mul(u64, self.source_ordinal, 4), 3);
    }
};
pub const Endpoint = struct { address: u32, initial: u32, final: u32, last_clock: u32 };
fn c(comptime S: type, value: u32) S {
    if (S == core.fields.packed_qm31.PackedQM31) return S.splat(Q.fromBase(M.fromCanonical(value)));
    return S.fromBase(M.fromCanonical(value));
}
fn word(comptime S: type, row: [COLUMN_COUNT]S) S {
    return row[0].add(row[1].mul(c(S, 65536)));
}
fn clock(comptime S: type, row: [COLUMN_COUNT]S) S {
    return row[11].add(row[12].mul(c(S, 65536)));
}
pub fn constraints(comptime S: type, current: [COLUMN_COUNT]S, next: [COLUMN_COUNT]S, active: S, next_active: S, trace_last: S, max_local_clock: S) [CONSTRAINT_COUNT]S {
    return constraintsMode(false, S, current, next, active, next_active, trace_last, max_local_clock);
}
/// Previous-row orientation for the existing PCS mask interface. The boundary
/// selector is the independently fixed first row, not a private witness flag.
pub fn constraintsPrevious(comptime S: type, current: [COLUMN_COUNT]S, previous: [COLUMN_COUNT]S, active: S, previous_active: S, trace_first: S, max_local_clock: S) [CONSTRAINT_COUNT]S {
    return constraintsMode(true, S, current, previous, active, previous_active, trace_first, max_local_clock);
}
fn constraintsMode(comptime previous: bool, comptime S: type, current: [COLUMN_COUNT]S, neighbor: [COLUMN_COUNT]S, active: S, neighbor_active: S, trace_boundary: S, max_local_clock: S) [CONSTRAINT_COUNT]S {
    @setEvalBranchQuota(10000);
    const one = S.one();
    const edge = active.mul(neighbor_active).mul(one.sub(trace_boundary));
    var out: [CONSTRAINT_COUNT]S = undefined;
    out[0] = active.mul(active.sub(one));
    out[1] = neighbor_active.mul(neighbor_active.sub(one));
    out[2] = trace_boundary.mul(trace_boundary.sub(one));
    out[3] = active.mul(current[1].add(current[2]).sub(c(S, 4095)));
    out[4] = active.mul(current[12].add(current[13]).sub(c(S, 2047)));
    out[5] = active.mul(current[15].add(current[16]).sub(c(S, 2047)));
    out[6] = active.mul(clock(S, current).add(current[14]).add(current[15].mul(c(S, 65536))).sub(max_local_clock));
    out[7] = active.mul(clock(S, current).mul(current[17]).sub(one));
    out[8] = edge.mul(current[19].add(current[20]).sub(c(S, 4095)));
    out[9] = edge.mul((if (previous) word(S, current).sub(word(S, neighbor)) else word(S, neighbor).sub(word(S, current))).sub(one).sub(current[18]).sub(current[19].mul(c(S, 65536))));
    for (18..21, 10..) |column, index| out[index] = one.sub(edge).mul(current[column]);
    out[13] = current[21].mul(current[21].sub(one));
    out[14] = current[22].mul(current[22].sub(one));
    for (current, 15..) |value, index| out[index] = one.sub(active).mul(value);
    return out;
}
/// Native ordinary RAM uses aligned BYTE addresses below 2^30. Caller
/// word-index tuples are not silently admitted as the same local bus.
pub fn localTuple(comptime S: type, row: [COLUMN_COUNT]S, comptime final: bool) [7]S {
    const offset = if (final) 7 else 3;
    return .{ S.one(), word(S, row).mul(c(S, 4)), if (final) clock(S, row) else S.zero() } ++ row[offset..][0..4].*;
}
/// One net RAM transition per source/address, rather than one per access.
/// Source ordinal comes from the independently admitted execution schedule.
pub fn globalTuple(comptime S: type, row: [COLUMN_COUNT]S, policy: Policy) ![11]S {
    const time = try policy.globalClock();
    const carry = row[21].add(row[22].mul(c(S, 2)));
    const address_low = row[0].mul(c(S, 4)).sub(carry.mul(c(S, 65536)));
    const address_high = row[1].mul(c(S, 4)).add(carry);
    var result: [11]S = undefined;
    result[0] = S.one();
    result[1] = address_low;
    result[2] = address_high;
    for (0..4) |index| result[3 + index] = c(S, @intCast((time >> @as(u6, @intCast(16 * index))) & 65535));
    result[7] = row[3].add(row[4].mul(c(S, 256)));
    result[8] = row[5].add(row[6].mul(c(S, 256)));
    result[9] = row[7].add(row[8].mul(c(S, 256)));
    result[10] = row[9].add(row[10].mul(c(S, 256)));
    return result;
}
/// This extra range16 request is essential: without it the two carry bits
/// could select a different signed low address limb while preserving its sum.
pub fn derivedRange16(comptime S: type, row: [COLUMN_COUNT]S) [1]S {
    const carry = row[21].add(row[22].mul(c(S, 2)));
    return .{row[0].mul(c(S, 4)).sub(carry.mul(c(S, 65536)))};
}

pub fn construct(endpoint: Endpoint, next_address: ?u32, policy: Policy) ![COLUMN_COUNT]Q {
    try policy.validate();
    if (endpoint.address & 3 != 0 or endpoint.address >= 1 << 30 or endpoint.last_clock == 0 or endpoint.last_clock > policy.max_local_clock) return error.InvalidRamEndpoint;
    var row: [COLUMN_COUNT]Q = @splat(Q.zero());
    const address = endpoint.address >> 2;
    row[0] = c(Q, address & 65535);
    row[1] = c(Q, address >> 16);
    row[2] = c(Q, 4095 - (address >> 16));
    for (0..4) |index| {
        row[3 + index] = c(Q, (endpoint.initial >> @as(u5, @intCast(8 * index))) & 255);
        row[7 + index] = c(Q, (endpoint.final >> @as(u5, @intCast(8 * index))) & 255);
    }
    const remaining = policy.max_local_clock - endpoint.last_clock;
    row[11] = c(Q, endpoint.last_clock & 65535);
    row[12] = c(Q, endpoint.last_clock >> 16);
    row[13] = c(Q, 2047 - (endpoint.last_clock >> 16));
    row[14] = c(Q, remaining & 65535);
    row[15] = c(Q, remaining >> 16);
    row[16] = c(Q, 2047 - (remaining >> 16));
    row[17] = try c(Q, endpoint.last_clock).inv();
    const carry = (address & 65535) >> 14;
    row[21] = c(Q, carry & 1);
    row[22] = c(Q, carry >> 1);
    if (next_address) |next| {
        if (next & 3 != 0 or next >= 1 << 30 or next <= endpoint.address) return error.UnorderedRamEndpoints;
        const gap = (next >> 2) - address - 1;
        row[18] = c(Q, gap & 65535);
        row[19] = c(Q, gap >> 16);
        row[20] = c(Q, 4095 - (gap >> 16));
    }
    return row;
}

pub fn constructWithPrevious(endpoint: Endpoint, previous_address: ?u32, policy: Policy) ![COLUMN_COUNT]Q {
    var row = try construct(endpoint, null, policy);
    if (previous_address) |previous| {
        if (previous & 3 != 0 or previous >= endpoint.address) return error.UnorderedRamEndpoints;
        const gap = (endpoint.address >> 2) - (previous >> 2) - 1;
        row[18] = c(Q, gap & 65535);
        row[19] = c(Q, gap >> 16);
        row[20] = c(Q, 4095 - (gap >> 16));
    }
    return row;
}
