//! Concrete paired Keccak geometry; no CPU, opcode or memory caller layout.
const std = @import("std");
pub const STATE = 1600;
pub const PARITY = 320;
pub const ACTIVE_A = STATE + PARITY;
pub const ACTIVE_B = ACTIVE_A + 1;
pub const BASE_ID = ACTIVE_B + 1;
pub const MAIN = BASE_ID + 1;
pub const HEADER = 13;
pub const ROWS_PER_PAIR = 29;
pub const FIXED = 32; // Domain-only phase, first, slot index and complete slot.
pub const FIRST = 29;
pub const SLOT_INDEX = 30;
pub const COMPLETE_SLOT = 31;
pub const LOOKUPS = STATE + PARITY;
pub const IO_LANES = 25;
pub const IO_BATCHES = (IO_LANES + 2) / 3;
pub const BATCHES = LOOKUPS / 3 + IO_BATCHES;
pub const INTERACTION = 4 * BATCHES;
pub const IO_ARITY = 3 + 8; // call ID, direction, lane, eight bytes.
pub const DIRECT = 2 * STATE + PARITY + ACTIVE_A + HEADER;
pub const CONSTRAINTS = DIRECT + BATCHES;
pub const MASK_OFFSETS = [_]i32{ 0, -2, -1, 1, 2 };
/// Slot geometry of the paired permutation.
/// `pair29`: input planes A, B; states v0..v24; output planes A, B (29 rows).
/// `pair27` (throughput-r27-v1): one complemented A input plane; v0..v24;
/// one complemented A output plane (27 rows). Call B's IO bits are the linear
/// image (v + s[-1] - 1) / 8 of the packed state and the neighbouring plane.
pub const Geometry = enum {
    pair29,
    pair27,
    pub fn rowsPerPair(self: Geometry) usize {
        return if (self == .pair27) 27 else ROWS_PER_PAIR;
    }
    /// Fixed one-hot column of slot phase `phase`. pair27 keeps the pair29
    /// column meaning (0 input plane, 2 + r round r, 26 final state, 27
    /// output plane); columns 1 and 28 are identically zero there.
    pub fn phaseColumn(self: Geometry, phase: usize) usize {
        if (self == .pair29) return phase;
        return if (phase == 0) 0 else if (phase <= 25) phase + 1 else 27;
    }
};
pub fn logSize(calls: usize) !u32 {
    return logSizeFor(.pair29, calls);
}
pub fn logSizeFor(geometry: Geometry, calls: usize) !u32 {
    _ = try admitRoster(&.{calls}, &.{});
    const pairs = try std.math.divCeil(usize, calls, 2);
    const rows = try std.math.mul(usize, pairs, geometry.rowsPerPair());
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, rows)));
    // Degree-four quotient evaluation requires two extra circle bits.
    if (log > 26) return error.KeccakDomainTooLarge;
    return log;
}

/// Public request multiplicities must not wrap the characteristic. This bound
/// is independent of honest host-generated counters and precedes allocation.
pub const LookupMass = struct { chi: u64 = 0, xor5: u64 = 0, io: u64 = 0, bytes: u64 = 0 };
pub fn lookupMass(calls: usize) !LookupMass {
    const slots: u64 = @intCast(try std.math.divCeil(usize, calls, 2));
    return .{
        .chi = std.math.mul(u64, slots, 24 * 1600) catch return error.KeccakLookupMassExceeded,
        .xor5 = std.math.mul(u64, slots, 24 * 320) catch return error.KeccakLookupMassExceeded,
        .io = std.math.mul(u64, @intCast(calls), 2 * 25) catch return error.KeccakLookupMassExceeded,
    };
}
pub fn admitRoster(component_calls: []const usize, byte_request_counts: []const u64) !LookupMass {
    const modulus = @import("stwo_core").fields.m31.Modulus;
    var total = LookupMass{};
    for (component_calls) |calls| {
        const mass = try lookupMass(calls);
        total.chi = std.math.add(u64, total.chi, mass.chi) catch return error.KeccakLookupMassExceeded;
        total.xor5 = std.math.add(u64, total.xor5, mass.xor5) catch return error.KeccakLookupMassExceeded;
        total.io = std.math.add(u64, total.io, mass.io) catch return error.KeccakLookupMassExceeded;
        if (total.chi >= modulus or total.xor5 >= modulus or total.io >= modulus) return error.KeccakLookupMassExceeded;
    }
    for (byte_request_counts) |mass| {
        total.bytes = std.math.add(u64, total.bytes, mass) catch return error.ByteLookupMassExceeded;
        if (total.bytes >= modulus) return error.ByteLookupMassExceeded;
    }
    return total;
}

/// Throughput-v1 masses: per active round row 320 five-output chi queries and
/// 107 three-position xor5 queries (vs 1600/320 compact); IO is unchanged.
/// Each table row's multiplicity is bounded by its bus mass, so mass < p
/// rules out multiplicity wrap; the compact bound already implies this one.
pub fn lookupMassThroughput(calls: usize) !LookupMass {
    const slots: u64 = @intCast(try std.math.divCeil(usize, calls, 2));
    const P = @import("batch_policy.zig");
    return .{
        .chi = std.math.mul(u64, slots, 24 * P.THROUGHPUT_CHI) catch return error.KeccakLookupMassExceeded,
        .xor5 = std.math.mul(u64, slots, 24 * P.THROUGHPUT_XOR5) catch return error.KeccakLookupMassExceeded,
        .io = std.math.mul(u64, @intCast(calls), 2 * 25) catch return error.KeccakLookupMassExceeded,
    };
}
pub fn admitThroughputRoster(component_calls: []const usize) !LookupMass {
    const modulus = @import("stwo_core").fields.m31.Modulus;
    var total = LookupMass{};
    for (component_calls) |calls| {
        const mass = try lookupMassThroughput(calls);
        total.chi = std.math.add(u64, total.chi, mass.chi) catch return error.KeccakLookupMassExceeded;
        total.xor5 = std.math.add(u64, total.xor5, mass.xor5) catch return error.KeccakLookupMassExceeded;
        total.io = std.math.add(u64, total.io, mass.io) catch return error.KeccakLookupMassExceeded;
        if (total.chi >= modulus or total.xor5 >= modulus or total.io >= modulus) return error.KeccakLookupMassExceeded;
    }
    return total;
}
pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !void {
    return validateGeometryFor(.pair29, calls, first_id, log);
}
pub fn validateGeometryFor(geometry: Geometry, calls: usize, first_id: u32, log: u32) !void {
    _ = try logSizeFor(geometry, calls);
    if (first_id == 0 or first_id >= @import("stwo_core").fields.m31.Modulus or @as(u64, first_id) + calls > @import("stwo_core").fields.m31.Modulus) return error.InvalidKeccakCallId;
    if (log < 5 or log > 26 or log < try logSizeFor(geometry, calls)) return error.InvalidKeccakComponentGeometry;
}
