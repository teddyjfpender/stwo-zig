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
pub fn logSize(calls: usize) !u32 {
    _ = try admitRoster(&.{calls}, &.{});
    const pairs = try std.math.divCeil(usize, calls, 2);
    const rows = try std.math.mul(usize, pairs, ROWS_PER_PAIR);
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

pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !void {
    _ = try logSize(calls);
    if (first_id == 0 or first_id >= @import("stwo_core").fields.m31.Modulus or @as(u64, first_id) + calls > @import("stwo_core").fields.m31.Modulus) return error.InvalidKeccakCallId;
    if (log < 5 or log > 26 or log < try logSize(calls)) return error.InvalidKeccakComponentGeometry;
}
