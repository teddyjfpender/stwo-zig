//! Candidate replacement for RAM-only synthetic clock hops. These equations
//! prove an integer-positive gap RELATIVE TO independently authenticated
//! current/predecessor clock bounds and three range16 requests. They do not
//! authenticate an execution, a source roster, or a memory permutation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const NativeWitness = @import("../air/lang/typed_load_store_witness.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
pub const VERSION = 3;
pub const production_active = false;
pub const whole_source_qualified = false;
pub const COLUMN_COUNT = 3;
pub const CONSTRAINT_COUNT = 6;
pub const MAX_DEGREE = 3;
pub const CLOCK_BOUND: u32 = 1 << 27;
pub const HIGH_MAX: u32 = (1 << 11) - 1;
pub const Layout = struct {
    pub const low16 = 0;
    pub const high11 = 1;
    pub const high_slack11 = 2;
};
pub const Policy = struct {
    max_clock: u32,
    pub fn fromCycles(cycles: u32) !Policy {
        if (cycles == 0 or cycles > 1 << 24) return error.InvalidV3RamClockPolicy;
        return .{ .max_clock = @intCast(@import("../access_clock.zig").maximum(cycles)) };
    }
    pub fn validate(self: Policy) !void {
        if (self.max_clock == 0 or self.max_clock >= CLOCK_BOUND) return error.InvalidV3RamClockPolicy;
    }
    /// Host validation only. Original state/MemoryAccess AIR and exact source
    /// closure must establish these bounds for committed clock expressions.
    pub fn requireBounded(self: Policy, current: u32, previous: u32) !void {
        try self.validate();
        if (current == 0 or current > self.max_clock or previous > self.max_clock) return error.UnboundedV3RamClock;
    }
};
fn c(comptime S: type, value: u32) S {
    if (S == M) return M.fromCanonical(value);
    return @import("block_v7_memory_relations_v1.zig").lift(S, Q.fromBase(M.fromCanonical(value)));
}
/// Range16 supply is required for ALL THREE requested cells. In particular,
/// range16(high) alone would not make the composed gap 27 bits.
pub fn range16Requests(comptime S: type, active: S, row: [COLUMN_COUNT]S) [COLUMN_COUNT]struct { weight: S, value: S } {
    return .{ .{ .weight = active, .value = row[0] }, .{ .weight = active, .value = row[1] }, .{ .weight = active, .value = row[2] } };
}
pub fn constraints(comptime S: type, active: S, current: S, previous: S, row: [COLUMN_COUNT]S) [CONSTRAINT_COUNT]S {
    const inactive = S.one().sub(active);
    const gap = row[Layout.low16].add(row[Layout.high11].mul(c(S, 65536)));
    return .{
        active.mul(active.sub(S.one())),
        active.mul(current.sub(previous).sub(S.one()).sub(gap)),
        row[Layout.high11].add(row[Layout.high_slack11]).sub(active.mul(c(S, HIGH_MAX))),
        inactive.mul(row[0]),
        inactive.mul(row[1]),
        inactive.mul(row[2]),
    };
}
/// Both native loads and stores access RAM at the third subclock 4*c-1.
/// The source-read predecessor is physical src.previous_clock for loads;
/// destination.previous_clock is used for stores. Typed AIR authenticates
/// this exact conditional split and the fixed active selector independently.
pub fn constraintsNative(comptime S: type, active: S, main: []const S, row: [COLUMN_COUNT]S) ![CONSTRAINT_COUNT]S {
    if (main.len != Halt.NativeColumns.width) return error.InvalidV3RamClockRow;
    const store = main[Halt.NativeColumns.store_flags[0]].add(main[Halt.NativeColumns.store_flags[1]]).add(main[Halt.NativeColumns.store_flags[2]]);
    const source_previous = main[@intFromEnum(NativeWitness.RowSource.src_clock_prev)];
    const destination_previous = main[@intFromEnum(NativeWitness.RowSource.dst_clock_prev)];
    const previous = source_previous.add(store.mul(destination_previous.sub(source_previous)));
    return constraints(S, active, main[Halt.NativeColumns.clock].mul(c(S, 4)).sub(S.one()), previous, row);
}
pub fn witness(policy: Policy, active: bool, current: u32, previous: u32) ![COLUMN_COUNT]M {
    try policy.validate();
    if (!active) return @splat(M.zero());
    try policy.requireBounded(current, previous);
    if (current <= previous) return error.NonIncreasingV3RamClock;
    const gap = current - previous - 1;
    return .{ M.fromCanonical(gap & 65535), M.fromCanonical(gap >> 16), M.fromCanonical(HIGH_MAX - (gap >> 16)) };
}
/// Finite integer audit of the relative theorem, not a proof receipt. Since
/// both clocks are <2^27 and gap<2^27, a negative difference reduced mod M31
/// lies above p-2^27 >2^27 and cannot equal the nonnegative composed gap.
pub fn checkIntegerTheorem(policy: Policy, current: u32, previous: u32, row: [COLUMN_COUNT]M) !void {
    try policy.requireBounded(current, previous);
    for (row) |value| if (value.v >= 65536) return error.UnclosedV3RamClockRange16;
    for (constraints(M, M.one(), M.fromCanonical(current), M.fromCanonical(previous), row)) |value| if (!value.isZero()) return error.InvalidV3RamClockEquation;
    if (current <= previous or current - previous - 1 >= CLOCK_BOUND) return error.InvalidV3RamClockIntegerOrder;
}
comptime {
    if (core.fields.m31.Modulus - CLOCK_BOUND <= CLOCK_BOUND or 2 * 65535 >= core.fields.m31.Modulus) @compileError("V3 RAM clock no-wrap theorem no longer applies");
}
