//! Explicit candidate RAM-only integer bridge: 29 physical cells instead of
//! 48. Reconstruct the original witness and evaluate every original equation.
//! No product/profile selects this candidate until PCS and recursion admission
//! are integrated. This module alone grants no proof authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("block_execution_integer_algebra_v1.zig");
const Constructor = @import("block_execution_integer_bridge_v2.zig");
const Source = @import("block_execution_access_bridge_v2.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const production_active = false;
pub const VERSION: u32 = 1;
pub const COLUMN_COUNT: usize = 29;
pub const RESIDUAL_COUNT: usize = Original.RESIDUAL_COUNT + 1;
pub const retained = [_]usize{
    0, 1, 2, // word index: high byte is reconstructed from its six bits
    4, 5, 6, 7, // byte address
    8, 9, 10, // local clock: high byte is reconstructed from its three bits
    12, 13, 14, 15, // 32-bit global clock
    21, 22, 23, // internal address carries
    26, 27, 28, // internal 32-bit clock carries
    34, 35, 36, 37, 38, 39, // word high bits
    40, 41, 42, // local clock high bits
};
comptime {
    if (retained.len != COLUMN_COUNT) @compileError("compact bridge width drift");
    for (retained, 0..) |column, index| {
        if (column >= Original.COLUMN_COUNT or (index != 0 and column <= retained[index - 1]))
            @compileError("compact bridge map is not an ordered injection");
    }
}

/// Must be derived by the receiver from the admitted source span. A candidate
/// cannot choose an earlier clock offset or silently truncate a wide clock.
pub const Policy = struct {
    frame: Frame,
    base_clock: u64,
    pub fn init(frame: Frame) !Policy {
        const base = try Constructor.baseClockFromPublicFrame(frame);
        const last_cycle = try std.math.add(u64, frame.global_first_cycle, frame.cycle_count - 1);
        const last = try std.math.add(u64, try std.math.mul(u64, last_cycle - 1, 4), 3);
        if (last > std.math.maxInt(u32)) return error.CompactRamClockOutOfRange;
        return .{ .frame = frame, .base_clock = base };
    }
    pub fn validate(self: Policy) !void {
        if (!std.meta.eql(self, try init(self.frame))) return error.UntrustedCompactRamClock;
    }
    pub fn mix(self: Policy, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ 0x43524231, VERSION, COLUMN_COUNT, RESIDUAL_COUNT, @intFromEnum(self.frame.clock_frame), self.frame.cycle_count });
        channel.mixU64(self.frame.global_first_cycle);
        channel.mixU64(self.base_clock);
        for (retained) |column| channel.mixU32s(&.{@intCast(column)});
    }
};

pub fn Algebra(comptime S: type) type {
    return struct {
        const Old = Original.Algebra(S);
        pub fn expand(columns: [COLUMN_COUNT]S) Old.Witness {
            var full: [Original.COLUMN_COUNT]S = @splat(S.zero());
            for (retained, columns) |index, value| full[index] = value;
            var high_word = S.zero();
            for (full[34..40], 0..) |bit, index| high_word = high_word.add(bit.mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @intCast(index)))));
            full[3] = high_word;
            var high_clock = S.zero();
            for (full[40..43], 0..) |bit, index| high_clock = high_clock.add(bit.mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @intCast(index)))));
            full[11] = high_clock;
            // Boundary carries, high global-clock bytes/carries and unused RAM
            // register bits remain literal zero polynomials, including at OODS.
            return Old.Witness.fromColumns(full);
        }
        pub fn constraints(pair: Source.Pair(S), columns: [COLUMN_COUNT]S, base_clock_bytes: [8]S) Old.Residuals {
            var result = Old.constraints(pair, expand(columns), base_clock_bytes);
            std.debug.assert(result.len == Original.RESIDUAL_COUNT);
            result.values[result.len] = pair.active.mul(pair.space.sub(S.one()));
            result.len += 1;
            return result;
        }
        pub fn transitionAtPoint(pair: Source.Pair(S), columns: [COLUMN_COUNT]S) [@import("block_memory_relation_v2.zig").TRANSITION_ARITY]S {
            return Old.transitionAtPoint(pair, expand(columns));
        }
    };
}

pub fn construct(pair: Source.Pair(Q), policy: Policy) ![COLUMN_COUNT]Q {
    try policy.validate();
    const access = try Source.decodePair(pair);
    if (access.active) {
        if (access.space != 1) return error.RegisterAccessInCompactRamBridge;
        _ = try policy.frame.globalClock(access.local_clock);
    }
    const original = (try Constructor.Witness.fromPair(pair, policy.base_clock)).columns();
    var columns: [COLUMN_COUNT]Q = undefined;
    for (&columns, retained) |*value, index| value.* = original[index];
    return columns;
}
