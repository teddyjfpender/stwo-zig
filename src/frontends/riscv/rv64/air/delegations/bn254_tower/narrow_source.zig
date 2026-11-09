//! Typed immutable source expression authority for two independently sized
//! components in ONE Miller-line proof. A component is not a wrapped proof.
//! Arithmetic:32 rows/call. Input frontier:20 rows/call. One local SSA relation
//! closes across them; the external Wire35 claim closes against the CPU packet.
const std = @import("std");
const E = @import("../../evaluation.zig");
const D = @import("dag.zig");
const Micro = @import("micro.zig");
const B = @import("../curves/spec.zig");
const Schedule = @import("schedule.zig");
pub const AUTHORITY_VERSION = "op_miller_line_ssa_v1";
pub const TAG = @import("../../../ethereum_services/bn254_tower.zig").TAG;
pub const KIND: u32 = 12;
pub const Public = struct { calls: u32, first_id: u32 };
pub const Role = enum { frontier, arithmetic };
pub const ROW = 0;
pub const FIRST = 1;
pub const LAST = 2;
pub const CALL_INDEX = 3;
pub const WRITER_ID = 4;
pub const WRITER_WEIGHT = 5;
pub const GLOBAL_LABEL = 6;
pub const GLOBAL_WEIGHT = 7;
pub const READ_ID = 8;
pub const READ_WEIGHT = READ_ID + D.OPERANDS;
pub const MICRO_FIXED = READ_WEIGHT + D.OPERANDS;
pub const BYTE_VALUE = MICRO_FIXED + Micro.FIXED;
pub const CARRY_VALUE = BYTE_VALUE + 1;
pub const FIXED = CARRY_VALUE + 1;
pub const BYTE_MULT = Micro.MAIN;
pub const CARRY_MULT = BYTE_MULT + 1;
pub const FRONTIER_ACTIVE = 0;
pub const FRONTIER_VALUE = 1;
pub const FRONTIER_MAIN = 33;
pub const FrontierRow = [FRONTIER_MAIN]u32;
pub const MIN_LOG = 8;
pub const MAX_LOG = 22;
pub fn period(role: Role) usize {
    return if (role == .frontier) D.INPUTS else D.STEPS;
}
pub fn mainWidth(role: Role) usize {
    return if (role == .frontier) FRONTIER_MAIN else Micro.MAIN;
}
pub fn fixedRow(role: Role, index: usize, log: u32) [FIXED]u32 {
    const rows = @as(usize, 1) << @intCast(log);
    std.debug.assert(index < rows);
    const step = index % period(role);
    var result: [FIXED]u32 = @splat(0);
    result[ROW] = @intCast(index);
    result[FIRST] = @intFromBool(index == 0);
    result[LAST] = @intFromBool(index == rows - 1);
    result[CALL_INDEX] = @intCast(index / period(role));
    result[BYTE_VALUE] = @intCast(index % 256);
    result[CARRY_VALUE] = @intCast(index % Micro.CARRY_LIMIT);
    if (role == .frontier) {
        result[WRITER_ID] = @intCast(step);
        result[WRITER_WEIGHT] = D.FANOUT[step];
        result[GLOBAL_LABEL] = @intCast(step);
        result[GLOBAL_WEIGHT] = B.M31 - 1;
    } else {
        const instruction = D.PROGRAM[step];
        result[WRITER_ID] = instruction.output;
        result[WRITER_WEIGHT] = D.FANOUT[instruction.output];
        if (instruction.output >= 34 and instruction.output < 46) {
            result[GLOBAL_LABEL] = 20 + instruction.output - 34;
            result[GLOBAL_WEIGHT] = 1;
        }
        for (instruction.operands(), 0..) |id, slot| {
            result[READ_ID + slot] = id;
            result[READ_WEIGHT + slot] = @intFromBool(id < D.VALUES);
        }
        result[MICRO_FIXED..][0..Micro.FIXED].* = Micro.fixed(step);
    }
    return result;
}
pub fn validate(role: Role, public: Public, log: u32) !void {
    _ = try Schedule.mass(public.calls);
    if (public.first_id == 0 or public.first_id >= B.M31 or public.calls > B.M31 - public.first_id) return error.TowerGeometry;
    if (log < MIN_LOG or log > MAX_LOG or public.calls > ((@as(u64, 1) << @intCast(log)) - 1) / period(role)) return error.TowerGeometry;
}
pub fn frontierRow(input: *const [D.INPUTS]u256, step: usize) FrontierRow {
    std.debug.assert(step < D.INPUTS);
    var out: FrontierRow = @splat(0);
    out[FRONTIER_ACTIVE] = 1;
    for (0..32) |byte| out[FRONTIER_VALUE + byte] = @as(u8, @truncate(input[step] >> @intCast(8 * byte)));
    return out;
}
inline fn k(comptime F: type, x: u32) F {
    return E.qFor(F, x);
}
pub fn tuple(comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), id: F, value_start: usize) [35]F {
    var out: [35]F = undefined;
    out[0] = k(F, KIND);
    out[1] = E.firstIdFor(F, public).add(v.fixed(CALL_INDEX));
    out[2] = id;
    for (0..32) |byte| out[3 + byte] = v.main(value_start + byte);
    return out;
}
/// Local-source term order is protocol authority:
/// arithmetic BYTE[97], U15[31], SSA reads[7], SSA weighted writer[1];
/// frontier SSA weighted writer[1]. Distinct relation transcript domains are
/// mandatory. No caller can replace this expression with a CPU-bridge formula.
pub fn emitLocal(comptime role: Role, comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), sink: anytype) void {
    const active = v.main(0);
    if (role == .arithmetic) {
        for (0..32) |byte| sink.byte(v.main(Micro.RESULT + byte), active);
        for (0..Micro.G.q_bytes) |byte| sink.byte(v.main(Micro.QUOTIENT + byte), active);
        for (0..32) |byte| sink.byte(v.main(Micro.DISTANCE + byte), active);
        for (0..Micro.G.carries) |carry| sink.carry(v.main(Micro.CARRY + carry), active);
        for (0..D.OPERANDS) |slot| sink.ssa(tuple(F, v, public, v.fixed(READ_ID + slot), Micro.OPERANDS + 32 * slot), active.mul(v.fixed(READ_WEIGHT + slot)).neg());
    }
    const start = if (role == .arithmetic) Micro.RESULT else FRONTIER_VALUE;
    sink.ssa(tuple(F, v, public, v.fixed(WRITER_ID), start), active.mul(v.fixed(WRITER_WEIGHT)));
}
/// Source-owned provider expressions complete the two local range arguments.
/// Consumer expression order above is unchanged; an instance-filtering sink
/// appends each provider after its corresponding consumer family.
pub fn emitRangeProviders(comptime F: type, v: anytype, sink: anytype) void {
    _ = F;
    sink.byte(v.fixed(BYTE_VALUE), v.main(BYTE_MULT).neg());
    sink.carry(v.fixed(CARRY_VALUE), v.main(CARRY_MULT).neg());
}
pub fn globalFraction(comptime role: Role, comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F))) struct { tuple: [35]F, weight: F } {
    return .{ .tuple = tuple(F, v, public, v.fixed(GLOBAL_LABEL), if (role == .arithmetic) Micro.RESULT else FRONTIER_VALUE), .weight = v.main(0).mul(v.fixed(GLOBAL_WEIGHT)) };
}
pub const MicroView = struct {
    // Concrete views adapt the16 periodic literal/sign columns without copying
    // witness storage or duplicating the arithmetic expression authority.
    pub fn Of(comptime View: type) type {
        return struct {
            base: View,
            pub fn main(self: *const @This(), index: usize) @TypeOf(self.base.main(index)) {
                return self.base.main(index);
            }
            pub fn fixed(self: *const @This(), index: usize) @TypeOf(self.base.fixed(index)) {
                return self.base.fixed(MICRO_FIXED + index);
            }
        };
    }
};
/// Main-only authority plus one exact prefix bound. Public calls bind a whole
///20/32-row roster, and the final domain row must be inactive. Therefore a
/// claimant cannot truncate a call, duplicate an active callid or turn on a
/// later inactive row. The shared local relation then closes immutable edges.
pub fn emitMain(comptime role: Role, comptime F: type, v: anytype, public: E.CallSpanFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    const active = v.main(0);
    if (role == .frontier) {
        E.booleanFor(F, sink, active);
    } else {
        const adapter = MicroView.Of(@TypeOf(v)){ .base = v };
        Micro.emitMain(F, &adapter, sink);
    }
    const previous = v.previousActive();
    const first = v.fixed(FIRST);
    sink.emit(first.mul(F.one().sub(active)));
    sink.emit(F.one().sub(first).mul(active).mul(F.one().sub(previous)));
    sink.emit(previous.mul(F.one().sub(active)).mul(v.fixed(ROW).sub(E.callsFor(F, public).mul(k(F, @intCast(period(role)))))));
    sink.emit(v.fixed(LAST).mul(active));
}
pub const Cost = struct { frontier_log: u32, arithmetic_log: u32, committed_main_cells: u64, lifted_main_columns: usize, local_byte_facts_padded: u64, local_carry_facts_padded: u64, local_ssa_facts_padded: u64 };
pub fn cost(public: Public) !Cost {
    const frontier_log: u32 = @intCast(std.math.log2_int_ceil(u64, @as(u64, public.calls) * D.INPUTS + 1));
    const arithmetic_log: u32 = @intCast(std.math.log2_int_ceil(u64, @as(u64, public.calls) * D.STEPS + 1));
    try validate(.frontier, public, frontier_log);
    try validate(.arithmetic, public, arithmetic_log);
    const f: u64 = @as(u64, 1) << @intCast(frontier_log);
    const a: u64 = @as(u64, 1) << @intCast(arithmetic_log);
    return .{
        .frontier_log = frontier_log,
        .arithmetic_log = arithmetic_log,
        .committed_main_cells = f * FRONTIER_MAIN + a * Micro.MAIN,
        .lifted_main_columns = FRONTIER_MAIN + Micro.MAIN,
        .local_byte_facts_padded = 128 * a,
        .local_carry_facts_padded = 32 * a,
        .local_ssa_facts_padded = 8 * a + f,
    };
}
