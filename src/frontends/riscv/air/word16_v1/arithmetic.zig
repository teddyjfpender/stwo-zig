//! Generic scalar equations. Inputs are canonical only after ALL range/event
//! producers and register boundary obligations have been closed.
const A = @import("abi.zig");
const R = @import("relations.zig");
pub const RegOp = enum { add, sub };
pub fn RegisterRow(comptime S: type) type {
    return struct { clock: S, pc: S, lhs: A.Read(S), rhs: A.Read(S), destination: A.Write(S), result: A.Word(S), rd_nonzero: S, rd_inverse: S };
}
pub fn ImmediateRow(comptime S: type) type {
    return struct { clock: S, pc: S, source: A.Read(S), destination: A.Write(S), immediate: S, result: A.Word(S), rd_nonzero: S, rd_inverse: S };
}
/// With canonical 16-bit limbs, every numerator has absolute value < 2^18.
/// Boolean/ternary carries and the high equation therefore enforce integer
/// arithmetic, not equality only modulo M31. Final carry/borrow is discarded
/// exactly as RV32 modular arithmetic requires.
pub fn register(comptime S: type, comptime op: RegOp, row: RegisterRow(S), active: S, constraints: anytype, events: anytype) void {
    A.padding(S, constraints, active, row);
    const low = if (op == .add) row.lhs.value.lo.add(row.rhs.value.lo).sub(row.result.lo) else row.rhs.value.lo.add(row.result.lo).sub(row.lhs.value.lo);
    const carry_low = A.divide65536(S, low);
    const high = if (op == .add) row.lhs.value.hi.add(row.rhs.value.hi).add(carry_low).sub(row.result.hi) else row.rhs.value.hi.add(carry_low).add(row.result.hi).sub(row.lhs.value.hi);
    const carry_high = A.divide65536(S, high);
    A.enforce(S, constraints, active, A.boolResidual(S, carry_low), 2);
    A.enforce(S, constraints, active, A.boolResidual(S, carry_high), 2);
    A.destination(S, constraints, active, row.destination, row.result, row.rd_nonzero, row.rd_inverse);
    R.wordRange(S, events, active, row.result);
    R.read(S, events, .register_word, active, row.lhs, A.accessClock(S, row.clock, 0));
    R.read(S, events, .register_word, active, row.rhs, A.accessClock(S, row.clock, 1));
    R.write(S, events, .register_word, active, row.destination, A.accessClock(S, row.clock, 2));
    events.rom(active, row.pc, @as(u32, if (op == .add) 0 else 1), row.destination.address, row.lhs.address, row.rhs.address);
    R.sequential(S, events, active, row.clock, row.pc);
}
pub fn immediate(comptime S: type, row: ImmediateRow(S), active: S, constraints: anytype, events: anytype) void {
    A.padding(S, constraints, active, row);
    // ROM membership is required to bind immediate to canonical [-2048,2047].
    const carry_low = A.divide65536(S, row.source.value.lo.add(row.immediate).sub(row.result.lo));
    const carry_high = A.divide65536(S, row.source.value.hi.add(carry_low).sub(row.result.hi));
    A.enforce(S, constraints, active, A.ternaryResidual(S, carry_low), 3);
    A.enforce(S, constraints, active, A.ternaryResidual(S, carry_high), 3);
    A.destination(S, constraints, active, row.destination, row.result, row.rd_nonzero, row.rd_inverse);
    R.wordRange(S, events, active, row.result);
    R.read(S, events, .register_word, active, row.source, A.accessClock(S, row.clock, 0));
    R.write(S, events, .register_word, active, row.destination, A.accessClock(S, row.clock, 1));
    events.rom(active, row.pc, @as(u32, 10), row.destination.address, row.source.address, row.immediate);
    R.sequential(S, events, active, row.clock, row.pc);
}
