//! Byte views remain explicitly tied to halfword ports. The fixed bitwise
//! table is the bound authority for every input and output byte.
const A = @import("abi.zig");
const R = @import("relations.zig");
pub const Op = enum(u32) { xor = 5, or_ = 8, and_ = 9 };
pub fn Row(comptime S: type) type {
    return struct {
        clock: S,
        pc: S,
        lhs: A.Read(S),
        rhs: A.Read(S),
        destination: A.Write(S),
        lhs_bytes: [4]S,
        rhs_bytes: [4]S,
        result_bytes: [4]S,
        rd_nonzero: S,
        rd_inverse: S,
    };
}
pub fn evaluate(comptime S: type, comptime op: Op, row: Row(S), active: S, constraints: anytype, events: anytype) void {
    A.padding(S, constraints, active, row);
    const lhs = A.Word(S).packedBytes(row.lhs_bytes);
    const rhs = A.Word(S).packedBytes(row.rhs_bytes);
    const result = A.Word(S).packedBytes(row.result_bytes);
    A.equalWord(S, constraints, active, row.lhs.value, lhs);
    A.equalWord(S, constraints, active, row.rhs.value, rhs);
    A.destination(S, constraints, active, row.destination, result, row.rd_nonzero, row.rd_inverse);
    for (0..4) |i| events.bitwise(active, @intFromEnum(op), .{ row.lhs_bytes[i], row.rhs_bytes[i], row.result_bytes[i] });
    R.read(S, events, .register_word, active, row.lhs, A.accessClock(S, row.clock, 0));
    R.read(S, events, .register_word, active, row.rhs, A.accessClock(S, row.clock, 1));
    R.write(S, events, .register_word, active, row.destination, A.accessClock(S, row.clock, 2));
    events.rom(active, row.pc, @intFromEnum(op), row.destination.address, row.lhs.address, row.rhs.address);
    R.sequential(S, events, active, row.clock, row.pc);
}
pub const ImmediateOp = enum(u32) { xor = 13, or_ = 14, and_ = 15 };
pub fn ImmediateRow(comptime S: type) type {
    return struct {
        clock: S,
        pc: S,
        source: A.Read(S),
        destination: A.Write(S),
        immediate: S,
        immediate_sign: S,
        immediate_low12: S,
        source_bytes: [4]S,
        immediate_bytes: [4]S,
        result_bytes: [4]S,
        rd_nonzero: S,
        rd_inverse: S,
    };
}
pub fn immediate(comptime S: type, comptime op: ImmediateOp, row: ImmediateRow(S), active: S, constraints: anytype, events: anytype) void {
    A.padding(S, constraints, active, row);
    // Enforce canonical sign extension of the ROM-bound signed immediate.
    A.enforce(S, constraints, active, A.boolResidual(S, row.immediate_sign), 2);
    A.enforce(S, constraints, active, row.immediate.sub(row.immediate_low12).add(row.immediate_sign.mul(A.c(S, 4096))), 1);
    events.range16(active, row.immediate_low12.mul(A.c(S, 16)));
    // Bit11 agrees with sign; a second bounded residual excludes an arbitrary
    // sign choice for the same 12-bit value.
    events.range16(active, row.immediate_low12.sub(row.immediate_sign.mul(A.c(S, 2048))).mul(A.c(S, 32)));
    const immediate_word = A.Word(S).packedBytes(row.immediate_bytes);
    A.enforce(S, constraints, active, immediate_word.lo.sub(row.immediate_low12.add(row.immediate_sign.mul(A.c(S, 61440)))), 1);
    A.enforce(S, constraints, active, immediate_word.hi.sub(row.immediate_sign.mul(A.c(S, 65535))), 1);
    A.equalWord(S, constraints, active, row.source.value, A.Word(S).packedBytes(row.source_bytes));
    A.destination(S, constraints, active, row.destination, A.Word(S).packedBytes(row.result_bytes), row.rd_nonzero, row.rd_inverse);
    const byte_op: u32 = switch (op) {
        .xor => 5,
        .or_ => 8,
        .and_ => 9,
    };
    for (0..4) |i| events.bitwise(active, byte_op, .{ row.source_bytes[i], row.immediate_bytes[i], row.result_bytes[i] });
    R.read(S, events, .register_word, active, row.source, A.accessClock(S, row.clock, 0));
    R.write(S, events, .register_word, active, row.destination, A.accessClock(S, row.clock, 1));
    events.rom(active, row.pc, @intFromEnum(op), row.destination.address, row.source.address, row.immediate);
    R.sequential(S, events, active, row.clock, row.pc);
}
