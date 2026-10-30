//! Honest bounded witness materialization, never a verifier/admission authority.
//! Semantic rows are intentionally NOT a qualified compact physical layout.
const std = @import("std");
const A = @import("abi.zig");
const Arithmetic = @import("arithmetic.zig");
const Logic = @import("logic.zig");
const LS = @import("load_store.zig");
pub const Read = struct { address: u5, previous_clock: u32, value: u32 };
pub const Destination = struct { address: u5, previous_clock: u32, before: u32 };
pub const Memory = struct { previous_clock: u32, before: u32 };
pub const Limits = struct { max_rows: usize = 1 << 24, max_bytes: usize = 1 << 30, max_cycles: u32 = 1 << 24 };
pub fn read(input: Read) A.Read(A.M) {
    return .{ .address = A.c(A.M, input.address), .previous_clock = A.c(A.M, input.previous_clock), .value = A.Word(A.M).fromU32(input.value) };
}
fn destination(input: Destination, result: u32) A.Write(A.M) {
    return .{ .address = A.c(A.M, input.address), .previous_clock = A.c(A.M, input.previous_clock), .before = A.Word(A.M).fromU32(input.before), .after = A.Word(A.M).fromU32(if (input.address == 0) 0 else result) };
}
fn inverseRegister(address: u5) A.M {
    return if (address == 0) A.M.zero() else A.c(A.M, address).inv() catch unreachable;
}
fn validate(clock: u32, pc: u32, limits: Limits) !void {
    if (clock == 0 or clock > limits.max_cycles or limits.max_cycles > (1 << 24) or pc >= 1 << 30 or pc % 4 != 0) return error.InvalidWord16Instruction;
}
fn previous(clock: u32, comptime ordinal: u2, value: u32) !void {
    // Share this namespace's exact generic subclock expression. Validated
    // clock<=2^24 makes its canonical M31 result an exact host integer too.
    const emitted = A.accessClock(A.M, A.c(A.M, clock), ordinal).v;
    if (value >= emitted or (value != 0 and value % 4 == 0)) return error.InvalidWord16PreviousClock;
}
fn validateRead(input: Read, clock: u32, comptime ordinal: u2) !void {
    try previous(clock, ordinal, input.previous_clock);
    if (input.address == 0 and input.value != 0) return error.NonzeroWord16X0;
}
fn validateDestination(input: Destination, clock: u32, comptime ordinal: u2) !void {
    try previous(clock, ordinal, input.previous_clock);
    if (input.address == 0 and input.before != 0) return error.NonzeroWord16X0;
}
fn immediateValid(immediate: i32) !void {
    if (immediate < -2048 or immediate > 2047) return error.InvalidWord16Immediate;
}
pub fn arithmetic(comptime op: Arithmetic.RegOp, clock: u32, pc: u32, lhs: Read, rhs: Read, rd: Destination, limits: Limits) !Arithmetic.RegisterRow(A.M) {
    try validate(clock, pc, limits);
    try validateRead(lhs, clock, 0);
    try validateRead(rhs, clock, 1);
    try validateDestination(rd, clock, 2);
    const result = if (op == .add) lhs.value +% rhs.value else lhs.value -% rhs.value;
    return .{ .clock = A.c(A.M, clock), .pc = A.c(A.M, pc), .lhs = read(lhs), .rhs = read(rhs), .destination = destination(rd, result), .result = A.Word(A.M).fromU32(result), .rd_nonzero = A.c(A.M, @intFromBool(rd.address != 0)), .rd_inverse = inverseRegister(rd.address) };
}
pub fn addi(clock: u32, pc: u32, source: Read, rd: Destination, immediate: i32, limits: Limits) !Arithmetic.ImmediateRow(A.M) {
    try validate(clock, pc, limits);
    try immediateValid(immediate);
    try validateRead(source, clock, 0);
    try validateDestination(rd, clock, 1);
    const result = source.value +% @as(u32, @bitCast(immediate));
    return .{ .clock = A.c(A.M, clock), .pc = A.c(A.M, pc), .source = read(source), .destination = destination(rd, result), .immediate = A.signed(A.M, immediate), .result = A.Word(A.M).fromU32(result), .rd_nonzero = A.c(A.M, @intFromBool(rd.address != 0)), .rd_inverse = inverseRegister(rd.address) };
}
fn bytes(value: u32) [4]A.M {
    var result: [4]A.M = undefined;
    for (&result, 0..) |*byte, i| byte.* = A.c(A.M, (value >> @as(u5, @intCast(8 * i))) & 255);
    return result;
}
fn logicValue(comptime op: Logic.Op, left: u32, right: u32) u32 {
    return switch (op) {
        .xor => left ^ right,
        .or_ => left | right,
        .and_ => left & right,
    };
}
pub fn logic(comptime op: Logic.Op, clock: u32, pc: u32, lhs: Read, rhs: Read, rd: Destination, limits: Limits) !Logic.Row(A.M) {
    try validate(clock, pc, limits);
    try validateRead(lhs, clock, 0);
    try validateRead(rhs, clock, 1);
    try validateDestination(rd, clock, 2);
    const result = logicValue(op, lhs.value, rhs.value);
    return .{ .clock = A.c(A.M, clock), .pc = A.c(A.M, pc), .lhs = read(lhs), .rhs = read(rhs), .destination = destination(rd, result), .lhs_bytes = bytes(lhs.value), .rhs_bytes = bytes(rhs.value), .result_bytes = bytes(result), .rd_nonzero = A.c(A.M, @intFromBool(rd.address != 0)), .rd_inverse = inverseRegister(rd.address) };
}
pub fn logicImmediate(comptime op: Logic.ImmediateOp, clock: u32, pc: u32, source: Read, rd: Destination, immediate: i32, limits: Limits) !Logic.ImmediateRow(A.M) {
    try validate(clock, pc, limits);
    try immediateValid(immediate);
    try validateRead(source, clock, 0);
    try validateDestination(rd, clock, 1);
    const unsigned: u32 = @bitCast(immediate);
    const byte_op: Logic.Op = switch (op) {
        .xor => .xor,
        .or_ => .or_,
        .and_ => .and_,
    };
    const result = logicValue(byte_op, source.value, unsigned);
    return .{ .clock = A.c(A.M, clock), .pc = A.c(A.M, pc), .source = read(source), .destination = destination(rd, result), .immediate = A.signed(A.M, immediate), .immediate_sign = A.c(A.M, @intFromBool(immediate < 0)), .immediate_low12 = A.c(A.M, unsigned & 4095), .source_bytes = bytes(source.value), .immediate_bytes = bytes(unsigned), .result_bytes = bytes(result), .rd_nonzero = A.c(A.M, @intFromBool(rd.address != 0)), .rd_inverse = inverseRegister(rd.address) };
}
fn effective(base: u32, immediate: i32, comptime width: u3) !u32 {
    try immediateValid(immediate);
    const address = @as(i64, base) + immediate;
    if (base >= 1 << 30 or address < 0 or address >= 1 << 30 or @mod(address, width) != 0) return error.InvalidWord16Address;
    return @intCast(address);
}
fn addressFields(address: u32) LS.Address(A.M) {
    return .{ .quarter_low14 = A.c(A.M, (address >> 2) & 0x3fff), .quarter_high14 = A.c(A.M, address >> 16), .offset_bits = .{ A.c(A.M, address & 1), A.c(A.M, (address >> 1) & 1) } };
}
fn halt(address: u32, policy: LS.Halt) ![2]A.M {
    if (policy.address >= 1 << 30 or policy.address % 4 != 0) return error.InvalidWord16HaltPolicy;
    if (policy.permitted_native_cycle) |cycle| if (cycle == 0 or cycle > 1 << 24) return error.InvalidWord16HaltPolicy;
    const delta = A.c(A.M, address).sub(A.c(A.M, policy.address));
    return if (delta.isZero()) .{ A.M.one(), A.M.zero() } else .{ A.M.zero(), try delta.inv() };
}
pub fn load(comptime op: LS.Load, clock: u32, pc: u32, base: Read, rd: Destination, immediate: i32, memory: Memory, policy: LS.Halt, limits: Limits) !LS.LoadRow(A.M) {
    try validate(clock, pc, limits);
    try validateRead(base, clock, 0);
    try previous(clock, 1, memory.previous_clock);
    try validateDestination(rd, clock, 2);
    const width: u3 = switch (op) {
        .lw => 4,
        .lh, .lhu => 2,
        else => 1,
    };
    const address = try effective(base.value, immediate, width);
    const selected = if (width == 4) 0 else (memory.before >> @as(u5, @intCast((address & 3) * 8))) & @as(u32, if (width == 1) 255 else 65535);
    const sign: u32 = switch (op) {
        .lb => selected >> 7,
        .lh => selected >> 15,
        else => 0,
    };
    const result = switch (op) {
        .lw => memory.before,
        .lb => selected | (if (sign != 0) @as(u32, 0xffffff00) else 0),
        .lh => selected | (if (sign != 0) @as(u32, 0xffff0000) else 0),
        .lbu, .lhu => selected,
    };
    return .{ .clock = A.c(A.M, clock), .pc = A.c(A.M, pc), .base = read(base), .memory = .{ .address = A.c(A.M, address & ~@as(u32, 3)), .previous_clock = A.c(A.M, memory.previous_clock), .value = A.Word(A.M).fromU32(memory.before) }, .destination = destination(rd, result), .immediate = A.signed(A.M, immediate), .address = addressFields(address), .memory_bytes = if (op == .lw) @splat(A.M.zero()) else bytes(memory.before), .selected = A.c(A.M, selected), .sign = A.c(A.M, sign), .result = A.Word(A.M).fromU32(result), .rd_nonzero = A.c(A.M, @intFromBool(rd.address != 0)), .rd_inverse = inverseRegister(rd.address), .halt_auxiliary = try halt(address & ~@as(u32, 3), policy) };
}
pub fn store(comptime op: LS.Store, clock: u32, pc: u32, base: Read, source: Read, immediate: i32, memory: Memory, policy: LS.Halt, limits: Limits) !LS.StoreRow(A.M) {
    try validate(clock, pc, limits);
    try validateRead(base, clock, 0);
    try validateRead(source, clock, 1);
    try previous(clock, 2, memory.previous_clock);
    const width: u3 = switch (op) {
        .sw => 4,
        .sh => 2,
        .sb => 1,
    };
    const address = try effective(base.value, immediate, width);
    const shift: u5 = @intCast((address & 3) * 8);
    const mask: u32 = if (op == .sw) 0xffffffff else if (op == .sh) @as(u32, 0xffff) << shift else @as(u32, 0xff) << shift;
    const after = if (op == .sw) source.value else (memory.before & ~mask) | ((source.value << shift) & mask);
    return .{ .clock = A.c(A.M, clock), .pc = A.c(A.M, pc), .base = read(base), .source = read(source), .memory = .{ .address = A.c(A.M, address & ~@as(u32, 3)), .previous_clock = A.c(A.M, memory.previous_clock), .before = A.Word(A.M).fromU32(memory.before), .after = A.Word(A.M).fromU32(after) }, .immediate = A.signed(A.M, immediate), .address = addressFields(address), .source_bytes = if (op == .sw) @splat(A.M.zero()) else bytes(source.value), .before_bytes = if (op == .sw) @splat(A.M.zero()) else bytes(memory.before), .after_bytes = if (op == .sw) @splat(A.M.zero()) else bytes(after), .halt_auxiliary = try halt(address & ~@as(u32, 3), policy) };
}
/// Fixed-capacity ownership: no hidden ArrayList growth or transient doubling.
/// The caller chooses each canonical component's power-of-two domain. The
/// future receiver must independently derive that geometry, not trust this.
pub fn BoundedRows(comptime Row: type) type {
    return struct {
        a: std.mem.Allocator,
        rows: []Row,
        active_count: usize = 0,
        const Self = @This();
        pub fn init(a: std.mem.Allocator, capacity: usize, limits: Limits) !Self {
            if (capacity == 0 or !std.math.isPowerOfTwo(capacity) or capacity > limits.max_rows or capacity > (1 << 24)) return error.InvalidWord16RowCapacity;
            if (try std.math.mul(usize, capacity, @sizeOf(Row)) > limits.max_bytes) return error.Word16WitnessBudgetExceeded;
            return .{ .a = a, .rows = try a.alloc(Row, capacity) };
        }
        pub fn append(self: *Self, row: Row) !void {
            if (self.active_count == self.rows.len) return error.Word16RowCapacityExceeded;
            self.rows[self.active_count] = row;
            self.active_count += 1;
        }
        pub fn pad(self: *Self) !void {
            if (self.active_count == 0) return error.EmptyWord16Component;
            @memset(self.rows[self.active_count..], std.mem.zeroes(Row));
        }
        pub fn deinit(self: *Self) void {
            self.a.free(self.rows);
            self.* = undefined;
        }
    };
}
