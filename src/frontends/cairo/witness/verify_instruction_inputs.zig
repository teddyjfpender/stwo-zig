//! Canonical compact inputs for the Cairo `verify_instruction` witness.
//!
//! Every active opcode component feeds only its real rows into Rust's
//! `verify_instruction::ClaimGenerator`; `add_inputs` deliberately truncates
//! packed producer output to `n_active_rows`. The consumer merges equal
//! instruction tuples, orders them by pc, then pads its own trace with the
//! first tuple and zero multiplicity.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const opcodes = @import("../adapter/opcodes.zig");
const execution_tables = @import("execution_tables.zig");

pub const tuple_word_count: usize = 7;
pub const input_column_count: usize = 10;
pub const Tuple = [tuple_word_count]u32;

pub const Error = error{
    EmptyInput,
    InvalidRowCount,
    InvalidColumn,
    MissingInstruction,
    InvalidInstruction,
    ConflictingInstruction,
    CountOverflow,
};

pub const Row = struct {
    tuple: Tuple,
    multiplicity: u32,
};

pub const CompactInput = struct {
    allocator: std.mem.Allocator,
    rows: []Row,

    pub fn deinit(self: *CompactInput) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn columnCount(_: CompactInput) usize {
        return input_column_count;
    }

    pub fn paddedRowCount(self: CompactInput) Error!usize {
        return @max(std.math.ceilPowerOfTwo(usize, self.rows.len) catch
            return Error.CountOverflow, 16);
    }

    pub fn realRowCount(self: CompactInput) usize {
        return self.rows.len;
    }

    pub fn validateRowCount(self: CompactInput, row_count: usize) Error!void {
        if (row_count != try self.paddedRowCount()) return Error.InvalidRowCount;
    }

    /// Writes the standard compact-consumer layout:
    /// `[tuple x7, enabler, iota, multiplicity]`.
    pub fn writeColumn(self: CompactInput, column: usize, destination: []u32) Error!void {
        try self.validateRowCount(destination.len);
        if (column >= input_column_count) return Error.InvalidColumn;
        for (destination, 0..) |*value, row_index| {
            const active = row_index < self.rows.len;
            const row = self.rows[if (active) row_index else 0];
            value.* = switch (column) {
                0...tuple_word_count - 1 => row.tuple[column],
                7 => @intFromBool(active),
                8 => @intCast(row_index),
                9 => if (active) row.multiplicity else 0,
                else => unreachable,
            };
        }
    }
};

/// Reconstructs the exact multiset fed by the pinned Rust opcode writers.
pub fn gather(allocator: std.mem.Allocator, input: *const adapter.ProverInput) !CompactInput {
    var multiplicities = std.AutoHashMap(Tuple, u32).init(allocator);
    defer multiplicities.deinit();

    for (input.state_transitions.casm_states_by_opcode.states) |states| {
        if (states.items.len == 0) continue;
        for (states.items) |state| {
            try addMultiplicity(&multiplicities, try instructionTuple(input, state.pc.v), 1);
        }
    }
    if (multiplicities.count() == 0) return Error.EmptyInput;

    const rows = try allocator.alloc(Row, multiplicities.count());
    errdefer allocator.free(rows);
    var iterator = multiplicities.iterator();
    var row_index: usize = 0;
    while (iterator.next()) |entry| : (row_index += 1) rows[row_index] = .{
        .tuple = entry.key_ptr.*,
        .multiplicity = entry.value_ptr.*,
    };
    std.mem.sortUnstable(Row, rows, {}, lessThanPc);
    for (rows[1..], rows[0 .. rows.len - 1]) |current, previous| {
        if (current.tuple[0] == previous.tuple[0] and
            !std.mem.eql(u32, &current.tuple, &previous.tuple))
            return Error.ConflictingInstruction;
    }
    return .{ .allocator = allocator, .rows = rows };
}

fn lessThanPc(_: void, lhs: Row, rhs: Row) bool {
    return lhs.tuple[0] < rhs.tuple[0];
}

fn addMultiplicity(map: *std.AutoHashMap(Tuple, u32), tuple: Tuple, increment: u32) !void {
    const result = try map.getOrPut(tuple);
    if (!result.found_existing) result.value_ptr.* = 0;
    result.value_ptr.* = std.math.add(u32, result.value_ptr.*, increment) catch
        return Error.CountOverflow;
}

/// Converts the 9-bit memory limbs back into Rust's relation tuple
/// `(pc, [offset0..2], [felt5_high, felt6], opcode_extension)`.
fn instructionTuple(input: *const adapter.ProverInput, pc: u32) Error!Tuple {
    if (pc >= input.memory.address_to_id.len) return Error.MissingInstruction;
    const encoded = input.memory.address_to_id[pc];
    if (encoded.isEmpty()) return Error.MissingInstruction;
    switch (encoded.raw >> 30) {
        0 => if (encoded.index() >= input.memory.small_values.len) return Error.MissingInstruction,
        1 => if (encoded.index() >= input.memory.f252_values.len) return Error.MissingInstruction,
        else => return Error.InvalidInstruction,
    }

    var limbs: [execution_tables.BIG_LIMB_COUNT]u32 = undefined;
    for (&limbs, 0..) |*limb, index| limb.* = execution_tables.limb(
        input,
        execution_tables.MEMORY_VALUE_TABLE,
        encoded.raw,
        @intCast(index),
    );
    for (limbs[8..]) |limb| if (limb != 0) return Error.InvalidInstruction;

    return .{
        pc,
        limbs[0] | ((limbs[1] & 0x7f) << 9),
        (limbs[1] >> 7) | (limbs[2] << 2) | ((limbs[3] & 0x1f) << 11),
        (limbs[3] >> 5) | (limbs[4] << 4) | ((limbs[5] & 0x7) << 13),
        limbs[5] & 0x1f8,
        limbs[6],
        limbs[7],
    };
}

fn encodeInstruction(offset0: u16, offset1: u16, offset2: u16, felt5_high: u16, felt6: u16, extension: u16) u128 {
    return @as(u128, offset0) |
        (@as(u128, offset1) << 16) |
        (@as(u128, offset2) << 32) |
        (@as(u128, felt5_high) << 45) |
        (@as(u128, felt6) << 54) |
        (@as(u128, extension) << 63);
}

test "Cairo verify instruction inputs: only active opcode rows contribute multiplicity" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const memory = @import("../common/memory.zig");
    var grouped = opcodes.CasmStatesByOpcode.init(std.testing.allocator);
    defer grouped.deinit(std.testing.allocator);
    try grouped.get(.add_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(0),
        .ap = M31.zero(),
        .fp = M31.zero(),
    });
    try grouped.get(.add_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(1),
        .ap = M31.zero(),
        .fp = M31.zero(),
    });
    try grouped.get(.ret_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(1),
        .ap = M31.zero(),
        .fp = M31.zero(),
    });

    const values = [_]u128{
        encodeInstruction(0x7ffe, 0x7fff, 0x7fff, 88, 130, 0),
        encodeInstruction(0x8001, 0x9234, 0xabcd, 0x118, 0x155, 1),
    };
    var addresses = [_]memory.EncodedMemoryValueId{ memory.EncodedMemoryValueId.small(0), memory.EncodedMemoryValueId.small(1) };
    var input: adapter.ProverInput = undefined;
    input.state_transitions.casm_states_by_opcode = grouped;
    input.memory = .{
        .config = .{},
        .address_to_id = &addresses,
        .f252_values = &.{},
        .small_values = @constCast(&values),
    };

    var compact = try gather(std.testing.allocator, &input);
    defer compact.deinit();
    try std.testing.expectEqual(@as(usize, 2), compact.rows.len);
    try std.testing.expectEqual(@as(usize, 16), try compact.paddedRowCount());
    try std.testing.expectEqual(@as(u32, 1), compact.rows[0].multiplicity);
    try std.testing.expectEqual(@as(u32, 2), compact.rows[1].multiplicity);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0x7ffe, 0x7fff, 0x7fff, 88, 130, 0 }, &compact.rows[0].tuple);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0x8001, 0x9234, 0xabcd, 0x118, 0x155, 1 }, &compact.rows[1].tuple);

    var column: [16]u32 = undefined;
    try compact.writeColumn(0, &column);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 0 }, column[0..3]);
    try compact.writeColumn(7, &column);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 0 }, column[0..3]);
    try compact.writeColumn(8, &column);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2 }, column[0..3]);
    try compact.writeColumn(9, &column);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 0 }, column[0..3]);
}

test "Cairo verify instruction inputs: missing and non-instruction memory fail closed" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const memory = @import("../common/memory.zig");
    var grouped = opcodes.CasmStatesByOpcode.init(std.testing.allocator);
    defer grouped.deinit(std.testing.allocator);
    try grouped.get(.ret_opcode).append(std.testing.allocator, .{
        .pc = M31.zero(),
        .ap = M31.zero(),
        .fp = M31.zero(),
    });
    var addresses = [_]memory.EncodedMemoryValueId{memory.EncodedMemoryValueId.EMPTY};
    var input: adapter.ProverInput = undefined;
    input.state_transitions.casm_states_by_opcode = grouped;
    input.memory = .{ .config = .{}, .address_to_id = &addresses, .f252_values = &.{}, .small_values = &.{} };
    try std.testing.expectError(Error.MissingInstruction, gather(std.testing.allocator, &input));
}

test "Cairo verify instruction inputs: multiplicity overflow fails closed" {
    var multiplicities = std.AutoHashMap(Tuple, u32).init(std.testing.allocator);
    defer multiplicities.deinit();
    const tuple = [_]u32{0} ** tuple_word_count;
    try addMultiplicity(&multiplicities, tuple, std.math.maxInt(u32));
    try std.testing.expectError(Error.CountOverflow, addMultiplicity(&multiplicities, tuple, 1));
}
