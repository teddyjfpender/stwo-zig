//! Backend-neutral materialization of directly seeded Cairo witness inputs.

const std = @import("std");
const cairo_adapter = @import("../adapter/mod.zig");
const cairo_opcodes = @import("../adapter/opcodes.zig");
const CasmState = @import("../common/cpu.zig").CasmState;

pub const Error = error{
    MissingBinding,
    InvalidCardinality,
    InvalidBindingSize,
};

pub const builtin_components = [_][]const u8{
    "bitwise_builtin",
    "ec_op_builtin",
    "range_check96_builtin",
    "range_check_builtin",
    "pedersen_builtin",
    "poseidon_builtin",
};

const OpcodeInput = struct {
    states: []const CasmState,
    includes_iota: bool,
};

/// One source-derived input slab that can be materialized into any backend's
/// storage. Opcode rows have an exact padded size; builtin rows inherit their
/// authenticated component size and require power-of-two geometry.
pub const DirectInput = union(enum) {
    opcode: OpcodeInput,
    builtin: u32,

    pub fn columnCount(self: DirectInput) usize {
        return switch (self) {
            .opcode => |opcode| if (opcode.includes_iota) 5 else 4,
            .builtin => 3,
        };
    }

    pub fn validateRowCount(self: DirectInput, row_count: usize) Error!void {
        switch (self) {
            .opcode => |opcode| {
                const expected = @max(
                    std.math.ceilPowerOfTwo(usize, opcode.states.len) catch
                        return Error.InvalidBindingSize,
                    16,
                );
                if (row_count != expected) return Error.InvalidBindingSize;
            },
            .builtin => {
                if (row_count < 16 or !std.math.isPowerOfTwo(row_count))
                    return Error.InvalidBindingSize;
            },
        }
    }

    pub fn writeColumn(self: DirectInput, column: usize, destination: []u32) Error!void {
        try self.validateRowCount(destination.len);
        if (column >= self.columnCount()) return Error.InvalidCardinality;
        switch (self) {
            .opcode => |opcode| {
                for (destination, 0..) |*value, row| {
                    const state = opcode.states[if (row < opcode.states.len) row else 0];
                    value.* = switch (column) {
                        0 => state.pc.v,
                        1 => state.ap.v,
                        2 => state.fp.v,
                        3 => @intFromBool(row < opcode.states.len),
                        4 => @intCast(row),
                        else => unreachable,
                    };
                }
            },
            .builtin => |begin_addr| {
                for (destination, 0..) |*value, row| value.* = switch (column) {
                    0 => begin_addr,
                    1 => 1,
                    2 => @intCast(row),
                    else => unreachable,
                };
            },
        }
    }
};

/// Resolves a directly seeded component. Unsupported gather/compact components
/// return null; known components with absent source data fail closed.
pub fn resolve(input: *const cairo_adapter.ProverInput, component: []const u8) Error!?DirectInput {
    for (cairo_opcodes.direct_witness_lanes) |lane| {
        if (!std.mem.eql(u8, lane.label, component)) continue;
        const states = input.state_transitions.casm_states_by_opcode.getConst(lane.tag);
        if (states.len == 0) return Error.MissingBinding;
        return .{ .opcode = .{ .states = states, .includes_iota = lane.includes_iota } };
    }

    const segment = if (std.mem.eql(u8, component, "bitwise_builtin"))
        input.builtin_segments.bitwise_builtin
    else if (std.mem.eql(u8, component, "ec_op_builtin"))
        input.builtin_segments.ec_op_builtin
    else if (std.mem.eql(u8, component, "range_check96_builtin"))
        input.builtin_segments.range_check96_builtin
    else if (std.mem.eql(u8, component, "range_check_builtin"))
        input.builtin_segments.range_check_builtin
    else if (std.mem.eql(u8, component, "pedersen_builtin"))
        input.builtin_segments.pedersen_builtin
    else if (std.mem.eql(u8, component, "poseidon_builtin"))
        input.builtin_segments.poseidon_builtin
    else
        return null;
    const addresses = segment orelse return Error.MissingBinding;
    if (addresses.begin_addr > std.math.maxInt(u32)) return Error.InvalidCardinality;
    return .{ .builtin = @intCast(addresses.begin_addr) };
}

test "Cairo direct inputs: opcode rows preserve padding active flag and iota" {
    const M31 = @import("stwo_core").fields.m31.M31;
    var grouped = cairo_opcodes.CasmStatesByOpcode.init(std.testing.allocator);
    defer grouped.deinit(std.testing.allocator);
    try grouped.get(.blake_compress_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(11),
        .ap = M31.fromCanonical(12),
        .fp = M31.fromCanonical(13),
    });
    try grouped.get(.blake_compress_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(21),
        .ap = M31.fromCanonical(22),
        .fp = M31.fromCanonical(23),
    });
    var input: cairo_adapter.ProverInput = undefined;
    input.state_transitions.casm_states_by_opcode = grouped;

    const direct = (try resolve(&input, "blake_compress_opcode")) orelse
        return error.MissingInput;
    try std.testing.expectEqual(@as(usize, 5), direct.columnCount());

    var column: [16]u32 = undefined;
    try direct.writeColumn(0, &column);
    try std.testing.expectEqualSlices(u32, &.{ 11, 21 }, column[0..2]);
    try std.testing.expectEqual(@as(u32, 11), column[15]);
    try direct.writeColumn(3, &column);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 0, 0 }, column[0..4]);
    try direct.writeColumn(4, &column);
    for (column, 0..) |value, row| try std.testing.expectEqual(@as(u32, @intCast(row)), value);
}

test "Cairo direct inputs: builtin seeds use authenticated component geometry" {
    var input: cairo_adapter.ProverInput = undefined;
    input.builtin_segments = .{ .poseidon_builtin = .{ .begin_addr = 4096, .stop_ptr = 4128 } };
    const direct = (try resolve(&input, "poseidon_builtin")) orelse return error.MissingInput;
    try std.testing.expectEqual(@as(usize, 3), direct.columnCount());

    var column: [32]u32 = undefined;
    try direct.writeColumn(0, &column);
    for (column) |value| try std.testing.expectEqual(@as(u32, 4096), value);
    try direct.writeColumn(1, &column);
    for (column) |value| try std.testing.expectEqual(@as(u32, 1), value);
    try direct.writeColumn(2, &column);
    for (column, 0..) |value, row| try std.testing.expectEqual(@as(u32, @intCast(row)), value);
}

test "Cairo direct inputs: invalid geometry and absent inputs fail closed" {
    var input: cairo_adapter.ProverInput = undefined;
    input.builtin_segments = .{};
    try std.testing.expectError(Error.MissingBinding, resolve(&input, "bitwise_builtin"));
    try std.testing.expect((try resolve(&input, "memory_address_to_id")) == null);

    const direct = DirectInput{ .builtin = 7 };
    var invalid_rows: [17]u32 = undefined;
    try std.testing.expectError(Error.InvalidBindingSize, direct.writeColumn(0, &invalid_rows));
    var valid_rows: [16]u32 = undefined;
    try std.testing.expectError(Error.InvalidCardinality, direct.writeColumn(3, &valid_rows));
}
