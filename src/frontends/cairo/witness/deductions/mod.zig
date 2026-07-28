//! Backend-neutral host implementation of official Cairo witness deductions.

const std = @import("std");
const blake = @import("blake.zig");
const felt252 = @import("felt252.zig");
const mod_biguint = @import("mod_biguint.zig");
const partial_ec_mul_generic = @import("partial_ec_mul_generic.zig");
const pedersen = @import("pedersen.zig");
const poseidon = @import("poseidon.zig");
const stark_curve = @import("stark_curve.zig");
const program = @import("../program.zig");

pub const PedersenTable = struct {
    window_bits: u5,
    points: []const stark_curve.AffinePoint,
};

pub const Context = struct {
    pedersen_table: ?PedersenTable = null,
};

pub const Selector = enum(u32) {
    blake_g = 0,
    blake_round_sigma = 1,
    partial_ec_mul_w18 = 2,
    pedersen_points_table_w18 = 3,
    felt_add = 4,
    felt_sub = 5,
    felt_mul = 6,
    felt_div = 7,
    poseidon_round_keys = 8,
    poseidon_cube = 9,
    poseidon_full_round_chain = 10,
    poseidon_3_partial_rounds_chain = 11,
    partial_ec_mul_w9 = 12,
    pedersen_points_table_w9 = 13,
    partial_ec_mul_generic = 14,
    add_mod_is_zero = 15,
    mul_mod_quotient = 16,
    triple_xor_32 = 17,
    blake_round = 18,
};

pub fn context() program.DeduceContext {
    return .{
        .context = undefined,
        .call_fn = call,
        .table_call_fn = callWithTables,
    };
}

pub fn contextWithConfig(config: *const Context) program.DeduceContext {
    return .{
        .context = @ptrCast(@constCast(config)),
        .call_fn = callConfigured,
        .table_call_fn = callWithTablesConfigured,
    };
}

pub fn supportsProgram(witness_program: program.Program) bool {
    for (witness_program.insts) |inst| {
        const op = std.meta.intToEnum(program.Op, inst.op) catch return false;
        if (op == .deduce_call and !supports(inst.imm)) return false;
    }
    return true;
}

pub fn supports(raw_selector: u32) bool {
    const selector = std.meta.intToEnum(Selector, raw_selector) catch return false;
    return switch (selector) {
        .blake_g,
        .blake_round_sigma,
        .partial_ec_mul_w18,
        .pedersen_points_table_w18,
        .felt_add,
        .felt_sub,
        .felt_mul,
        .felt_div,
        .poseidon_round_keys,
        .poseidon_cube,
        .poseidon_full_round_chain,
        .poseidon_3_partial_rounds_chain,
        .partial_ec_mul_w9,
        .pedersen_points_table_w9,
        .partial_ec_mul_generic,
        .add_mod_is_zero,
        .mul_mod_quotient,
        .triple_xor_32,
        .blake_round,
        => true,
    };
}

fn call(_: *anyopaque, raw_selector: u32, args: []const u32, outputs: []u32) !void {
    return callWithTables(undefined, raw_selector, args, outputs, .zero());
}

fn callWithTables(
    _: *anyopaque,
    raw_selector: u32,
    args: []const u32,
    outputs: []u32,
    tables: program.TableContext,
) !void {
    return dispatch(null, raw_selector, args, outputs, tables);
}

fn callConfigured(
    raw_context: *anyopaque,
    raw_selector: u32,
    args: []const u32,
    outputs: []u32,
) !void {
    return callWithTablesConfigured(
        raw_context,
        raw_selector,
        args,
        outputs,
        .zero(),
    );
}

fn callWithTablesConfigured(
    raw_context: *anyopaque,
    raw_selector: u32,
    args: []const u32,
    outputs: []u32,
    tables: program.TableContext,
) !void {
    const config: *const Context = @ptrCast(@alignCast(raw_context));
    return dispatch(config, raw_selector, args, outputs, tables);
}

fn dispatch(
    config: ?*const Context,
    raw_selector: u32,
    args: []const u32,
    outputs: []u32,
    tables: program.TableContext,
) !void {
    const selector = std.meta.intToEnum(Selector, raw_selector) catch
        return error.UnsupportedDeduction;
    switch (selector) {
        .blake_g => try blake.applyG(args, outputs),
        .blake_round_sigma => try blake.applyRoundSigma(args, outputs),
        .partial_ec_mul_w18 => try partialEcMul(config, args, outputs, 18),
        .pedersen_points_table_w18 => try pedersenPoints(config, args, outputs, 18),
        .felt_add => try felt252.apply(.add, args, outputs),
        .felt_sub => try felt252.apply(.sub, args, outputs),
        .felt_mul => try felt252.apply(.mul, args, outputs),
        .felt_div => try felt252.apply(.div, args, outputs),
        .poseidon_round_keys => try poseidon.applyRoundKeys(args, outputs),
        .poseidon_cube => try poseidon.applyCube(args, outputs),
        .poseidon_full_round_chain => try poseidon.applyFullRound(args, outputs),
        .poseidon_3_partial_rounds_chain => try poseidon.applyThreePartialRounds(args, outputs),
        .partial_ec_mul_w9 => try partialEcMul(config, args, outputs, 9),
        .pedersen_points_table_w9 => try pedersenPoints(config, args, outputs, 9),
        .partial_ec_mul_generic => try partial_ec_mul_generic.apply(args, outputs),
        .add_mod_is_zero => try mod_biguint.applyAddIsZero(args, outputs),
        .mul_mod_quotient => try mod_biguint.applyMulQuotient(args, outputs),
        .triple_xor_32 => try blake.applyTripleXor(args, outputs),
        .blake_round => try blake.applyRound(args, outputs, tables),
    }
}

fn partialEcMul(
    config: ?*const Context,
    args: []const u32,
    outputs: []u32,
    comptime window_bits: u5,
) !void {
    if (config) |active| {
        if (active.pedersen_table) |table| {
            if (table.window_bits != window_bits)
                return error.InvalidPedersenTableWindow;
            return pedersen.applyPartialEcMulCached(
                args,
                outputs,
                window_bits,
                table.points,
            );
        }
    }
    return if (window_bits == 9)
        pedersen.applyPartialEcMulWindowBits9(args, outputs)
    else
        pedersen.applyPartialEcMul(args, outputs);
}

fn pedersenPoints(
    config: ?*const Context,
    args: []const u32,
    outputs: []u32,
    comptime window_bits: u5,
) !void {
    if (config) |active| {
        if (active.pedersen_table) |table| {
            if (table.window_bits != window_bits)
                return error.InvalidPedersenTableWindow;
            return pedersen.applyPointsTableCached(
                args,
                outputs,
                window_bits,
                table.points,
            );
        }
    }
    return if (window_bits == 9)
        pedersen.applyPointsTableWindowBits9(args, outputs)
    else
        pedersen.applyPointsTable(args, outputs);
}

test {
    _ = felt252;
    _ = blake;
    _ = mod_biguint;
    _ = partial_ec_mul_generic;
    _ = pedersen;
    _ = poseidon;
    _ = stark_curve;
}

test "Cairo deductions report only executable selectors" {
    try std.testing.expect(supports(@intFromEnum(Selector.blake_g)));
    try std.testing.expect(supports(@intFromEnum(Selector.partial_ec_mul_generic)));
    try std.testing.expect(supports(@intFromEnum(Selector.partial_ec_mul_w9)));
    try std.testing.expect(!supports(std.math.maxInt(u32)));
}
