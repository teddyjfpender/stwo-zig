//! Backend-neutral host implementation of official Cairo witness deductions.

const std = @import("std");
const blake = @import("blake.zig");
const felt252 = @import("felt252.zig");
const mod_biguint = @import("mod_biguint.zig");
const partial_ec_mul_generic = @import("partial_ec_mul_generic.zig");
const program = @import("../program.zig");

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
    const selector = std.meta.intToEnum(Selector, raw_selector) catch
        return error.UnsupportedDeduction;
    switch (selector) {
        .blake_g => try blake.applyG(args, outputs),
        .blake_round_sigma => try blake.applyRoundSigma(args, outputs),
        .felt_add => try felt252.apply(.add, args, outputs),
        .felt_sub => try felt252.apply(.sub, args, outputs),
        .felt_mul => try felt252.apply(.mul, args, outputs),
        .felt_div => try felt252.apply(.div, args, outputs),
        .partial_ec_mul_generic => try partial_ec_mul_generic.apply(args, outputs),
        .add_mod_is_zero => try mod_biguint.applyAddIsZero(args, outputs),
        .mul_mod_quotient => try mod_biguint.applyMulQuotient(args, outputs),
        .triple_xor_32 => try blake.applyTripleXor(args, outputs),
        .blake_round => try blake.applyRound(args, outputs, tables),
        else => return error.UnsupportedDeduction,
    }
}

test {
    _ = felt252;
    _ = blake;
    _ = mod_biguint;
    _ = partial_ec_mul_generic;
}
