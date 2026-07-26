//! Backend-neutral host implementation of official Cairo witness deductions.

const std = @import("std");
const felt252 = @import("felt252.zig");
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
};

pub fn context() program.DeduceContext {
    return .{ .context = undefined, .call_fn = call };
}

fn call(_: *anyopaque, raw_selector: u32, args: []const u32, outputs: []u32) !void {
    const selector = std.meta.intToEnum(Selector, raw_selector) catch
        return error.UnsupportedDeduction;
    switch (selector) {
        .felt_add => try felt252.apply(.add, args, outputs),
        .felt_sub => try felt252.apply(.sub, args, outputs),
        .felt_mul => try felt252.apply(.mul, args, outputs),
        .felt_div => try felt252.apply(.div, args, outputs),
        else => return error.UnsupportedDeduction,
    }
}

test {
    _ = felt252;
}
