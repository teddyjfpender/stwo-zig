//! Canonical deduction IDs and row shapes shared by native codegen and execution.
pub const native_abi_version: u32 = 2;
pub const max_batch_rows: usize = 256;
pub const batch_scratch_bytes: usize = 256 * 1024;

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

    pub fn shape(self: Selector) struct { args: usize, outputs: usize } {
        return switch (self) {
            .blake_g => .{ .args = 6, .outputs = 4 },
            .blake_round_sigma => .{ .args = 1, .outputs = 16 },
            .partial_ec_mul_w18 => .{ .args = 72, .outputs = 72 },
            .partial_ec_mul_w9 => .{ .args = 86, .outputs = 86 },
            .partial_ec_mul_generic => .{ .args = 125, .outputs = 125 },
            .pedersen_points_table_w18, .pedersen_points_table_w9 => .{ .args = 1, .outputs = 56 },
            .felt_add, .felt_sub, .felt_mul, .felt_div => .{ .args = 56, .outputs = 28 },
            .poseidon_round_keys => .{ .args = 1, .outputs = 30 },
            .poseidon_cube => .{ .args = 10, .outputs = 10 },
            .poseidon_full_round_chain => .{ .args = 32, .outputs = 32 },
            .poseidon_3_partial_rounds_chain => .{ .args = 42, .outputs = 42 },
            .add_mod_is_zero => .{ .args = 336, .outputs = 1 },
            .mul_mod_quotient => .{ .args = 448, .outputs = 32 },
            .triple_xor_32 => .{ .args = 3, .outputs = 1 },
            .blake_round => .{ .args = 19, .outputs = 19 },
        };
    }

    pub fn benefitsFromBatch(self: Selector) bool {
        return switch (self) {
            .partial_ec_mul_w18, .partial_ec_mul_w9, .partial_ec_mul_generic, .felt_div => true,
            else => false,
        };
    }
};
