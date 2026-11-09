//! RV32M committed columns in pinned Stark-V generated order.

const M31 = @import("stwo_core").fields.m31.M31;

pub const MulColumns = struct {
    enabler: M31,
    clock: M31,
    pc: M31,
    rd_addr: M31,
    rd_prev_0: M31,
    rd_prev_1: M31,
    rd_prev_2: M31,
    rd_prev_3: M31,
    rd_clock_prev: M31,
    rd_next_0: M31,
    rd_next_1: M31,
    rd_next_2: M31,
    rd_next_3: M31,
    rs1_addr: M31,
    rs1_prev_0: M31,
    rs1_prev_1: M31,
    rs1_prev_2: M31,
    rs1_prev_3: M31,
    rs1_clock_prev: M31,
    rs1_next_0: M31,
    rs1_next_1: M31,
    rs1_next_2: M31,
    rs1_next_3: M31,
    rs2_addr: M31,
    rs2_prev_0: M31,
    rs2_prev_1: M31,
    rs2_prev_2: M31,
    rs2_prev_3: M31,
    rs2_clock_prev: M31,
    rs2_next_0: M31,
    rs2_next_1: M31,
    rs2_next_2: M31,
    rs2_next_3: M31,
    result_0: M31,
    result_1: M31,
    result_2: M31,
    result_3: M31,
    rd_nonzero: M31,
    rd_inv: M31,

    pub const N_COLUMNS = @typeInfo(@This()).@"struct".fields.len;
};

pub const MulhColumns = struct {
    clock: M31,
    pc: M31,
    rd_addr: M31,
    rd_prev_0: M31,
    rd_prev_1: M31,
    rd_prev_2: M31,
    rd_prev_3: M31,
    rd_clock_prev: M31,
    rd_next_0: M31,
    rd_next_1: M31,
    rd_next_2: M31,
    rd_next_3: M31,
    rs1_addr: M31,
    rs1_prev_0: M31,
    rs1_prev_1: M31,
    rs1_prev_2: M31,
    rs1_prev_3: M31,
    rs1_clock_prev: M31,
    rs1_next_0: M31,
    rs1_next_1: M31,
    rs1_next_2: M31,
    rs1_next_3: M31,
    rs2_addr: M31,
    rs2_prev_0: M31,
    rs2_prev_1: M31,
    rs2_prev_2: M31,
    rs2_prev_3: M31,
    rs2_clock_prev: M31,
    rs2_next_0: M31,
    rs2_next_1: M31,
    rs2_next_2: M31,
    rs2_next_3: M31,
    rd_high_0: M31,
    rd_high_1: M31,
    rd_high_2: M31,
    rd_high_3: M31,
    rs1_sign: M31,
    rs2_sign: M31,
    opcode_mulh_flag: M31,
    opcode_mulhsu_flag: M31,
    opcode_mulhu_flag: M31,
    result_0: M31,
    result_1: M31,
    result_2: M31,
    result_3: M31,
    rd_nonzero: M31,
    rd_inv: M31,

    pub const N_COLUMNS = @typeInfo(@This()).@"struct".fields.len;
};

pub const DivColumns = struct {
    clock: M31,
    pc: M31,
    rd_addr: M31,
    rd_prev_0: M31,
    rd_prev_1: M31,
    rd_prev_2: M31,
    rd_prev_3: M31,
    rd_clock_prev: M31,
    rd_next_0: M31,
    rd_next_1: M31,
    rd_next_2: M31,
    rd_next_3: M31,
    rs1_addr: M31,
    rs1_prev_0: M31,
    rs1_prev_1: M31,
    rs1_prev_2: M31,
    rs1_prev_3: M31,
    rs1_clock_prev: M31,
    rs1_next_0: M31,
    rs1_next_1: M31,
    rs1_next_2: M31,
    rs1_next_3: M31,
    rs2_addr: M31,
    rs2_prev_0: M31,
    rs2_prev_1: M31,
    rs2_prev_2: M31,
    rs2_prev_3: M31,
    rs2_clock_prev: M31,
    rs2_next_0: M31,
    rs2_next_1: M31,
    rs2_next_2: M31,
    rs2_next_3: M31,
    zero_divisor: M31,
    r_zero: M31,
    q_0: M31,
    q_1: M31,
    q_2: M31,
    q_3: M31,
    r_0: M31,
    r_1: M31,
    r_2: M31,
    r_3: M31,
    b_sign: M31,
    c_sign: M31,
    q_sign: M31,
    sign_xor: M31,
    c_sum_inv: M31,
    r_sum_inv: M31,
    r_abs_0: M31,
    r_abs_1: M31,
    r_abs_2: M31,
    r_abs_3: M31,
    r_inv_0: M31,
    r_inv_1: M31,
    r_inv_2: M31,
    r_inv_3: M31,
    lt_marker_0: M31,
    lt_marker_1: M31,
    lt_marker_2: M31,
    lt_marker_3: M31,
    lt_diff: M31,
    opcode_div_flag: M31,
    opcode_divu_flag: M31,
    opcode_rem_flag: M31,
    opcode_remu_flag: M31,
    rd_nonzero: M31,
    rd_inv: M31,

    pub const N_COLUMNS = @typeInfo(@This()).@"struct".fields.len;
};

test "RV32M layouts expose exact oracle boundary fields" {
    const std = @import("std");
    const mul = @typeInfo(MulColumns).@"struct".fields;
    const mulh = @typeInfo(MulhColumns).@"struct".fields;
    const div = @typeInfo(DivColumns).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 39), mul.len);
    try std.testing.expectEqualStrings("enabler", mul[0].name);
    try std.testing.expectEqualStrings("clock", mul[1].name);
    try std.testing.expectEqualStrings("pc", mul[2].name);
    try std.testing.expectEqualStrings("rd_high_0", mulh[32].name);
    try std.testing.expectEqualStrings("opcode_mulhu_flag", mulh[40].name);
    try std.testing.expectEqualStrings("rd_nonzero", mulh[45].name);
    try std.testing.expectEqualStrings("zero_divisor", div[32].name);
    try std.testing.expectEqualStrings("q_0", div[34].name);
    try std.testing.expectEqualStrings("r_abs_0", div[48].name);
    try std.testing.expectEqualStrings("lt_diff", div[60].name);
    try std.testing.expectEqualStrings("opcode_remu_flag", div[64].name);
    try std.testing.expectEqualStrings("rd_inv", div[66].name);
}
