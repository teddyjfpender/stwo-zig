//! Independently sized unsigned 64x64 product plus signed/high/W output policy.
const O = @import("../../../decode.zig").Opcode;
pub const OPCODES = [_]O{ .MUL, .MULH, .MULHU, .MULHSU, .MULW };
pub const A = 0;
pub const B = A + 8;
pub const RESULT = B + 8;
pub const PRODUCT = RESULT + 8;
pub const CARRY_LOW = PRODUCT + 16;
pub const CARRY_HIGH = CARRY_LOW + 15;
pub const BORROW = CARRY_HIGH + 15;
pub const SIGN_A = BORROW + 8;
pub const SIGN_B = SIGN_A + 1;
pub const SIGN_RESULT = SIGN_B + 1;
pub const SELECTORS = SIGN_RESULT + 1;
pub const COUNT = SELECTORS + OPCODES.len;
pub const MAIN = COUNT + 1;
pub const FIXED = 3; // Domain index/first/last only; exact count is main/public.
pub const BYTE_QUERIES = 40 + 45 + 8 + 3;
pub const EVENTS = BYTE_QUERIES + 1;
pub const BATCHES = (EVENTS + 2) / 3;
pub const INTERACTION = 4 * BATCHES;
pub const TUPLE = 25;
pub const MAX_DEGREE = 4;
pub const CONSTRAINTS = 174;
pub fn opcodeIndex(op: O) !usize {
    for (OPCODES, 0..) |candidate, i| if (op == candidate) return i;
    return error.InvalidRv64MultiplicationOpcode;
}
