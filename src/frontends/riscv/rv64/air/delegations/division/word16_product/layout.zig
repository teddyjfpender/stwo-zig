//! Native2n DIV/REM truth, using existing MUL/MULHU as unsigned product truths.
//!
//! Trims (see design/riscv-proving-stack/rv64-div-canonical-input-trims.md):
//! * PRODUCT_HIGH is no longer committed. The MULHU support tuple carries the
//!   constant zero word in its result coordinates; the MUL provider's byte
//!   ranged RESULT must therefore be zero, exactly as the former four
//!   `PRODUCT_HIGH[i] = 0` residuals required.
//! * The eight direct U16 memberships of the A/B operand limbs are removed.
//!   A/B canonicality comes from the closed CPU FUNCTION relation (REG
//!   induction + ROM), exactly like the ALU v4 argument. C, ABS_A, REMAINDER,
//!   GAP, OUT and the three sign queries keep explicit U16 anchors.
//! QUOTIENT, ABS_B and PRODUCT_LOW are NOT ranged here: they are canonical only
//! because the MUL provider byte-ranges its A/B/RESULT coordinates after the
//! FUNCTION13 -> byte25 basis change. Never remove those MUL byte queries.
const O = @import("../../../../decode.zig").Opcode;
pub const OPCODES = [_]O{ .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW };
pub const A = 0;
pub const B = 4;
pub const C = 8;
pub const ABS_A = 12;
pub const ABS_B = 16;
pub const QUOTIENT = 20;
pub const REMAINDER = 24;
pub const PRODUCT_LOW = 28;
pub const GAP = 32;
pub const OUT = 36;
pub const CARRY_A = 40;
pub const CARRY_B = 44;
pub const CARRY_SUM = 48;
pub const BORROW_GAP = 52;
pub const CARRY_OUT = 56;
pub const SIGN_A = 60;
pub const SIGN_B = 61;
pub const SIGN_OUT32 = 62;
pub const NEG_A = 63;
pub const NEG_B = 64;
pub const NEG_OUT = 65;
pub const ZERO = 66;
pub const ZERO_DIV = 67;
pub const DIVISOR_INVERSE = 68;
pub const SELECTORS = 69;
pub const COUNT = 77;
pub const MAIN = 78;
pub const FIXED = 3;
/// U16 queries: C(4), ABS_A(4), REMAINDER(4), GAP(4), OUT(4), the two
/// selected-top sign queries (quadratic) and the OUT32 sign query.
pub const RANGE_QUERIES = 23;
pub const RANGE_QUADRATIC = [_]usize{ 20, 21 };
pub const FUNCTION_QUERIES = 3;
pub const LINEAR_QUERIES = FUNCTION_QUERIES + RANGE_QUERIES - RANGE_QUADRATIC.len;
pub const PAIRS = LINEAR_QUERIES / 2;
pub const INVERSES = PAIRS + RANGE_QUADRATIC.len;
pub const QUADRATIC_INVERSES = 4 * PAIRS;
pub const PREFIX = 4 * INVERSES;
pub const INTERACTION = PREFIX + 4;
pub const MAX_DEGREE = 3;
pub const ARITHMETIC_CONSTRAINTS = 164;
pub const CONSTRAINTS = ARITHMETIC_CONSTRAINTS + INVERSES + 2;
comptime {
    if (LINEAR_QUERIES % 2 != 0) @compileError("DIV linear queries must form strict pairs");
    if (PAIRS != 12 or INTERACTION != 60 or CONSTRAINTS != 180) @compileError("DIV v2 layout drifted");
    if (SELECTORS + OPCODES.len != COUNT or COUNT + 1 != MAIN) @compileError("DIV selector layout drifted");
}
