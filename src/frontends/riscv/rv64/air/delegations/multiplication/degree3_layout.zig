//! Separate strict-pair encoding; legacy triple/4n layout stays unchanged.
const Old = @import("layout.zig");
pub const MAIN = Old.MAIN;
pub const FIXED = Old.FIXED;
pub const COUNT = Old.COUNT;
pub const BYTE_QUERIES = Old.BYTE_QUERIES;
pub const BYTE_PAIRS = BYTE_QUERIES / 2;
pub const FUNCTION_INVERSE = 4 * BYTE_PAIRS;
pub const PREFIX = FUNCTION_INVERSE + 4;
pub const INTERACTION = PREFIX + 4;
pub const ARITHMETIC_CONSTRAINTS = Old.CONSTRAINTS - Old.BATCHES;
pub const CONSTRAINTS = ARITHMETIC_CONSTRAINTS + BYTE_PAIRS + 3;
pub const MAX_DEGREE = 3;
