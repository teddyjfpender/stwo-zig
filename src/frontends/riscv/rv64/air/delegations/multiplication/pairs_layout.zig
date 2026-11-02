//! Opt-in MUL byte-pair encoding (Geometry.mul_u8_pairs). The legacy degree3
//! layout stays unchanged. The 96 BYTE queries become 48 tagged byte-pair
//! queries (x, y, 0, 1) of the AND relation, served by the AND table's pair
//! multiplicity column (the same tuple family the byte-pair CPU uses). Two
//! pair queries share one strict inverse column; the FUNCTION fraction is
//! fused into the prefix residual (no FUNCTION inverse column).
const Old = @import("layout.zig");
pub const MAIN = Old.MAIN;
pub const FIXED = Old.FIXED;
pub const COUNT = Old.COUNT;
pub const BYTE_QUERIES = Old.BYTE_QUERIES;
/// Byte pair k is (byte[2k], byte[2k+1]) in provider.byteValues order.
pub const PAIR_QUERIES = BYTE_QUERIES / 2;
/// Strict inverse column j covers pair queries 2j and 2j+1.
pub const PAIR_COLUMNS = PAIR_QUERIES / 2;
pub const PREFIX = 4 * PAIR_COLUMNS;
pub const INTERACTION = PREFIX + 4;
pub const ARITHMETIC_CONSTRAINTS = Old.CONSTRAINTS - Old.BATCHES;
/// PAIR_COLUMNS strict inverses, the fused prefix and last*prefix.
pub const CONSTRAINTS = ARITHMETIC_CONSTRAINTS + PAIR_COLUMNS + 2;
pub const MAX_DEGREE = 3;
pub const MAX_LOG = @import("degree3_layout.zig").MAX_LOG;
comptime {
    if (BYTE_QUERIES % 4 != 0) @compileError("MUL byte pairs require a multiple of four byte queries");
}
/// Separate transcript domain, mixed ONLY when Geometry.mul_u8_pairs is set.
pub fn identity() [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.multiplication.degree3.u8-pairs.v1:inter100/D3;BYTE96->AND-relation tagged pairs (x,y,0,1) k=(b[2k],b[2k+1]);inverse I_j*p_2j*p_2j+1=1, contribution (p_2j+p_2j+1)*I_j;FUNCTION fused((S-S'+claim*first-C)*d_fn+active);last*S");
    return hash.finalResult();
}
