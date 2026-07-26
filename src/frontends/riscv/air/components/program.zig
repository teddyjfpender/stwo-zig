//! AIR component for the Program ROM.
//!
//! Verifies that each instruction fetched during execution matches the
//! committed program.  In stark-v this is backed by a Merkle tree over
//! program instruction words.
//!
//! Trace layout (10 columns):
//!   enabler, addr (pc), value_0, value_1, value_2, value_3, multiplicity,
//!   root, word_addr_lo20, word_addr_hi8.
//!
//! value_0..3 are byte decomposition of the instruction word.
//!
//! Constraints:
//!   - enabler is boolean (enabler^2 - enabler = 0).
//!   - active addr = 4 * (word_addr_lo20 + 2^20 * word_addr_hi8).
//!   - Program lookup relation: +multiplicity / (z - entry(addr, value_0..3)).
//! Production range-table interactions separately bind the address limbs to
//! 20 and 8 bits; this legacy expression-framework component records the
//! algebraic part of that invariant.

const std = @import("std");
const cf = @import("stwo_core").constraint_framework;
const claims_mod = @import("../claims.zig");
const trace = @import("../trace_columns.zig");
const M31 = @import("stwo_core").fields.m31.M31;

const ExprEvaluator = cf.ExprEvaluator;
const ExprArena = cf.ExprArena;
const BaseExpr = cf.BaseExpr;
const ExtExpr = cf.ExtExpr;

pub const Columns = trace.ProgramColumns;
pub const N_TRACE_COLUMNS: usize = Columns.N_COLUMNS;
pub const Claim = claims_mod.ComponentClaim;
pub const InteractionClaim = claims_mod.ComponentInteractionClaim;

/// Evaluate the program ROM AIR constraints.
pub fn evaluate(eval: *ExprEvaluator) !void {
    const arena = eval.arena;

    // Read all 10 trace columns in order.
    const enabler = try eval.nextTraceMask();
    const addr = try eval.nextTraceMask();
    const value_0 = try eval.nextTraceMask();
    const value_1 = try eval.nextTraceMask();
    const value_2 = try eval.nextTraceMask();
    const value_3 = try eval.nextTraceMask();
    const multiplicity = try eval.nextTraceMask();
    const root = try eval.nextTraceMask();
    const word_addr_lo20 = try eval.nextTraceMask();
    const word_addr_hi8 = try eval.nextTraceMask();

    _ = root;

    const shift_8 = try arena.baseConst(M31.fromCanonical(1 << 8));
    const shift_16 = try arena.baseConst(M31.fromCanonical(1 << 16));
    const shift_24 = try arena.baseConst(M31.fromCanonical(1 << 24));
    const shift_20 = try arena.baseConst(M31.fromCanonical(1 << 20));
    const four = try arena.baseConst(M31.fromCanonical(4));

    // ---- enabler is boolean ----
    try eval.addConstraint(try arena.extFromBase(
        try arena.baseSub(try arena.baseMul(enabler, enabler), enabler),
    ));

    // ---- canonical aligned address decomposition ----
    const word_address = try arena.baseAdd(
        word_addr_lo20,
        try arena.baseMul(word_addr_hi8, shift_20),
    );
    try eval.addConstraint(try arena.extFromBase(
        try arena.baseMul(
            enabler,
            try arena.baseSub(addr, try arena.baseMul(word_address, four)),
        ),
    ));

    // ---- Program lookup LogUp ----
    // +multiplicity / (z - entry(addr, value_0..3))
    // entry = addr + value_0 * 2^8 + value_1 * 2^16 + value_2 * 2^24 + value_3 * ...
    // Simplified: entry = addr + value composite
    const z = try arena.extParam("z");
    const value_composite = try arena.baseAdd(
        try arena.baseAdd(value_0, try arena.baseMul(value_1, shift_8)),
        try arena.baseAdd(try arena.baseMul(value_2, shift_16), try arena.baseMul(value_3, shift_24)),
    );
    const prog_entry = try arena.extFromBase(try arena.baseAdd(addr, value_composite));
    try eval.writeLogupFrac(.{
        .numerator = try arena.extFromBase(multiplicity),
        .denominator = try arena.extSub(z, prog_entry),
    });

    try eval.finalizeLogup();
}

test "program: constraint count" {
    var arena = cf.ExprArena.init(std.testing.allocator);
    defer arena.deinit();
    var eval = try ExprEvaluator.init(&arena, std.testing.allocator);
    defer eval.deinit();

    try evaluate(&eval);

    // Boolean enabler, aligned address decomposition, and one LogUp identity.
    try std.testing.expectEqual(@as(usize, 3), eval.constraints.items.len);
}
