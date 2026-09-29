//! The lookups shared by the two hand-written `verify_bitwise_xor_12`
//! evaluators, `crates/cairo_verifier/src/components/verify_bitwise_xor_12.rs`
//! and `crates/circuit_verifier/src/components/verify_bitwise_xor_12.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Both loop over the 16
//! expansions of the 10-bit xor table by the operands' top two bits with the
//! same op order; they differ only in where they create the relation
//! constant and in the Cairo AIR's trailing size check, which stay in the
//! callers (`cairo.zig`, `circuit.zig`).

const component_list = @import("../../common/component_list.zig");
const tree = @import("eval_tree.zig");

const constantM31 = tree.constantM31;

/// `EXPAND_BITS`: the top bits of each 12-bit operand.
pub const expand_bits = 2;
/// `LIMB_BITS`: the bits of the preprocessed `bitwise_xor_10_*` columns.
pub const limb_bits = 10;
/// `(ELEM_BITS - EXPAND_BITS) * 2`: rows of the expanded table.
pub const log_size = 2 * limb_bits;
/// One multiplicity column per `(i, j)` expansion.
pub const trace_columns = 1 << (2 * expand_bits);
/// `N_INTERACTION_COLUMNS`: the lookups are finalized in pairs.
pub const interaction_columns = 4 * (trace_columns / 2);
/// The `VerifyBitwiseXor_12` relation id (the same relation in both AIRs).
pub const relation_id = component_list.VERIFY_BITWISE_XOR_12_RELATION_ID;

comptime {
    const facts = component_list.component_facts.verify_bitwise_xor_12;
    if (facts.trace_columns != trace_columns or facts.interaction_columns != interaction_columns or
        facts.log_size.fixed != log_size)
        @compileError("verify_bitwise_xor_12 shape differs from component_list.component_facts");
}

/// The preprocessed columns of the 10-bit table: operands `a`, `b` and `a ^ b`.
pub const a_column = "bitwise_xor_10_0";
pub const b_column = "bitwise_xor_10_1";
pub const c_column = "bitwise_xor_10_2";

/// For `i, j` in `0..4`: yields `(relation, a_low + (i << 10), b_low + (j << 10),
/// c_low + ((i ^ j) << 10))` with numerator `-multiplicities[4 i + j]`.
pub fn addLookups(
    interp: anytype,
    relation: @TypeOf(interp.ctx.*).Var,
    a_low: @TypeOf(interp.ctx.*).Var,
    b_low: @TypeOf(interp.ctx.*).Var,
    c_low: @TypeOf(interp.ctx.*).Var,
    multiplicities: []const @TypeOf(interp.ctx.*).Var,
) !void {
    const ctx = interp.ctx;
    if (multiplicities.len != trace_columns) return error.TraceColumnCountMismatch;
    var next: usize = 0;
    for (0..1 << expand_bits) |i| {
        for (0..1 << expand_bits) |j| {
            const a = try ctx.add(a_low, try constantM31(ctx, @intCast(i << limb_bits)));
            const b = try ctx.add(b_low, try constantM31(ctx, @intCast(j << limb_bits)));
            const c = try ctx.add(c_low, try constantM31(ctx, @intCast((i ^ j) << limb_bits)));
            const numerator = try ctx.sub(ctx.zero(), multiplicities[next]);
            next += 1;
            try interp.acc.addToRelation(ctx, numerator, &.{ relation, a, b, c });
        }
    }
}
