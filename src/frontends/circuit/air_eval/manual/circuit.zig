//! Hand-written circuit-AIR evaluators: ports of
//! `crates/circuit_verifier/src/components/{eq,qm31_ops,verify_bitwise_xor_12}.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Each function is the body of
//! the Rust `CircuitEval::evaluate`, in its call order. Their shapes and
//! relation ids are the circuit components' static facts in
//! `common/component_list.zig`.

const component_list = @import("../../common/component_list.zig");
const tree = @import("eval_tree.zig");
const xor_12 = @import("verify_bitwise_xor_12.zig");

const facts = component_list.component_facts;
const constantM31 = tree.constantM31;

/// `CircuitEqComponent::evaluate`.
pub fn evaluateEq(interp: anytype) !void {
    const ctx = interp.ctx;
    const relation = try constantM31(ctx, component_list.GATE_RELATION_ID);
    const in0_address = try interp.acc.getPreprocessedColumn("eq_in0_address");
    const in1_address = try interp.acc.getPreprocessedColumn("eq_in1_address");
    const cols = interp.data.traceColumns();
    if (cols.len != facts.eq.trace_columns) return error.TraceColumnCountMismatch;
    try interp.acc.addToRelation(ctx, ctx.one(), &.{ relation, in0_address, cols[0], cols[1], cols[2], cols[3] });
    try interp.acc.addToRelation(ctx, ctx.one(), &.{ relation, in1_address, cols[0], cols[1], cols[2], cols[3] });
}

// Operand indices of the qm31_ops constraint trees.
const add_flag = 0;
const sub_flag = 1;
const mul_flag = 2;
const pointwise_mul_flag = 3;
/// `input_op0_limb{k}_col{k}`, `input_op1_limb{k}_col{4+k}`, `input_dst_limb{k}_col{8+k}`.
fn op0(comptime k: usize) tree.Node {
    return tree.x(4 + k);
}
fn op1(comptime k: usize) tree.Node {
    return tree.x(8 + k);
}
fn dst(comptime k: usize) tree.Node {
    return tree.x(12 + k);
}

fn bitConstraint(comptime flag: usize) tree.Node {
    return tree.mul(tree.x(flag), tree.sub(tree.x(flag), tree.lit(1)));
}

/// The `add`, `sub` and `pointwise_mul` terms shared by every output limb.
fn linearTerms(comptime mul_term: tree.Node, comptime k: usize) tree.Node {
    const t = tree;
    return t.add(
        t.add(
            t.add(
                t.mul(mul_term, t.x(mul_flag)),
                t.mul(t.add(op0(k), op1(k)), t.x(add_flag)),
            ),
            t.mul(t.sub(op0(k), op1(k)), t.x(sub_flag)),
        ),
        t.mul(t.mul(op0(k), op1(k)), t.x(pointwise_mul_flag)),
    );
}

const qm31_ops_constraints = blk: {
    const t = tree;
    const all_flags = t.sub(t.add(t.add(t.add(t.x(add_flag), t.x(sub_flag)), t.x(mul_flag)), t.x(pointwise_mul_flag)), t.lit(1));
    const mul0 = t.sub(t.sub(t.add(
        t.sub(t.mul(op0(0), op1(0)), t.mul(op0(1), op1(1))),
        t.mul(t.lit(2), t.sub(t.mul(op0(2), op1(2)), t.mul(op0(3), op1(3)))),
    ), t.mul(op0(2), op1(3))), t.mul(op0(3), op1(2)));
    const mul1 = t.sub(t.add(t.add(
        t.add(t.mul(op0(0), op1(1)), t.mul(op0(1), op1(0))),
        t.mul(t.lit(2), t.add(t.mul(op0(2), op1(3)), t.mul(op0(3), op1(2)))),
    ), t.mul(op0(2), op1(2))), t.mul(op0(3), op1(3)));
    const mul2 = t.sub(t.add(t.sub(t.mul(op0(0), op1(2)), t.mul(op0(1), op1(3))), t.mul(op0(2), op1(0))), t.mul(op0(3), op1(1)));
    const mul3 = t.add(t.add(t.add(t.mul(op0(0), op1(3)), t.mul(op0(1), op1(2))), t.mul(op0(2), op1(1))), t.mul(op0(3), op1(0)));
    break :blk [_]tree.Node{
        all_flags,
        bitConstraint(add_flag),
        bitConstraint(sub_flag),
        bitConstraint(mul_flag),
        bitConstraint(pointwise_mul_flag),
        t.sub(dst(0), linearTerms(mul0, 0)),
        t.sub(dst(1), linearTerms(mul1, 1)),
        t.sub(dst(2), linearTerms(mul2, 2)),
        t.sub(dst(3), linearTerms(mul3, 3)),
    };
};

/// `CircuitQm31OpsComponent::evaluate`.
pub fn evaluateQm31Ops(interp: anytype) !void {
    const ctx = interp.ctx;
    const acc = interp.acc;
    const relation = try constantM31(ctx, component_list.GATE_RELATION_ID);
    const flags = [_]@TypeOf(ctx.*).Var{
        try acc.getPreprocessedColumn("qm31_ops_add_flag"),
        try acc.getPreprocessedColumn("qm31_ops_sub_flag"),
        try acc.getPreprocessedColumn("qm31_ops_mul_flag"),
        try acc.getPreprocessedColumn("qm31_ops_pointwise_mul_flag"),
    };
    const op0_addr = try acc.getPreprocessedColumn("qm31_ops_in0_address");
    const op1_addr = try acc.getPreprocessedColumn("qm31_ops_in1_address");
    const dst_addr = try acc.getPreprocessedColumn("qm31_ops_out_address");
    const multiplicity = try acc.getPreprocessedColumn("qm31_ops_mults");
    const cols = interp.data.traceColumns();
    if (cols.len != facts.qm31_ops.trace_columns) return error.TraceColumnCountMismatch;

    var operands: [16]@TypeOf(ctx.*).Var = undefined;
    @memcpy(operands[0..4], &flags);
    @memcpy(operands[4..16], cols);
    inline for (qm31_ops_constraints) |constraint| {
        try acc.addConstraint(ctx, try tree.emit(constraint, ctx, &operands));
    }

    try acc.addToRelation(ctx, ctx.one(), &.{ relation, op0_addr, cols[0], cols[1], cols[2], cols[3] });
    try acc.addToRelation(ctx, ctx.one(), &.{ relation, op1_addr, cols[4], cols[5], cols[6], cols[7] });
    const neg_mults = try ctx.sub(ctx.zero(), multiplicity);
    try acc.addToRelation(ctx, neg_mults, &.{ relation, dst_addr, cols[8], cols[9], cols[10], cols[11] });
}

/// `verify_bitwise_xor_12::Component::evaluate` (circuit AIR): 16 lookups of
/// the 10-bit table expanded by the top two bits of each operand.
pub fn evaluateVerifyBitwiseXor12(interp: anytype) !void {
    const relation = try constantM31(interp.ctx, xor_12.relation_id);
    const a_low = try interp.acc.getPreprocessedColumn(xor_12.a_column);
    const b_low = try interp.acc.getPreprocessedColumn(xor_12.b_column);
    const c_low = try interp.acc.getPreprocessedColumn(xor_12.c_column);
    try xor_12.addLookups(interp, relation, a_low, b_low, c_low, interp.data.traceColumns());
}
