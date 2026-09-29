//! Hand-written circuit-AIR evaluators: ports of
//! `crates/circuit_verifier/src/components/{eq,qm31_ops,verify_bitwise_xor_12}.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Each function is the body of
//! the Rust `CircuitEval::evaluate`, in its call order.

const stwo_core = @import("stwo_core");
const constraint_eval = @import("../../stark_verifier/constraint_eval.zig");
const tree = @import("eval_tree.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const RelationUse = constraint_eval.RelationUse;

/// `M31::from(378353459)`, the circuit `Gate` relation id, as hard-coded upstream.
const gate_relation_id: u32 = 378353459;
/// The `VerifyBitwiseXor_12` relation id, as hard-coded upstream.
const xor_12_relation_id: u32 = 648362599;

pub const Shape = struct {
    trace_columns: usize,
    interaction_columns: usize,
    relation_uses: []const RelationUse,
    /// The preprocessed column whose log size is the component's, or null
    /// for a fixed `log_size`.
    log_size_column: ?[]const u8,
    log_size: ?u32,
};

pub const eq_shape: Shape = .{
    .trace_columns = 4,
    .interaction_columns = 4,
    .relation_uses = &.{.{ .relation_id = "Gate", .uses = 2 }},
    .log_size_column = "eq_in0_address",
    .log_size = null,
};

pub const qm31_ops_shape: Shape = .{
    .trace_columns = 12,
    .interaction_columns = 8,
    .relation_uses = &.{.{ .relation_id = "Gate", .uses = 2 }},
    .log_size_column = "qm31_ops_in0_address",
    .log_size = null,
};

const xor_12_expand_bits = 2;
const xor_12_limb_bits = 10;

pub const verify_bitwise_xor_12_shape: Shape = .{
    .trace_columns = 1 << (2 * xor_12_expand_bits),
    .interaction_columns = 4 * ((1 << (2 * xor_12_expand_bits)) / 2),
    .relation_uses = &.{},
    .log_size_column = null,
    .log_size = 2 * xor_12_limb_bits,
};

fn constantM31(ctx: anytype, value: u32) !@TypeOf(ctx.*).Var {
    return ctx.constant(QM31.fromBase(M31.fromCanonical(value)));
}

/// `CircuitEqComponent::evaluate`.
pub fn evaluateEq(interp: anytype) !void {
    const ctx = interp.ctx;
    const relation = try constantM31(ctx, gate_relation_id);
    const in0_address = try interp.acc.getPreprocessedColumn("eq_in0_address");
    const in1_address = try interp.acc.getPreprocessedColumn("eq_in1_address");
    const cols = interp.data.traceColumns();
    if (cols.len != eq_shape.trace_columns) return error.TraceColumnCountMismatch;
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
    const relation = try constantM31(ctx, gate_relation_id);
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
    if (cols.len != qm31_ops_shape.trace_columns) return error.TraceColumnCountMismatch;

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
    const ctx = interp.ctx;
    const relation = try constantM31(ctx, xor_12_relation_id);
    const a_low = try interp.acc.getPreprocessedColumn("bitwise_xor_10_0");
    const b_low = try interp.acc.getPreprocessedColumn("bitwise_xor_10_1");
    const c_low = try interp.acc.getPreprocessedColumn("bitwise_xor_10_2");
    const cols = interp.data.traceColumns();
    if (cols.len != verify_bitwise_xor_12_shape.trace_columns) return error.TraceColumnCountMismatch;
    var next: usize = 0;
    for (0..1 << xor_12_expand_bits) |i| {
        for (0..1 << xor_12_expand_bits) |j| {
            const multiplicity = cols[next];
            next += 1;
            const a = try ctx.add(a_low, try constantM31(ctx, @intCast(i << xor_12_limb_bits)));
            const b = try ctx.add(b_low, try constantM31(ctx, @intCast(j << xor_12_limb_bits)));
            const c = try ctx.add(c_low, try constantM31(ctx, @intCast((i ^ j) << xor_12_limb_bits)));
            const neg_multiplicity = try ctx.sub(ctx.zero(), multiplicity);
            try interp.acc.addToRelation(ctx, neg_multiplicity, &.{ relation, a, b, c });
        }
    }
}
