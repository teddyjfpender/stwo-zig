//! In-circuit LogUp terms: port of `crates/stark_verifier/src/logup.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! Every function emits builder ops in the order of the Rust `eval!` bodies:
//! left operand, right operand, then the op. The builder's index-only
//! peepholes decide which ops become gates; nothing here folds values.

/// A `Fraction<Var, Var>`.
pub fn LogupTerm(comptime Var: type) type {
    return struct { numerator: Var, denominator: Var };
}

/// `logup_term`: the fraction `numerator / combine_term(element)`.
pub fn logupTerm(
    comptime Ctx: type,
    ctx: *Ctx,
    interaction_elements: [2]Ctx.Var,
    numerator: Ctx.Var,
    element: []const Ctx.Var,
) !LogupTerm(Ctx.Var) {
    const denominator = try combineTerm(Ctx, ctx, element, interaction_elements);
    return .{ .numerator = numerator, .denominator = denominator };
}

/// `combine_term`: Horner over the reversed element in `alpha`, minus `z`,
/// where `interaction_elements = [z, alpha]`.
pub fn combineTerm(
    comptime Ctx: type,
    ctx: *Ctx,
    element: []const Ctx.Var,
    interaction_elements: [2]Ctx.Var,
) !Ctx.Var {
    if (element.len == 0) return error.EmptyLookupElement;
    var value = element[element.len - 1];
    var i = element.len - 1;
    while (i > 0) {
        i -= 1;
        value = try ctx.mul(value, interaction_elements[1]);
        value = try ctx.add(value, element[i]);
    }
    return ctx.sub(value, interaction_elements[0]);
}

/// `single_logup_constraint`: `shifted_diff * denominator - numerator`.
pub fn singleLogupConstraint(
    comptime Ctx: type,
    ctx: *Ctx,
    term: LogupTerm(Ctx.Var),
    shifted_diff: Ctx.Var,
) !Ctx.Var {
    const scaled = try ctx.mul(shifted_diff, term.denominator);
    return ctx.sub(scaled, term.numerator);
}

/// `pair_logup_constraint`: the single constraint of `term0 + term1`, whose
/// numerator is `t1.n * t0.d + t0.n * t1.d` in that operand order.
pub fn pairLogupConstraint(
    comptime Ctx: type,
    ctx: *Ctx,
    term0: LogupTerm(Ctx.Var),
    term1: LogupTerm(Ctx.Var),
    shifted_diff: Ctx.Var,
) !Ctx.Var {
    const denominator = try ctx.mul(term0.denominator, term1.denominator);
    const lhs = try ctx.mul(term1.numerator, term0.denominator);
    const rhs = try ctx.mul(term0.numerator, term1.denominator);
    const numerator = try ctx.add(lhs, rhs);
    return singleLogupConstraint(Ctx, ctx, .{ .numerator = numerator, .denominator = denominator }, shifted_diff);
}

test "Gate tuple Horner order and LogUp residual equations" {
    const std = @import("std");
    const fields = @import("stwo_core").fields;
    const M31 = fields.m31.M31;
    const QM31 = fields.qm31.QM31;
    const gate_relation_id = @import("../common/component_list.zig").GATE_RELATION_ID;
    const Context = struct {
        const Var = QM31;

        fn add(_: *@This(), left: Var, right: Var) !Var {
            return left.add(right);
        }

        fn sub(_: *@This(), left: Var, right: Var) !Var {
            return left.sub(right);
        }

        fn mul(_: *@This(), left: Var, right: Var) !Var {
            return left.mul(right);
        }
    };

    var ctx = Context{};
    try std.testing.expectEqual(@as(u32, 378353459), gate_relation_id);
    const tuple = [_]QM31{
        QM31.fromBase(M31.fromCanonical(gate_relation_id)),
        QM31.fromBase(M31.fromCanonical(12)),
        QM31.fromBase(M31.fromCanonical(3)),
        QM31.fromBase(M31.fromCanonical(5)),
        QM31.fromBase(M31.fromCanonical(8)),
        QM31.fromBase(M31.fromCanonical(13)),
    };
    const alpha = QM31.fromU32Unchecked(7, 2, 0, 1);
    const z = QM31.fromU32Unchecked(19, 0, 3, 0);
    const combined = try combineTerm(Context, &ctx, &tuple, .{ z, alpha });
    var polynomial = QM31.zero();
    var power = QM31.one();
    for (tuple) |coefficient| {
        polynomial = polynomial.add(coefficient.mul(power));
        power = power.mul(alpha);
    }
    try std.testing.expect(combined.eql(polynomial.sub(z)));
    try std.testing.expectError(error.EmptyLookupElement, combineTerm(Context, &ctx, &[_]QM31{}, .{ z, alpha }));

    const two = QM31.fromU32Unchecked(2, 1, 0, 0);
    const three = QM31.fromBase(M31.fromCanonical(3));
    const five = QM31.fromBase(M31.fromCanonical(5));
    const left = LogupTerm(QM31){ .numerator = three, .denominator = two };
    const right = LogupTerm(QM31){ .numerator = two, .denominator = five };
    const single_diff = three.mul(two.inv());
    const pair_diff = single_diff.add(two.mul(five.inv()));
    try std.testing.expect((try singleLogupConstraint(Context, &ctx, left, single_diff)).eql(QM31.zero()));
    try std.testing.expect((try pairLogupConstraint(Context, &ctx, left, right, pair_diff)).eql(QM31.zero()));
    try std.testing.expect(!(try pairLogupConstraint(Context, &ctx, left, right, pair_diff.add(QM31.one()))).eql(QM31.zero()));

    // Zero denominators make the paired residual vanish regardless of diff.
    const degenerate = LogupTerm(QM31){ .numerator = QM31.one(), .denominator = QM31.zero() };
    try std.testing.expect((try pairLogupConstraint(Context, &ctx, degenerate, degenerate, z)).eql(QM31.zero()));
}
