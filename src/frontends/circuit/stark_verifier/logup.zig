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
