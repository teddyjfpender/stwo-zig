//! Candidate optimization uses ONLY immutable source literal writer IDs.
//! Public/hint witness values are never inspected or used for shape selection.
const N = @import("../bn254_mac12/normalize.zig");
pub const Fold = struct { terms: [145]N.Term = undefined, len: usize = 0 };
pub fn apply(input: []const N.Term, zero: u32, one: u32) !Fold {
    if (input.len > 145) return error.PairingLiteralExpressionBound;
    if (zero == one or zero >= 2147483647 or one >= 2147483647) return error.PairingLiteralAuthority;
    var out = Fold{};
    for (input) |original| {
        var term = original;
        if (term.coefficient == 0 or term.a == zero or (term.b != null and term.b.? == zero)) continue;
        if (term.b) |b| {
            if (b == one) term.b = null else if (term.a == one) {
                term.a = b;
                term.b = null;
            }
        }
        out.terms[out.len] = term;
        out.len += 1;
    }
    return out;
}
