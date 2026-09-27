//! Fixed public arithmetic-wire claims shared by lowering and verification.
const core = @import("stwo_core");
const m31 = core.fields.m31;
const M31 = m31.M31;
const QM31 = core.fields.qm31.QM31;
const universal = @import("universal_challenges.zig");
pub const PublicWireTerm = @import("verifier_wire_protocol.zig").PublicWireTerm;

pub const PublicClaimError = universal.Error || QM31.Error || error{
    InvalidPublicAnchor,
    ZeroDenominator,
};

pub const PublicTermParts = struct { tuple: [6]QM31, numerator: QM31 };
/// One native/recursive authority for fixed public-anchor tuple order and sign.
pub fn publicTermParts(term: PublicWireTerm) PublicClaimError!PublicTermParts {
    if (term.circuit_id >= m31.Modulus or term.node_id >= m31.Modulus or
        term.multiplicity == 0 or term.multiplicity >= m31.Modulus or
        term.role == .request)
    {
        return error.InvalidPublicAnchor;
    }
    const words = term.value.toM31Array();
    const tuple = [6]QM31{
        QM31.fromBase(M31.fromCanonical(term.circuit_id)),
        QM31.fromBase(M31.fromCanonical(term.node_id)),
        QM31.fromBase(words[0]),
        QM31.fromBase(words[1]),
        QM31.fromBase(words[2]),
        QM31.fromBase(words[3]),
    };
    var numerator = QM31.fromBase(M31.fromCanonical(term.multiplicity));
    if (term.role == .consume) numerator = numerator.neg();
    return .{ .tuple = tuple, .numerator = numerator };
}

pub fn publicTermClaim(challenge: *const universal.Elements, term: PublicWireTerm) PublicClaimError!QM31 {
    const parts = try publicTermParts(term);
    const denominator = challenge.combineSecure(&parts.tuple) catch return error.InvalidPublicAnchor;
    const inverse_value = denominator.inv() catch return error.ZeroDenominator;
    return parts.numerator.mul(inverse_value);
}

pub fn inputTermClaim(
    challenge: *const universal.Elements,
    circuit_id: u32,
    node_id: u32,
    value: QM31,
    multiplicity: u32,
) PublicClaimError!QM31 {
    if (circuit_id >= m31.Modulus or node_id >= m31.Modulus or
        multiplicity == 0 or multiplicity >= m31.Modulus)
    {
        return error.InvalidPublicAnchor;
    }
    const words = value.toM31Array();
    const denominator = challenge.combineSecure(&.{
        QM31.fromBase(M31.fromCanonical(circuit_id)),
        QM31.fromBase(M31.fromCanonical(node_id)),
        QM31.fromBase(words[0]),
        QM31.fromBase(words[1]),
        QM31.fromBase(words[2]),
        QM31.fromBase(words[3]),
    }) catch return error.InvalidPublicAnchor;
    const inverse_value = denominator.inv() catch return error.ZeroDenominator;
    return QM31.fromBase(M31.fromCanonical(multiplicity)).mul(inverse_value);
}
