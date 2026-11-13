//! Fixed guest-relation event used by caller and provider components.
//!
//! Padding exits before denominator evaluation.  Active rows carry one unit
//! term whose sign is fixed by the reviewed request/emit role; there is no
//! scalar multiplicity field and no access ordinal in this representation.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const challenges = @import("relation_challenges.zig");
const registry = @import("relation_registry.zig");

pub const Tuple = [registry.guest_relation_arity]M31;

pub const Error = error{
    InvalidLiveness,
    InvalidPadding,
    InvalidRole,
    ZeroDenominator,
};

pub const Event = struct {
    role: registry.Role,
    active: M31,
    tuple: Tuple,

    pub fn validate(self: Event) Error!void {
        if (!self.active.eql(M31.zero()) and !self.active.eql(M31.one())) {
            return error.InvalidLiveness;
        }
        if (self.role != .request and self.role != .emit) {
            return error.InvalidRole;
        }
        if (self.active.isZero()) {
            for (self.tuple) |value| {
                if (!value.isZero()) return error.InvalidPadding;
            }
        }
    }

    pub fn numerator(self: Event) Error!QM31 {
        try self.validate();
        const magnitude = QM31.fromBase(self.active);
        return if (self.role == .request) magnitude.neg() else magnitude;
    }

    pub fn denominator(
        self: Event,
        relation: *const challenges.Poseidon2V1Relations,
    ) Error!QM31 {
        try self.validate();
        return relation.guest_poseidon2_io.combineBase(self.tuple);
    }

    /// Return this row's exact LogUp contribution.
    ///
    /// An inactive canonical row returns before combining or inverting its
    /// all-zero tuple, so padding is safe even when that denominator is zero.
    pub fn term(
        self: Event,
        relation: *const challenges.Poseidon2V1Relations,
    ) Error!QM31 {
        try self.validate();
        if (self.active.isZero()) return QM31.zero();
        const inverse = (try self.denominator(relation)).inv() catch
            return error.ZeroDenominator;
        return (try self.numerator()).mul(inverse);
    }
};
