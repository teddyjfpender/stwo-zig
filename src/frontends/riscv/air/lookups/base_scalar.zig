//! Private one-limb scalar adapter for committed RISC-V lookup rows.
//!
//! The typed opcode-relation builder names its base-field embedding
//! constructor `fromBase`, while core `M31` deliberately has no identity
//! constructor by that name. This wrapper supplies the builder's scalar
//! interface without promoting committed values into QM31.

const M31 = @import("stwo_core").fields.m31.M31;

pub const Scalar = struct {
    value: M31,

    pub inline fn fromBase(value: M31) Scalar {
        return .{ .value = value };
    }

    pub inline fn zero() Scalar {
        return fromBase(M31.zero());
    }

    pub inline fn one() Scalar {
        return fromBase(M31.one());
    }

    pub inline fn isZero(self: Scalar) bool {
        return self.value.isZero();
    }

    pub inline fn add(lhs: Scalar, rhs: Scalar) Scalar {
        return fromBase(lhs.value.add(rhs.value));
    }

    pub inline fn sub(lhs: Scalar, rhs: Scalar) Scalar {
        return fromBase(lhs.value.sub(rhs.value));
    }

    pub inline fn neg(self: Scalar) Scalar {
        return fromBase(self.value.neg());
    }

    pub inline fn mul(lhs: Scalar, rhs: Scalar) Scalar {
        return fromBase(lhs.value.mul(rhs.value));
    }
};

comptime {
    if (@sizeOf(Scalar) != @sizeOf(M31) or
        @alignOf(Scalar) != @alignOf(M31))
    {
        @compileError("lookup base scalar must be layout-identical to M31");
    }
}
