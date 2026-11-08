//! Cold polynomial recorder using the existing external-verifier lane contract.
//! Publics, claims and challenges are wires, so no live field value decides
//! parameter aliasing. The underlying IR remains the native OM31 polynomial IR.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const Underlying = A.evaluation.symbolic.SymbolicLane(O);
pub const Recording = A.evaluation.symbolic.Recording(O);
pub const Lane = struct {
    pub const rv64_external_lane = true;
    pub const rv64_extension_degree = 8;
    const Self = @This();
    id: u32,
    fn wrap(v: Underlying) Self {
        return .{ .id = v.id };
    }
    fn raw(v: Self) Underlying {
        return .{ .id = v.id };
    }
    pub fn zero() Self {
        return wrap(Underlying.zero());
    }
    pub fn one() Self {
        return wrap(Underlying.one());
    }
    pub fn fromU32(value: u32) Self {
        return wrap(Underlying.fromU32(value));
    }
    pub fn fromBase(value: core.fields.m31.M31) Self {
        return wrap(Underlying.fromBase(value));
    }
    pub fn literal(value: O) Self {
        return wrap(Underlying.literal(value));
    }
    pub fn fromQm31(value: core.fields.qm31.QM31) Self {
        var c: [8]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
        @memcpy(c[0..4], &value.toM31Array());
        return literal(O.fromM31Array(c));
    }
    pub fn input(tree: u8, column: usize, offset: i8) Self {
        return wrap(Underlying.input(tree, column, offset));
    }
    /// Only cold semantic IDs enter here. Runtime parameter values are separate
    /// device data; equal/zero live values never collapse two named wires.
    pub fn parameter(id: u32) Self {
        if (id >= core.fields.m31.Modulus - 1) @panic("symbolic semantic parameter ID out of range");
        return wrap(Underlying.fromConst(O.fromBase(core.fields.m31.M31.fromCanonical(id + 1))));
    }
    pub fn add(a: Self, b: Self) Self {
        return wrap(raw(a).add(raw(b)));
    }
    pub fn sub(a: Self, b: Self) Self {
        return wrap(raw(a).sub(raw(b)));
    }
    pub fn mul(a: Self, b: Self) Self {
        return wrap(raw(a).mul(raw(b)));
    }
    pub fn neg(a: Self) Self {
        return wrap(raw(a).neg());
    }
    pub fn square(a: Self) Self {
        return a.mul(a);
    }
    pub fn fromPartialEvals(c: [8]Self) Self {
        var v: [8]Underlying = undefined;
        for (c, &v) |a, *b| b.* = raw(a);
        return wrap(Underlying.fromPartialEvals(v));
    }
    /// Constraint IR is polynomial. Inverse witnesses and derived public
    /// denominators must be supplied explicitly, never silently approximated.
    pub fn inv(_: Self) Self {
        const builder = Underlying.active orelse @panic("symbolic inverse outside recording");
        if (builder.failure == null) builder.failure = error.NonPolynomialInverse;
        return zero();
    }
};
comptime {
    A.evaluation.assertExternalLane(Lane);
}
