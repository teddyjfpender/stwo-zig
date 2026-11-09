//! Versioned algebra for constant register0. The original operation/ordinal
//! and RW effect remain intact. Every register0 value and predecessor clock
//! is proved locally before its custody fractions and gap request disappear.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const TAG: u32 = 0x58304c43; // X0LC
pub const VERSION: u32 = 1;
pub const HINT_COLUMNS: usize = 2;
pub const CONSTRAINT_COUNT: usize = 17;
pub const MAX_DEGREE: u32 = 4;

pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/x0-local-custody/v1\x00");
    hash.update("hint=nz,inverse;exact-zero-index;space-bit-authenticated;inactive-or-RW-hints-zero\x00");
    hash.update("active-register0-before4-after4-zero;predecessor0;keep=space+nz;RW-nz-and-inverse-zero;consume-emit-gap-same-weight\x00");
    hash.update("instruction-and-access-ordinal-unchanged;public-x0-values-and-final-clock0;degree4\x00");
    return hash.finalResult();
}

pub const Hint = struct {
    nonzero: M,
    inverse: M,
    /// Host witness construction only. Receiver authority is the algebra.
    pub fn forAddress(space: u1, address: u32) !Hint {
        if (space == 1) return .{ .nonzero = M.zero(), .inverse = M.zero() };
        if (address >= 32) return error.InvalidX0RegisterIndex;
        return if (address == 0)
            .{ .nonzero = M.zero(), .inverse = M.zero() }
        else
            .{ .nonzero = M.one(), .inverse = M.fromCanonical(address).invUncheckedNonZero() };
    }
};

pub fn Algebra(comptime S: type) type {
    return struct {
        pub const Access = struct {
            active: S,
            space: S,
            address: S,
            previous_clock: S,
            before: [4]S,
            after: [4]S,
            nonzero: S,
            inverse: S,
        };
        /// Algebraic at all quotient/OODS points, including inactive values.
        /// Space/active boolean evidence and exact addresses belong to the
        /// authentic operation AIR; this helper repeats those guards so its
        /// standalone scalar contract is also explicit.
        pub fn constraints(access: Access) [CONSTRAINT_COUNT]S {
            const one = S.one();
            const register = one.sub(access.space);
            const live_register = access.active.mul(register);
            // nz already vanishes on RW accesses. Using the affine sum here
            // keeps dynamic load/store space and quadratic access liveness
            // within degree four, without an extra (1-space)*nz product.
            const zero_register = access.active.mul(one.sub(access.space).sub(access.nonzero));
            const inactive_or_rw = one.sub(live_register);
            var result: [CONSTRAINT_COUNT]S = undefined;
            result[0] = access.active.mul(one.sub(access.active));
            result[1] = access.space.mul(one.sub(access.space));
            result[2] = access.active.mul(access.nonzero.mul(one.sub(access.nonzero)));
            result[3] = zero_register.mul(access.address);
            result[4] = access.active.mul(access.address.mul(access.inverse).sub(access.nonzero));
            result[5] = inactive_or_rw.mul(access.nonzero);
            result[6] = inactive_or_rw.mul(access.inverse);
            for (access.before, access.after, 0..) |before, after, index| {
                result[7 + index] = zero_register.mul(before);
                result[11 + index] = zero_register.mul(after);
            }
            result[15] = zero_register.mul(access.previous_clock);
            // Normalize the inverse at register0 too. This makes replay roots
            // canonical and rejects unconstrained hint capacity in empty rows.
            result[16] = zero_register.mul(access.inverse);
            return result;
        }
        pub fn custodyWeight(access: Access) S {
            return access.space.add(access.nonzero);
        }
        pub fn weightedNumerator(access: Access, authentic_numerator: S) S {
            return authentic_numerator.mul(custodyWeight(access));
        }
    };
}

pub fn requirePublic(data: anytype) !void {
    if (data.initial_regs[0] != 0 or data.final_regs[0] != 0 or data.reg_last_clock[0] != 0)
        return error.UntrustedX0LocalPublicBoundary;
}

test "block-v5 x0 local algebra rejects coherent source write and hint forgeries without a chain" {
    const Q = core.fields.qm31.QM31;
    const A = Algebra(Q);
    var value = A.Access{ .active = Q.one(), .space = Q.zero(), .address = Q.zero(), .previous_clock = Q.zero(), .before = @splat(Q.zero()), .after = @splat(Q.zero()), .nonzero = Q.zero(), .inverse = Q.zero() };
    for (A.constraints(value)) |constraint| try std.testing.expect(constraint.isZero());
    try std.testing.expect(A.custodyWeight(value).isZero());
    // A coherent nonzero read can satisfy read equality and a correspondingly
    // forged arithmetic result. Its local x0 equations still reject it.
    value.before[2] = Q.one();
    value.after[2] = Q.one();
    try std.testing.expect(!A.constraints(value)[9].isZero());
    try std.testing.expect(!A.constraints(value)[13].isZero());
    value.before = @splat(Q.zero());
    value.after = @splat(Q.zero());
    value.previous_clock = Q.one();
    try std.testing.expect(!A.constraints(value)[15].isZero());
    value.previous_clock = Q.zero();
    value.nonzero = Q.one();
    try std.testing.expect(!A.constraints(value)[4].isZero());
    value.nonzero = Q.zero();
    value.inverse = Q.one();
    try std.testing.expect(!A.constraints(value)[16].isZero());
}

test "block-v5 x0 local algebra preserves nonzero register and RW fractions all ordinals" {
    const Q = core.fields.qm31.QM31;
    const A = Algebra(Q);
    for ([_]u1{ 0, 1 }) |space| for (0..32) |address| {
        const hint = try Hint.forAddress(space, @intCast(address));
        var value = A.Access{ .active = Q.one(), .space = Q.fromBase(M.fromCanonical(space)), .address = Q.fromBase(M.fromCanonical(@intCast(address))), .previous_clock = Q.zero(), .before = @splat(Q.zero()), .after = @splat(Q.zero()), .nonzero = Q.fromBase(hint.nonzero), .inverse = Q.fromBase(hint.inverse) };
        if (space == 1 or address != 0) {
            value.previous_clock = Q.fromBase(M.fromCanonical(7));
            value.before = @splat(Q.fromBase(M.fromCanonical(255)));
            value.after = @splat(Q.fromBase(M.fromCanonical(42)));
        }
        for (A.constraints(value)) |constraint| try std.testing.expect(constraint.isZero());
        const expected = if (space == 0 and address == 0) Q.zero() else Q.one();
        try std.testing.expect(A.custodyWeight(value).eql(expected));
        for ([_]Q{ Q.one(), Q.one().neg() }) |authentic| try std.testing.expect(A.weightedNumerator(value, authentic).eql(authentic.mul(expected)));
    };
    try std.testing.expectError(error.InvalidX0RegisterIndex, Hint.forAddress(0, 32));
}
