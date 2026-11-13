//! Sixteen independent row lanes, implemented with the existing native-width
//! field kernels. This does not change core/RV32 SIMD width or field arithmetic.
const std = @import("std");
const core = @import("stwo_core");
const m31 = core.fields.m31;
const M = m31.M31;
const Q = core.fields.qm31.QM31;
const NativeSecure = core.fields.packed_qm31.PackedQM31;
pub const LANES = 16;
pub const NATIVE_LANES = m31.PACK_WIDTH;
pub const PACKS = LANES / NATIVE_LANES;
comptime {
    if (NATIVE_LANES > LANES or LANES % NATIVE_LANES != 0) @compileError("Row packets require native SIMD width dividing16");
}
pub const PackedBase = struct {
    /// Optional structural relation-field trait; shared polynomial code imports no frontend.
    pub const SecureField = PackedSecure;
    pub inline fn toSecure(self: PackedBase) PackedSecure {
        return PackedSecure.fromBase(self);
    }
    packs: [PACKS]m31.PackedM31,
    pub inline fn zero() PackedBase {
        return .{ .packs = @splat(@splat(0)) };
    }
    pub inline fn one() PackedBase {
        return .{ .packs = @splat(@splat(1)) };
    }
    pub inline fn splat(value: M) PackedBase {
        return .{ .packs = @splat(m31.splatPacked(value)) };
    }
    pub inline fn fromBase(value: M) PackedBase {
        return splat(value);
    }
    pub inline fn fromCanonical(value: u32) PackedBase {
        return splat(M.fromCanonical(value));
    }
    pub inline fn fromLanes(values: [LANES]M) PackedBase {
        return load(&values);
    }
    pub inline fn load(ptr: [*]const M) PackedBase {
        var result: PackedBase = undefined;
        inline for (0..PACKS) |i| result.packs[i] = m31.loadPacked(ptr + i * NATIVE_LANES);
        return result;
    }
    pub inline fn store(self: PackedBase, ptr: [*]M) void {
        inline for (0..PACKS) |i| m31.storePacked(ptr + i * NATIVE_LANES, self.packs[i]);
    }
    pub inline fn lane(self: PackedBase, index: usize) M {
        std.debug.assert(index < LANES);
        return M.fromCanonical(self.packs[index / NATIVE_LANES][index % NATIVE_LANES]);
    }
    pub inline fn add(lhs: PackedBase, rhs: PackedBase) PackedBase {
        var result: PackedBase = undefined;
        inline for (0..PACKS) |i| result.packs[i] = m31.addPacked(lhs.packs[i], rhs.packs[i]);
        return result;
    }
    pub inline fn sub(lhs: PackedBase, rhs: PackedBase) PackedBase {
        var result: PackedBase = undefined;
        inline for (0..PACKS) |i| result.packs[i] = m31.subPacked(lhs.packs[i], rhs.packs[i]);
        return result;
    }
    pub inline fn mul(lhs: PackedBase, rhs: PackedBase) PackedBase {
        @setEvalBranchQuota(1_000_000);
        var result: PackedBase = undefined;
        inline for (0..PACKS) |i| result.packs[i] = m31.mulPacked(lhs.packs[i], rhs.packs[i]);
        return result;
    }
    pub inline fn square(value: PackedBase) PackedBase {
        return value.mul(value);
    }
    pub inline fn neg(value: PackedBase) PackedBase {
        var result: PackedBase = undefined;
        inline for (0..PACKS) |i| result.packs[i] = m31.negPacked(value.packs[i]);
        return result;
    }
    pub inline fn eql(lhs: PackedBase, rhs: PackedBase) bool {
        inline for (0..PACKS) |i| if (!@reduce(.And, lhs.packs[i] == rhs.packs[i])) return false;
        return true;
    }
    pub inline fn isZero(self: PackedBase) bool {
        return self.eql(zero());
    }
};
pub const PackedSecure = struct {
    pub inline fn fromBaseScalar(value: M) PackedSecure {
        return fromBase(PackedBase.splat(value));
    }
    packs: [PACKS]NativeSecure,
    pub inline fn zero() PackedSecure {
        return .{ .packs = @splat(NativeSecure.zero()) };
    }
    pub inline fn one() PackedSecure {
        return .{ .packs = @splat(NativeSecure.one()) };
    }
    pub inline fn splat(value: Q) PackedSecure {
        return .{ .packs = @splat(NativeSecure.splat(value)) };
    }
    pub inline fn fromBase(value: PackedBase) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = NativeSecure.fromBase(value.packs[i]);
        return result;
    }
    pub inline fn fromLanes(values: [LANES]Q) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = NativeSecure.fromLanes(values[i * NATIVE_LANES ..][0..NATIVE_LANES].*);
        return result;
    }
    pub inline fn fromCoordinates(values: [4]PackedBase) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = NativeSecure.fromCoordinates(.{ values[0].packs[i], values[1].packs[i], values[2].packs[i], values[3].packs[i] });
        return result;
    }
    pub inline fn fromPartialEvals(values: [4]PackedSecure) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = NativeSecure.fromPartialEvals(.{ values[0].packs[i], values[1].packs[i], values[2].packs[i], values[3].packs[i] });
        return result;
    }
    pub inline fn coordinates(self: PackedSecure) [4]PackedBase {
        var result: [4]PackedBase = undefined;
        inline for (0..PACKS) |i| {
            const coords = self.packs[i].coordinates();
            inline for (0..4) |c| result[c].packs[i] = coords[c];
        }
        return result;
    }
    pub inline fn lane(self: PackedSecure, index: usize) Q {
        std.debug.assert(index < LANES);
        return self.packs[index / NATIVE_LANES].lane(index % NATIVE_LANES);
    }
    pub inline fn add(lhs: PackedSecure, rhs: PackedSecure) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = lhs.packs[i].add(rhs.packs[i]);
        return result;
    }
    pub inline fn sub(lhs: PackedSecure, rhs: PackedSecure) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = lhs.packs[i].sub(rhs.packs[i]);
        return result;
    }
    pub inline fn mul(lhs: PackedSecure, rhs: PackedSecure) PackedSecure {
        @setEvalBranchQuota(1_000_000);
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = lhs.packs[i].mul(rhs.packs[i]);
        return result;
    }
    pub inline fn mulBase(lhs: PackedSecure, rhs: PackedBase) PackedSecure {
        @setEvalBranchQuota(1_000_000);
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = lhs.packs[i].mulBase(rhs.packs[i]);
        return result;
    }
    pub inline fn square(value: PackedSecure) PackedSecure {
        return value.mul(value);
    }
    pub inline fn neg(value: PackedSecure) PackedSecure {
        var result: PackedSecure = undefined;
        inline for (0..PACKS) |i| result.packs[i] = value.packs[i].neg();
        return result;
    }
    pub inline fn eql(lhs: PackedSecure, rhs: PackedSecure) bool {
        const left = lhs.coordinates();
        const right = rhs.coordinates();
        inline for (0..4) |i| if (!left[i].eql(right[i])) return false;
        return true;
    }
    pub inline fn isZero(self: PackedSecure) bool {
        return self.eql(zero());
    }
};
