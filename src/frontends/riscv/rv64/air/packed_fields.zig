//! RV64 aliases for the neutral sixteen-row field packet authority.
const fields = @import("../../air/packed_fields16.zig");
pub const LANES = fields.LANES;
pub const NATIVE_LANES = fields.NATIVE_LANES;
pub const PACKS = fields.PACKS;
pub const PackedBase = fields.PackedBase;
pub const PackedSecure = fields.PackedSecure;

const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const O = core.fields.om31.OM31;
const wide = core.fields.packed_om31;
/// Explicit field identity: base arithmetic stays packed M31, while the tagged
/// type prevents inferring QM31 challenge/interaction storage for an OM31 AIR.
pub fn BaseForField(comptime C: type) type {
    if (C == Q) return PackedBase;
    if (C == O) return PackedOmBase;
    @compileError("unsupported RV64 relation field");
}
pub fn SecureForField(comptime C: type) type {
    if (C == Q) return PackedSecure;
    if (C == O) return PackedOmSecure;
    @compileError("unsupported RV64 relation field");
}
pub const PackedOmBase = struct {
    raw: PackedBase,
    pub const SecureField = PackedOmSecure;
    pub fn toSecure(x: @This()) PackedOmSecure {
        return PackedOmSecure.fromBase(x);
    }
    pub fn zero() @This() {
        return .{ .raw = PackedBase.zero() };
    }
    pub fn one() @This() {
        return .{ .raw = PackedBase.one() };
    }
    pub fn splat(x: M) @This() {
        return .{ .raw = PackedBase.splat(x) };
    }
    pub fn fromBase(x: M) @This() {
        return splat(x);
    }
    pub fn fromCanonical(x: u32) @This() {
        return .{ .raw = PackedBase.fromCanonical(x) };
    }
    pub fn fromLanes(x: [LANES]M) @This() {
        return .{ .raw = PackedBase.fromLanes(x) };
    }
    pub fn load(x: [*]const M) @This() {
        return .{ .raw = PackedBase.load(x) };
    }
    pub fn store(x: @This(), ptr: [*]M) void {
        x.raw.store(ptr);
    }
    pub fn lane(x: @This(), i: usize) M {
        return x.raw.lane(i);
    }
    pub fn add(x: @This(), y: @This()) @This() {
        return .{ .raw = x.raw.add(y.raw) };
    }
    pub fn sub(x: @This(), y: @This()) @This() {
        return .{ .raw = x.raw.sub(y.raw) };
    }
    pub fn mul(x: @This(), y: @This()) @This() {
        return .{ .raw = x.raw.mul(y.raw) };
    }
    pub fn neg(x: @This()) @This() {
        return .{ .raw = x.raw.neg() };
    }
    pub fn square(x: @This()) @This() {
        return x.mul(x);
    }
    pub fn eql(x: @This(), y: @This()) bool {
        return x.raw.eql(y.raw);
    }
    pub fn isZero(x: @This()) bool {
        return x.raw.isZero();
    }
};
pub const PackedOmSecure = struct {
    packs: [PACKS]wide.PackedOM31,
    pub fn zero() @This() {
        return .{ .packs = @splat(wide.PackedOM31.zero()) };
    }
    pub fn one() @This() {
        return .{ .packs = @splat(wide.PackedOM31.one()) };
    }
    pub fn splat(x: O) @This() {
        return .{ .packs = @splat(wide.splat(x)) };
    }
    pub fn fromBaseScalar(x: M) @This() {
        return fromBase(PackedOmBase.splat(x));
    }
    pub fn fromBase(x: PackedOmBase) @This() {
        var out = zero();
        inline for (0..PACKS) |i| out.packs[i].c0 = core.fields.packed_qm31.PackedQM31.fromBase(x.raw.packs[i]);
        return out;
    }
    pub fn fromLanes(x: [LANES]O) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| out.packs[i] = wide.loadNative(x[i * NATIVE_LANES ..][0..NATIVE_LANES]);
        return out;
    }
    pub fn fromCoordinates(x: [8]PackedOmBase) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| {
            var coordinates_: [8]core.fields.m31.PackedM31 = undefined;
            inline for (0..8) |c| coordinates_[c] = x[c].raw.packs[i];
            out.packs[i] = wide.fromCoordinates(coordinates_);
        }
        return out;
    }
    /// Coordinates may already be extension-valued at OODS points.
    pub fn fromPartialEvals(x: [8]@This()) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| {
            var input: [8]wide.PackedOM31 = undefined;
            inline for (0..8) |j| input[j] = x[j].packs[i];
            out.packs[i] = wide.PackedOM31.fromPartialEvals(input);
        }
        return out;
    }

    pub fn coordinates(x: @This()) [8]PackedOmBase {
        var out: [8]PackedOmBase = undefined;
        inline for (0..PACKS) |i| {
            const c = wide.coordinates(x.packs[i]);
            inline for (0..8) |j| out[j].raw.packs[i] = c[j];
        }
        return out;
    }
    pub fn lane(x: @This(), i: usize) O {
        return wide.lane(x.packs[i / NATIVE_LANES], i % NATIVE_LANES);
    }
    pub fn add(x: @This(), y: @This()) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| out.packs[i] = x.packs[i].add(y.packs[i]);
        return out;
    }
    pub fn sub(x: @This(), y: @This()) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| out.packs[i] = x.packs[i].sub(y.packs[i]);
        return out;
    }
    pub inline fn mul(x: @This(), y: @This()) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| out.packs[i] = wide.mul(x.packs[i], y.packs[i]);
        return out;
    }
    /// Pointer accumulation avoids constructing/passing a 512-byte splatted
    /// weight and returning a 512-byte weighted residual for each base constraint.
    /// One native pack updates at a time through existing field arithmetic.
    pub fn addScaledBase(self: *@This(), scalar: O, value: PackedOmBase) void {
        const weight = wide.splat(scalar);
        inline for (0..PACKS) |i| self.packs[i] = self.packs[i].add(weight.mulBase(value.raw.packs[i]));
    }
    pub fn mulBase(x: @This(), y: PackedOmBase) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| out.packs[i] = x.packs[i].mulBase(y.raw.packs[i]);
        return out;
    }
    pub fn neg(x: @This()) @This() {
        var out: @This() = undefined;
        inline for (0..PACKS) |i| out.packs[i] = x.packs[i].neg();
        return out;
    }
    pub fn square(x: @This()) @This() {
        return x.mul(x);
    }
    pub fn eql(x: @This(), y: @This()) bool {
        inline for (0..LANES) |i| if (!x.lane(i).eql(y.lane(i))) return false;
        return true;
    }
    pub fn isZero(x: @This()) bool {
        return x.eql(zero());
    }
};
