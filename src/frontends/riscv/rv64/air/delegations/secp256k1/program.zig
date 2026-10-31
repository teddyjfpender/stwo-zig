//! AIR reuses the same std-only operation topology as native service execution.
const native = @import("../../../ethereum_services/secp256k1.zig");
pub const field = @import("../../../../air/guest_precompile/secp256k1_field.zig");
pub const affine = @import("../../../../air/guest_precompile/secp256k1_affine.zig");
pub const Kind = native.Kind;
pub const Ref = native.Ref;
pub const Operation = native.Operation;
pub const MAX_OPS = native.MAX_OPS;
pub const MAX_WIRES = native.MAX_WIRES;
pub const Program = native.Program;
pub const add = native.add;
pub const double = native.double;
pub const get = native.get;
pub const Values = native.Values;
pub const execute = native.execute;
pub const resolve = native.resolve;
pub const bytes = native.bytes;

comptime {
    if (native.MODULUS != field.base_modulus.integer()) @compileError("native/AIR secp modulus drift");
}
