//! Existing independently sized arithmetic and cryptographic delegation AIRs.
//! Callers and runtime profiles retain their own admission and closure policies.
pub const main_storage = @import("main_storage.zig");
pub const keccak = @import("keccak/mod.zig");
pub const secp256k1 = @import("secp256k1/mod.zig");
pub const division = @import("division/mod.zig");
pub const multiplication = @import("multiplication/mod.zig");
pub const registry = @import("registry.zig");
