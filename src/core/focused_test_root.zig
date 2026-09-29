//! Explicit discovery within the core package, including embedded tests.
comptime {
    @import("std").testing.refAllDeclsRecursive(@import("fields/mod.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("crypto/blake2s_backend.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("vcs/blake2_hash.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("vcs_lifted/blake2_merkle.zig"));
}
