//! Explicit discovery within the core package, including embedded tests.
comptime {
    @import("std").testing.refAllDeclsRecursive(@import("fields/mod.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("crypto/blake2s_backend.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("vcs/blake2_hash.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("vcs_lifted/blake2_merkle.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("vcs_lifted/sparse_h3_source_projection_v2.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("pcs/paired_claim_rows_v2.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("vcs_lifted/owned_paired_gate_v2.zig"));
}
