//! Small edit loop for typed compact-Poseidon lowering and admission identity.
test {
    _ = @import("air/lang/typed_poseidon2_compact_test.zig");
    _ = @import("air/memory_commitment/poseidon2_universal_identity_v2.zig");
}
