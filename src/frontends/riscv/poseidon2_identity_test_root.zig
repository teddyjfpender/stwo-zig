//! Focused canonical provider-identity gate; avoids compiling the entire
//! RISC-V frontend while a recursive protocol identity is being re-pinned.
test {
    _ = @import("air/memory_commitment/poseidon2_universal_identity_v2.zig");
}
