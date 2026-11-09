//! Cross-layer identity pins for executable admission metadata.

const std = @import("std");
const execution_profile = @import("stwo_riscv_isa").modules.execution_profile;
const compiler_identity = @import("stwo_riscv_memory").modules.typed_typed_poseidon2_identity;
const keccakf_authority = @import("stwo_riscv_precompiles").modules.air_keccakf_authority;

comptime {
    if (!std.mem.eql(
        u8,
        &compiler_identity.CANONICAL_SEMANTIC_DIGEST,
        &execution_profile.poseidon2_semantic_digest,
    )) {
        @compileError("Poseidon2 ELF admission and typed program digests differ");
    }
    if (!std.mem.eql(
        u8,
        &keccakf_authority.execution_semantic_digest,
        &execution_profile.keccakf_semantic_digest,
    )) {
        @compileError("Keccak-f ELF admission and typed execution digests differ");
    }
}

test "Keccak-f ELF admission digest equals the typed execution authority" {
    try std.testing.expectEqualStrings(
        "riscv.keccakf_1600.permute.v1",
        keccakf_authority.execution_semantic_preimage,
    );
    try std.testing.expectEqualSlices(
        u8,
        &keccakf_authority.execution_semantic_digest,
        &execution_profile.keccakf_semantic_digest,
    );
}

test "Poseidon2 ELF admission digest equals the canonical typed program digest" {
    try std.testing.expectEqualSlices(
        u8,
        &compiler_identity.CANONICAL_SEMANTIC_DIGEST,
        &execution_profile.poseidon2_semantic_digest,
    );
}
