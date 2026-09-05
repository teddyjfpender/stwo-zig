//! Cross-layer identity pins for executable admission metadata.

const std = @import("std");
const execution_profile = @import("isa/execution_profile.zig");
const compiler_identity = @import("air/lang/typed_poseidon2_identity.zig");
const keccakf_authority = @import("air/guest_precompile/keccakf_authority.zig");

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
