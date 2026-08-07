//! Cross-layer identity pins for executable admission metadata.

const std = @import("std");
const execution_profile = @import("isa/execution_profile.zig");
const compiler_identity = @import("air/lang/typed_poseidon2_identity.zig");

comptime {
    if (!std.mem.eql(
        u8,
        &compiler_identity.CANONICAL_SEMANTIC_DIGEST,
        &execution_profile.poseidon2_semantic_digest,
    )) {
        @compileError("Poseidon2 ELF admission and typed program digests differ");
    }
}

test "Poseidon2 ELF admission digest equals the canonical typed program digest" {
    try std.testing.expectEqualSlices(
        u8,
        &compiler_identity.CANONICAL_SEMANTIC_DIGEST,
        &execution_profile.poseidon2_semantic_digest,
    );
}
