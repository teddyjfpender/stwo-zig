const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const child_capability =
    @import("recursive_common_fold_child_capability_v2.zig");
const registry = @import("recursive_circuit_registry_v1.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Proof = subject.Types(Engine);

test "role0 q193 cold owner and fold-child contracts instantiate" {
    std.testing.refAllDeclsRecursive(Proof);
    std.testing.refAllDeclsRecursive(Proof.OwnedColdProofV4);
    std.testing.refAllDeclsRecursive(Proof.EvidenceV4);
    std.testing.refAllDeclsRecursive(Proof.FreshFoldChildV4);
    try std.testing.expectEqual(
        registry.CircuitRoleV4.ethereum_incremental_leaf_wrapper_v4,
        Proof.OwnedColdProofV4.ROLE,
    );
    try std.testing.expectEqual(
        registry.CircuitRoleV4.ethereum_incremental_leaf_wrapper_v4,
        Proof.EvidenceV4.ROLE,
    );
    try std.testing.expect(
        Proof.CoreV4.KernelV4.VERIFIER_REPLAY_SHARING_AVAILABLE,
    );
    try std.testing.expect(
        !Proof.CoreV4.KernelV4.SERIALIZABLE_VERIFIER_REPLAY_AUTHORITY,
    );
    try std.testing.expect(!subject.WRAPPER_PROOF_AVAILABLE);
    try std.testing.expect(!subject.COLD_WRAPPER_CAPTURE_AVAILABLE);
    try std.testing.expect(!subject.FOLD_CHILD_PROJECTION_AVAILABLE);
}

test "role0 fold child is the typed schema4 real branch" {
    const Empty = struct {
        wrapper: @import("recursive_common_wrapper_authority_v2.zig").FreshWrapperViewV2,
        ingress: Proof.Ingress,
        graph: Proof.Graph,
        query_words: *const [193]@import("stwo_core").fields.m31.M31,
        query_log_size: u32,
        final_transcript_digest: *const frontend.recursion.poseidon2_channel.Digest,
        final_transcript_draw_count: u32,
        query_words_identity_sha256: *const [32]u8,

        pub fn validateBorrowed(_: @This()) !void {}
    };
    const Tagged = subject.TaggedFoldChildV4(
        Proof.EvidenceV4,
        Empty,
        Empty,
    );
    std.testing.refAllDecls(Tagged);
    try std.testing.expect(
        Tagged != child_capability.TaggedFoldChildV2(
            child_capability.UnavailableRealLeafChildV2,
            Empty,
            Empty,
        ),
    );
}
