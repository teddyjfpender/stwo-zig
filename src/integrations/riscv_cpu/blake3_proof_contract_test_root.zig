//! Complete retained CPU BLAKE3 proof and adversarial corpus.
test {
    _ = @import("blake3_proof_tests/blake3_challenge_committed_test.zig");
    _ = @import("blake3_proof_tests/blake3_field_bytes_proof_test.zig");
    _ = @import("blake3_proof_tests/blake3_lifted_path_test.zig");
    _ = @import("blake3_proof_tests/blake3_memory_path_proof_test.zig");
    _ = @import("blake3_proof_tests/blake3_memory_update_chain_test.zig");
    _ = @import("blake3_proof_tests/blake3_memory_update_proof_test.zig");
    _ = @import("blake3_proof_tests/blake3_merkle_path_test.zig");
    _ = @import("blake3_proof_tests/blake3_private_draw_test.zig");
    _ = @import("blake3_proof_tests/blake3_public_subtree_proof_test.zig");
    _ = @import("blake3_proof_tests/blake3_query_proof_test.zig");
    _ = @import("blake3_proof_tests/blake3_routed_node_test.zig");
    _ = @import("blake3_proof_tests/blake3_routed_transcript_test.zig");
    _ = @import("blake3_proof_tests/blake3_transcript_transition_test.zig");
    _ = @import("blake3_proof_tests/readonly_consistency_test.zig");
    const std = @import("std");
    const required = .{
        "BLAKE3 native draw produces constrained scalar challenges in a complete CPU proof",
        "BLAKE3 canonical field bytes feed an authenticated complete hash proof",
        "BLAKE3 lifted geometry matches native decommitments and a complete typed path proof",
        "BLAKE3 memory path proves all 30 levels and rejects a changed root",
        "BLAKE3 memory path proves a full canonical program field",
        "BLAKE3 memory update proves chained insertion deletion and preserved words",
        "BLAKE3 memory update proves admission rejects disconnected transitions",
        "BLAKE3 memory update proves shared siblings and rejects changed after root",
        "BLAKE3 private sibling word semantics pin and reject out of range bytes",
        "BLAKE3 path witnesses match every native direction and keep siblings private",
        "BLAKE3 private sibling paths verify in complete CPU proofs",
        "BLAKE3 absorption feeds private state into a complete ordered challenge proof",
        "public subtree path proves private siblings and rejects a changed admitted root",
        "BLAKE3 raw query indices verify in a complete CPU draw proof",
        "BLAKE3 routed Merkle proof authenticates both private child digests",
        "BLAKE3 routed transcript payloads preserve fixed schedules and own read receipts",
        "BLAKE3 private routed words and canonical fields verify in a transcript proof",
        "BLAKE3 transcript absorption proves with private intermediate state",
        "Read-only consistency pins sorted sparse table semantics and full u32 indices",
        "Read-only consistency verifies unsorted duplicate inputs in a complete CPU proof",
        "Read-only input authenticates byte indices scalar values and stable table tuples",
    };
    // A dropped leaf cannot be compensated by unrelated dependency tests.
    inline for (required) |suffix| {
        var found: usize = 0;
        for (@import("builtin").test_functions) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".test." ++ suffix)) found += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), found);
    }
}
