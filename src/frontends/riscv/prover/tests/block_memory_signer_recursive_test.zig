//! Diagnostic recursive binding of a fully verified signer/Keccak block core.
const std = @import("std");
const fixture = @import("block_memory_core_sha_fixture_test.zig");
const singleton = @import("../block_v3_canonical_singleton_test_support.zig");
const parent = @import("../../recursion/blake3_execution_parent_protocol.zig");
const staged_leaf = @import("../block_v4_cpu_staged_recursive_leaf_v3.zig");
const v3 = @import("../../recursion/blake3_block_execution_span_v3.zig");

test "block-v4 signer Keccak q8 core recursively verifies leaf and exact root" {
    const callback = struct {
        fn verify(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            try std.testing.expectEqual(@as(u64, 103), view.verified.event_count);
            var proof = try singleton.proveWithProfile(a, view, .diagnostic_q8_pow0);
            defer proof.deinit(a);
            try std.testing.expectEqual(parent.Profile.diagnostic_q8_pow0, proof.leaf_admission.key.profile);
            try std.testing.expectEqual(parent.Profile.diagnostic_q8_pow0, proof.outer_admission.key.profile);
            try std.testing.expect(proof.leaf_bytes.len > 0 and proof.outer_bytes.len > 0);
            std.debug.print("BLOCK_V4_SIGNER_RECURSIVE_Q8 verified=true events=103 leaf_bytes={d} outer_bytes={d} peak_bytes={d} leaf_ns={d} outer_ns={d}\n", .{ proof.leaf_bytes.len, proof.outer_bytes.len, proof.peak_live_bytes, proof.leaf_prove_ns, proof.outer_prove_ns });
        }
    };
    try fixture.withSignerCoreFixture(parent.PCS_CONFIG, callback.verify);
}

test "block-v4 staged signer leaf reopens native bytes and verifies recursive descriptor" {
    const callback = struct {
        fn verify(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            const job = view.statement.complete_pins.?.expected_job;
            const statement = try v3.leaf(job, &view.segment.base);
            var produced = try staged_leaf.prove(a, view.wire.execution[0].native_artifact, view.prepared, view.prepared.id, statement, view.statement.seal, view.execution_receipt, .diagnostic_q8_pow0);
            defer produced.deinit(a);
            try std.testing.expectEqualDeep(statement, produced.descriptor.statement);
            try std.testing.expectEqualDeep(produced.admission, produced.descriptor.admission);
            try std.testing.expect(produced.bytes.len > 0);
            var node = try produced.openNode(a);
            defer node.deinit();
            try node.validate();
            var wrong_key = view.prepared.id;
            wrong_key[0] ^= 1;
            try std.testing.expectError(error.UntrustedExecutionKey, staged_leaf.prove(a, view.wire.execution[0].native_artifact, view.prepared, wrong_key, statement, view.statement.seal, view.execution_receipt, .diagnostic_q8_pow0));
        }
    };
    try fixture.withSignerCoreFixture(parent.PCS_CONFIG, callback.verify);
}
