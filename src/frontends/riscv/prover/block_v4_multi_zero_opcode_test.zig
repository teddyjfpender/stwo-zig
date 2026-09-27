//! Unpadded precompile-only second leaf has a native-only opcode receipt.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const core = @import("stwo_core");
const fixture = @import("block_v4_multi_core_fixture_test.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const execution_receiver = @import("block_execution_batch_receiver_v2.zig").ForEthereumShaBackend(Cpu);

test "block-v4 unpadded precompile-only second leaf closes core and recursive binding" {
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const callback = struct {
        fn verify(a: std.mem.Allocator, view: fixture.View) !void {
            try std.testing.expectEqual(@as(u64, 0), view.statement.execution_active_counts[1]);
            try std.testing.expect(view.statement.execution_extension_active_counts[1] > 0);
            try std.testing.expectEqual(@as(u64, 0), view.receipts[1].event_count);
            const execution = &view.executions[1];
            const admitted = view.execution_pins[1];
            var wrong_root = view.receipts[1].witness_root;
            wrong_root[0] ^= 1;
            try std.testing.expectError(error.InvalidEmptyExecutionSidecar, execution_receiver.verify(a, view.wire.execution[1], execution.prepared, admitted.expected_key_id, admitted.statement, view.statement.seal, 1, wrong_root, view.config));
            var bogus_bytes = view.wire.execution[1];
            bogus_bytes.sidecar_stark = &.{1};
            try std.testing.expectError(error.InvalidEmptyExecutionSidecar, execution_receiver.verify(a, bogus_bytes, execution.prepared, admitted.expected_key_id, admitted.statement, view.statement.seal, 1, view.receipts[1].witness_root, view.config));
            var bogus_claims = view.wire.execution[1];
            bogus_claims.sidecar_claims = view.wire.execution[0].sidecar_claims[0..1];
            try std.testing.expectError(error.InvalidExecutionSlotClaims, execution_receiver.verify(a, bogus_claims, execution.prepared, admitted.expected_key_id, admitted.statement, view.statement.seal, 1, view.receipts[1].witness_root, view.config));
            const native_proof = try Native.codec.decode(a, view.wire.execution[1].native_artifact, execution.prepared, execution.prepared.id);
            var capture = try Native.ForBackend(Cpu).verifyCaptureOwned(a, native_proof, execution.prepared, execution.prepared.id);
            defer capture.deinit();
            const statement = try v3.leaf(admitted.statement.job, &view.segments[1].base);
            try std.testing.expectEqualDeep(admitted.statement, statement);
            var prepared = try v3.prepare(a, execution.prepared, &capture, execution.prepared.id, 2, statement, view.statement.seal, view.receipts[1].witness_root, &view.receipts[1]);
            defer prepared.deinit();
            const Api = parent.ForBackend(Cpu);
            const key = try Api.deriveKeyWithProfile(a, &prepared, .diagnostic_q8_pow0);
            const admission = try parent.protocol.Admission.init(key, try key.identity());
            const plan = try Api.Plan.init(a, &prepared.rows, admission);
            defer plan.deinit();
            var proof = try plan.prove(a, &prepared.rows);
            defer proof.deinit();
            const bytes = try parent.codec.encode(a, &proof, &admission);
            defer a.free(bytes);
            _ = try linked.verifyLeafBytes(a, bytes, admission, admission.expected_id, statement, &execution.prepared.native.public_data, view.config, view.statement.seal, execution.prepared.id, view.receipts[1].native_roots, view.receipts[1].witness_root, &view.receipts[1]);
            std.debug.print("BLOCK_V4_ZERO_OPCODE verified=true segments=2 second_opcode=0 second_external={d} leaf_bytes={d}\n", .{ view.statement.execution_extension_active_counts[1], bytes.len });
        }
    };
    try fixture.withUnpaddedFixture(config, callback.verify);
}
