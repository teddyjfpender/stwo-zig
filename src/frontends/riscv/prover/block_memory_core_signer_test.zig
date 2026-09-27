//! Real signer and Keccak caller rows close against sorted memory in one
//! freshly verified block-v4 core, not merely against an isolated sidecar.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("block_memory_core_sha_fixture_test.zig");
const external = @import("block_execution_external_trace_v2.zig");
const batch = @import("block_memory_batch_verify_v2.zig");

test "Ethereum signer Keccak caller accesses close with opcode and sorted memory core" {
    const use = struct {
        fn accept(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            try std.testing.expectEqual(@as(u64, 94), try external.expectedEventCount(&view.owner.statement));
            try std.testing.expectEqual(@as(usize, 1), view.wire.execution_extensions.len);
            try std.testing.expectEqual(@as(usize, 94), view.wire.execution_extensions[0].claims.len);
            try std.testing.expectEqual(view.execution_receipt.event_count + 94, view.verified.event_count);
            try std.testing.expect(view.statement.seal.extension_rosters_bound);
            const pins = [_]batch.EthereumShaExecutionPin(Cpu){view.execution_pin};
            var missing = view.wire;
            missing.execution_extensions = &.{};
            try std.testing.expectError(error.InvalidExecutionExtensionProofCensus,
                batch.verifyCoreOwnedWithExtension(Cpu, a, view.statement, missing, &pins, view.public_initial, view.config));
            std.debug.print("BLOCK_V4_SIGNER_CORE verified=true events={d} external=94 opcode={d}\n",
                .{ view.verified.event_count, view.execution_receipt.event_count });
        }
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    try fixture.withSignerCoreFixture(config, use.accept);
}
