const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("block_memory_core_sha_fixture_test.zig");
const batch = @import("block_memory_batch_verify_v2.zig");

test "Ethereum SHA Keccak caller accesses close with opcode and sorted memory core" {
    const use = struct {
        fn accept(a: std.mem.Allocator, view: fixture.FixtureView) !void {
            try std.testing.expectEqual(@as(u64, 108), view.verified.event_count);
            try std.testing.expect(view.statement.seal.extension_rosters_bound);
            const pins = [_]batch.EthereumShaExecutionPin(Cpu){view.execution_pin};
            var missing = view.wire;
            missing.execution_extensions = &.{};
            try std.testing.expectError(error.InvalidExecutionExtensionProofCensus, batch.verifyCoreOwnedWithExtension(Cpu, a, view.statement, missing, &pins, view.public_initial, view.config));
            var extra = view.wire;
            const duplicated = [_]@import("block_memory_batch_wire_v3.zig").SerializedExternalProof{
                view.wire.execution_extensions[0], view.wire.execution_extensions[0],
            };
            extra.execution_extensions = &duplicated;
            try std.testing.expectError(error.InvalidExecutionExtensionProofCensus, batch.verifyCoreOwnedWithExtension(Cpu, a, view.statement, extra, &pins, view.public_initial, view.config));
            var wrong_index = view.wire;
            const reindexed = [_]@import("block_memory_batch_wire_v3.zig").SerializedExternalProof{.{
                .instance_index = 1,
                .stark_bytes = view.wire.execution_extensions[0].stark_bytes,
                .claims = view.wire.execution_extensions[0].claims,
            }};
            wrong_index.execution_extensions = &reindexed;
            try std.testing.expectError(error.InvalidExecutionExtensionProofOrder, batch.verifyCoreOwnedWithExtension(Cpu, a, view.statement, wrong_index, &pins, view.public_initial, view.config));
            var wrong_statement = view.statement;
            const wrong_counts = [_]u64{102};
            wrong_statement.execution_extension_active_counts = &wrong_counts;
            try std.testing.expectError(error.UnsealedExecutionExtensionRangeRoster, batch.verifyCoreOwnedWithExtension(Cpu, a, wrong_statement, view.wire, &pins, view.public_initial, view.config));
        }
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    try fixture.withExtendedCoreFixture(config, use.accept);
}
