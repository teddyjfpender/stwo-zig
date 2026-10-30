const std = @import("std");
const core = @import("stwo_core");
const Scope = @import("../../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Original = @import("../../prover/block_v8_endpoint_global_bridge_proof_v1.zig");
const Bridge = @import("../block_v8_endpoint_bridge_recursive_v1.zig");
const Observer = struct {
    pub fn observeBridge(a: std.mem.Allocator, scope: *const Scope.Owned, original: *const Original.Proof) !void {
        if (scope.batch_start != 0 or scope.sources.len != scope.roster_count) return error.ExpectedCompleteBridgeFixture;
        const trusted = Bridge.Statement.Trusted{ .block_statement = scope.epoch.statement, .config = scope.epoch.config };
        const input = Bridge.Statement.Input{ .sources = scope.sources, .global_memory = scope.entries[scope.entries.len - 1], .batch_first = 0, .batch_count = @intCast(scope.sources.len) };
        const metadata = try Bridge.Statement.Owned.init(a, trusted, input);
        defer metadata.deinit();
        const selected: @import("../blake3_execution_parent_protocol.zig").Profile = if (trusted.config.fri_config.n_queries == 70) .csp_q70_pow26 else .diagnostic_q8_pow0;
        var root = blk: {
            const profile = try Bridge.Profile.Owned.derive(a, metadata, original.claims, .{});
            defer profile.deinit();
            var captured = try Original.verifyConditionalAndCapture(a, metadata.scope, &original.stark, original.claims, .{});
            defer captured.deinit();
            var witness = try Bridge.Composition.prepare(a, profile, &captured);
            defer witness.deinit();
            var transcript = try Bridge.Transcript.replay(a, profile, &captured, 4);
            defer transcript.deinit();
            var cold = try Bridge.Transcript.fixed(a, profile, 4, .{});
            defer cold.deinit();
            try std.testing.expectEqualDeep(cold.id, transcript.plan.id);
            const public = try Bridge.Composition.publicValues(a, profile);
            defer a.free(public);
            try std.testing.expectEqual(scope.sources.len + 1, public.len);
            break :blk try Bridge.Pipeline.produce(a, profile, &captured, .{ .profile = selected });
        };
        defer root.deinit();
        const fresh = try Bridge.Statement.Owned.init(a, trusted, input);
        defer fresh.deinit();
        var verified = try Bridge.Pipeline.verify(a, root.bytes, root.claims, fresh, .{}, .{ .profile = selected });
        defer verified.deinit();
        var expected = core.fields.qm31.QM31.zero();
        for (original.claims) |claim| expected = expected.add(claim);
        try std.testing.expect(verified.summary.transition.eql(expected));
        try std.testing.expectEqual(.conditional_endpoint_root_rebinding, verified.summary.scope);
        std.debug.print("B8_BRIDGE_RECURSION queries={d} pow={d} sources={d} bytes={d} proof_ns={d} same_endpoint_roots=true fresh_key=true global_ram=conditional\n", .{ trusted.config.fri_config.n_queries, trusted.config.pow_bits, scope.sources.len, root.bytes.len, root.stats.proof_ns });
    }
};
test "diagnostic late bridge actual recursive proof authenticates root rebinding and aggregate" {
    try @import("../../prover/tests/block_v8_endpoint_local_proof_test.zig").qualifyWithObserver(@import("../blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(), Observer);
}
test "canonical late bridge actual recursive proof authenticates root rebinding and aggregate" {
    try @import("../../prover/tests/block_v8_endpoint_local_proof_test.zig").qualifyWithObserver(@import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(), Observer);
}
