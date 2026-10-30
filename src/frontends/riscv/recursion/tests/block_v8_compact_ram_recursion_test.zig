const std = @import("std");
const core = @import("stwo_core");
const Global = @import("../block_v8_compact_ram_recursive_v1.zig");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Observer = struct {
    pub fn observeCompactGlobal(a: std.mem.Allocator, policy: Global.Original.Policy, epoch: E.Epoch, entries: []const E.Entry, original: *const Global.Original.Proof) !void {
        std.debug.print("COMPACT_RECURSION stage=metadata\n", .{});
        const metadata = try Global.Statement.Owned.init(a, .{ .config = policy.config, .policy = policy }, .{ .epoch = epoch, .entries = entries, .roots = original.roots });
        defer metadata.deinit();
        var root = blk: {
            std.debug.print("COMPACT_RECURSION stage=profile\n", .{});
            const profile = try Global.Profile.Owned.derive(a, metadata, original.claims, .{});
            defer profile.deinit();
            std.debug.print("COMPACT_RECURSION stage=capture\n", .{});
            var capture = try Global.Original.verifyAndCaptureConditional(a, policy, epoch, entries, original, .{});
            defer capture.deinit();
            std.debug.print("COMPACT_RECURSION stage=composition\n", .{});
            var witness = try Global.Composition.prepare(a, profile, &capture);
            defer witness.deinit();
            std.debug.print("COMPACT_RECURSION stage=transcript\n", .{});
            var replay = try Global.Transcript.replay(a, profile, &capture, 4);
            defer replay.deinit();
            var fixed = try Global.Transcript.fixed(a, profile, 4, .{});
            defer fixed.deinit();
            try std.testing.expectEqualDeep(fixed.id, replay.plan.id);
            break :blk try Global.Pipeline.produce(a, profile, &capture, .{});
        };
        defer root.deinit();
        var verified = try Global.Pipeline.verify(a, root.bytes, root.claims, metadata, .{}, .{});
        defer verified.deinit();
        try std.testing.expect(verified.summary.transition.eql(original.claims.ram[0]));
        std.debug.print("B8_COMPACT_GLOBAL_RECURSION queries=70 pow=26 bytes={d} proof_ns={d} snapshot_public_ports=0 fresh_key=true\n", .{ root.bytes.len, root.stats.proof_ns });
    }
};
test "canonical compact global actual recursive proof closes separately anchored boundaries and ranges" {
    try @import("../../prover/tests/block_v8_endpoint_local_execution_test.zig").qualifyWithObserver(true, Observer);
}
