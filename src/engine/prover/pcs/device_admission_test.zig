//! Header admission only: actual PCS scheme, no device pointer dereference.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("stwo_prover_api");
const D = api.device_pcs;
const host = @import("commitment_tree.zig").HostMerkleBackend;
const Scheme = @import("scheme_family.zig").ForField(D.O).CommitmentSchemeProver(host, D.H, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel);

test "admission actual PCS replay keeps owned validation distinct from same-tag scheme refusal" {
    const a = std.testing.allocator;
    var scheme = try Scheme.init(a, .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 3) });
    defer scheme.deinit(a);
    var original = [_]D.Column{.{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 1 } }};
    var replay = original;
    replay[0].device.?.words = @ptrFromInt(8192);
    replay[0].device.?.generation = 2;
    const root: D.H.Hash = @splat(1);
    var tree = D.Tree{ .root = root, .columns = &replay };
    var detail: ?api.error_codes.DeviceFailure = null;
    // Same tag before entering the API validator is an Engine-owned refusal.
    try std.testing.expectError(error.DeviceMainReplayNotAdmitted, scheme.refreshDeviceOm31MainDiagnosed(tree, &detail));
    try std.testing.expect(detail == null);
    scheme.device_om31_trace_trees[1] = .{ .root = root, .columns = &original };
    tree.root[0] ^= 1;
    try std.testing.expectError(error.DeviceMainReplayRootMismatch, scheme.refreshDeviceOm31MainDiagnosed(tree, &detail));
    try std.testing.expectEqual(@as(u16, 0x3503), detail.?.entry.code);
    tree.root = root;
    replay[0].device = null;
    try std.testing.expectError(error.DeviceTraceHostColumn, scheme.refreshDeviceOm31MainDiagnosed(tree, &detail));
    try std.testing.expectEqual(@as(u16, 0x3504), detail.?.entry.code);
    replay = original;
    original[0].device = null;
    try std.testing.expectError(error.DeviceMainReplayNotAdmitted, scheme.refreshDeviceOm31MainDiagnosed(tree, &detail));
    try std.testing.expectEqual(@as(u16, 0x3505), detail.?.entry.code);
    scheme.device_om31_trace_trees[1] = null;
    try std.testing.expectError(error.DeviceMainReplayNotAdmitted, scheme.refreshDeviceOm31MainDiagnosed(tree, &detail));
    try std.testing.expect(detail == null);
    scheme.device_om31_trace_trees[1] = .{ .root = root, .columns = &original };
    original = replay;
    replay[0].log_size = 4;
    try std.testing.expectError(error.InvalidDeviceTraceTree, scheme.refreshDeviceOm31MainDiagnosed(tree, &detail));
    try std.testing.expectEqual(@as(u16, 0x3506), detail.?.entry.code);
    replay = original;
    replay[0].device.?.generation = 2;
    try scheme.refreshDeviceOm31MainDiagnosed(tree, &detail);
    try std.testing.expect(detail == null);
    try std.testing.expectEqualSlices(u8, &root, &scheme.device_om31_trace_trees[1].?.root);
}
