//! One synchronous adapter from independently verified native fragments to
//! concrete source views. Reuses the existing verified PCS capture; never runs
//! a second native verifier. All referenced native buffers expire at return.
const std = @import("std");
const Captured = @import("../sponge_cpu/captured_source.zig");
const Receiver = @import("../sponge_cpu/receiver.zig");
const Gkr = @import("../pure_p2_gkr_template.zig");
pub fn visit(a: std.mem.Allocator, value: Receiver.Verified, sink: Captured.Sink) !void {
    const ordinal: u32 = @intCast(value.ordinal);
    const manifest = value.manifest.digest;
    switch (value.source) {
        .cpu => |s| try Captured.cpu(a, s.value.setup, s.value.request, s.value.span, s.first, ordinal, s.value.key, manifest, value.main, s.encoded, value.capture, sink),
        .detached => |s| try Captured.detachedCaptured(a, s.value.key, s.value.geometry, ordinal, manifest, value.main, s.encoded, value.capture, sink),
        .catalog => |s| try Captured.classicTruth(a, s.value.key, s.value.truth, try s.value.key.expected(s.value.truth, ordinal), manifest, value.main, s.encoded, value.capture, sink),
        .local_catalog => |s| {
            const key = s.value.local_key orelse return error.OpRootLeafSourceAuthority;
            try Captured.truth(a, key, s.value.truth, try key.expected(s.value.truth, ordinal), manifest, value.main, s.encoded, value.capture, sink);
        },
        .miller => |s| try Captured.classicMiller(a, s.value.key, s.value.span, try s.value.key.expected(s.value.span, ordinal), manifest, value.main, s.encoded, value.capture, sink),
        .local_miller => |s| {
            const key = s.value.local_key orelse return error.OpRootLeafSourceAuthority;
            try Captured.localMiller(a, key, s.value.span, try key.expected(s.value.span, ordinal), manifest, value.main, s.encoded, value.capture, sink);
        },
    }
}
/// Only coefficient-vector lengths are transported. All instance dimensions,
/// masks, rounds and admitted degrees are derived afresh from the source key.
pub fn template(a: std.mem.Allocator, member: Captured.View) !?[]u8 {
    return switch (member) {
        .cpu => |s| blk: {
            var roster = try @import("../sponge_cpu/frame.zig").Roster.init(a, s.setup, s.request.sponge.calls, s.key.frontier_log, s.request.base.epoch, s.expected.ordinal);
            defer roster.deinit();
            break :blk try Gkr.fromProofFor(a, roster.instances, s.child);
        },
        .detached => |s| try Gkr.fromProofFor(a, &(try s.geometry.instances()), s.child),
        .truth => |s| blk: {
            const shapes = try @import("../truth_local_gkr/authority.zig").shapes(s.truth);
            const instances = @import("../truth_local_gkr/native.zig").instances(shapes);
            break :blk try Gkr.Truth.fromProof(a, &instances, s.local);
        },
        .local_miller => |s| try Gkr.fromProofFor(a, &(try (try s.key.geometry(s.span)).instances()), s.local),
        .classic_truth, .classic_miller => null,
    };
}
pub const Leaf = @import("../pure_p2_op_root_receiver.zig").Leaf;
/// Owned untrusted sidecar, to be admitted only after complete closure and
/// authenticated only by the final physical root. Caller frees claims.
pub fn metadata(a: std.mem.Allocator, member: Captured.View) !Leaf {
    const receipt: ?[36]u8 = switch (member) {
        .classic_truth, .classic_miller => null,
        inline else => |s| s.receipt,
    };
    const claims = switch (member) {
        .detached => |s| blk: {
            const flat = try a.alloc(@import("../full_p2_common.zig").O, 24);
            for (s.claims, 0..) |row, i| @memcpy(flat[3 * i ..][0..3], &row);
            break :blk flat;
        },
        inline else => |s| try a.dupe(@import("../full_p2_common.zig").O, s.claims[0..]),
    };
    return .{ .ordinal = member.ordinal(), .main = switch (member) {
        inline else => |s| s.main,
    }, .receipt = receipt, .claims = claims };
}
