//! Independent native-batch public policy reconstruction for recursive parents.
//! Original native policies and exported receipts are verifier-owned inputs;
//! the resulting normalized frame object alone does not prove anything.
const std = @import("std");
const prep = @import("block_v6_native_batch_prepare_v1.zig");
const bus = @import("block_v6_native_batch_public_v1.zig");
const protocol = @import("block_v6_native_batch_protocol_v1.zig");
const frames = @import("block_v5_open_child_frames_v2.zig");
pub const Receipt = @import("../prover/block_v5_native_execution_proof_v3.zig").OpenReceipt;

pub const Expected = struct {
    native: []const *const prep.NativeAdmission,
    exported: []const Receipt,
    key: protocol.Key,
    expected_id: [32]u8,
    schedule: []const bus.Wire,

    pub fn reconstruct(self: Expected, a: std.mem.Allocator) !frames.Child {
        if (self.native.len == 0 or self.native.len > bus.MAX_CHILDREN or self.native.len != self.exported.len or self.native.len != self.key.child_count)
            return error.InvalidNativeBatchReceiverPolicy;
        const children = try a.alloc(bus.Child, self.native.len);
        defer a.free(children);
        for (self.native, self.exported, children) |admitted, receipt, *child| {
            if (!std.meta.eql(admitted.config, self.key.config) or !std.meta.eql(admitted.config, self.key.context.child_config))
                return error.NativeBatchSecurityMismatch;
            child.* = try prep.publicChild(a, admitted, receipt);
        }
        const policy = try protocol.Admission.init(self.key, self.expected_id, self.schedule, .{ .children = children });
        return frames.fromNativeBatchV6(a, policy);
    }
};
