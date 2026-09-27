//! Independent nested open-equation receiver. Known native/v1/v2 public policy
//! reconstructs all child transcript cells and supplies; proof bytes cannot
//! select a child setup, tuple or span. No complete-block authority is returned.
const std = @import("std");
const core = @import("stwo_core");
const normalized = @import("block_v5_open_child_frames_v2.zig");
const bus = @import("block_v5_open_parent_public_bus_v2.zig");
const protocol = @import("block_v5_reusable_open_parent_protocol_v2.zig");
const parent = @import("blake3_execution_parent_proof.zig");
const span_mod = @import("block_v5_pc_clock_span_v1.zig");
pub const Expected = union(enum) {
    native: @import("block_v5_open_parent_receiver_v1.zig").ExpectedChild,
    open_v1: @import("block_v5_reusable_open_parent_protocol_v1.zig").Admission,
    open_v2: protocol.Admission,
    pub fn reconstruct(self: Expected, a: std.mem.Allocator) !normalized.Child {
        return switch (self) {
            .native => |value| normalized.fromNative(a, value.native, value.exported, value.recursive_key, value.recursive_key_id, value.recursive_schedule),
            .open_v1 => |value| normalized.fromOpenV1(a, value),
            .open_v2 => |value| normalized.fromOpenV2(a, value),
        };
    }
};
pub const OuterPins = struct {
    job_id: [32]u8,
    source_image_digest: [32]u8,
    sealed_digest: [32]u8,
    segment_count: u32,
    first_cycle: u64,
    last_cycle: u64,
    initial_pc: u32,
    final_pc: u32,
    pub fn require(self: OuterPins, span: span_mod.Span) !void {
        if (!std.meta.eql(self.job_id, span.job_id) or !std.meta.eql(self.source_image_digest, span.source_image_digest) or
            !std.meta.eql(self.sealed_digest, span.sealed_digest) or self.segment_count != span.segment_count or
            span.first_index != 0 or span.job_segment_count != self.segment_count or self.first_cycle != span.first_cycle or
            self.last_cycle != span.last_cycle or self.initial_pc != span.initial_pc or self.final_pc != span.final_pc)
            return error.UntrustedV5ExactOuterStatement;
    }
};
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    span: span_mod.Span,
    native_open_sum: core.fields.qm31.QM31,
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: protocol.Key, expected_key_id: [32]u8, schedule: []const bus.Wire, purpose: bus.Purpose, expected: []const Expected, outer: ?OuterPins) !OpenEquation {
    if (expected.len == 0 or expected.len > 32 or (purpose == .exact_outer) != (outer != null)) return error.InvalidV5NestedReceiverPolicy;
    var children: [32]normalized.Child = undefined;
    var initialized: usize = 0;
    defer for (children[0..initialized]) |*child| child.deinit();
    var open = core.fields.qm31.QM31.zero();
    for (expected, 0..) |policy, i| {
        children[i] = try policy.reconstruct(a);
        initialized += 1;
        open = open.add(children[i].native_open_sum);
    }
    const values = bus.Values{ .purpose = purpose, .children = children[0..initialized] };
    const span = try values.outputSpan();
    if (outer) |pins| try pins.require(span);
    const admission = try protocol.Admission.init(key, expected_key_id, schedule, values);
    var owned = try parent.codec.decode(a, bytes, &admission);
    var equation = try parent.verify(&owned, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, expected_key_id);
    return .{ .equation = equation, .span = span, .native_open_sum = open };
}
