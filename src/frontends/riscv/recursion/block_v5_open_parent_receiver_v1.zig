//! Fresh open v3 parent equation receiver. Independent native admissions select
//! the full child public tuples and exact PC/clock spans. Global closures are
//! required separately; no CompleteBlock or legacy forest authority is exposed.
const std = @import("std");
const core = @import("stwo_core");
const public = @import("block_v5_open_parent_public_bus_v1.zig");
const protocol = @import("block_v5_reusable_open_parent_protocol_v1.zig");
const leaf_protocol = @import("block_v5_reusable_native_parent_protocol_v1.zig");
const leaf_bus = @import("block_v5_recursive_public_bus_v1.zig");
const native_admission = @import("../prover/block_v5_native_recursive_admission_v3.zig");
const native_proof = @import("../prover/block_v5_native_execution_proof_v3.zig");
const parent = @import("blake3_execution_parent_proof.zig");
const spans = @import("block_v5_pc_clock_span_v1.zig");
pub const ExpectedChild = struct {
    native: *const native_admission.Prepared,
    exported: native_proof.OpenReceipt,
    recursive_key: leaf_protocol.Key,
    recursive_key_id: [32]u8,
    recursive_schedule: []const leaf_bus.Wire,
    pub fn publicChild(self: ExpectedChild, a: std.mem.Allocator) !public.Child {
        const values = try leaf_bus.Values.fromNative(a, self.native, self.exported);
        const child = public.Child{
            .admission = try leaf_protocol.Admission.init(self.recursive_key, self.recursive_key_id, self.recursive_schedule, values),
            .span = try spans.leaf(self.native.pin, self.native.shape, self.native.sealed.digest, self.native.sealed.execution_instance_count),
        };
        try child.validate();
        return child;
    }
};
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    pc_clock_span: spans.Span,
    /// Still open: this includes ordinary component claims and PC compensation.
    /// It must be partitioned/fresh-closed with program/memory/lookup/precompile
    /// providers before final block authority, never asserted zero here.
    combined_native_open_sum: core.fields.qm31.QM31,
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: protocol.Key, expected_key_id: [32]u8, schedule: []const public.Wire, expected: []const ExpectedChild) !OpenEquation {
    if (expected.len != 2 and expected.len != 4) return error.InvalidV5PcClockFanIn;
    var children: [4]public.Child = undefined;
    var open = core.fields.qm31.QM31.zero();
    for (expected, children[0..expected.len]) |policy, *child| {
        child.* = try policy.publicChild(a);
        open = open.add(policy.exported.open_sum);
    }
    const values = public.Values{ .children = children[0..expected.len] };
    const authority = try protocol.Admission.init(key, expected_key_id, schedule, values);
    var owned = try parent.codec.decode(a, bytes, &authority);
    var equation = try parent.verify(&owned, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, expected_key_id);
    return .{ .equation = equation, .pc_clock_span = try values.outputSpan(), .combined_native_open_sum = open };
}
