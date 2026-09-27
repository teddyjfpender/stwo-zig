//! Fresh reusable native-equation receiver. This exports open relation terms;
//! only independently fresh global ROM/memory/lookup closures can authorize a
//! block. It never accepts a CPU-verified receipt as the recursive equation.
const std = @import("std");
const core = @import("stwo_core");
const bus = @import("block_v5_recursive_public_bus_v1.zig");
const protocol = @import("block_v5_reusable_native_parent_protocol_v1.zig");
const native = @import("../prover/block_v5_native_execution_proof_v1.zig");
const admitted_mod = @import("../prover/block_v5_native_recursive_admission_v1.zig");
const parent = @import("blake3_execution_parent_proof.zig");
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    public_values: bus.Values,
    /// Open intermediate PC/clock assertion; no perleaf register custody.
    pc_clock_span: ?@import("block_v5_pc_clock_span_v1.zig").Span = null,
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
/// All tuple values are reconstructed from independently admitted native public
/// data, B5SS entries and exported claim. Proof bytes provide no setup selection.
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: protocol.Key, expected_key_id: [32]u8, schedule: []const bus.Wire, admitted: anytype, expected_open: anytype) !OpenEquation {
    if (!std.meta.eql(key.config, admitted.config) or
        !std.meta.eql(key.context.child_config, admitted.config)) return error.NativeV5RecursiveSecurityMismatch;
    const values = try bus.Values.fromNative(a, admitted, expected_open);
    const authority = try protocol.Admission.init(key, expected_key_id, schedule, values);
    var owned = try parent.codec.decode(a, bytes, &authority);
    var equation = try parent.verify(&owned, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, expected_key_id);
    const span = if (comptime @TypeOf(admitted.pin) == @import("../prover/block_v5_native_public_admission_v1.zig").Admission)
        try @import("block_v5_pc_clock_span_v1.zig").leaf(admitted.pin, admitted.shape, admitted.sealed.digest, admitted.sealed.execution_instance_count)
    else
        null;
    return .{ .equation = equation, .public_values = values, .pc_clock_span = span };
}
