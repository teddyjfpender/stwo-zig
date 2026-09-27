//! Original compiler-owned provider masks, including its admitted override.
const std = @import("std");
const core = @import("stwo_core");
pub fn prepare(a: std.mem.Allocator, admitted: *const @import("../../prover/block_v5_program_table_recursive_admission_v1.zig").Prepared, capture: *const @import("../../prover/block_v5_program_table_recursive_capture_v1.zig").VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const Native = @import("../../prover/block_v5_program_table_proof_v1.zig");
    var definition = try Native.Air.build(a);
    defer definition.deinit();
    const relation_plan = try @import("universal_relation_binding.zig").Binding(Native.Air).authenticate(&definition);
    const manifest = Native.Roster.Manifest{ .log_sizes = .{admitted.plan.log_size} };
    const component = try Native.Roster.Component(Native.Air).init(&definition, relation_plan, &manifest, .program, admitted.plan.log_size, .{}, &capture.relations, capture.receipt.claim);
    const handle = try @import("block_v5_program_table_composition_v1.zig").verifier(&component);
    return @import("blake3_execution_deep.zig").prepareComponents(a, core.air.components.Components{ .components = &.{handle}, .n_preprocessed_columns = 6 }, admitted.logs, admitted.config, &capture.proof);
}
