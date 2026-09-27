//! Actual physical lane mask geometry, not received proof-selected masks.
const std = @import("std");
const core = @import("stwo_core");
pub fn prepare(a: std.mem.Allocator, admitted: *const @import("../../prover/block_v5_ram_lanes_recursive_admission_v1.zig").Prepared, capture: *const @import("../../prover/block_v5_ram_lanes_recursive_capture_v1.zig").VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const Spec = @import("../../prover/block_v5_ram_lanes_component_v1.zig").Spec;
    const Adapter = @import("../../prover/block_v5_word_quotient_adapter_v1.zig").For(Spec);
    const component = Adapter{ .log_size = admitted.pin.claim.row_log, .spec = .{ .claim = admitted.pin.claim, .interaction_claim = capture.receipt.sums, .challenges = &capture.challenges } };
    return @import("blake3_execution_deep.zig").prepareComponents(a, core.air.components.Components{ .components = &.{component.asVerifierComponent()}, .n_preprocessed_columns = Spec.FIXED_COUNT }, admitted.logs, admitted.config, &capture.proof);
}
