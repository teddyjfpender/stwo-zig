//! Actual original B5IN2 classifier masks, selected by independent source geometry.
const std = @import("std");
const core = @import("stwo_core");
pub fn prepare(a: std.mem.Allocator, admitted: *const @import("../../prover/block_v5_native_readonly_source_recursive_admission_v2.zig").Prepared, capture: *const @import("../../prover/block_v5_native_readonly_source_recursive_capture_v2.zig").VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const Spec = @import("../../prover/block_v5_readonly_input_component_v1.zig").Spec;
    const Adapter = @import("../../prover/block_v5_word_quotient_adapter_v1.zig").For(Spec);
    const challenges = try @import("../../prover/block_v5_readonly_input_global_protocol_v2.zig").forGroup(capture.challenges, admitted.pin.group_id);
    const component = Adapter{ .log_size = admitted.pin.classifier.row_log, .spec = .{ .claim = capture.receipt.claim, .challenges = &challenges } };
    return @import("blake3_execution_deep.zig").prepareComponents(a, core.air.components.Components{ .components = &.{component.asVerifierComponent()}, .n_preprocessed_columns = 1 }, admitted.logs, admitted.config, &capture.proof);
}
