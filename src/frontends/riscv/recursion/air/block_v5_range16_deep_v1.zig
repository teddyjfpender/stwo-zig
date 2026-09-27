//! Actual range provider mask geometry, not received proof-selected masks.
const std = @import("std");
const core = @import("stwo_core");
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const Spec = @import("../../prover/block_v5_range16_component_v1.zig").Spec;
    const Adapter = @import("../../prover/block_v5_word_quotient_adapter_v1.zig").For(Spec);
    const component = Adapter{ .log_size = @import("../../prover/block_v5_range16_v1.zig").TABLE_LOG, .spec = .{ .claim = capture.receipt.claim, .challenges = &capture.challenges } };
    return @import("blake3_execution_deep.zig").prepareComponents(a, core.air.components.Components{ .components = &.{component.asVerifierComponent()}, .n_preprocessed_columns = 1 }, admitted.logs, admitted.config, &capture.proof);
}
