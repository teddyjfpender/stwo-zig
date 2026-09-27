const std = @import("std");
const core = @import("stwo_core");
const admission = @import("../../prover/block_v5_native_recursive_admission_v3.zig");
const capture_mod = @import("../../prover/block_v5_native_execution_proof_v3.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const admission.Prepared, capture: *const capture_mod.VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const joined = try @import("../../prover/block_v5_native_components_v3.zig").Owner.initWithExternalForProfile(
        a,
        admitted.shape,
        capture.native_claims,
        capture.relations,
        admitted.pin,
        admitted.template.external_retirements,
        admitted.template.execution_profile,
    );
    defer joined.deinit();
    return @import("blake3_execution_deep.zig").prepareComponents(a, core.air.components.Components{ .components = joined.verifying.components.active(), .n_preprocessed_columns = admitted.logs[0].len }, admitted.logs, admitted.config, &capture.proof);
}
