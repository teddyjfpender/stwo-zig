//! All original nineteen component masks, actual DEEP/FRI geometry.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_arithmetic_recursive_capture_v1.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const owner = try Admission.Profile.Assembly(.verifier).createBlockV5Standalone(a, &admitted.statement, admitted.total_steps, &capture.original.relations, &capture.original.claims);
    defer owner.destroy(a);
    return @import("blake3_execution_deep.zig").prepareComponents(a, .{ .components = owner.active(), .n_preprocessed_columns = admitted.logs[0].len }, admitted.logs, admitted.config, &capture.proof);
}
