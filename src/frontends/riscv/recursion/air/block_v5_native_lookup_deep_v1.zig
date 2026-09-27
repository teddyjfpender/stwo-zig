//! Original six mixed-size component masks, offsets, lifting and PCS DEEP.
const std = @import("std");
const core = @import("stwo_core");
pub fn prepare(a: std.mem.Allocator, admitted: *const @import("../../prover/block_v5_native_lookup_recursive_admission_v1.zig").Prepared, capture: *const @import("../../prover/block_v5_native_lookup_recursive_capture_v1.zig").VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    try capture.validate(admitted, expected);
    const relations = try @import("universal_provider_relations.zig").SharedProviderRelations.init(&capture.relations);
    const owner = try @import("../../prover/block_v5_native_lookup_assembly_v1.zig").Owner.init(a, relations, capture.receipt.claims);
    defer owner.destroy(a);
    const handles = owner.verifierHandles();
    return @import("blake3_execution_deep.zig").prepareComponents(a, core.air.components.Components{ .components = &handles, .n_preprocessed_columns = admitted.logs[0].len }, admitted.logs, admitted.config, &capture.proof);
}
