//! Dynamic original native operands for the independently compiled graph.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("../block_v7_native_fixed_profile_v1.zig");
const Native = @import("../../prover/block_v7_native_proof_v1.zig");
const C = @import("block_v7_native_composition_v1.zig");
pub fn composition(a: std.mem.Allocator, profile: *const Profile.Owned, compiled: *const C.Compiled, captured: *const Native.VerifiedCapture) ![]core.fields.qm31.QM31 {
    if (captured.proof.sampled_values.len != try profile.sampleCount() or compiled.sources.len != compiled.circuit.input_count) return error.InvalidNativeCompositionInputs;
    const public = try C.publicInputs(a, profile, captured.claims, captured.memory_claims);
    defer a.free(public);
    const draws = try @import("block_v7_memory_joint_inputs_v1.zig").challenges(a, profile.epoch);
    const out = try a.alloc(core.fields.qm31.QM31, compiled.sources.len);
    errdefer a.free(out);
    for (compiled.sources, out) |source, *value| value.* = switch (source) {
        .sample => |i| if (i < captured.proof.sampled_values.len) captured.proof.sampled_values[i] else return error.InvalidNativeCompositionInputs,
        .public_input => |i| if (i < public.len) public[i] else return error.InvalidNativeCompositionInputs,
        .challenge => |i| if (i < draws.len) draws[i] else return error.InvalidNativeCompositionInputs,
        .composition => captured.proof.composition_randomness,
        .oods => captured.proof.oods_seed,
        else => return error.InvalidNativeCompositionInputs,
    };
    return out;
}
