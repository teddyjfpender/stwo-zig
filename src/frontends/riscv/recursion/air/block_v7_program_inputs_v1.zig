//! Canonical joint composition operands from admitted metadata and physical
//! claims. This is not a verifier-success receipt; the graph proves equations.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Profile = @import("../block_v7_program_fixed_profile_v1.zig");
pub fn publicInputs(a: std.mem.Allocator, profile: *const Profile.Owned) ![]Q {
    return a.dupe(Q, &.{profile.input.claim});
}

pub const challenges = @import("block_v7_memory_joint_inputs_v1.zig").challenges;
pub fn composition(a: std.mem.Allocator, profile: *const Profile.Owned, compiled: *const @import("block_v7_program_composition_v1.zig").Compiled, captured: *const core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher)) ![]Q {
    if (captured.sampled_values.len != try profile.sampleCount() or compiled.sources.len != compiled.circuit.input_count) return error.InvalidProgramInputs;
    const public = try publicInputs(a, profile);
    defer a.free(public);
    const draws = try challenges(a, profile.input.policy.epoch);
    const out = try a.alloc(Q, compiled.sources.len);
    errdefer a.free(out);
    for (compiled.sources, out) |source, *value| value.* = switch (source) {
        .sample => |i| if (i < captured.sampled_values.len) captured.sampled_values[i] else return error.InvalidProgramInputs,
        .public_input => |i| if (i < public.len) public[i] else return error.InvalidProgramInputs,
        .challenge => |i| if (i < draws.len) draws[i] else return error.InvalidProgramInputs,
        .composition => captured.composition_randomness,
        .oods => captured.oods_seed,
        else => return error.InvalidProgramInputs,
    };
    return out;
}
