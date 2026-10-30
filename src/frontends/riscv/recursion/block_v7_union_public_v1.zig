//! Exact public operands for one joined original verifier. Values alone confer
//! no proof authority. Parent verification must close their complete wire sum
//! and independently check the original execution/global public statement.
const std = @import("std");
const core = @import("stwo_core");
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Transcript = @import("air/block_v7_union_transcript_v1.zig");
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const P = struct {
    pub const Admission = struct {
        pub const Prepared = Profile.Owned;
    };
    pub const Statement = struct {
        pub const PUBLIC_CIRCUIT = Transcript.PUBLIC_CIRCUIT;
        pub const Statement = Frames.Statement;
    };
    pub const IDENTITY_TAG: u32 = 0x42375549;
    pub const SCHEDULE_TAG: u32 = 0x42375553;
    pub fn rootWordOffset(frame: *const Frames.Statement, roots: usize, tree: usize) !u32 {
        const words = try std.math.mul(usize, roots, 8);
        if (tree >= roots or words > frame.words.len) return error.InvalidUnionPublicRoots;
        return std.math.cast(u32, frame.words.len - words + 8 * tree) orelse error.InvalidUnionPublicRoots;
    }
};
pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamilyWithBoundedRoots(P);
pub const Wire = API.Wire;
pub const Values = API.Values;
pub const supply = API.supply;
pub const scheduleDigest = API.scheduleDigest;
pub fn reconstruct(a: std.mem.Allocator, profile: *const Profile.Owned, claims: *const Multi.Claims) !Values {
    try profile.validateAgainst(claims);
    var frame = try Transcript.statement(a, profile, claims);
    errdefer frame.deinit();
    var components = try Multi.AdmittedComponents.init(a, profile.statement.trusted, profile.statement.input, claims, profile.limits.original);
    defer components.deinit();
    const public = try @import("air/block_v7_union_composition_v1.zig").publicValues(a, profile, &components, claims);
    errdefer a.free(public);
    const values = Values{ .allocator = a, .template = profile.seal, .statement = frame, .public = public, .roots_count = try Transcript.firstInteraction(profile) };
    try values.validate();
    return values;
}
pub fn collect(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, composition: *const @import("air/blake3_execution_composition.zig").Prepared, transcript: *const @import("air/blake3_native_transcript.zig").Planned, values: Values, max_wires: usize) ![]Wire {
    try values.validate();
    if (!std.meta.eql(values.template, profile.seal) or values.roots_count != try Transcript.firstInteraction(profile) or capture.proof.commitments.len != profile.trace_count + 1 or capture.proof.trace_paths.len != capture.proof.commitments.len) return error.InvalidUnionPublicRoots;
    const reads = try a.alloc(u32, values.roots_count);
    defer a.free(reads);
    for (reads, 0..) |*count, tree| {
        const offset = try P.rootWordOffset(&values.statement, values.roots_count, tree);
        if (!std.meta.eql(try values.statement.digest(offset), capture.proof.commitments[tree])) return error.UntrustedUnionFirstRoot;
        count.* = std.math.cast(u32, capture.proof.trace_paths[tree].positions.len) orelse return error.InvalidUnionPublicRoots;
    }
    for (composition.sources, composition.inputs) |source, value| if (source == .public_input) {
        if (source.public_input >= values.public.len or !value.eql(values.public[source.public_input])) return error.UntrustedUnionPublicOperand;
    };
    return API.collectFixedSchedulePerTree(a, &transcript.plan, composition, values.statement.words.len, values.public.len, reads, max_wires);
}
