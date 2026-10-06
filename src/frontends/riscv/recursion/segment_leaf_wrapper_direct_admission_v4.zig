//! Verifier-owned identity admission for a detached direct V3 leaf.
//!
//! This is a precondition of fresh STARK verification, not a publication.
//! The caller supplies the expected native ProgramV2 and Tree0 identities;
//! the verifier obtains the observed values from a freshly verified native
//! child and recomputes the wrapper Tree0 root from admitted source columns.
const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const roster = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const protocol = @import("segment_leaf_wrapper_protocol_direct_v4.zig");

pub const Digest = channel.Digest;

pub const ExpectedNative = struct {
    program_identity: Digest,
    tree0_root: Digest,

    pub fn validate(self: ExpectedNative) !void {
        try canonical(self.program_identity);
        try canonical(self.tree0_root);
    }
};

pub fn requireExpectedNative(expected: ExpectedNative, observed: ExpectedNative) !void {
    try expected.validate();
    try observed.validate();
    if (!std.meta.eql(expected, observed))
        return error.UnexpectedDirectNativeChild;
}

/// Constructed by the verifier after PlanV4 source validation and an
/// independent preprocessed-tree commitment. Never deserialize this record
/// from the detached artifact or use its fields as proof of child validity.
pub const IndependentBinding = struct {
    native: ExpectedNative,
    plan_seal: [32]u8,
    profile_id: Digest,
    wrapper_preprocessed_root: Digest,
    verification_key_id: Digest,

    pub fn fromVerifiedSources(
        plan: *const roster.Plan,
        expected_native: ExpectedNative,
        recomputed_wrapper_root: Digest,
    ) !IndependentBinding {
        try expected_native.validate();
        try canonical(recomputed_wrapper_root);
        try plan.validate();
        return .{
            .native = expected_native,
            .plan_seal = plan.seal,
            .profile_id = try protocol.protocolId(plan),
            .wrapper_preprocessed_root = recomputed_wrapper_root,
            .verification_key_id = try protocol.verificationKeyId(plan, recomputed_wrapper_root),
        };
    }
};

/// `observed_native` comes only from a fresh native verifier owner. Requiring
/// this comparison before reading an artifact prevents its metadata from
/// selecting the child identity, wrapper key, or wrapper Tree0 root.
pub fn admit(
    expected_native: ExpectedNative,
    observed_native: ExpectedNative,
    independent: IndependentBinding,
    artifact: anytype,
) !void {
    try requireExpectedNative(expected_native, observed_native);
    if (!std.meta.eql(expected_native, independent.native))
        return error.UnexpectedDirectNativeChild;
    if (!std.mem.eql(u8, &independent.plan_seal, &artifact.manifest_seal) or
        !std.meta.eql(independent.profile_id, artifact.profile_id))
        return error.UnexpectedDirectWrapperProfile;
    if (!std.meta.eql(independent.wrapper_preprocessed_root, artifact.preprocessed_root))
        return error.UnexpectedDirectWrapperRoot;
    if (!std.meta.eql(independent.verification_key_id, artifact.verification_key_id))
        return error.UnexpectedDirectWrapperKey;
}

fn canonical(value: Digest) !void {
    for (value) |word| if (word >= core.fields.m31.Modulus)
        return error.NonCanonicalDirectIdentity;
}

test "direct detached admission rejects artifact-selected native child root and key" {
    const expected = ExpectedNative{
        .program_identity = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .tree0_root = .{ 11, 12, 13, 14, 15, 16, 17, 18 },
    };
    const independent = IndependentBinding{
        .native = expected,
        .plan_seal = .{9} ** 32,
        .profile_id = .{ 21, 22, 23, 24, 25, 26, 27, 28 },
        .wrapper_preprocessed_root = .{ 31, 32, 33, 34, 35, 36, 37, 38 },
        .verification_key_id = .{ 41, 42, 43, 44, 45, 46, 47, 48 },
    };
    var artifact: struct {
        manifest_seal: [32]u8,
        profile_id: Digest,
        preprocessed_root: Digest,
        verification_key_id: Digest,
    } = .{
        .manifest_seal = independent.plan_seal,
        .profile_id = independent.profile_id,
        .preprocessed_root = independent.wrapper_preprocessed_root,
        .verification_key_id = independent.verification_key_id,
    };
    try admit(expected, expected, independent, &artifact);

    var changed = expected;
    changed.program_identity[0] += 1;
    try std.testing.expectError(error.UnexpectedDirectNativeChild, admit(expected, changed, independent, &artifact));
    changed = expected;
    changed.tree0_root[0] += 1;
    try std.testing.expectError(error.UnexpectedDirectNativeChild, admit(expected, changed, independent, &artifact));
    artifact.preprocessed_root[0] += 1;
    try std.testing.expectError(error.UnexpectedDirectWrapperRoot, admit(expected, expected, independent, &artifact));
    artifact.preprocessed_root = independent.wrapper_preprocessed_root;
    artifact.verification_key_id[0] += 1;
    try std.testing.expectError(error.UnexpectedDirectWrapperKey, admit(expected, expected, independent, &artifact));
    artifact.verification_key_id = independent.verification_key_id;
    artifact.manifest_seal[0] += 1;
    try std.testing.expectError(error.UnexpectedDirectWrapperProfile, admit(expected, expected, independent, &artifact));
    artifact.manifest_seal = independent.plan_seal;
    artifact.profile_id[0] += 1;
    try std.testing.expectError(error.UnexpectedDirectWrapperProfile, admit(expected, expected, independent, &artifact));
    changed = expected;
    changed.tree0_root[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalDirectIdentity, admit(expected, changed, independent, &artifact));
}
