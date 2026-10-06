//! Narrow adapter gate; the fixture is field-canonical but not a child proof.
const std = @import("std");
const core = @import("stwo_core");
const subject = @import("recursion/air/segment_leaf_wrapper_field_manifest_v3.zig");
const field = @import("recursion/segment_leaf_wrapper_field_witness_v3.zig");
const program_authority = @import("recursion/transcript_program_v2_field_authority_v1.zig");
const provider_authority = @import("recursion/segment_outer_shared_provider_field_authority_v1.zig");
const word_witness = @import("recursion/transcript_program_v2_field_word_witness_v1.zig");
const hash_witness = @import("recursion/segment_leaf_wrapper_field_hash_witness_v3.zig");
const channel = @import("recursion/poseidon2_channel.zig");
const word_air = @import("recursion/air/transcript_program_v2_field_source_v1.zig");
const hash_air = @import("recursion/air/vm_public_claim_hash.zig");
const hash_relation = @import("recursion/air/vm_public_claim_hash_relation.zig");
const universal = @import("recursion/air/universal_challenges.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

test "V3 field extension binds four typed adapters and refuses publication" {
    const a = std.testing.allocator;
    const values = [_]M31{ M31.one(), M31.fromCanonical(17), M31.fromCanonical(65535) };
    var native = try fixtureNative(a, &values);
    defer native.deinit();
    var provider = try fixtureProvider(a, &values);
    defer provider.deinit();
    const manifest = try subject.Manifest.build(a, &native, &provider);
    try manifest.validateAgainst(a, &native, &provider);
    try std.testing.expectEqualDeep(
        manifest.program_input.digest,
        native.program.digest,
    );
    try checkWordAdapter(&manifest, .program_words);
    try checkHashAdapter(&manifest, .program_hash, &native.program_hash);
    try checkWordAdapter(&manifest, .provider_words);
    try checkHashAdapter(&manifest, .provider_hash, &provider.hash);
    try std.testing.expectError(error.V3WrapperProofUnavailable, manifest.requireCompleteWrapperProof());
    var changed = manifest;
    changed.placements[subject.keyIndex(.provider_hash)].?.geometry.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidV3FieldManifest, changed.validate());
    changed = manifest;
    changed.provider_input.digest[0] ^= 1;
    try std.testing.expectError(error.InvalidV3FieldManifest, changed.validate());
    provider.words.rows[0][0] = provider.words.rows[0][0].add(M31.one());
    try std.testing.expectError(error.InvalidFieldWordWitness, manifest.validateAgainst(a, &native, &provider));
}

fn fixtureNative(a: std.mem.Allocator, input: []const M31) !field.NativeV1 {
    const words = try a.dupe(M31, input);
    errdefer a.free(words);
    const digest = channel.hashCanonicalWords(words, program_authority.PROGRAM_DOMAIN);
    var source = try word_witness.WordsV1.init(a, words, field.PROGRAM_SCOPE);
    errdefer source.deinit();
    var hash = try hash_witness.HashV1.init(a, words, program_authority.PROGRAM_DOMAIN, field.PROGRAM_SCOPE, @import("recursion/air/ethereum_leaf_link_source_v1.zig").PROGRAM_AUTHORITY_KIND, hash_witness.PROGRAM_STEP_BASE, digest);
    errdefer hash.deinit();
    return .{ .program = .{ .allocator = a, .words = words, .digest = digest }, .program_words = source, .program_hash = hash, .tree0_root = .{0} ** channel.RATE };
}

fn fixtureProvider(a: std.mem.Allocator, input: []const M31) !field.ProviderV1 {
    const words = try a.dupe(M31, input);
    errdefer a.free(words);
    const digest = channel.hashCanonicalWords(words, provider_authority.DOMAIN);
    var source = try word_witness.WordsV1.init(a, words, field.PROVIDER_SCOPE);
    errdefer source.deinit();
    var hash = try hash_witness.HashV1.init(a, words, provider_authority.DOMAIN, field.PROVIDER_SCOPE, hash_witness.PROVIDER_FIELD_DIGEST_KIND, hash_witness.PROVIDER_STEP_BASE, digest);
    errdefer hash.deinit();
    return .{ .authority = .{ .allocator = a, .words = words, .digest = digest }, .words = source, .hash = hash };
}

fn checkWordAdapter(manifest: *const subject.Manifest, comptime key: subject.ComponentKey) !void {
    var definition = try word_air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try word_air.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const placement = try manifest.placement(key);
    const component = try subject.WordAdapter.init(&definition, plan, manifest, key, placement.geometry.log_size, .{}, &relations, QM31.zero());
    _ = try component.binding(manifest);
}

fn checkHashAdapter(manifest: *const subject.Manifest, comptime key: subject.ComponentKey, witness: *const hash_witness.HashV1) !void {
    var definition = try hash_air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try hash_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const placement = try manifest.placement(key);
    const parameters = try manifest.hashParameters(key);
    try std.testing.expectEqual(witness.domain, parameters[1].toU32());
    try std.testing.expectEqual(witness.digest_kind, parameters[4].toU32());
    const component = try subject.HashAdapter.init(&definition, plan, manifest, key, placement.geometry.log_size, parameters, &relations, QM31.zero());
    _ = try component.binding(manifest);
}
