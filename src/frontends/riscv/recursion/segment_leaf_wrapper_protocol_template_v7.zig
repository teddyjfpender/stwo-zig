//! VPR7/VPK7 candidate identity for an independently rebuilt V6 template.
//!
//! The template contains no V2 manifest seal or leaf proof identity. A full
//! deterministic preprocessing writer is still missing, so a root supplied to
//! `candidateVerificationKeyId` is only a test vector, never an admitted key.
const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const frozen = @import("protocol.zig");
const security = @import("segment_v3_production_security_policy.zig");
const template_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const relation = @import("../air/lang/relation.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 7;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x5650_5237; // VPR7
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x5650_4b37; // VPK7
pub const PCS_CONFIG = security.REQUIRED_PCS_CONFIG;
pub const INTERACTION_POW_BITS = security.REQUIRED_INTERACTION_POW_BITS;
pub const PRODUCTION_PROOF_ACTIVATION = false;

comptime {
    if (template_mod.COMPONENT_COUNT != 50 or
        PCS_CONFIG.securityBits() < frozen.MIN_CONFIGURED_PCS_BITS or
        INTERACTION_POW_BITS != 10 or
        PROTOCOL_ID_DOMAIN >= core.fields.m31.Modulus or
        VERIFICATION_KEY_ID_DOMAIN >= core.fields.m31.Modulus)
        @compileError("VPR7/VPK7 security or template shape drifted");
}

pub fn candidateProtocolId(template: *const template_mod.TemplateManifestV6) !channel.Digest {
    try template.validate();
    var words: [54]M31 = undefined;
    var at: usize = 0;
    put(&words, &at, FORMAT_VERSION);
    put(&words, &at, template_mod.COMPONENT_COUNT);
    put(&words, &at, 3); // preprocessed, main, interaction trees
    put(&words, &at, frozen.TARGET_SECURITY_BITS);
    put(&words, &at, frozen.FIELD_ID);
    put(&words, &at, frozen.HASH_SUITE_ID);
    inline for (.{ @as(u32, 1), @as(u32, 2) }) |role| {
        put(&words, &at, role);
        put(&words, &at, PCS_CONFIG.pow_bits);
        put(&words, &at, PCS_CONFIG.fri_config.log_blowup_factor);
        put(&words, &at, @intCast(PCS_CONFIG.fri_config.n_queries));
        put(&words, &at, PCS_CONFIG.fri_config.fold_step);
        put(&words, &at, PCS_CONFIG.fri_config.log_last_layer_degree_bound);
        put(&words, &at, 0);
        put(&words, &at, INTERACTION_POW_BITS);
    }
    putSha(&words, &at, template.seal);
    putSha(&words, &at, relation.registryOrderDigest());
    std.debug.assert(at == words.len);
    return channel.hashCanonicalWords(&words, PROTOCOL_ID_DOMAIN);
}

/// Pure candidate derivation. A production VPK7 must take its root only from
/// completed verifier-owned template preprocessing, not this external value.
pub fn candidateVerificationKeyId(template: *const template_mod.TemplateManifestV6, template_root: channel.Digest) !channel.Digest {
    const protocol_id = try candidateProtocolId(template);
    var words: [16]M31 = undefined;
    for (protocol_id, 0..) |word, index| words[index] = M31.fromCanonical(word);
    for (template_root, 0..) |word, index| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalTemplateRootV6;
        words[8 + index] = M31.fromCanonical(word);
    }
    return channel.hashCanonicalWords(&words, VERIFICATION_KEY_ID_DOMAIN);
}

pub fn requireAdmittedKey(_: *const template_mod.TemplateManifestV6) error{TemplatePreprocessingUnavailable}!void {
    return error.TemplatePreprocessingUnavailable;
}

fn put(words: []M31, at: *usize, value: u32) void {
    words[at.*] = M31.fromCanonical(value);
    at.* += 1;
}

fn putSha(words: []M31, at: *usize, value: [32]u8) void {
    for (0..16) |index| put(words, at, std.mem.readInt(u16, value[index * 2 ..][0..2], .little));
}

test "VPR7 candidate is shape-only while VPK7 awaits a rebuilt template root" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v4 = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const v5 = @import("air/segment_leaf_wrapper_roster_direct_v5.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const link_program = @import("ethereum_leaf_link_program_v3.zig");
    const child_program = @import("ethereum_leaf_child_field_program_v1.zig");
    const old_protocol = @import("segment_leaf_wrapper_protocol_direct_v5.zig");
    const v6_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const native = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(allocator, &plans.vm, 128, &child_fixture.components, &child_fixture.infra, false);
    const shape = v4.Shape{ .program_words = native.canonical_program_word_count, .base_poseidon_calls = 1193 };
    const core_query_mapping = try template_mod.pinnedCoreQueryReference();
    const template = try template_mod.TemplateManifestV6.build(allocator, &v6_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, &core_query_mapping, 128, false);
    const vpr7 = try candidateProtocolId(&template);
    const root = [_]u32{1} ** 8;
    const vpk7 = try candidateVerificationKeyId(&template, root);
    try std.testing.expect(!std.meta.eql(vpr7, vpk7));
    const first_leaf = try v2.assemble(&v6_catalog, fixture.authorityIds());
    var other_ids = fixture.authorityIds();
    other_ids.transcript_manifest_id[0] += 1;
    const second_leaf = try v2.assemble(&v6_catalog, other_ids);
    var link = try link_program.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try child_program.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const first_old = try v5.Plan.build(allocator, &first_leaf, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    const second_old = try v5.Plan.build(allocator, &second_leaf, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    try std.testing.expect(!std.meta.eql(try old_protocol.verificationKeyId(&first_old, root), try old_protocol.verificationKeyId(&second_old, root)));
    const rebuilt_template = try template_mod.TemplateManifestV6.build(allocator, &v6_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, &core_query_mapping, 128, false);
    try std.testing.expect(std.meta.eql(vpk7, try candidateVerificationKeyId(&rebuilt_template, root)));
    var changed_root = root;
    changed_root[0] = 2;
    try std.testing.expect(!std.meta.eql(vpk7, try candidateVerificationKeyId(&template, changed_root)));
    changed_root[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalTemplateRootV6, candidateVerificationKeyId(&template, changed_root));
    const changed_shape = v4.Shape{ .program_words = shape.program_words, .base_poseidon_calls = 1194 };
    const other = try template_mod.TemplateManifestV6.build(allocator, &v6_catalog, changed_shape, &child_fixture.components, &child_fixture.infra, &plans.vm, &core_query_mapping, 128, false);
    try std.testing.expect(!std.meta.eql(vpr7, try candidateProtocolId(&other)));
    try std.testing.expectError(error.TemplatePreprocessingUnavailable, requireAdmittedKey(&template));
}
