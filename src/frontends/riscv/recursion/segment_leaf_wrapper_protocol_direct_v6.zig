//! VPR7/VPK7 namespace for the physical V6 direct roster. Admission stays
//! disabled until row5 NPV2 and the complete 50-row proof are qualified.

const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const prior = @import("segment_leaf_wrapper_protocol_direct_v5.zig");
const roster = @import("air/segment_leaf_wrapper_roster_direct_v6.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 7;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x5650_5237; // VPR7
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x5650_4b37; // VPK7
pub const PCS_CONFIG = prior.PCS_CONFIG;
pub const INTERACTION_POW_BITS = prior.INTERACTION_POW_BITS;
pub const ChainConfig = prior.ChainConfig;
pub const REQUIRED_CHAIN = prior.REQUIRED_CHAIN;
pub const PRODUCTION_PROOF_ACTIVATION = false;

comptime {
    if (roster.COMPONENT_COUNT != 50 or
        PROTOCOL_ID_DOMAIN >= core.fields.m31.Modulus or
        VERIFICATION_KEY_ID_DOMAIN >= core.fields.m31.Modulus)
        @compileError("V6 direct protocol profile drifted");
}

pub fn protocolId(plan: *const roster.Plan) !channel.Digest {
    try plan.validate();
    try REQUIRED_CHAIN.validate();
    const prior_id = try prior.protocolId(&plan.legacy_plan);
    var words: [26]M31 = undefined;
    words[0] = M31.fromCanonical(FORMAT_VERSION);
    words[1] = M31.fromCanonical(roster.COMPONENT_COUNT);
    for (prior_id, 0..) |word, index| words[2 + index] = M31.fromCanonical(word);
    for (0..16) |index|
        words[10 + index] = M31.fromCanonical(std.mem.readInt(u16, plan.seal[index * 2 ..][0..2], .little));
    return channel.hashCanonicalWords(&words, PROTOCOL_ID_DOMAIN);
}

pub fn verificationKeyId(plan: *const roster.Plan, preprocessed_root: channel.Digest) !channel.Digest {
    const protocol_id = try protocolId(plan);
    var words: [16]M31 = undefined;
    for (protocol_id, 0..) |word, index| words[index] = M31.fromCanonical(word);
    for (preprocessed_root, 0..) |word, index| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalDirectPreprocessedRoot;
        words[8 + index] = M31.fromCanonical(word);
    }
    return channel.hashCanonicalWords(&words, VERIFICATION_KEY_ID_DOMAIN);
}

test "VPR7 binds the new row36 identity and VPK7 binds pinned Tree0" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const v4 = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const program_mod = @import("ethereum_leaf_link_program_v3.zig");
    const child_mod = @import("ethereum_leaf_child_field_program_v1.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    var child = try child_mod.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    const plan = try roster.Plan.build(allocator, &manifest, &program, shape, &child, &child_fixture.components, &child_fixture.infra);
    const id = try protocolId(&plan);
    try std.testing.expect(!std.meta.eql(id, try prior.protocolId(&plan.legacy_plan)));
    const root = [_]u32{1} ** 8;
    const key = try verificationKeyId(&plan, root);
    var changed = root;
    changed[0] = 2;
    try std.testing.expect(!std.meta.eql(key, try verificationKeyId(&plan, changed)));
    try std.testing.expectError(error.V6WrapperProofUnavailable, plan.requireCompleteWrapperProof());
}
