//! VPR6/VPK6 protocol namespace for the direct 50-row native leaf roster.
//! A pinned preprocessed root and native child key remain verifier inputs;
//! this module does not authorize publication of an unproved cohort.

const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const frozen = @import("protocol.zig");
const security = @import("segment_v3_production_security_policy.zig");
const roster = @import("air/segment_leaf_wrapper_roster_direct_v5.zig");
const relation = @import("../air/lang/relation.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 6;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x5650_5236; // VPR6
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x5650_4b36; // VPK6
pub const PCS_CONFIG = security.REQUIRED_PCS_CONFIG;
pub const INTERACTION_POW_BITS = security.REQUIRED_INTERACTION_POW_BITS;
pub const PRODUCTION_PROOF_ACTIVATION = false;

comptime {
    if (roster.COMPONENT_COUNT != 50 or
        PCS_CONFIG.securityBits() < frozen.MIN_CONFIGURED_PCS_BITS or
        INTERACTION_POW_BITS != 10 or
        PROTOCOL_ID_DOMAIN >= core.fields.m31.Modulus or
        VERIFICATION_KEY_ID_DOMAIN >= core.fields.m31.Modulus)
        @compileError("direct V5 leaf security profile or roster drifted");
}

pub const ChainConfig = struct {
    native_pcs: core.pcs.PcsConfig,
    native_interaction_pow_bits: u32,
    wrapper_pcs: core.pcs.PcsConfig,
    wrapper_interaction_pow_bits: u32,

    pub fn validate(self: ChainConfig) !void {
        if (!std.meta.eql(self.native_pcs, PCS_CONFIG) or
            self.native_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.InsecureDirectNativeChild;
        if (!std.meta.eql(self.wrapper_pcs, PCS_CONFIG) or
            self.wrapper_interaction_pow_bits != INTERACTION_POW_BITS)
            return error.InsecureDirectWrapper;
    }
};

pub const REQUIRED_CHAIN = ChainConfig{
    .native_pcs = PCS_CONFIG,
    .native_interaction_pow_bits = INTERACTION_POW_BITS,
    .wrapper_pcs = PCS_CONFIG,
    .wrapper_interaction_pow_bits = INTERACTION_POW_BITS,
};

/// Domain-separated from VPR5 and commits the full 50-row plan seal.
pub fn protocolId(plan: *const roster.Plan) !channel.Digest {
    try plan.validate();
    var words: [54]M31 = undefined;
    var at: usize = 0;
    put(&words, &at, FORMAT_VERSION);
    put(&words, &at, roster.COMPONENT_COUNT);
    put(&words, &at, roster.TREE_COUNT);
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
    putSha(&words, &at, plan.seal);
    putSha(&words, &at, relation.registryOrderDigest());
    std.debug.assert(at == words.len);
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

fn put(words: []M31, at: *usize, value: u32) void {
    words[at.*] = M31.fromCanonical(value);
    at.* += 1;
}

fn putSha(words: []M31, at: *usize, digest: [32]u8) void {
    for (0..16) |index|
        put(words, at, std.mem.readInt(u16, digest[index * 2 ..][0..2], .little));
}

test "VPR6 rejects weak native and wrapper profiles" {
    try REQUIRED_CHAIN.validate();
    var changed = REQUIRED_CHAIN;
    changed.native_pcs.fri_config.n_queries = 70;
    try std.testing.expectError(error.InsecureDirectNativeChild, changed.validate());
    changed = REQUIRED_CHAIN;
    changed.wrapper_interaction_pow_bits = 0;
    try std.testing.expectError(error.InsecureDirectWrapper, changed.validate());
}

test "VPR6 and VPK6 bind the 50-row seal and pinned root" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const v4 = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const old_protocol = @import("segment_leaf_wrapper_protocol_direct_v4.zig");
    const link_program = @import("ethereum_leaf_link_program_v3.zig");
    const child_program = @import("ethereum_leaf_child_field_program_v1.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base_manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var link = try link_program.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try child_program.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    const plan = try roster.Plan.build(allocator, &base_manifest, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    const legacy_id = try old_protocol.protocolId(&plan.base_plan);
    const new_id = try protocolId(&plan);
    try std.testing.expect(!std.meta.eql(legacy_id, new_id));
    const root = [_]u32{1} ** 8;
    const key = try verificationKeyId(&plan, root);
    var changed_root = root;
    changed_root[0] = 2;
    try std.testing.expect(!std.meta.eql(key, try verificationKeyId(&plan, changed_root)));
    changed_root[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalDirectPreprocessedRoot, verificationKeyId(&plan, changed_root));
    try std.testing.expectError(error.V5WrapperProofUnavailable, plan.requireCompleteWrapperProof());
}
