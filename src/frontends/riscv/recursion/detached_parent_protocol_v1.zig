//! Shared native/standalone transcript for the small detached two-child parent.
//! Profiles are explicitly admitted separately from CSP. Key hashes authorize
//! nothing unless pinned independently by callers.
const std = @import("std");
const core = @import("stwo_core");
const recursion = struct {
    const span_continuation_v1 = @import("span_continuation_v1.zig");
    const outer_parent_child_admission = @import("outer_parent_child_admission_profile.zig");
    const protocol = @import("protocol.zig");
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const air = struct {
        const universal_challenges = @import("air/universal_challenges.zig");
    };
};
const continuation = recursion.span_continuation_v1;
const cohort = @import("detached_parent_contract_v1.zig");
const manifest_mod = cohort.manifest_mod;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const payload = @import("detached_payload_v1.zig");
const recipe_mod = @import("detached_parent_fixed_recipe_v1.zig");
pub const FixedRecipeV1 = recipe_mod.FixedRecipeV1;
pub const VERSION: u32 = 3;
pub const DEVELOPMENT_ONLY = true;
pub const PCS_CONFIG = recursion.outer_parent_child_admission.OUTER_PCS_CONFIG;
pub const PUBLIC_SCOPE: u32 = 3;
pub const ExpectedV1 = continuation.Words;
pub const PublicationMode = continuation.Mode;
pub const ClaimsV1 = cohort.ClaimsV1;
pub const ProfileV1 = enum(u8) {
    detached_continuation_development_q3_v2 = 2,
    recursive_q193_v1 = 3,
    pub fn pcsConfig(self: ProfileV1) core.pcs.PcsConfig {
        return switch (self) {
            .detached_continuation_development_q3_v2 => PCS_CONFIG,
            .recursive_q193_v1 => recursion.protocol.PCS_CONFIG,
        };
    }
    pub fn interactionPowBits(self: ProfileV1) u32 {
        return switch (self) {
            .detached_continuation_development_q3_v2 => 0,
            .recursive_q193_v1 => recursion.protocol.INTERACTION_POW_BITS,
        };
    }
};
pub const mixInteractionPow = @import("detached_claims_v1.zig").mixInteractionPow;

pub const KeyV1 = struct {
    version: u32 = VERSION,
    profile: ProfileV1 = .detached_continuation_development_q3_v2,
    publication_mode: PublicationMode = .root,
    pcs_config: core.pcs.PcsConfig = PCS_CONFIG,
    manifest: manifest_mod.Manifest,
    parameters: cohort.ParametersV1,
    preprocessed_root: recursion.poseidon2_channel.Digest,
    child_key_sha256: [2][32]u8,
    fixed_recipe: FixedRecipeV1,

    pub fn validate(self: *const KeyV1) !void {
        _ = try self.identity();
    }

    pub fn identity(self: *const KeyV1) ![32]u8 {
        if (self.version != VERSION or !std.meta.eql(self.pcs_config, self.profile.pcsConfig())) return error.DetachedParentProfileMismatch;
        try self.parameters.validate(&self.manifest);
        if (self.fixed_recipe.version != recipe_mod.VERSION) return error.DetachedParentFixedRecipeMismatch;
        if (std.mem.allEqual(u32, &self.preprocessed_root, 0)) return error.DetachedParentKeyMismatch;
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus) return error.DetachedParentKeyMismatch;
        for (self.child_key_sha256) |pin| if (std.mem.allEqual(u8, &pin, 0)) return error.DetachedParentKeyMismatch;
        for (self.fixed_recipe.children) |child| {
            if (std.mem.allEqual(u8, &child.key_identity, 0) or std.mem.allEqual(u32, &child.preprocessed_root, 0) or
                std.mem.allEqual(u8, &child.manifest_seal, 0) or std.mem.allEqual(u8, &child.pcs_graph_identity_digest, 0))
                return error.DetachedParentFixedRecipeMismatch;
            for (child.preprocessed_root) |word| if (word >= core.fields.m31.Modulus)
                return error.DetachedParentFixedRecipeMismatch;
        }
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(switch (self.profile) {
            .detached_continuation_development_q3_v2 => "stwo-zig/segment-v2-detached-two-child-development-parent/v3\x00",
            .recursive_q193_v1 => "stwo-zig/segment-v2-detached-two-child-q193-parent/v2\x00",
        });
        for ([_]u32{ VERSION, @intFromEnum(self.profile), @intFromEnum(self.publication_mode), @intFromEnum(std.meta.activeTag(self.fixed_recipe.boundary)), self.pcs_config.pow_bits, self.pcs_config.fri_config.log_blowup_factor, self.pcs_config.fri_config.log_last_layer_degree_bound, @intCast(self.pcs_config.fri_config.n_queries), self.pcs_config.fri_config.fold_step, self.fixed_recipe.version, manifest_mod.FORMAT_VERSION, continuation.VERSION, PUBLIC_SCOPE, continuation.WORD_COUNT }) |word| hashWord(&hash, word);
        if (self.profile == .recursive_q193_v1) hashWord(&hash, self.profile.interactionPowBits());
        hash.update(&self.manifest.seal);
        hash.update(&recursion.air.universal_challenges.registryOrderDigest());
        for (recursion.protocol.PROTOCOL_ID_WORDS) |word| hashWord(&hash, word);
        for (self.fixed_recipe.children, self.child_key_sha256) |child, pin| {
            hash.update(&pin);
            hash.update(&child.key_identity);
            for (child.preprocessed_root) |word| hashWord(&hash, word);
            hash.update(&child.manifest_seal);
            hash.update(&child.composition_layout_manifest_id);
            for (child.vm_schedule_digest) |word| hashWord(&hash, word);
            for (child.recursion_schedule_digest) |word| hashWord(&hash, word);
            hash.update(&child.pcs_graph_identity_digest);
            hashWord(&hash, child.sampled_value_count);
            for (child.trace_tree_heights) |word| hashWord(&hash, word);
            hashWord(&hash, child.fri_layer_count);
            hashWord(&hash, child.last_layer_coefficient_count);
        }
        switch (self.fixed_recipe.boundary) {
            .segment => |boundary| {
                hashWord(&hash, @intFromEnum(recipe_mod.ChildFamily.segment));
                for (boundary.sections, boundary.memory) |sections, memory| {
                    hashU16(&hash, sections.version);
                    for (sections.counts) |count| hashWord(&hash, count);
                    hashU16(&hash, memory.version);
                    for ([_][]const u32{ memory.entry_addresses, memory.exit_addresses }) |addresses| {
                        hashWord(&hash, @intCast(addresses.len));
                        for (addresses) |address| hashWord(&hash, address);
                    }
                }
            },
            .parent => hashWord(&hash, @intFromEnum(recipe_mod.ChildFamily.parent)),
        }
        hashWord(&hash, self.parameters.poseidon_active_rows);
        for (self.parameters.words, 0..) |words, row| {
            hashWord(&hash, @intCast(row));
            hashWord(&hash, @intCast(words.len));
            for (words) |word| hashWord(&hash, word.toU32());
        }
        for (self.preprocessed_root) |word| hashWord(&hash, word);
        return hash.finalResult();
    }
};

pub fn validateExpected(expected: *const ExpectedV1) !void {
    try continuation.validate(expected, .intermediate);
}

pub fn publicTuple(index: usize, word: M31) [3]M31 {
    return .{ M31.fromCanonical(PUBLIC_SCOPE), M31.fromCanonical(@intCast(index)), word };
}

/// Every published word is requested exactly once by the admitted routing AIR,
/// including words whose arithmetic fanout is zero. No producer scalar enters.
pub fn publicBoundary(expected: *const ExpectedV1, relations: *const cohort.Relations) !QM31 {
    try validateExpected(expected);
    const relation = try relations.getExact(.recursion_statement_word);
    var result = QM31.zero();
    for (expected, 0..) |word, index| {
        const denominator = try relation.combineBase(&publicTuple(index, word));
        result = result.add(try denominator.inv());
    }
    return result;
}

/// Called after the fixed and main tree commitments, before relation draws.
pub fn mixAdmission(channel: anytype, key: *const KeyV1, expected: *const ExpectedV1) !void {
    const identity = try key.identity();
    try continuation.validate(expected, key.publication_mode);
    payload.begin(channel, .admission_header);
    channel.mixU32s(&.{ 0x4450_4131, VERSION, manifest_mod.COMPONENT_COUNT, PUBLIC_SCOPE, expected.len });
    var pin_words: [8]u32 = undefined;
    for (&pin_words, 0..) |*word, index| word.* = std.mem.readInt(u32, identity[index * 4 ..][0..4], .little);
    payload.begin(channel, .key_identity);
    channel.mixU32s(&pin_words);
    var words: [continuation.WORD_COUNT]u32 = undefined;
    for (&words, expected) |*word, value| word.* = value.toU32();
    payload.begin(channel, .expected_u32);
    channel.mixU32s(&words);
}

/// Independent challenges separate all47 tuple domains. Exact global LogUp
/// closure is checked using STARK-bound row claims and derived public requests;
/// there is no freely supplied per-domain decomposition or boundary receipt.
pub fn mixClaimsAndBoundary(channel: anytype, key: *const KeyV1, expected: *const ExpectedV1, claims: ClaimsV1, relations: *const cohort.Relations) !void {
    _ = try claims.vector(&key.manifest);
    const boundary = try publicBoundary(expected, relations);
    var total = boundary;
    for (claims.values) |claim| total = total.add(claim);
    if (!total.isZero()) return error.DetachedParentClaimClosureMismatch;
    payload.begin(channel, .claims_header);
    channel.mixU32s(&.{ 0x4450_4331, VERSION, manifest_mod.COMPONENT_COUNT });
    payload.begin(channel, .claims);
    channel.mixFelts(&claims.values);
    payload.begin(channel, .boundary_header);
    channel.mixU32s(&.{ 0x4450_4231, VERSION, PUBLIC_SCOPE, expected.len, 2 });
    payload.begin(channel, .boundary);
    channel.mixFelts(&.{boundary});
    payload.begin(channel, .partials);
    channel.mixFelts(&claims.poseidon_partials);
}

fn hashWord(hash: anytype, word: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    hash.update(&bytes);
}

fn hashU16(hash: anytype, word: u16) void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, word, .little);
    hash.update(&bytes);
}
