//! Field encoding of the two authenticated shared providers in a SegmentV2
//! outer proof. This is verifier-side input preparation, not a recursive proof.

const std = @import("std");
const core = @import("stwo_core");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const shared = @import("air/universal_shared_provider.zig");
const provider_relations = @import("air/universal_provider_relations.zig");
const universal = @import("air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");
const channel = @import("poseidon2_channel.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 1;
pub const DOMAIN: u32 = 0x5350_4631; // SPF1
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const AuthorityV1 = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    digest: channel.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        poseidon_partials: [2]QM31,
    ) !AuthorityV1 {
        const words = try canonicalWords(allocator, manifest, claims, relations, poseidon_partials);
        return .{
            .allocator = allocator,
            .words = words,
            .digest = channel.hashCanonicalWords(words, DOMAIN),
        };
    }

    pub fn deinit(self: *AuthorityV1) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const AuthorityV1,
        manifest: *const manifest_mod.Manifest,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        poseidon_partials: [2]QM31,
    ) !void {
        const expected = try canonicalWords(self.allocator, manifest, claims, relations, poseidon_partials);
        defer self.allocator.free(expected);
        if (!wordsEqual(self.words, expected) or
            !std.meta.eql(self.digest, channel.hashCanonicalWords(self.words, DOMAIN)))
            return error.SharedProviderFieldAuthorityMismatch;
    }
};

/// Pins rows 34/35 to the sealed 39-row manifest, exact copied native
/// challenges, and the two Poseidon partial sums retained by the verifier.
/// A wrapper still has to prove that these words came from its child proof.
pub fn canonicalWords(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    claims: *const manifest_mod.ClaimVector,
    relations: *const universal.UniversalRelations,
    poseidon_partials: [2]QM31,
) ![]M31 {
    try manifest.validate();
    try claims.validate(manifest);
    const copied = try shared.SharedProviderRelations.init(relations);
    try copied.validateAgainst(relations);
    if (!provider_relations.secureIsCanonical(&poseidon_partials[0]) or
        !provider_relations.secureIsCanonical(&poseidon_partials[1]))
        return error.NonCanonicalSharedProviderField;
    const poseidon_claim = claims.values[@intFromEnum(manifest_mod.ComponentKey.poseidon2)];
    if (!poseidon_partials[0].add(poseidon_partials[1]).eql(poseidon_claim))
        return error.SharedProviderClaimMismatch;

    var words: std.ArrayList(M31) = .empty;
    errdefer words.deinit(allocator);
    try scalar(&words, allocator, FORMAT_VERSION);
    try scalar(&words, allocator, manifest.roster_count);
    try bytes(&words, allocator, &manifest.seal);
    try bytes(&words, allocator, &claims.seal);
    try bytes(&words, allocator, &relations.registry_order_digest);
    for ([_]manifest_mod.ComponentKey{ .poseidon2, .range_check_8_8 }) |key| {
        const item = try manifest.placement(key);
        try scalar(&words, allocator, @intFromEnum(key));
        try u32Value(&words, allocator, item.geometry.log_size);
        try u32Value(&words, allocator, item.preprocessed_offset);
        try u32Value(&words, allocator, item.main_offset);
        try u32Value(&words, allocator, item.interaction_offset);
        try u32Value(&words, allocator, item.constraint_offset);
        try bytes(&words, allocator, &item.geometry.semantic_digest);
        try secure(&words, allocator, claims.values[@intFromEnum(key)]);
    }
    for (poseidon_partials) |partial| try secure(&words, allocator, partial);
    for ([_]relation.Domain{ .poseidon2, .poseidon2_io, .range_check_8_8 }) |domain| {
        const element = relations.get(domain);
        try scalar(&words, allocator, @intFromEnum(domain));
        try scalar(&words, allocator, element.arity);
        try secure(&words, allocator, element.z);
        try secure(&words, allocator, element.alpha);
    }
    return words.toOwnedSlice(allocator);
}

fn secure(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: QM31) !void {
    if (!provider_relations.secureIsCanonical(&value))
        return error.NonCanonicalSharedProviderField;
    for ([_]M31{ value.c0.a, value.c0.b, value.c1.a, value.c1.b }) |limb|
        try words.append(allocator, limb);
}

fn bytes(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: []const u8) !void {
    try u32Value(words, allocator, std.math.cast(u32, value.len) orelse return error.SharedProviderFieldWordOverflow);
    for (value) |byte| try scalar(words, allocator, byte);
}

fn u32Value(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: u32) !void {
    try scalar(words, allocator, value & 0xffff);
    try scalar(words, allocator, value >> 16);
}

fn scalar(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: anytype) !void {
    const raw = std.math.cast(u32, value) orelse return error.NonCanonicalSharedProviderField;
    if (raw >= core.fields.m31.Modulus) return error.NonCanonicalSharedProviderField;
    try words.append(allocator, M31.fromCanonical(raw));
}

fn wordsEqual(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}
