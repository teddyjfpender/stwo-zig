//! Public-output LogUp boundary, derivable from the published node alone.
//! No child proof, producer state or permutation-call buffer is required.
const std = @import("std");
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").recursion.air;
const public = @import("recursive_field_node_public_v2.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const recorder = air.composition_graph_recorder;
pub const Error = error{ InvalidPublicOutputBoundary, ZeroDenominator };
pub const BoundaryEvidenceV3 = struct {
    format_version: u16 = 3,
    domain: @TypeOf(@import("stwo_riscv_frontend").recursion.binary_global_closure_outer_source.PROVIDER_DOMAIN) = .recursion_statement_word,
    tuple_count: u32 = public.AIR_WORD_COUNT,
    public_words_sha256: [32]u8,
    challenge_sha256: [32]u8,
    claimed_sum: QM31,
    identity_sha256: [32]u8,
    pub fn validate(self: *const BoundaryEvidenceV3) !void {
        if (self.format_version != 3 or self.domain != .recursion_statement_word or self.tuple_count != public.AIR_WORD_COUNT or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self))) return error.InvalidPublicOutputBoundary;
    }
};

pub fn derive(node: *const public.NodePublicV2, relations: *const air.universal_challenges.UniversalRelations) !BoundaryEvidenceV3 {
    const words = try node.canonicalAirWords();
    const relation = try relations.getExact(.recursion_statement_word);
    var sum = QM31.zero();
    for (words, 0..) |word, index| {
        const denominator = try relation.combineBase(&.{ M31.fromCanonical(air.field_public_word_v3.PUBLIC_SCOPE), M31.fromCanonical(@intCast(index)), M31.fromCanonical(word) });
        sum = sum.sub(denominator.inv() catch return error.ZeroDenominator);
    }
    var words_hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (words) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        words_hash.update(&bytes);
    }
    var challenges = std.crypto.hash.sha2.Sha256.init(.{});
    hashField(&challenges, relation.z);
    hashField(&challenges, relation.alpha);
    var result = BoundaryEvidenceV3{ .public_words_sha256 = words_hash.finalResult(), .challenge_sha256 = challenges.finalResult(), .claimed_sum = sum, .identity_sha256 = undefined };
    result.identity_sha256 = identity(&result);
    try result.validate();
    return result;
}

/// Child verification computes the same public boundary from bound inputs.
/// Inverses lower to the existing arithmetic AIR; no claim is a graph literal.
pub fn recordSum(words: *const [public.AIR_WORD_COUNT]recorder.Scalar, challenges: *const recorder.ChallengeSet) !recorder.Scalar {
    const relation = challenges.get(.recursion_statement_word);
    var sum = recorder.Scalar.zero();
    for (words, 0..) |word, index| {
        const denominator = try relation.combine(&.{ recorder.Scalar.fromBase(M31.fromCanonical(air.field_public_word_v3.PUBLIC_SCOPE)), recorder.Scalar.fromBase(M31.fromCanonical(@intCast(index))), word });
        sum = sum.sub(denominator.inverse());
    }
    return sum;
}
fn identity(value: *const BoundaryEvidenceV3) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/common-fold-public-output/v3\x00");
    hash.update(&value.public_words_sha256);
    hash.update(&value.challenge_sha256);
    hashField(&hash, value.claimed_sum);
    return hash.finalResult();
}
fn hashField(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word.toU32(), .little);
        hash.update(&bytes);
    }
}
