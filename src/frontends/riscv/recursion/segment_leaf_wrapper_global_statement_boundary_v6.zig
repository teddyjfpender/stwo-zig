//! Verifier-owned public boundary for the 412 global span Statement words
//! emitted by direct row40 in G3S1. The caller must supply the expected
//! words independently of the wrapper proof and mix this boundary before
//! Tree2. It is not an admitted proof while the V6 roster is incomplete.

const std = @import("std");
const core = @import("stwo_core");
const span = @import("span_statement.zig");
const source = @import("air/ethereum_leaf_link_source_v1.zig");
const universal = @import("air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const FORMAT_VERSION: u16 = 6;
pub const DOMAIN = relation.Domain.recursion_statement_word;
pub const WORD_COUNT: usize = span.SPAN_STATEMENT_CANONICAL_WORDS;
pub const SCOPE: u32 = source.GLOBAL_STATEMENT_SCOPE;
pub const ID_DOMAIN = "stwo-zig/riscv-global-span-statement-boundary/v6\x00";
pub const TRANSCRIPT_DOMAIN: u32 = 0x4753_5636; // GSV6
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const ExpectedPublic = struct {
    words: span.StatementWords,

    /// Must be called with verifier-supplied words before relation challenges
    /// are drawn. The challenge-dependent boundary claim is mixed later.
    pub fn mixBeforeRelations(self: *const ExpectedPublic, channel: anytype) void {
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, @intFromEnum(DOMAIN), WORD_COUNT, SCOPE });
        var words: [WORD_COUNT]u32 = undefined;
        for (&words, self.words) |*destination, word| destination.* = word.toU32();
        channel.mixU32s(&words);
    }
};

pub const BoundaryV6 = struct {
    expected: ExpectedPublic,
    claimed_sum: QM31,
    identity: [32]u8,

    pub fn derive(expected: ExpectedPublic, relations: *const universal.UniversalRelations) !BoundaryV6 {
        try relations.validate();
        const challenge = try relations.getExact(DOMAIN);
        var sum = QM31.zero();
        for (expected.words, 0..) |word, index| {
            const tuple = [_]M31{ M31.fromCanonical(SCOPE), M31.fromCanonical(@intCast(index)), word };
            sum = sum.sub(try (try challenge.combineBase(&tuple)).inv());
        }
        var result = BoundaryV6{ .expected = expected, .claimed_sum = sum, .identity = undefined };
        result.identity = result.identityHash();
        return result;
    }

    pub fn validateAgainst(self: *const BoundaryV6, expected: ExpectedPublic, relations: *const universal.UniversalRelations) !void {
        const wanted = try derive(expected, relations);
        if (!std.meta.eql(self.*, wanted)) return error.InvalidGlobalStatementBoundaryV6;
    }

    pub fn addToClosure(self: *const BoundaryV6, expected: ExpectedPublic, relations: *const universal.UniversalRelations, totals: *[universal.RELATION_COUNT]QM31, framework_total: *QM31) !void {
        try self.validateAgainst(expected, relations);
        totals[@intFromEnum(DOMAIN)] = totals[@intFromEnum(DOMAIN)].add(self.claimed_sum);
        framework_total.* = framework_total.add(self.claimed_sum);
    }

    pub fn appendTupleContributions(self: *const BoundaryV6, ledger: *@import("air/relation_interaction.zig").TupleLedger) !void {
        for (self.expected.words, 0..) |word, index| {
            const tuple = [_]QM31{
                .fromBase(M31.fromCanonical(SCOPE)),
                .fromBase(M31.fromCanonical(@intCast(index))),
                .fromBase(word),
            };
            try ledger.append(DOMAIN, 51, 0, .consume, QM31.one().neg(), &tuple);
        }
    }

    pub fn mixClaimAfterRelations(self: *const BoundaryV6, channel: anytype, expected: ExpectedPublic, relations: *const universal.UniversalRelations) !void {
        try self.validateAgainst(expected, relations);
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION });
        channel.mixFelts(&.{self.claimed_sum});
        var digest_words: [8]u32 = undefined;
        for (&digest_words, 0..) |*word, index|
            word.* = std.mem.readInt(u32, self.identity[index * 4 ..][0..4], .little);
        channel.mixU32s(&digest_words);
    }

    fn identityHash(self: *const BoundaryV6) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(ID_DOMAIN);
        hashWord(&hash, FORMAT_VERSION);
        hashWord(&hash, SCOPE);
        for (self.expected.words) |word| hashWord(&hash, word.toU32());
        for (self.claimed_sum.toM31Array()) |limb| hashWord(&hash, limb.toU32());
        return hash.finalResult();
    }
};

fn hashWord(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test "global span boundary closes exactly 412 G3S1 words and rejects mutation" {
    const allocator = std.testing.allocator;
    var expected = ExpectedPublic{ .words = @splat(M31.zero()) };
    for (&expected.words, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(index + 1));
    const relations = universal.UniversalRelations.dummy();
    const boundary = try BoundaryV6.derive(expected, &relations);
    try boundary.validateAgainst(expected, &relations);
    var ledger = @import("air/relation_interaction.zig").TupleLedger.init(allocator);
    defer ledger.deinit();
    try boundary.appendTupleContributions(&ledger);
    for (expected.words, 0..) |word, index| {
        const tuple = [_]QM31{
            .fromBase(M31.fromCanonical(SCOPE)),
            .fromBase(M31.fromCanonical(@intCast(index))),
            .fromBase(word),
        };
        try ledger.append(DOMAIN, 40, 3, .emit, QM31.one(), &tuple);
    }
    try std.testing.expect(ledger.classify().isClosed());
    expected.words[17] = expected.words[17].add(M31.one());
    try std.testing.expectError(error.InvalidGlobalStatementBoundaryV6, boundary.validateAgainst(expected, &relations));
    var first = @import("poseidon2_channel.zig").Channel{};
    boundary.expected.mixBeforeRelations(&first);
    var changed = @import("poseidon2_channel.zig").Channel{};
    expected.mixBeforeRelations(&changed);
    try std.testing.expect(!std.meta.eql(first.drawU32s(), changed.drawU32s()));
    var claim_channel = @import("poseidon2_channel.zig").Channel{};
    try boundary.mixClaimAfterRelations(&claim_channel, boundary.expected, &relations);
    try std.testing.expectError(error.InvalidGlobalStatementBoundaryV6, boundary.mixClaimAfterRelations(&claim_channel, expected, &relations));
}
