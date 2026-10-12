//! Verifier-owned public LAS2 boundary for the direct leaf wrapper.
//!
//! Row 40 emits exactly 24 LAS2 statement tuples. This boundary consumes
//! those tuples from the caller's independently expected link, native
//! ProgramV2, and native Tree0 identities. It does not derive expectations
//! from a proof artifact or grant wrapper-proof publication.

const std = @import("std");
const core = @import("stwo_core");
const authority = @import("ethereum_leaf_direct_public_authority_v3.zig");
const universal = @import("air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");

const QM31 = core.fields.qm31.QM31;
pub const FORMAT_VERSION: u16 = 4;
pub const TRANSCRIPT_DOMAIN: u32 = 0x4c42_5634; // LBV4
pub const ID_DOMAIN = "stwo-zig/riscv-direct-leaf-las2-boundary/v4\x00";
pub const DOMAIN = relation.Domain.recursion_statement_word;
pub const TERM_COUNT: u32 = authority.WORD_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const ExpectedPublic = struct {
    link: authority.Digest,
    native_program: authority.Digest,
    native_tree0: authority.Digest,

    pub fn words(self: ExpectedPublic) !authority.Words {
        return (try authority.AuthorityV1.fromDigests(
            self.link,
            self.native_program,
            self.native_tree0,
        )).words;
    }
};

pub const BoundaryV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    domain: relation.Domain = DOMAIN,
    term_count: u32 = TERM_COUNT,
    expected_words: authority.Words,
    claimed_sum: QM31,
    identity: [32]u8,

    pub fn derive(expected: ExpectedPublic, relations: *const universal.UniversalRelations) !BoundaryV4 {
        try relations.validate();
        const words = try expected.words();
        const challenge = try relations.getExact(DOMAIN);
        var sum = QM31.zero();
        const expected_authority = try authority.AuthorityV1.fromSlice(&words);
        for (0..TERM_COUNT) |index| {
            const tuple = try expected_authority.statementTuple(index);
            sum = sum.sub(try (try challenge.combineBase(&tuple)).inv());
        }
        var result = BoundaryV4{
            .expected_words = words,
            .claimed_sum = sum,
            .identity = undefined,
        };
        result.identity = identity(&result);
        return result;
    }

    pub fn validateAgainst(self: *const BoundaryV4, expected: ExpectedPublic, relations: *const universal.UniversalRelations) !void {
        if (self.format_version != FORMAT_VERSION or self.domain != DOMAIN or self.term_count != TERM_COUNT)
            return error.InvalidDirectLas2Boundary;
        const wanted = try derive(expected, relations);
        if (!std.meta.eql(self.*, wanted)) return error.InvalidDirectLas2Boundary;
    }

    pub fn addToClosure(
        self: *const BoundaryV4,
        expected: ExpectedPublic,
        relations: *const universal.UniversalRelations,
        domain_totals: *[universal.RELATION_COUNT]QM31,
        framework_total: *QM31,
    ) !void {
        try self.validateAgainst(expected, relations);
        domain_totals[@intFromEnum(DOMAIN)] = domain_totals[@intFromEnum(DOMAIN)].add(self.claimed_sum);
        framework_total.* = framework_total.add(self.claimed_sum);
    }

    /// Call after the committed interaction claims and before Tree 2 on both
    /// prover and verifier. The caller must also add `claimed_sum` to the
    /// `recursion_statement_word` domain and framework closure totals.
    pub fn mixInto(self: *const BoundaryV4, channel: anytype, expected: ExpectedPublic, relations: *const universal.UniversalRelations) !void {
        try self.validateAgainst(expected, relations);
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, @intFromEnum(DOMAIN), TERM_COUNT, authority.SCOPE });
        channel.mixU32s(&self.expected_words);
        channel.mixFelts(&.{self.claimed_sum});
        channel.mixU32s(&digestWords(self.identity));
    }
};

fn identity(self: *const BoundaryV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ID_DOMAIN);
    hashInt(&hash, u16, self.format_version);
    hashInt(&hash, u8, @intFromEnum(self.domain));
    hashInt(&hash, u32, self.term_count);
    hashInt(&hash, u32, authority.SCOPE);
    for (self.expected_words) |word| hashInt(&hash, u32, word);
    for (self.claimed_sum.toM31Array()) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return result;
}

test "LAS2 public boundary consumes exact expected words and rejects changed identity" {
    const M31 = core.fields.m31.M31;
    const projection_air = @import("air/ethereum_leaf_link_projection_v1.zig");
    const program_mod = @import("ethereum_leaf_link_program_v3.zig");
    const interaction = @import("air/relation_interaction.zig");
    const expected = ExpectedPublic{
        .link = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .native_program = .{ 11, 12, 13, 14, 15, 16, 17, 18 },
        .native_tree0 = .{ 21, 22, 23, 24, 25, 26, 27, 28 },
    };
    const relations = universal.UniversalRelations.dummy();
    var boundary = try BoundaryV4.derive(expected, &relations);
    try boundary.validateAgainst(expected, &relations);
    try std.testing.expectEqual(TERM_COUNT, boundary.term_count);
    const challenge = try relations.getExact(DOMAIN);
    var independently_summed = QM31.zero();
    const words = try authority.AuthorityV1.fromSlice(&boundary.expected_words);
    for (0..TERM_COUNT) |index| {
        const tuple = try words.statementTuple(index);
        independently_summed = independently_summed.sub(try (try challenge.combineBase(&tuple)).inv());
    }
    try std.testing.expect(boundary.claimed_sum.eql(independently_summed));
    var domain_totals = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
    var framework_total = QM31.zero();
    try boundary.addToClosure(expected, &relations, &domain_totals, &framework_total);
    try std.testing.expect(domain_totals[@intFromEnum(DOMAIN)].eql(boundary.claimed_sum));
    try std.testing.expect(framework_total.eql(boundary.claimed_sum));

    // The actual pinned row-40 LAS2 schedule must emit the exact tuples that
    // the verifier-owned boundary consumes, not a parallel host paraphrase.
    var program = try program_mod.ProgramV3.init(std.testing.allocator);
    defer program.deinit();
    var projection_definition = try projection_air.build(std.testing.allocator);
    defer projection_definition.deinit();
    const projection_plan = try projection_air.authenticate(&projection_definition);
    var projection_rows: [TERM_COUNT]projection_air.Row = undefined;
    const start = program.projection_rows.len - TERM_COUNT;
    for (&projection_rows, 0..) |*row, index|
        row.* = program.projection_rows[start + index].logical(M31.fromCanonical(boundary.expected_words[index]));
    const mask: u64 = @as(u64, 1) << @intFromEnum(DOMAIN);
    var ledger = interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try projection_plan.appendPreparedTupleContributions(&ledger, 40, &projection_rows, mask);
    for (0..TERM_COUNT) |index| {
        const tuple = try words.statementTuple(index);
        const secure = [_]QM31{ QM31.fromBase(tuple[0]), QM31.fromBase(tuple[1]), QM31.fromBase(tuple[2]) };
        try ledger.append(DOMAIN, 47, 0, .consume, QM31.one().neg(), &secure);
    }
    try std.testing.expect(ledger.classify().isClosed());

    var changed = expected;
    changed.native_program[0] += 1;
    try std.testing.expectError(error.InvalidDirectLas2Boundary, boundary.validateAgainst(changed, &relations));
    var changed_ledger = interaction.TupleLedger.init(std.testing.allocator);
    defer changed_ledger.deinit();
    try projection_plan.appendPreparedTupleContributions(&changed_ledger, 40, &projection_rows, mask);
    const changed_raw_words = try changed.words();
    const changed_words = try authority.AuthorityV1.fromSlice(&changed_raw_words);
    for (0..TERM_COUNT) |index| {
        const tuple = try changed_words.statementTuple(index);
        const secure = [_]QM31{ QM31.fromBase(tuple[0]), QM31.fromBase(tuple[1]), QM31.fromBase(tuple[2]) };
        try changed_ledger.append(DOMAIN, 47, 0, .consume, QM31.one().neg(), &secure);
    }
    try std.testing.expectEqual(@as(usize, 2), changed_ledger.classify().unmatched_by_domain[@intFromEnum(DOMAIN)]);
    changed = expected;
    changed.native_tree0[7] += 1;
    try std.testing.expectError(error.InvalidDirectLas2Boundary, boundary.validateAgainst(changed, &relations));
    changed = expected;
    changed.link[0] += 1;
    try std.testing.expectError(error.InvalidDirectLas2Boundary, boundary.validateAgainst(changed, &relations));
    boundary.expected_words[0] += 1;
    try std.testing.expectError(error.InvalidDirectLas2Boundary, boundary.validateAgainst(expected, &relations));
    boundary.expected_words[0] -= 1;
    boundary.claimed_sum = boundary.claimed_sum.add(QM31.one());
    try std.testing.expectError(error.InvalidDirectLas2Boundary, boundary.validateAgainst(expected, &relations));
    boundary.claimed_sum = boundary.claimed_sum.sub(QM31.one());
    boundary.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidDirectLas2Boundary, boundary.validateAgainst(expected, &relations));
    boundary.identity[0] ^= 1;

    var channel = @import("poseidon2_channel.zig").Channel{};
    try boundary.mixInto(&channel, expected, &relations);
    var changed_channel = @import("poseidon2_channel.zig").Channel{};
    const changed_boundary = try BoundaryV4.derive(changed, &relations);
    try changed_boundary.mixInto(&changed_channel, changed, &relations);
    try std.testing.expect(!std.meta.eql(channel.drawU32s(), changed_channel.drawU32s()));
}
