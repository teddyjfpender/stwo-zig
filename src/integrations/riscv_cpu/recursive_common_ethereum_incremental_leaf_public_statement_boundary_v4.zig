//! External verifier boundary for the NodePublic words mixed by secure cohort
//! authority. This is not an AIR producer: row17 emits these public words and
//! the verifier subtracts their independently reconstructed relation claim.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const node_mod = @import("recursive_field_node_public_v2.zig");
const air = frontend.recursion.air;
const interaction = air.relation_interaction;
const universal = air.universal_challenges;
const QM31 = core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const TERM_COUNT: u32 = node_mod.AIR_WORD_COUNT;
pub const DOMAIN: @FieldType(interaction.TupleContribution, "domain") = .recursion_statement_word;
pub const PUBLIC_SCOPE: u32 = air.field_public_word_v3.PUBLIC_SCOPE;
pub const Error = error{EthereumIncrementalPublicStatementBoundaryMismatchV4};

pub const PublicStatementBoundaryV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    domain: @TypeOf(DOMAIN) = DOMAIN,
    term_count: u32 = TERM_COUNT,
    source_authority_identity_sha256: [32]u8,
    claimed_sum: QM31,
    identity_sha256: [32]u8,

    pub fn derive(node_public: *const node_mod.NodePublicV2, relations: *const universal.UniversalRelations) !PublicStatementBoundaryV4 {
        const words = try node_public.canonicalAirWords();
        try relations.validate();
        var claim = QM31.zero();
        for (words, 0..) |word, index| {
            const coordinates = tuple(@intCast(index), word);
            const denominator = try relations.get(DOMAIN).combineSecure(&coordinates);
            claim = claim.sub(try denominator.inv());
        }
        var result = PublicStatementBoundaryV4{
            .source_authority_identity_sha256 = sourceIdentity(&words),
            .claimed_sum = claim,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = result.identity();
        try result.validate();
        return result;
    }

    /// Structural integrity only. Public-input authentication requires derive
    /// or validateAgainst with independently supplied verifier public words.
    pub fn validate(self: *const PublicStatementBoundaryV4) Error!void {
        if (self.format_version != FORMAT_VERSION or self.schema_version != SCHEMA_VERSION or
            self.domain != DOMAIN or self.term_count != TERM_COUNT or
            std.mem.allEqual(u8, &self.source_authority_identity_sha256, 0) or
            !std.mem.eql(u8, &self.identity_sha256, &self.identity()))
            return error.EthereumIncrementalPublicStatementBoundaryMismatchV4;
        for (self.claimed_sum.toM31Array()) |limb| {
            if (limb.toU32() >= core.fields.m31.Modulus)
                return error.EthereumIncrementalPublicStatementBoundaryMismatchV4;
        }
    }

    pub fn validateAgainst(self: *const PublicStatementBoundaryV4, node_public: *const node_mod.NodePublicV2, relations: *const universal.UniversalRelations) !void {
        try self.validate();
        const expected = try derive(node_public, relations);
        if (!std.mem.eql(u8, &self.identity_sha256, &expected.identity_sha256))
            return error.EthereumIncrementalPublicStatementBoundaryMismatchV4;
    }

    pub fn identity(self: *const PublicStatementBoundaryV4) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/ethereum-node-public-boundary/v4-schema1\x00");
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hashInt(&hash, u8, @intFromEnum(self.domain));
        hashInt(&hash, u32, self.term_count);
        hash.update(&self.source_authority_identity_sha256);
        for (self.claimed_sum.toM31Array()) |limb| hashInt(&hash, u32, limb.toU32());
        return hash.finalResult();
    }
};

/// The component label is diagnostic provenance only; tuple coordinates and
/// signs exactly match the verifier's scalar boundary above.
pub fn appendTupleContributions(ledger: *interaction.TupleLedger, node_public: *const node_mod.NodePublicV2, component: u8) !void {
    const words = try node_public.canonicalAirWords();
    for (words, 0..) |word, index| {
        const coordinates = tuple(@intCast(index), word);
        try ledger.append(DOMAIN, component, 0, .consume, QM31.one().neg(), &coordinates);
    }
}

fn tuple(index: u32, word: u32) [3]QM31 {
    return .{
        QM31.fromU32Unchecked(PUBLIC_SCOPE, 0, 0, 0),
        QM31.fromU32Unchecked(index, 0, 0, 0),
        QM31.fromU32Unchecked(word, 0, 0, 0),
    };
}

fn sourceIdentity(words: *const [node_mod.AIR_WORD_COUNT]u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum-node-public-boundary-source/v4-schema1\x00");
    hash.update(&node_mod.abiIdentitySha256());
    hashInt(&hash, u32, PUBLIC_SCOPE);
    hashInt(&hash, u32, TERM_COUNT);
    for (words) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "Ethereum public statement boundary exact tuples and negative claim" {
    const node = try fixtureNode("source-a");
    const relations = universal.UniversalRelations.dummy();
    const boundary = try PublicStatementBoundaryV4.derive(&node, &relations);
    try boundary.validateAgainst(&node, &relations);
    var ledger = interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try appendTupleContributions(&ledger, &node, 255);
    try std.testing.expectEqual(@as(usize, 450), ledger.contributions.items.len);
    const words = try node.canonicalAirWords();
    var emitted_claim = QM31.zero();
    for (words, ledger.contributions.items, 0..) |word, contribution, index| {
        const expected = tuple(@intCast(index), word);
        try std.testing.expectEqual(DOMAIN, contribution.domain);
        try std.testing.expectEqual(.consume, contribution.role);
        try std.testing.expectEqual(@as(u8, 3), contribution.arity);
        try std.testing.expect(contribution.signed_weight.eql(QM31.one().neg()));
        for (expected, contribution.tuple_prefix[0..3]) |a, b| try std.testing.expect(a.eql(b));
        emitted_claim = emitted_claim.add(try (try relations.get(DOMAIN).combineSecure(&expected)).inv());
    }
    try std.testing.expect(emitted_claim.add(boundary.claimed_sum).isZero());
    for (words, 0..) |word, index| {
        const coordinates = tuple(@intCast(index), word);
        try ledger.append(DOMAIN, 17, 0, .emit, QM31.one(), &coordinates);
    }
    try std.testing.expect(ledger.classify().isClosed());
}

test "Ethereum public statement boundary rejects changed public words and claims" {
    const node = try fixtureNode("source-a");
    const changed = try fixtureNode("source-b");
    const relations = universal.UniversalRelations.dummy();
    const boundary = try PublicStatementBoundaryV4.derive(&node, &relations);
    try std.testing.expectError(error.EthereumIncrementalPublicStatementBoundaryMismatchV4, boundary.validateAgainst(&changed, &relations));
    var forged = boundary;
    forged.claimed_sum = forged.claimed_sum.add(QM31.one());
    forged.identity_sha256 = forged.identity();
    try forged.validate();
    try std.testing.expectError(error.EthereumIncrementalPublicStatementBoundaryMismatchV4, forged.validateAgainst(&node, &relations));
    forged = boundary;
    forged.term_count -= 1;
    forged.identity_sha256 = forged.identity();
    try std.testing.expectError(error.EthereumIncrementalPublicStatementBoundaryMismatchV4, forged.validate());
}

fn fixtureNode(source: []const u8) !node_mod.NodePublicV2 {
    const recursion = frontend.recursion;
    const span = recursion.span_statement;
    const channel = recursion.poseidon2_channel;
    const digest = channel.hashBytes("boundary-fixture", 0x4658);
    const initial = try span.MachineState.init(0, [_]u32{0} ** 32, digest, digest);
    const final = try span.MachineState.init(4, [_]u32{0} ** 32, digest, digest);
    const complete = try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, digest, initial, final, digest, digest, 8);
    const job = try span.JobContext.init(complete, 210);
    const statement = try span.SpanStatement.emptyLeaf(job, 210);
    var words: [node_mod.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&words, try statement.canonicalWords()) |*out, word| out.* = word.toU32();
    return node_mod.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 210), words, channel.hashBytes(source, 0x4658));
}

comptime {
    if (TERM_COUNT != 450 or PUBLIC_SCOPE != 4) @compileError("NodePublic boundary ABI drift");
}
