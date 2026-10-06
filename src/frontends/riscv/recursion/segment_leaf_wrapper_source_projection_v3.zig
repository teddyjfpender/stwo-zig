//! Typed main-column materialization for V3 wrapper rows 39 and 40.
//!
//! This is a witness builder, not proof admission. The native capture owns the
//! 28 transcript claims and local statement; the strong outer verifier supplies
//! the provider words and root before a 49-row transaction may consume this
//! witness. All raw, verifier, and statement joins are checked here, and
//! the complete raw-word multiplicity is checked against hash/arithmetic use.

const std = @import("std");
const core = @import("stwo_core");
const program_mod = @import("ethereum_leaf_link_program_v2.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const field_witness = @import("segment_leaf_wrapper_field_witness_v3.zig");
const field_hash = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const provider_authority = @import("segment_outer_shared_provider_field_authority_v1.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const metadata_mod = @import("segment_leaf_local_authority_v3.zig");
const link_mod = @import("segment_leaf_local_verified_link_v3.zig");
const segment_v2 = @import("segment_statement_v2.zig");

const M31 = core.fields.m31.M31;
const Digest = [program_mod.DIGEST_WORD_COUNT]u32;

pub const PRODUCTION_PROOF_ACTIVATION = false;

/// These are reconstructed from the independently verified native and strong
/// outer children; final recursive authority still requires 49-row AIR.
const ChildFieldDigestsV3 = struct {
    program: Digest,
    preprocessed_root: Digest,
    provider_digest: Digest,
};

const Sources = struct {
    metadata: metadata_mod.IdentityWords,
    link: link_mod.IdentityWords,
    metadata_digest: Digest,
    link_digest: Digest,
    local_authority: Digest,
    local_wire: Digest,
    local_receipt: Digest,
    fields: ChildFieldDigestsV3,
    transcript_claims: [program_mod.TRANSCRIPT_CLAIM_COUNT][4]M31,
    local_statement: []const M31,
};

pub const WitnessV3 = struct {
    allocator: std.mem.Allocator,
    source_values: []M31,
    projection_values: []M31,

    /// Child fields are rebuilt from the native program authority and the
    /// snapshot minted *after* strong 39-row verification. This only prepares
    /// rows: the eventual 49-row verifier must prove those child facts.
    pub fn initFromVerifiedChildren(
        allocator: std.mem.Allocator,
        program: *const program_mod.ProgramV2,
        prepared: anytype,
        metadata: *const metadata_mod.MetadataV3,
        link: *const link_mod.VerifiedLinkV3,
        native_fields: *const field_witness.NativeV1,
        strong: anytype,
        manifest: *const manifest_mod.Manifest,
    ) !WitnessV3 {
        try prepared.validate();
        try program.validate();
        try native_fields.validateAgainst(prepared);
        try strong.field_snapshot.validateAgainst(manifest, &strong.artifact);
        try link.validateAgainst(
            metadata,
            &prepared.capture.public_data.data,
            &prepared.capture.receipt,
        );
        const claims = prepared.capture.vm_air.canonical_claims;
        if (claims.len != program_mod.TRANSCRIPT_CLAIM_COUNT)
            return error.InvalidV3LeafSource;
        var transcript_claims: [program_mod.TRANSCRIPT_CLAIM_COUNT][4]M31 = undefined;
        for (claims, 0..) |claim, index| {
            transcript_claims[index] = .{
                claim.c0.a, claim.c0.b, claim.c1.a, claim.c1.b,
            };
        }
        // Row 45 consumes the same PFD1 digest limbs that row 39 emits. Its
        // hash witness must recompute them from the strong verifier's words.
        var provider_hash = try field_hash.HashV1.init(
            allocator,
            strong.field_snapshot.provider.words,
            provider_authority.DOMAIN,
            field_witness.PROVIDER_SCOPE,
            field_hash.PROVIDER_FIELD_DIGEST_KIND,
            field_hash.PROVIDER_STEP_BASE,
            strong.field_snapshot.provider.digest,
        );
        defer provider_hash.deinit();
        const sources = Sources{
            .metadata = try metadata.identityWords(),
            .link = try link.identityWords(),
            .metadata_digest = try canonicalDigest(try metadata.identity()),
            .link_digest = try canonicalDigest(link.identity),
            .local_authority = try canonicalDigest(prepared.capture.receipt.authority_id),
            .local_wire = try canonicalDigest(prepared.capture.receipt.wire_id),
            .local_receipt = try canonicalDigest(prepared.capture.receipt.identity),
            .fields = .{
                .program = try canonicalDigest(native_fields.program.digest),
                .preprocessed_root = try canonicalDigest(strong.field_snapshot.preprocessed_root),
                .provider_digest = try canonicalDigest(provider_hash.digest),
            },
            .transcript_claims = transcript_claims,
            .local_statement = prepared.capture.public_data.data.words(),
        };
        return build(allocator, program, &sources);
    }

    pub fn deinit(self: *WitnessV3) void {
        self.allocator.free(self.projection_values);
        self.allocator.free(self.source_values);
        self.* = undefined;
    }

    pub fn sourceRow(self: *const WitnessV3, program: *const program_mod.ProgramV2, index: usize) !source_air.Row {
        if (index >= self.source_values.len or index >= program.source_rows.len)
            return error.InvalidV3LeafSource;
        return program.source_rows[index].logical(self.source_values[index]);
    }

    pub fn projectionRow(self: *const WitnessV3, program: *const program_mod.ProgramV2, index: usize) !@import("air/ethereum_leaf_link_projection_v1.zig").Row {
        if (index >= self.projection_values.len or index >= program.projection_rows.len)
            return error.InvalidV3LeafProjection;
        return program.projection_rows[index].logical(self.projection_values[index]);
    }
};

fn build(allocator: std.mem.Allocator, program: *const program_mod.ProgramV2, sources: *const Sources) !WitnessV3 {
    try program.validate();
    const source_values = try allocator.alloc(M31, program.source_rows.len);
    errdefer allocator.free(source_values);
    const projection_values = try allocator.alloc(M31, program.projection_rows.len);
    errdefer allocator.free(projection_values);
    for (program.source_rows, source_values) |row, *destination|
        destination.* = try sourceValue(row, sources);
    for (program.projection_rows, projection_values) |row, *destination|
        destination.* = try projectionValue(row, sources);
    try checkRawMultiplicity(program);
    try checkProviderDigestMultiplicity(program);
    return .{ .allocator = allocator, .source_values = source_values, .projection_values = projection_values };
}

fn sourceValue(row: program_mod.SourceScheduleRowV1, sources: *const Sources) !M31 {
    if (row.active != 1) return error.InvalidV3LeafSource;
    if (row.raw_mask == 1) return raw(sources, row.scope, row.index_0);
    if (row.transcript_mask == 1) {
        if (row.kind != source_air.TRANSCRIPT_CLAIM_KIND or
            row.index_0 >= program_mod.TRANSCRIPT_CLAIM_COUNT or row.index_1 >= 4)
            return error.InvalidV3LeafSource;
        return sources.transcript_claims[row.index_0][row.index_1];
    }
    if (row.verifier_mask == 1) return verifier(sources, row.kind, row.index_0, row.index_1);
    return error.InvalidV3LeafSource;
}

fn projectionValue(row: program_mod.ProjectionScheduleRowV1, sources: *const Sources) !M31 {
    if (row.active != 1) return error.InvalidV3LeafProjection;
    const value = if (row.raw_mask == 1)
        try raw(sources, row.raw_scope, row.raw_index)
    else if (row.verifier_mask == 1)
        try verifier(sources, row.verifier_kind, row.verifier_index_0, row.verifier_index_1)
    else if (row.constant_source_mask == 1)
        M31.zero()
    else
        return error.InvalidV3LeafProjection;
    if (row.raw_join_mask == 1 and !value.eql(try raw(sources, row.raw_join_scope, row.raw_join_index)))
        return error.V3LeafRawJoinMismatch;
    if (row.raw_mask == 1 and row.verifier_mask == 1 and
        !value.eql(try verifier(sources, row.verifier_kind, row.verifier_index_0, row.verifier_index_1)))
        return error.V3LeafVerifierJoinMismatch;
    if (row.expected_mask == 1 and value.toU32() != row.expected)
        return error.V3LeafExpectedMismatch;
    if (row.local_statement_mask == 1) {
        if (row.statement_scope != @import("segment_leaf_authority_v2.zig").WIRE_SCOPE or
            row.statement_index >= sources.local_statement.len or
            !value.eql(sources.local_statement[row.statement_index]))
            return error.V3LeafLocalStatementMismatch;
    }
    if (row.global_statement_mask == 1 and row.statement_scope == source_air.GLOBAL_STATEMENT_SCOPE) {
        if (row.statement_index >= @import("span_statement.zig").SPAN_STATEMENT_CANONICAL_WORDS or
            !value.eql(sources.metadata[program_mod.METADATA_BASE_START + row.statement_index]))
            return error.V3LeafGlobalStatementMismatch;
    }
    return value;
}

fn raw(sources: *const Sources, scope: u32, index: u32) !M31 {
    if (scope == source_air.METADATA_SCOPE and index < sources.metadata.len)
        return sources.metadata[index];
    if (scope == source_air.LINK_SCOPE and index < sources.link.len)
        return sources.link[index];
    return error.InvalidV3LeafRawCoordinate;
}

fn verifier(sources: *const Sources, kind: u32, index_0: u32, index_1: u32) !M31 {
    if (index_0 != 0 or index_1 >= program_mod.DIGEST_WORD_COUNT)
        return error.InvalidV3LeafVerifierCoordinate;
    const digest: Digest = switch (kind) {
        source_air.METADATA_DIGEST_KIND => sources.metadata_digest,
        source_air.LINK_DIGEST_KIND => sources.link_digest,
        source_air.LOCAL_AUTHORITY_DIGEST_KIND => sources.local_authority,
        source_air.LOCAL_WIRE_DIGEST_KIND => sources.local_wire,
        source_air.LOCAL_RECEIPT_DIGEST_KIND => sources.local_receipt,
        source_air.PROGRAM_AUTHORITY_KIND => sources.fields.program,
        source_air.PREPROCESSED_ROOT_KIND => sources.fields.preprocessed_root,
        field_hash.PROVIDER_FIELD_DIGEST_KIND => sources.fields.provider_digest,
        else => return error.InvalidV3LeafVerifierCoordinate,
    };
    if (digest[index_1] >= core.fields.m31.Modulus)
        return error.InvalidV3LeafVerifierCoordinate;
    return M31.fromCanonical(digest[index_1]);
}

fn canonicalDigest(value: Digest) !Digest {
    for (value) |word| if (word >= core.fields.m31.Modulus)
        return error.InvalidV3LeafVerifierCoordinate;
    return value;
}

/// Source raw use counts must equal one hash-preimage use, every row-40
/// primary/secondary raw read, and the ten row-41 arithmetic reads. This is
/// exact for the two local raw scopes; other relation domains close later.
fn checkRawMultiplicity(program: *const program_mod.ProgramV2) !void {
    var metadata = [_]u32{1} ** metadata_mod.METADATA_IDENTITY_WORDS;
    var link = [_]u32{1} ** link_mod.IDENTITY_WORDS;
    for (program.projection_rows) |row| {
        if (row.raw_mask == 1) try increment(&metadata, &link, row.raw_scope, row.raw_index);
        if (row.raw_join_mask == 1) try increment(&metadata, &link, row.raw_join_scope, row.raw_join_index);
    }
    metadata[program_mod.METADATA_ENTRY_CONTINUATION_ROOT] += 1;
    metadata[program_mod.METADATA_EXIT_CONTINUATION_ROOT] += 1;
    metadata[program_mod.METADATA_COMPLETION_START] += 1;
    for (0..4) |offset| {
        metadata[program_mod.METADATA_GLOBAL_START + offset] += 1;
        metadata[program_mod.METADATA_GLOBAL_END + offset] += 1;
    }
    for (0..2) |offset| metadata[program_mod.METADATA_LOCAL_COUNT_START + offset] += 1;
    for (program.source_rows) |row| {
        if (row.raw_mask != 1) continue;
        const expected = if (row.scope == source_air.METADATA_SCOPE and row.index_0 < metadata.len)
            metadata[row.index_0]
        else if (row.scope == source_air.LINK_SCOPE and row.index_0 < link.len)
            link[row.index_0]
        else
            return error.InvalidV3LeafRawCoordinate;
        if (row.use_count != expected) return error.V3LeafRawMultiplicityMismatch;
    }
}

/// The PFD1 source emits each digest limb twice: once for row 40 and once for
/// row 45's field-hash `recursion_verifier_input_word` consumption. The latter
/// is checked by HashV1.init against the strong snapshot's provider words.
fn checkProviderDigestMultiplicity(program: *const program_mod.ProgramV2) !void {
    var source_count = [_]u32{0} ** program_mod.DIGEST_WORD_COUNT;
    var projection_count = [_]u32{0} ** program_mod.DIGEST_WORD_COUNT;
    for (program.source_rows) |row| {
        if (row.kind != field_hash.PROVIDER_FIELD_DIGEST_KIND) continue;
        if (row.active != 1 or row.verifier_mask != 1 or row.index_0 != 0 or
            row.index_1 >= source_count.len or row.use_count != 2)
            return error.V3ProviderDigestTupleMismatch;
        source_count[row.index_1] += 1;
    }
    for (program.projection_rows) |row| {
        if (row.verifier_kind != field_hash.PROVIDER_FIELD_DIGEST_KIND) continue;
        if (row.active != 1 or row.verifier_mask != 1 or
            row.verifier_index_0 != 0 or row.verifier_index_1 >= projection_count.len)
            return error.V3ProviderDigestTupleMismatch;
        projection_count[row.verifier_index_1] += 1;
    }
    for (source_count, projection_count) |sources, projections|
        if (sources != 1 or projections != 1)
            return error.V3ProviderDigestTupleMismatch;
}

fn increment(metadata: *[metadata_mod.METADATA_IDENTITY_WORDS]u32, link: *[link_mod.IDENTITY_WORDS]u32, scope: u32, index: u32) !void {
    if (scope == source_air.METADATA_SCOPE and index < metadata.len) {
        metadata[index] += 1;
    } else if (scope == source_air.LINK_SCOPE and index < link.len) {
        link[index] += 1;
    } else return error.InvalidV3LeafRawCoordinate;
}

test "row 39 and 40 exact raw multiplicity matches hash and arithmetic consumers" {
    var program = try program_mod.ProgramV2.init(std.testing.allocator);
    defer program.deinit();
    try checkRawMultiplicity(&program);
    try checkProviderDigestMultiplicity(&program);
    program.source_rows[0].use_count += 1;
    try std.testing.expectError(error.V3LeafRawMultiplicityMismatch, checkRawMultiplicity(&program));
}

test "row 39 provider digest emission cannot lose its second consumer" {
    var program = try program_mod.ProgramV2.init(std.testing.allocator);
    defer program.deinit();
    const first = program_mod.SOURCE_ROW_COUNT - program_mod.DIGEST_WORD_COUNT;
    program.source_rows[first].use_count = 1;
    try std.testing.expectError(error.V3ProviderDigestTupleMismatch, checkProviderDigestMultiplicity(&program));
    program.source_rows[first].use_count = 2;
    program.source_rows[first].active = 0;
    try std.testing.expectError(error.V3ProviderDigestTupleMismatch, checkProviderDigestMultiplicity(&program));
    program.source_rows[first].active = 1;
    try checkProviderDigestMultiplicity(&program);
}

test "row 40 rejects a mutated typed raw join" {
    var sources: Sources = undefined;
    @memset(&sources.metadata, M31.zero());
    @memset(&sources.link, M31.zero());
    sources.link[0] = M31.fromCanonical(link_mod.FORMAT_VERSION);
    sources.link[1] = M31.fromCanonical(link_mod.SCHEMA_VERSION);
    sources.metadata[program_mod.METADATA_SEGMENT_INDEX_START] = M31.fromCanonical(7);
    sources.link[34] = M31.fromCanonical(8);
    const row = program_mod.ProjectionScheduleRowV1{
        .active = 1,
        .raw_mask = 1,
        .verifier_mask = 0,
        .constant_source_mask = 0,
        .global_statement_mask = 0,
        .local_statement_mask = 0,
        .expected_mask = 0,
        .raw_scope = source_air.LINK_SCOPE,
        .raw_index = 34,
        .raw_join_mask = 1,
        .raw_join_scope = source_air.METADATA_SCOPE,
        .raw_join_index = program_mod.METADATA_SEGMENT_INDEX_START,
        .verifier_kind = 0,
        .verifier_index_0 = 0,
        .verifier_index_1 = 0,
        .statement_scope = 0,
        .statement_index = 0,
        .expected = 0,
    };
    try std.testing.expectError(error.V3LeafRawJoinMismatch, projectionValue(row, &sources));
}

test "row 40 rejects verifier and local-statement tuple mutations" {
    const zero = M31.zero();
    const zero_digest: Digest = .{0} ** program_mod.DIGEST_WORD_COUNT;
    const local_statement = [_]M31{zero} ** 64;
    var sources = Sources{
        .metadata = .{zero} ** metadata_mod.METADATA_IDENTITY_WORDS,
        .link = .{zero} ** link_mod.IDENTITY_WORDS,
        .metadata_digest = zero_digest,
        .link_digest = zero_digest,
        .local_authority = zero_digest,
        .local_wire = zero_digest,
        .local_receipt = zero_digest,
        .fields = .{
            .program = zero_digest,
            .preprocessed_root = zero_digest,
            .provider_digest = zero_digest,
        },
        .transcript_claims = .{.{ zero, zero, zero, zero }} ** program_mod.TRANSCRIPT_CLAIM_COUNT,
        .local_statement = &local_statement,
    };
    sources.link[2] = M31.fromCanonical(1);
    const verifier_join = program_mod.ProjectionScheduleRowV1{
        .active = 1,
        .raw_mask = 1,
        .verifier_mask = 1,
        .constant_source_mask = 0,
        .global_statement_mask = 0,
        .local_statement_mask = 0,
        .expected_mask = 0,
        .raw_scope = source_air.LINK_SCOPE,
        .raw_index = 2,
        .raw_join_mask = 0,
        .raw_join_scope = 0,
        .raw_join_index = 0,
        .verifier_kind = source_air.METADATA_DIGEST_KIND,
        .verifier_index_0 = 0,
        .verifier_index_1 = 0,
        .statement_scope = 0,
        .statement_index = 0,
        .expected = 0,
    };
    try std.testing.expectError(error.V3LeafVerifierJoinMismatch, projectionValue(verifier_join, &sources));
    const local_join = program_mod.ProjectionScheduleRowV1{
        .active = 1,
        .raw_mask = 1,
        .verifier_mask = 0,
        .constant_source_mask = 0,
        .global_statement_mask = 0,
        .local_statement_mask = 1,
        .expected_mask = 0,
        .raw_scope = source_air.LINK_SCOPE,
        .raw_index = 2,
        .raw_join_mask = 0,
        .raw_join_scope = 0,
        .raw_join_index = 0,
        .verifier_kind = 0,
        .verifier_index_0 = 0,
        .verifier_index_1 = 0,
        .statement_scope = @import("segment_leaf_authority_v2.zig").WIRE_SCOPE,
        .statement_index = 0,
        .expected = 0,
    };
    try std.testing.expectError(error.V3LeafLocalStatementMismatch, projectionValue(local_join, &sources));
}

test "row 39 and 40 materialize the complete typed schedule" {
    var program = try program_mod.ProgramV2.init(std.testing.allocator);
    defer program.deinit();
    const zero = M31.zero();
    const zero_digest: Digest = .{0} ** program_mod.DIGEST_WORD_COUNT;
    const local_statement = [_]M31{zero} ** 4096;
    var sources = Sources{
        .metadata = .{zero} ** metadata_mod.METADATA_IDENTITY_WORDS,
        .link = .{zero} ** link_mod.IDENTITY_WORDS,
        .metadata_digest = zero_digest,
        .link_digest = zero_digest,
        .local_authority = zero_digest,
        .local_wire = zero_digest,
        .local_receipt = zero_digest,
        .fields = .{
            .program = zero_digest,
            .preprocessed_root = zero_digest,
            .provider_digest = zero_digest,
        },
        .transcript_claims = .{.{ zero, zero, zero, zero }} ** program_mod.TRANSCRIPT_CLAIM_COUNT,
        .local_statement = &local_statement,
    };
    sources.link[0] = M31.fromCanonical(link_mod.FORMAT_VERSION);
    sources.link[1] = M31.fromCanonical(link_mod.SCHEMA_VERSION);
    var witness = try build(std.testing.allocator, &program, &sources);
    defer witness.deinit();
    try std.testing.expectEqual(program_mod.SOURCE_ROW_COUNT, witness.source_values.len);
    try std.testing.expectEqual(program_mod.PROJECTION_ROW_COUNT, witness.projection_values.len);
    _ = try witness.sourceRow(&program, 0);
    _ = try witness.projectionRow(&program, 0);
    sources.link[34] = M31.fromCanonical(1);
    try std.testing.expectError(error.V3LeafRawJoinMismatch, build(std.testing.allocator, &program, &sources));
}

comptime {
    if (program_mod.SOURCE_ROW_COUNT != 794 or program_mod.PROJECTION_ROW_COUNT != 1093 or
        program_mod.TRANSCRIPT_CLAIM_COUNT != 28 or segment_v2.FORMAT_VERSION != 2)
        @compileError("V3 leaf source/projection geometry drifted");
}
