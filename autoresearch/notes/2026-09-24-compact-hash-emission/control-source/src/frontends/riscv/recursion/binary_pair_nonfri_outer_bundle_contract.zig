//! Internal binary pair nonfri outer bundle authority shard; use binary_pair_nonfri_outer_bundle.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const fixed_wire = @import("fixed_wire.zig");
pub const pair_authority = @import("binary_pair_authority.zig");
pub const pair_node = @import("pair_node.zig");
pub const transcript_source_mod = @import("binary_transcript_outer_source.zig");
pub const statement_source = @import("outer_parent_statement_air_source.zig");
pub const statement_parent_source = @import("outer_parent_statement_source.zig");
pub const statement_transcript_source = @import("outer_parent_transcript_source.zig");
pub const statement_authority_mod = @import("segment_statement_outer_source.zig");
pub const range_authority = @import("outer_parent_range_authority.zig");
pub const inactive_source_mod = @import("binary_inactive_outer_source.zig");
pub const public_authority_mod = @import("segment_public_outer_source.zig");
pub const leaf_authority = @import("segment_leaf_authority.zig");
pub const global_closure = @import("binary_global_closure_outer_source.zig");

pub const air = @import("air/mod.zig");
pub const manifest_mod = air.universal_adapter_manifest;
pub const relation_interaction = air.relation_interaction;
pub const roster = air.universal_roster;
pub const schedule = air.verifier_schedule;
pub const shared_provider = air.universal_shared_provider;
pub const universal = air.universal_challenges;
pub const universal_manifest = air.universal_manifest;
pub const lowering = air.verifier_arithmetic_lowering;
pub const relation = @import("../air/lang/relation.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const GENERATED_FORMAT_VERSION: u16 = 1;
pub const AUDITED_FORMAT_VERSION: u16 = 1;
pub const FIRST_PREFIX_ROW: usize = @intFromEnum(roster.Component.control);
pub const PREFIX_ROW_COUNT: usize = 18;
pub const LAST_PREFIX_ROW: usize = @intFromEnum(
    roster.Component.vm_public_logup_control,
);
pub const SHARED_PROVIDER_ROW: usize = @intFromEnum(
    roster.Component.range_check_8_8,
);
pub const OWNED_ROW_COUNT: usize = PREFIX_ROW_COUNT + 1;

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const WHOLE_FRONTEND_VERIFIED = false;
pub const COMPLETE_PARENT_STARK_VERIFIED = false;
pub const PRODUCTION_ACTIVATION = false;

/// Current source costs. The bundle itself performs no heap allocation.
/// Rows 12--17 still inherit their source's transactional staging cost.
pub const HOT_BUNDLE_OVERHEAD_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_TREE_HEAP_ALLOCATIONS = [manifest_mod.TREE_COUNT]usize{
    transcript_source_mod.HOT_REUSED_TREE_HEAP_ALLOCATIONS[0] +
        statement_source.HOT_TRACE_HEAP_ALLOCATIONS +
        inactive_source_mod.HOT_TREE_HEAP_ALLOCATIONS[0],
    transcript_source_mod.HOT_REUSED_TREE_HEAP_ALLOCATIONS[1] +
        statement_source.HOT_TRACE_HEAP_ALLOCATIONS +
        inactive_source_mod.HOT_TREE_HEAP_ALLOCATIONS[1],
    transcript_source_mod.HOT_REUSED_TREE_HEAP_ALLOCATIONS[2] +
        statement_source.HOT_TRACE_HEAP_ALLOCATIONS +
        inactive_source_mod.HOT_TREE_HEAP_ALLOCATIONS[2],
};
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS: usize =
    HOT_TREE_HEAP_ALLOCATIONS[0] + HOT_TREE_HEAP_ALLOCATIONS[1] +
    HOT_TREE_HEAP_ALLOCATIONS[2];
pub const HOT_TREE_PAIR_AUTHENTICATIONS =
    [_]usize{0} ** manifest_mod.TREE_COUNT;
pub const HOT_ALL_TREES_PAIR_AUTHENTICATIONS: usize = 0;
pub const GENERATED_RECEIPT_HEAP_ALLOCATIONS: usize = 0;
pub const AUDITED_HANDOFF_HEAP_ALLOCATIONS: usize = 0;

/// Exact successful-preflight work per committed tree. `Manifest.placement`
/// revalidates and rehashes all 36 rows, so the hot boundary must never use it
/// after the one explicit validation. Nineteen reads check owned geometry and
/// fresh-zero storage; three reads prepare the prefix/provider range ends.
pub const HOT_PREFLIGHT_MANIFEST_VALIDATIONS_PER_TREE: usize = 1;
pub const HOT_PREFLIGHT_DIRECT_PLACEMENT_READS_PER_TREE: usize =
    OWNED_ROW_COUNT + 3;
pub const HOT_PREFLIGHT_OWNERSHIP_RANGES_PER_TREE: usize = 2;
pub const HOT_ALIAS_LOOP_PLACEMENT_READS_PER_TREE: usize = 0;
/// Rollback runs only after a successful preflight, so it may use the same
/// authenticated placement table without another manifest hash.
pub const HOT_ROLLBACK_DIRECT_PLACEMENT_READS_PER_TREE: usize = OWNED_ROW_COUNT;

/// The prover/generator custody path is implemented below. Independent
/// verifier custody must not be simulated with caller-authored claims.
pub const VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED = false;

pub const BUNDLE_ID_DOMAIN =
    "stwo-zig/typed-air/binary-pair-nonfri-bundle/v1\x00";
pub const GENERATED_ID_DOMAIN =
    "stwo-zig/typed-air/binary-pair-nonfri-generated/v1\x00";
pub const AUDITED_ID_DOMAIN =
    "stwo-zig/typed-air/binary-pair-nonfri-audited/v1\x00";

pub const Error = error{
    ArithmeticOverflow,
    AuditClaimMismatch,
    AuditIdentityMismatch,
    BundleIdentityMismatch,
    CrossCustodyMismatch,
    DestinationAlias,
    DestinationNotZero,
    GeneratedIdentityMismatch,
    InvalidAuditGeometry,
    InvalidTreeIndex,
    InvalidTraceShape,
    NonCanonicalField,
    ProviderAuthorityMismatch,
    ProviderDomainMismatch,
    ProviderSnapshotMismatch,
    RangeRequestClosureMismatch,
    VerifierAuditCustodyUnavailable,
};

pub const Claims = struct {
    transcript: transcript_source_mod.Claims,
    statement: statement_source.Claims,
    inactive: inactive_source_mod.Claims,

    pub fn validate(self: Claims) !void {
        try self.statement.verifyRangeClosure();
        try self.inactive.validateInactive();
        for (self.prefixValues()) |value| try requireCanonical(value);
        try requireCanonical(self.statement.range_check);
        try requireCanonical(self.statement.range_requests);
    }

    /// Exact proof-visible values for rows 0--17 in universal-roster order.
    pub fn prefixValues(self: Claims) [PREFIX_ROW_COUNT]QM31 {
        var result: [PREFIX_ROW_COUNT]QM31 = undefined;
        const transcript = self.transcript.asArray();
        const statement = self.statement.rosterValues();
        const inactive = self.inactive.asArray();
        @memcpy(result[0..10], &transcript);
        result[10] = statement[0];
        result[11] = statement[1];
        @memcpy(result[12..18], &inactive);
        return result;
    }

    pub fn sharedProviderValue(self: Claims) QM31 {
        return self.statement.range_check;
    }

    /// Prover-only diagnostic reconstructed from the row-11 request side.
    pub fn sharedProviderRequestContribution(self: Claims) QM31 {
        return self.statement.range_requests;
    }

    pub fn bindPrefixInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        for (self.transcript.asArray(), 0..) |value, index|
            try vector.bind(@enumFromInt(FIRST_PREFIX_ROW + index), value);
        try vector.bind(.statement_input, self.statement.statement_input);
        try vector.bind(
            .statement_semantics_input,
            self.statement.statement_semantics,
        );
        try self.inactive.bindInto(vector);
    }

    pub fn bindSharedProviderInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try vector.bind(.range_check_8_8, self.statement.range_check);
    }

    pub fn bindInto(self: Claims, vector: *manifest_mod.ClaimVector) !void {
        try self.bindPrefixInto(vector);
        try self.bindSharedProviderInto(vector);
    }
};

pub const DomainAudits = struct {
    transcript: transcript_source_mod.DomainAudits,
    statement: statement_source.DomainAudits,
    inactive: inactive_source_mod.DomainAudits,

    pub fn prefixValues(self: *const DomainAudits) [PREFIX_ROW_COUNT]relation_interaction.DomainAudit {
        var result: [PREFIX_ROW_COUNT]relation_interaction.DomainAudit = undefined;
        @memcpy(result[0..10], &self.transcript);
        result[10] = self.statement.statement_input;
        result[11] = self.statement.statement_semantics;
        @memcpy(result[12..18], &self.inactive);
        return result;
    }

    pub fn sharedProvider(self: *const DomainAudits) relation_interaction.DomainAudit {
        return self.statement.range_check;
    }

    /// Exact audited request-side contribution which row 35 must cancel.
    pub fn sharedProviderRequestContribution(self: *const DomainAudits) QM31 {
        var result = QM31.zero();
        const domain_index = @intFromEnum(relation.Domain.range_check_8_8);
        for (self.prefixValues()) |audit|
            result = result.add(audit.values[domain_index]);
        return result;
    }

    pub fn validateAgainst(self: *const DomainAudits, claims: Claims) !void {
        try claims.validate();
        const values = self.prefixValues();
        const claim_values = claims.prefixValues();
        for (values, claim_values, 0..) |audit, claim, row|
            try validateAudit(audit, claim, row);
        try validateAudit(
            self.statement.range_check,
            claims.statement.range_check,
            SHARED_PROVIDER_ROW,
        );

        const provider_domain = @intFromEnum(relation.Domain.range_check_8_8);
        for (self.statement.range_check.values, 0..) |value, index| {
            if (index != provider_domain and !value.isZero())
                return error.ProviderDomainMismatch;
        }
        if (!self.statement.range_check.values[provider_domain].eql(
            claims.statement.range_check,
        )) return error.ProviderDomainMismatch;

        const requests = self.sharedProviderRequestContribution();
        if (!requests.eql(claims.statement.range_requests))
            return error.AuditClaimMismatch;
        if (!requests.add(self.statement.range_check.total).isZero())
            return error.RangeRequestClosureMismatch;
    }

    pub fn prefixRowClaims(self: *const DomainAudits) [PREFIX_ROW_COUNT]global_closure.RowClaimsV1 {
        var result: [PREFIX_ROW_COUNT]global_closure.RowClaimsV1 = undefined;
        for (&result, self.prefixValues(), 0..) |*destination, audit, row|
            destination.* = rowClaim(@enumFromInt(row), audit);
        return result;
    }
};

/// Pointer-free receipt emitted only after all three real generators commit.
pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = GENERATED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    bundle_id: [32]u8,
    provider_source_authority_id: [32]u8,
    provider_snapshot_id: [32]u8,
    claims: Claims,
    identity: [32]u8,

    pub fn validateAgainst(self: *const GeneratedInteractionsV1, bundle: anytype) !void {
        try bundle.validate();
        if (self.format_version != GENERATED_FORMAT_VERSION or
            !allZero(&self.padding))
        {
            return error.GeneratedIdentityMismatch;
        }
        if (!std.mem.eql(u8, &self.bundle_id, &bundle.authority_seal))
            return error.BundleIdentityMismatch;
        try bundle.validateProviderIdentity(
            self.provider_source_authority_id,
            self.provider_snapshot_id,
        );
        try self.claims.validate();
        if (!std.mem.eql(u8, &self.identity, &generatedIdentity(self)))
            return error.GeneratedIdentityMismatch;
    }
};

/// Pointer-free, verifier-ready handoff for rows 0--17 and row 35. It is not
/// a complete global closure: rows 18--34 must be inserted by the FRI owner.
pub const AuditedInteractionsV1 = struct {
    format_version: u16 = AUDITED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    generated: GeneratedInteractionsV1,
    audits: DomainAudits,
    prefix_rows: [PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
    provider_claim: global_closure.ProviderClaimV1,
    identity: [32]u8,

    pub fn validateAgainst(self: *const AuditedInteractionsV1, bundle: anytype) !void {
        if (self.format_version != AUDITED_FORMAT_VERSION or
            !allZero(&self.padding))
        {
            return error.AuditIdentityMismatch;
        }
        try self.generated.validateAgainst(bundle);
        try self.audits.validateAgainst(self.generated.claims);
        const expected_rows = self.audits.prefixRowClaims();
        for (self.prefix_rows, expected_rows) |actual, expected|
            try requireRowClaimEqual(actual, expected);
        try self.provider_claim.validate();
        if (!std.mem.eql(
            u8,
            &self.provider_claim.source_authority_id,
            &self.generated.provider_source_authority_id,
        ) or !std.mem.eql(
            u8,
            &self.provider_claim.snapshot_id,
            &self.generated.provider_snapshot_id,
        ) or !self.provider_claim.claimed_sum.eql(
            self.generated.claims.statement.range_check,
        )) return error.ProviderSnapshotMismatch;
        if (!std.mem.eql(u8, &self.identity, &auditedIdentity(self)))
            return error.AuditIdentityMismatch;
    }
};

pub const Components = struct {
    transcript: transcript_source_mod.Components,
    statement: statement_source.Components,
    inactive: inactive_source_mod.Components,

    pub fn appendPrefixToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try self.transcript.appendToGate(manifest, gate);
        try gate.append(
            manifest,
            try self.statement.statement_input.binding(manifest),
        );
        try gate.append(
            manifest,
            try self.statement.statement_semantics.binding(manifest),
        );
        try self.inactive.appendToGate(manifest, gate);
    }

    pub fn appendSharedProviderToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(
            manifest,
            try self.statement.range_check.binding(manifest),
        );
    }
};

pub const VerifierDomainAuditAdapterV1 = struct {
    pub const available = VERIFIER_DOMAIN_AUDIT_CUSTODY_EXPOSED;

    /// Deliberately unavailable until the independent verifier publishes an
    /// authenticated `DomainAudit` and provider-snapshot receipt. Callers may
    /// not substitute the generator receipt for verifier custody.
    pub fn admit() error{VerifierAuditCustodyUnavailable}!void {
        return error.VerifierAuditCustodyUnavailable;
    }
};

pub fn validateAudit(
    audit: relation_interaction.DomainAudit,
    claim: QM31,
    row: usize,
) !void {
    if (row >= roster.COMPONENT_COUNT) return error.InvalidAuditGeometry;
    var total = QM31.zero();
    for (audit.values) |value| {
        try requireCanonical(value);
        total = total.add(value);
    }
    try requireCanonical(audit.total);
    try requireCanonical(claim);
    if (!total.eql(audit.total) or !audit.total.eql(claim))
        return error.AuditClaimMismatch;
}

pub fn rowClaim(
    row: roster.Component,
    audit: relation_interaction.DomainAudit,
) global_closure.RowClaimsV1 {
    var domains: [global_closure.DOMAIN_COUNT]global_closure.DomainClaimV1 = undefined;
    for (&domains, audit.values, 0..) |*destination, value, index| {
        destination.* = .{
            .active = @intFromBool(!value.isZero()),
            .domain = @enumFromInt(index),
            .value = value,
        };
    }
    return .{
        .row = row,
        .domains = domains,
        .claimed_sum = audit.total,
    };
}

pub fn requireRowClaimEqual(
    actual: global_closure.RowClaimsV1,
    expected: global_closure.RowClaimsV1,
) !void {
    if (actual.format_version != expected.format_version or
        actual.present != expected.present or actual.padding != expected.padding or
        actual.row != expected.row or actual.domain_count != expected.domain_count or
        !std.meta.eql(actual.header_padding, expected.header_padding) or
        !actual.claimed_sum.eql(expected.claimed_sum))
    {
        return error.AuditIdentityMismatch;
    }
    for (actual.domains, expected.domains) |left, right| {
        if (left.present != right.present or left.active != right.active or
            !std.meta.eql(left.padding, right.padding) or left.domain != right.domain or
            !left.value.eql(right.value))
        {
            return error.AuditIdentityMismatch;
        }
    }
}

pub fn validateCrossCustody(input: anytype) !void {
    const transcript = input.transcript_prepared;
    const statement = input.statement_prepared;
    const parent = input.statement_parent;
    if (!m31SlicesEql(&transcript.left_words, &statement.left_words) or
        !m31SlicesEql(&transcript.right_words, &statement.right_words) or
        !m31SlicesEql(&transcript.parent_words, &statement.parent_words) or
        !contextEql(transcript.authority.context, parent.transcript.context))
    {
        return error.CrossCustodyMismatch;
    }
    for (transcript.authority.children, parent.transcript.children, 0..) |left, right, index| {
        if (left.position != right.position or left.role != right.role or
            left.leaf_index != right.leaf_index or left.pair_index != right.pair_index or
            !std.meta.eql(left.session_id, right.session_id) or
            !std.meta.eql(left.parent_vk_id, right.parent_vk_id) or
            !std.meta.eql(left.statement_id, right.statement_id) or
            !std.meta.eql(left.summary_id, right.summary_id) or
            left.event_count != right.event_count or
            !std.meta.eql(left.signed_relation_total, right.signed_relation_total) or
            !m31SlicesEql(
                if (index == 0) &transcript.left_words else &transcript.right_words,
                &right.statement_words,
            ))
        {
            return error.CrossCustodyMismatch;
        }
        if (!std.meta.eql(
            statement.public.child_statement_ids[index],
            left.statement_id,
        )) return error.CrossCustodyMismatch;
    }
    if (!std.meta.eql(
        statement.public.execution_statement_id,
        transcript.authority.context.execution_statement_id,
    ) or !std.meta.eql(
        statement.public.parent_vk_id,
        transcript.authority.context.aggregator_vk_id,
    )) return error.CrossCustodyMismatch;
}

pub fn contextEql(
    left: pair_node.VerifierContextV1,
    right: statement_transcript_source.BoundContextV1,
) bool {
    return std.meta.eql(left.session_id, right.session_id) and
        std.meta.eql(left.job_id, right.job_id) and
        std.meta.eql(left.execution_statement_id, right.execution_statement_id) and
        std.meta.eql(left.public_call_commitment, right.public_call_commitment) and
        left.event_count == right.event_count and
        left.session_leaf_count == right.session_leaf_count and
        left.pair_index == right.pair_index and
        std.meta.eql(left.aggregator_vk_id, right.parent_vk_id);
}

pub fn validateProviderFromInputs(input: anytype) !void {
    const expected = range_authority.SourceAuthority.pinned();
    expected.validate() catch return error.ProviderAuthorityMismatch;
    input.statement_prepared.range.validateAgainst(
        &input.statement_workspace.range,
        .{
            .preprocessing = &input.statement_authority.statement_semantics_preprocessing,
            .values = input.statement_prepared.statement_values,
            .left = &input.statement_prepared.left_words,
            .right = &input.statement_prepared.right_words,
            .parent = &input.statement_prepared.parent_words,
        },
    ) catch return error.ProviderSnapshotMismatch;
    if (!std.mem.eql(
        u8,
        &input.statement_prepared.range.source_authority_digest,
        &expected.identityDigest(),
    )) return error.ProviderAuthorityMismatch;
    const batch = input.statement_prepared.range.provider();
    batch.validate() catch return error.ProviderSnapshotMismatch;
}

pub fn providerSourceAuthorityId(input: anytype) [32]u8 {
    return input.statement_prepared.range.source_authority_digest;
}

pub fn providerSnapshotId(input: anytype) [32]u8 {
    return input.statement_prepared.range.provider().authority_digest;
}

pub fn installedLogSizes(bundle: anytype) universal_manifest.LogSizes {
    var logs = [_]u32{0} ** roster.COMPONENT_COUNT;
    bundle.inputs.transcript_source.installLogSizes(&logs);
    statement_source.installLogSizes(bundle.inputs.statement_authority, &logs);
    bundle.inputs.inactive_source.installLogSizes(&logs);
    return logs;
}

pub fn generatedIdentity(receipt: *const GeneratedInteractionsV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_ID_DOMAIN);
    hashInt(&hash, u16, receipt.format_version);
    hash.update(&receipt.bundle_id);
    hash.update(&receipt.provider_source_authority_id);
    hash.update(&receipt.provider_snapshot_id);
    hashClaims(&hash, receipt.claims);
    return hash.finalResult();
}

pub fn auditedIdentity(receipt: *const AuditedInteractionsV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDITED_ID_DOMAIN);
    hashInt(&hash, u16, receipt.format_version);
    hash.update(&receipt.generated.identity);
    hashDomainAudits(&hash, &receipt.audits);
    for (receipt.prefix_rows) |row| hashRowClaim(&hash, row);
    hash.update(&receipt.provider_claim.identity);
    return hash.finalResult();
}

pub fn hashClaims(hash: anytype, claims: Claims) void {
    for (claims.transcript.asArray()) |value| hashQm31(hash, value);
    hashQm31(hash, claims.statement.statement_input);
    hashQm31(hash, claims.statement.statement_semantics);
    hashQm31(hash, claims.statement.range_check);
    hashQm31(hash, claims.statement.range_requests);
    for (claims.inactive.asArray()) |value| hashQm31(hash, value);
}

pub fn hashDomainAudits(hash: anytype, audits: *const DomainAudits) void {
    for (audits.prefixValues()) |audit| hashAudit(hash, audit);
    hashAudit(hash, audits.statement.range_check);
}

pub fn hashAudit(hash: anytype, audit: relation_interaction.DomainAudit) void {
    for (audit.values) |value| hashQm31(hash, value);
    hashQm31(hash, audit.total);
    hashInt(hash, u64, audit.logical_rows);
    hashInt(hash, u64, audit.event_terms);
}

pub fn hashRowClaim(hash: anytype, row: global_closure.RowClaimsV1) void {
    hashInt(hash, u16, row.format_version);
    hashInt(hash, u8, row.present);
    hashInt(hash, u8, @intFromEnum(row.row));
    hashInt(hash, u8, row.domain_count);
    for (row.domains) |claim| {
        hashInt(hash, u8, claim.present);
        hashInt(hash, u8, claim.active);
        hashInt(hash, u8, @intFromEnum(claim.domain));
        hashQm31(hash, claim.value);
    }
    hashQm31(hash, row.claimed_sum);
}

pub fn hashStatementWords(hash: anytype, words: []const M31) void {
    hashInt(hash, u32, words.len);
    for (words) |word| hashInt(hash, u32, word.toU32());
}

pub fn hashDigestWords(hash: anytype, digest: [8]u32) void {
    for (digest) |word| hashInt(hash, u32, word);
}

pub fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

pub fn m31SlicesEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}
