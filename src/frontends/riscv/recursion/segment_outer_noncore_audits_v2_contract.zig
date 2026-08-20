//! Internal segment outer noncore audits v2 authority shard; use segment_outer_noncore_audits_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const relation = @import("../air/lang/relation.zig");
pub const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const range_bridge = @import("air/range_check_8_8_bridge.zig");
pub const shared_provider = @import("air/universal_shared_provider.zig");

pub const control_air = @import("air/control.zig");
pub const transcript_air = @import("air/transcript_air.zig");
pub const transcript_binding_air = @import("air/transcript_binding.zig");
pub const transcript_state_air = @import("air/transcript_state.zig");
pub const transcript_word_air = @import("air/transcript_word.zig");
pub const transcript_payload_air = @import("air/transcript_payload.zig");
pub const pow_check_air = @import("air/pow_check.zig");
pub const pow_frame_air = @import("air/pow_frame.zig");
pub const relation_challenge_air = @import("air/relation_challenge.zig");
pub const verifier_randomness_air = @import("air/verifier_randomness.zig");
pub const statement_input_air = @import("air/statement_input.zig");
pub const public_air = @import("air/segment_public_outer_air_v2.zig");
pub const row17_air_v2 = @import("air/vm_public_logup_control_v2.zig");
pub const row17_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");

pub const transcript_source = @import("segment_transcript_outer_source_v2.zig");
pub const transcript_components = @import("segment_transcript_outer_components_v2.zig");
pub const statement_source = @import("segment_statement_outer_source_v2.zig");
pub const statement_components = @import("segment_statement_outer_components_v2.zig");
pub const public_source = @import("segment_public_outer_source_v2.zig");
pub const public_components = @import("segment_public_outer_components_v2.zig");
pub const range_authority = @import("segment_range_authority_v2.zig");
pub const boundary_authority = @import("segment_leaf_outer_authority_v2.zig");
pub const boundary_air = @import("segment_leaf_outer_air_v2.zig");
pub const input_provider_authority =
    @import("segment_publication_input_provider_authority_v2.zig");
pub const input_provider_air =
    @import("air/segment_publication_input_provider_v2.zig");
pub const input_provider_witness =
    @import("air/segment_publication_input_provider_witness_v2.zig");
pub const vm_leaf_context = @import("vm_leaf_context.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const DOMAIN_COUNT: usize = universal.RELATION_COUNT;
pub const NONCORE_ROW_COUNT: usize = 22;
pub const CORE_FIRST_ROW: usize = 18;
pub const CORE_LAST_ROW: usize = 34;
pub const CORE_ROW_COUNT: usize = CORE_LAST_ROW - CORE_FIRST_ROW + 1;
pub const NONCORE_ROW_INDICES = [_]u8{
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 35, 36,
    37, 38,
};
pub const NONCORE_ROW_MASK: u64 = rangeMask(0, 18) |
    componentBit(35) | componentBit(36) | componentBit(37) |
    componentBit(38);
pub const CORE_ROW_MASK: u64 = rangeMask(CORE_FIRST_ROW, CORE_LAST_ROW + 1);
pub const ALL_ROW_MASK: u64 = rangeMask(0, COMPONENT_COUNT);

/// `auditPreparedDomainSums` makes two bounded temporary allocations per
/// typed framework plan. Eighteen rows use that path. The single-domain range
/// provider, the two prepared boundary-domain receipts, and the committed
/// verifier-input provider receipt allocate nothing.
pub const COLD_TYPED_AUDIT_ALLOCATION_CALLS: usize = 2 * (10 + 2 + 6);
pub const HOT_AUDIT_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_INSTALL_HEAP_ALLOCATIONS: usize = 0;
pub const REBUILD_AND_INSTALL_REDUNDANT_AUDIT_PASSES: usize = 0;
pub const FAILS_BEFORE_FIRST_EXTERNAL_WRITE = true;
pub const NONCORE_AUDITS_AVAILABLE = true;
pub const WHOLE_COHORT_AUDITS_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROW17_LOGICAL_ROWS: usize = row17_witness_v2.LOGICAL_ROW_COUNT;
pub const ROW17_TYPED_EVENT_TERMS: usize =
    ROW17_LOGICAL_ROWS * row17_air_v2.RELATION_EVENT_COUNT;
pub const ROW17_ACTIVE_RELATION_EVENTS: usize =
    row17_witness_v2.ACTIVE_RELATION_EVENT_COUNT;

pub const RECEIPT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-noncore-audits/v1\x00";
pub const RELATION_CONTEXT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-noncore-relations/v1\x00";
pub const BOUNDARY_RELATION_CONTEXT_DOMAIN =
    "stwo-zig/typed-air/segment-leaf-outer-v2/relations/v1\x00";

pub const Error = error{
    AliasedDestination,
    ArithmeticOverflow,
    AuditIdentityMismatch,
    AuditRowMismatch,
    BoundaryRelationContextMismatch,
    ClaimMismatch,
    ComponentMaskOverlap,
    InvalidAuditGeometry,
    NonCanonicalField,
    ProviderDomainMismatch,
    RelationContextMismatch,
    UnsupportedWholeCohort,
};

pub const TranscriptInputsV2 = struct {
    owner: *const transcript_components.Source,
    workspace: *const transcript_components.Workspace,
    prepared: *const transcript_source.PreparedV2,
    claims: transcript_components.Claims,
};

pub const StatementInputsV2 = struct {
    authority: *const statement_components.AuthorityV2,
    prepared: *const statement_source.PreparedV2,
    logical_rows: []const statement_source.Air.Row,
    claims: statement_components.ClaimsV2,
};

pub const PublicInputsV2 = struct {
    owner: *const public_components.Source,
    workspace: *const public_components.Workspace,
    prepared: *const public_source.PreparedV2,
    claims: public_components.Claims,
};

pub const RangeInputsV2 = struct {
    authority: *const range_authority.ProviderAuthorityV2,
    prepared: *const range_authority.PreparedV2,
    sources: range_authority.SourcesV2,
    provider_relations: *const shared_provider.SharedProviderRelations,
    interaction: *const range_authority.ProviderInteractionV2,
};

/// This must be the independently rebuilt capture-backed boundary authority,
/// never the source-preflight-only `PreparedOuterAuthorityV2`.
pub const BoundaryInputsV2 = struct {
    authority: *const boundary_authority.AuthorityV2,
    prepared: *const boundary_authority.PreparedNativeVerifierOuterAuthorityV2,
};

pub const VerifierInputProviderInputsV2 = struct {
    authority: *const input_provider_authority.AuthorityV2,
    prepared: *const input_provider_authority.PreparedAuthorityV2,
    vm_context: *const vm_leaf_context.Context,
};

pub const InputsV2 = struct {
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    transcript: TranscriptInputsV2,
    statement: StatementInputsV2,
    public: PublicInputsV2,
    range: RangeInputsV2,
    boundary: BoundaryInputsV2,
    verifier_input_provider: VerifierInputProviderInputsV2,
};

pub const Custody = enum(u8) {
    independently_rebuilt_verifier_inputs = 1,
};

/// Pointer-free, exact-domain non-core receipt. `rows` and `claims` use the
/// order in `NONCORE_ROW_INDICES`; no absent core row is represented by a
/// fabricated zero audit.
pub const AuditsV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    domain_count: u8 = DOMAIN_COUNT,
    noncore_row_count: u8 = NONCORE_ROW_COUNT,
    custody: Custody = .independently_rebuilt_verifier_inputs,
    padding: [2]u8 = .{ 0, 0 },
    row_mask: u64 = NONCORE_ROW_MASK,
    manifest_seal: [32]u8,
    relation_context_identity: [32]u8,
    rows: [NONCORE_ROW_COUNT]relation_interaction.DomainAudit,
    claims: [NONCORE_ROW_COUNT]QM31,
    domain_residuals: [DOMAIN_COUNT]QM31,
    identity: [32]u8,

    pub fn validateAgainst(
        self: *const AuditsV2,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
    ) !void {
        try manifest.validate();
        try validateRelationsExact(relations);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.domain_count != DOMAIN_COUNT or
            self.noncore_row_count != NONCORE_ROW_COUNT or
            self.custody != .independently_rebuilt_verifier_inputs or
            !allZero(&self.padding) or self.row_mask != NONCORE_ROW_MASK or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(
                u8,
                &self.relation_context_identity,
                &relationContextIdentity(relations),
            ))
        {
            return error.AuditIdentityMismatch;
        }

        var residuals = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
        for (self.rows, self.claims, NONCORE_ROW_INDICES) |audit, claim, row| {
            try validateRowAudit(manifest, row, &audit, claim);
            for (audit.values, 0..) |value, domain|
                residuals[domain] = residuals[domain].add(value);
        }
        for (self.domain_residuals, residuals) |actual, expected| {
            try requireCanonical(actual);
            if (!actual.eql(expected)) return error.AuditRowMismatch;
        }
        if (!std.mem.eql(u8, &self.identity, &receiptIdentity(self)))
            return error.AuditIdentityMismatch;
    }

    pub fn claimAt(self: *const AuditsV2, row: u8) Error!QM31 {
        const index = noncoreIndex(row) orelse return error.AuditRowMismatch;
        return self.claims[index];
    }

    pub fn auditAt(
        self: *const AuditsV2,
        row: u8,
    ) Error!*const relation_interaction.DomainAudit {
        const index = noncoreIndex(row) orelse return error.AuditRowMismatch;
        return &self.rows[index];
    }

    /// Fail-atomic installation into the future full-cohort audit arrays. The
    /// caller's occupied mask is the authority for already-installed core
    /// rows; overlap is rejected before either destination changes.
    pub fn installInto(
        self: *const AuditsV2,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        destination_audits: *[COMPONENT_COUNT]relation_interaction.DomainAudit,
        destination_claims: *[COMPONENT_COUNT]QM31,
        occupied_mask: *u64,
    ) !void {
        try self.validateAgainst(manifest, relations);
        try installValidatedInto(
            self,
            destination_audits,
            destination_claims,
            occupied_mask,
        );
    }

    pub fn requireWholeCohort(_: *const AuditsV2) Error!void {
        return error.UnsupportedWholeCohort;
    }
};

pub fn installValidatedInto(
    receipt: *const AuditsV2,
    destination_audits: *[COMPONENT_COUNT]relation_interaction.DomainAudit,
    destination_claims: *[COMPONENT_COUNT]QM31,
    occupied_mask: *u64,
) Error!void {
    if (occupied_mask.* & ~ALL_ROW_MASK != 0 or
        occupied_mask.* & NONCORE_ROW_MASK != 0)
    {
        return error.ComponentMaskOverlap;
    }
    const source_bytes = std.mem.asBytes(receipt);
    if (overlap(source_bytes, std.mem.asBytes(destination_audits)) or
        overlap(source_bytes, std.mem.asBytes(destination_claims)) or
        overlap(source_bytes, std.mem.asBytes(occupied_mask)) or
        overlap(
            std.mem.asBytes(destination_audits),
            std.mem.asBytes(destination_claims),
        ) or
        overlap(
            std.mem.asBytes(destination_audits),
            std.mem.asBytes(occupied_mask),
        ) or
        overlap(
            std.mem.asBytes(destination_claims),
            std.mem.asBytes(occupied_mask),
        ))
    {
        return error.AliasedDestination;
    }
    const updated_mask = occupied_mask.* | NONCORE_ROW_MASK;
    for (NONCORE_ROW_INDICES, receipt.rows, receipt.claims) |row, audit, claim| {
        destination_audits[row] = audit;
        destination_claims[row] = claim;
    }
    occupied_mask.* = updated_mask;
}

pub fn validateRowAudit(
    manifest: *const manifest_mod.Manifest,
    row: u8,
    audit: *const relation_interaction.DomainAudit,
    claim: QM31,
) Error!void {
    if (audit.logical_rows == 0 or audit.event_terms == 0)
        return error.InvalidAuditGeometry;
    try requireCanonical(claim);
    var total = QM31.zero();
    for (audit.values) |value| {
        try requireCanonical(value);
        total = total.add(value);
    }
    try requireCanonical(audit.total);
    if (!total.eql(audit.total) or !audit.total.eql(claim))
        return error.ClaimMismatch;

    const expected_terms = std.math.mul(
        usize,
        audit.logical_rows,
        eventCount(row) orelse return error.AuditRowMismatch,
    ) catch return error.ArithmeticOverflow;
    if (audit.event_terms != expected_terms)
        return error.InvalidAuditGeometry;
    const trace_rows = traceSize(
        manifest.placements[row].?.geometry.log_size,
    ) catch return error.InvalidAuditGeometry;
    // The authenticated framework rows retain only logical source rows for
    // several sparse transcript/public components; their committed columns
    // are padded to the manifest domain by the Tree-2 writer. Row 35 is the
    // one dense table and must cover its entire 2^16 domain.
    if (row <= 17) {
        if (audit.logical_rows > trace_rows)
            return error.InvalidAuditGeometry;
    } else if (row == 35) {
        if (audit.logical_rows != trace_rows)
            return error.InvalidAuditGeometry;
    } else if (row == 36) {
        if (audit.logical_rows > trace_rows)
            return error.InvalidAuditGeometry;
    } else if (row == 37 and
        audit.logical_rows != boundary_authority.PUBLIC_LOGUP_LOGICAL_ROWS)
    {
        return error.InvalidAuditGeometry;
    } else if (row == 38 and
        audit.logical_rows != input_provider_authority.LOGICAL_ROW_COUNT)
    {
        return error.InvalidAuditGeometry;
    }
    if (row == 17 and
        (audit.logical_rows != ROW17_LOGICAL_ROWS or
            audit.event_terms != ROW17_TYPED_EVENT_TERMS))
    {
        return error.InvalidAuditGeometry;
    }

    switch (row) {
        0 => try requireOnlyDomains(row, &audit.values, &.{.recursion_step}),
        1 => try requireOnlyDomains(row, &audit.values, &.{
            .poseidon2_io,
            .recursion_hash_call_control,
            .recursion_hash_data,
            .recursion_hash_state,
            .recursion_hash_output,
        }),
        2 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_hash_call_control,
            .recursion_hash_data,
            .recursion_hash_output,
            .recursion_transcript_frame_output,
            .recursion_transcript_pow_frame,
            .recursion_step,
            .recursion_transcript_frame_word,
        }),
        3 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_transcript_frame_output,
            .recursion_transcript_draw_output,
            .recursion_transcript_digest_state,
            .recursion_transcript_frame_word,
        }),
        4 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_transcript_frame_word,
            .recursion_transcript_payload_word,
        }),
        5 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_transcript_payload_word,
            .recursion_verifier_input_word,
        }),
        6 => try requireOnlyDomains(row, &audit.values, &.{.recursion_pow_check}),
        7 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_transcript_pow_frame,
            .recursion_pow_check,
        }),
        8 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_transcript_draw_output,
            .recursion_relation_challenge_word,
        }),
        9 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_transcript_draw_output,
            .recursion_verifier_randomness_word,
        }),
        10 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_verifier_input_word,
            .recursion_statement_word,
        }),
        11 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_statement_word,
            .recursion_verifier_input_word,
            .range_check_8_8,
            .recursion_wire,
        }),
        12, 14, 15 => try requireOnlyDomains(
            row,
            &audit.values,
            &.{.recursion_wire},
        ),
        13 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_wire,
            .recursion_step,
            .poseidon2_io,
        }),
        16 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_relation_challenge_word,
            .recursion_wire,
        }),
        17 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_step,
            .recursion_wire,
        }),
        35 => try requireOnlyDomains(row, &audit.values, &.{.range_check_8_8}),
        36 => try requireOnlyDomains(row, &audit.values, &.{.recursion_statement_word}),
        37 => try requireOnlyDomains(row, &audit.values, &.{
            .recursion_verifier_input_word,
            .recursion_wire,
        }),
        38 => try requireOnlyDomains(
            row,
            &audit.values,
            &.{.recursion_verifier_input_word},
        ),
        else => return error.AuditRowMismatch,
    }
    if (row == 10 and !claim.isZero()) return error.ClaimMismatch;
}

pub fn eventCount(row: u8) ?usize {
    return switch (row) {
        0 => control_air.RELATION_EVENT_COUNT,
        1 => transcript_air.RELATION_EVENT_COUNT,
        2 => transcript_binding_air.RELATION_EVENT_COUNT,
        3 => transcript_state_air.RELATION_EVENT_COUNT,
        4 => transcript_word_air.RELATION_EVENT_COUNT,
        5 => transcript_payload_air.RELATION_EVENT_COUNT,
        6 => pow_check_air.RELATION_EVENT_COUNT,
        7 => pow_frame_air.RELATION_EVENT_COUNT,
        8 => relation_challenge_air.RELATION_EVENT_COUNT,
        9 => verifier_randomness_air.RELATION_EVENT_COUNT,
        10 => statement_input_air.RELATION_EVENT_COUNT,
        11 => statement_source.Air.RELATION_EVENT_COUNT,
        12 => public_air.PublicationHeader.RELATION_EVENT_COUNT,
        13 => public_air.NativePublicSums.RELATION_EVENT_COUNT,
        14 => public_air.PublicationSeal.RELATION_EVENT_COUNT,
        15 => public_air.StatementBoundary.RELATION_EVENT_COUNT,
        16 => public_air.NativeChallenges.RELATION_EVENT_COUNT,
        17 => row17_air_v2.RELATION_EVENT_COUNT,
        35 => range_bridge.RELATION_EVENT_COUNT,
        36 => boundary_air.Statement.RELATION_EVENT_COUNT,
        37 => boundary_air.PublicLogUp.RELATION_EVENT_COUNT,
        38 => input_provider_air.RELATION_EVENT_COUNT,
        else => null,
    };
}

pub fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidAuditGeometry;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn requireOnlyDomains(
    row: u8,
    values: *const [DOMAIN_COUNT]QM31,
    allowed: []const relation.Domain,
) Error!void {
    for (values, 0..) |value, index| {
        var admitted = false;
        for (allowed) |domain| admitted = admitted or
            index == @intFromEnum(domain);
        if (!admitted and !value.isZero()) {
            if (std.process.hasEnvVarConstant(
                "STWO_RECURSION_OUTER_CLOSURE_DIAGNOSTIC",
            )) {
                const limbs = value.toM31Array();
                std.debug.print(
                    "V2_NONCORE_PROVIDER_DOMAIN_MISMATCH row={d} domain={d} " ++
                        "value=[{d},{d},{d},{d}]\n",
                    .{
                        row,
                        index,
                        limbs[0].toU32(),
                        limbs[1].toU32(),
                        limbs[2].toU32(),
                        limbs[3].toU32(),
                    },
                );
            }
            return error.ProviderDomainMismatch;
        }
    }
}

pub fn validateRelationsExact(relations: *const universal.UniversalRelations) !void {
    try relations.validate();
    for (relations.elements) |element| {
        try requireCanonical(element.z);
        try requireCanonical(element.alpha);
        var power = QM31.one();
        for (element.alpha_powers) |actual| {
            try requireCanonical(actual);
            if (!actual.eql(power)) return error.RelationContextMismatch;
            power = power.mul(element.alpha);
        }
    }
}

pub fn relationContextIdentity(
    relations: *const universal.UniversalRelations,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(RELATION_CONTEXT_ID_DOMAIN);
    hashInt(&hash, u16, relations.format_version);
    hash.update(&relations.registry_order_digest);
    hashInt(&hash, u16, relations.elements.len);
    for (relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQM31(&hash, element.z);
        hashQM31(&hash, element.alpha);
        for (element.alpha_powers) |power| hashQM31(&hash, power);
    }
    return hash.finalResult();
}

pub fn receiptIdentity(value: *const AuditsV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(RECEIPT_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.component_count);
    hashInt(&hash, u8, value.domain_count);
    hashInt(&hash, u8, value.noncore_row_count);
    hashInt(&hash, u8, @intFromEnum(value.custody));
    hash.update(&value.padding);
    hashInt(&hash, u64, value.row_mask);
    hash.update(&value.manifest_seal);
    hash.update(&value.relation_context_identity);
    for (NONCORE_ROW_INDICES, value.rows, value.claims) |row, audit, claim| {
        hashInt(&hash, u8, row);
        for (audit.values) |domain_value| hashQM31(&hash, domain_value);
        hashQM31(&hash, audit.total);
        hashInt(&hash, u64, audit.logical_rows);
        hashInt(&hash, u64, audit.event_terms);
        hashQM31(&hash, claim);
    }
    for (value.domain_residuals) |residual| hashQM31(&hash, residual);
    return hash.finalResult();
}

pub fn noncoreIndex(row: u8) ?usize {
    for (NONCORE_ROW_INDICES, 0..) |candidate, index|
        if (row == candidate) return index;
    return null;
}

pub fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |limb| if (limb.toU32() >=
        stwo_core.fields.m31.Modulus)
    {
        return error.NonCanonicalField;
    };
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub fn hashQM31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn componentBit(index: anytype) u64 {
    return @as(u64, 1) << @intCast(index);
}

pub fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    var result: u64 = 0;
    inline for (first..end) |index| result |= componentBit(index);
    return result;
}
