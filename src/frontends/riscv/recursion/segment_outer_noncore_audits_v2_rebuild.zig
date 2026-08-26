//! Internal segment outer noncore audits v2 authority shard; use segment_outer_noncore_audits_v2.zig publicly.

const dependency_0 = @import("segment_outer_noncore_audits_v2_contract.zig");

const ALL_ROW_MASK = dependency_0.ALL_ROW_MASK;
const AuditsV2 = dependency_0.AuditsV2;
const BOUNDARY_RELATION_CONTEXT_DOMAIN = dependency_0.BOUNDARY_RELATION_CONTEXT_DOMAIN;
const BoundaryInputsV2 = dependency_0.BoundaryInputsV2;
const COLD_TYPED_AUDIT_ALLOCATION_CALLS = dependency_0.COLD_TYPED_AUDIT_ALLOCATION_CALLS;
const COMPONENT_COUNT = dependency_0.COMPONENT_COUNT;
const CORE_ROW_COUNT = dependency_0.CORE_ROW_COUNT;
const CORE_ROW_MASK = dependency_0.CORE_ROW_MASK;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const HOT_AUDIT_HEAP_ALLOCATIONS = dependency_0.HOT_AUDIT_HEAP_ALLOCATIONS;
const HOT_INSTALL_HEAP_ALLOCATIONS = dependency_0.HOT_INSTALL_HEAP_ALLOCATIONS;
const InputsV2 = dependency_0.InputsV2;
const NONCORE_AUDITS_AVAILABLE = dependency_0.NONCORE_AUDITS_AVAILABLE;
const NONCORE_ROW_COUNT = dependency_0.NONCORE_ROW_COUNT;
const NONCORE_ROW_INDICES = dependency_0.NONCORE_ROW_INDICES;
const NONCORE_ROW_MASK = dependency_0.NONCORE_ROW_MASK;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const PublicInputsV2 = dependency_0.PublicInputsV2;
const QM31 = dependency_0.QM31;
const REBUILD_AND_INSTALL_REDUNDANT_AUDIT_PASSES = dependency_0.REBUILD_AND_INSTALL_REDUNDANT_AUDIT_PASSES;
const ROW17_ACTIVE_RELATION_EVENTS = dependency_0.ROW17_ACTIVE_RELATION_EVENTS;
const ROW17_LOGICAL_ROWS = dependency_0.ROW17_LOGICAL_ROWS;
const ROW17_TYPED_EVENT_TERMS = dependency_0.ROW17_TYPED_EVENT_TERMS;
const RangeInputsV2 = dependency_0.RangeInputsV2;
const StatementInputsV2 = dependency_0.StatementInputsV2;
const TranscriptInputsV2 = dependency_0.TranscriptInputsV2;
const VerifierInputProviderInputsV2 = dependency_0.VerifierInputProviderInputsV2;
const WHOLE_COHORT_AUDITS_AVAILABLE = dependency_0.WHOLE_COHORT_AUDITS_AVAILABLE;
const boundary_air = dependency_0.boundary_air;
const boundary_authority = dependency_0.boundary_authority;
const hashInt = dependency_0.hashInt;
const hashQM31 = dependency_0.hashQM31;
const input_provider_air = dependency_0.input_provider_air;
const input_provider_authority = dependency_0.input_provider_authority;
const input_provider_witness = dependency_0.input_provider_witness;
const installValidatedInto = dependency_0.installValidatedInto;
const manifest_mod = dependency_0.manifest_mod;
const public_components = dependency_0.public_components;
const range_authority = dependency_0.range_authority;
const range_bridge = dependency_0.range_bridge;
const receiptIdentity = dependency_0.receiptIdentity;
const relation = dependency_0.relation;
const relationContextIdentity = dependency_0.relationContextIdentity;
const relation_interaction = dependency_0.relation_interaction;
const statement_components = dependency_0.statement_components;
const std = dependency_0.std;
const transcript_air = dependency_0.transcript_air;
const transcript_components = dependency_0.transcript_components;
const universal = dependency_0.universal;
const validateRelationsExact = dependency_0.validateRelationsExact;
const validateRowAudit = dependency_0.validateRowAudit;

/// Rebuilds every non-core audit into stack staging. No caller-owned output is
/// exposed until every source, claim, relation context, and row decomposition
/// has succeeded.
pub fn rebuild(
    allocator: std.mem.Allocator,
    inputs: InputsV2,
) !AuditsV2 {
    try inputs.manifest.validate();
    try validateRelationsExact(inputs.relations);

    var rows: [NONCORE_ROW_COUNT]relation_interaction.DomainAudit = undefined;
    var claims: [NONCORE_ROW_COUNT]QM31 = undefined;

    try rebuildTranscript(
        allocator,
        inputs.manifest,
        inputs.relations,
        inputs.transcript,
        rows[0..10],
        claims[0..10],
    );
    try rebuildStatement(
        allocator,
        inputs.manifest,
        inputs.relations,
        inputs.statement,
        rows[10..12],
        claims[10..12],
    );
    try rebuildPublic(
        allocator,
        inputs.manifest,
        inputs.relations,
        inputs.public,
        rows[12..18],
        claims[12..18],
    );
    try rebuildRange(inputs.relations, inputs.range, &rows[18], &claims[18]);
    try rebuildBoundary(
        inputs.manifest,
        inputs.relations,
        inputs.boundary,
        rows[19..21],
        claims[19..21],
    );
    try rebuildVerifierInputProvider(
        inputs.manifest,
        inputs.relations,
        inputs.boundary,
        inputs.verifier_input_provider,
        &rows[21],
        &claims[21],
    );

    var domain_residuals = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    for (rows, claims, NONCORE_ROW_INDICES) |audit, claim, row| {
        try validateRowAudit(inputs.manifest, row, &audit, claim);
        for (audit.values, 0..) |value, domain|
            domain_residuals[domain] = domain_residuals[domain].add(value);
    }
    var result = AuditsV2{
        .manifest_seal = inputs.manifest.seal,
        .relation_context_identity = relationContextIdentity(inputs.relations),
        .rows = rows,
        .claims = claims,
        .domain_residuals = domain_residuals,
        .identity = undefined,
    };
    result.identity = receiptIdentity(&result);
    try result.validateAgainst(inputs.manifest, inputs.relations);
    return result;
}

/// Replays every authenticated non-core source and only then installs all 22
/// rows into cohort storage. This is the preferred integration API: callers
/// cannot accidentally install a receipt rebuilt from different Tree-2
/// owners, logical rows, range requests, or boundary capture.
pub fn rebuildAndInstall(
    allocator: std.mem.Allocator,
    inputs: InputsV2,
    destination_audits: *[COMPONENT_COUNT]relation_interaction.DomainAudit,
    destination_claims: *[COMPONENT_COUNT]QM31,
    occupied_mask: *u64,
) !AuditsV2 {
    const result = try rebuild(allocator, inputs);
    // `rebuild` finishes with a complete receipt validation. Use the private
    // validated installer so the coherent convenience path does not replay
    // all 22x47 audit cells and 47 challenge power tables a third time.
    try installValidatedInto(
        &result,
        destination_audits,
        destination_claims,
        occupied_mask,
    );
    return result;
}

/// Cold revalidation for a retained receipt. This deliberately performs the
/// full authenticated replay rather than trusting its digest as a MAC.
pub fn validateAgainstInputs(
    receipt: *const AuditsV2,
    allocator: std.mem.Allocator,
    inputs: InputsV2,
) !void {
    try receipt.validateAgainst(inputs.manifest, inputs.relations);
    const rebuilt = try rebuild(allocator, inputs);
    if (!std.meta.eql(receipt.*, rebuilt))
        return error.AuditIdentityMismatch;
}

pub fn rebuildTranscript(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    inputs: TranscriptInputsV2,
    audits: *[10]relation_interaction.DomainAudit,
    claims: *[10]QM31,
) !void {
    try inputs.owner.validateAgainst(inputs.prepared, manifest);
    try inputs.workspace.validateAgainst(inputs.prepared);
    claims.* = inputs.claims.asArray();
    audits[0] = try inputs.owner.owners.control.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.control_rows,
        relations,
        claims[0],
    );
    audits[1] = try inputs.owner.owners.transcript_air.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.transcript_air_rows,
        relations,
        claims[1],
    );
    audits[2] = try inputs.owner.owners.transcript_binding.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.transcript_binding_rows,
        relations,
        claims[2],
    );
    audits[3] = try inputs.owner.owners.transcript_state.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.transcript_state_rows,
        relations,
        claims[3],
    );
    audits[4] = try inputs.owner.owners.transcript_word.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.transcript_word_rows,
        relations,
        claims[4],
    );
    audits[5] = try inputs.owner.owners.transcript_payload.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.transcript_payload_rows,
        relations,
        claims[5],
    );
    audits[6] = try inputs.owner.owners.pow_check.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.pow_check_rows,
        relations,
        claims[6],
    );
    audits[7] = try inputs.owner.owners.pow_frame.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.pow_frame_rows,
        relations,
        claims[7],
    );
    audits[8] = try inputs.owner.owners.relation_challenge.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.relation_challenge_rows,
        relations,
        claims[8],
    );
    audits[9] = try inputs.owner.owners.verifier_randomness.relation.auditPreparedDomainSums(
        allocator,
        inputs.workspace.verifier_randomness_rows,
        relations,
        claims[9],
    );
}

pub fn rebuildStatement(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    inputs: StatementInputsV2,
    audits: *[2]relation_interaction.DomainAudit,
    claims: *[2]QM31,
) !void {
    const result = try statement_components.auditInteractionDomains(
        allocator,
        inputs.authority,
        inputs.prepared,
        inputs.logical_rows,
        manifest,
        relations,
        inputs.claims,
        null,
    );
    audits.* = .{ result.row10_inactive, result.row11_statement };
    claims.* = inputs.claims.asArray();
}

pub fn rebuildPublic(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    inputs: PublicInputsV2,
    audits: *[6]relation_interaction.DomainAudit,
    claims: *[6]QM31,
) !void {
    try inputs.owner.validateAgainst(inputs.prepared, manifest);
    audits.* = try public_components.auditInteractionDomains(
        allocator,
        inputs.owner,
        inputs.workspace,
        inputs.prepared,
        relations,
        inputs.claims,
        null,
    );
    claims.* = inputs.claims.asArray();
}

pub fn rebuildRange(
    relations: *const universal.UniversalRelations,
    inputs: RangeInputsV2,
    audit: *relation_interaction.DomainAudit,
    claim: *QM31,
) !void {
    try inputs.authority.validate();
    try inputs.provider_relations.validateAgainst(relations);
    try inputs.interaction.validate();
    if (!std.mem.eql(
        u8,
        &inputs.prepared.source_authority_digest,
        &inputs.interaction.source_authority_digest,
    ) or !std.meta.eql(
        inputs.prepared.statement_prepared_id,
        inputs.interaction.statement_prepared_id,
    ) or inputs.prepared.request_count != inputs.interaction.request_count) {
        return error.ProviderDomainMismatch;
    }
    const value = inputs.interaction.claim();
    try inputs.prepared.verifyExactClosure(inputs.sources, relations, value);
    var values = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    values[@intFromEnum(relation.Domain.range_check_8_8)] = value;
    audit.* = .{
        .values = values,
        .total = value,
        .logical_rows = range_bridge.TABLE_SIZE,
        .event_terms = range_bridge.TABLE_SIZE * range_bridge.RELATION_EVENT_COUNT,
    };
    claim.* = value;
}

pub fn rebuildBoundary(
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    inputs: BoundaryInputsV2,
    audits: *[2]relation_interaction.DomainAudit,
    claims: *[2]QM31,
) !void {
    try inputs.authority.validate();
    try inputs.prepared.validate();
    if (!std.meta.eql(
        manifest.boundary_manifest_id,
        inputs.prepared.manifest.identity,
    ) or !std.mem.eql(
        u8,
        &manifest.boundary_authority_sha_id,
        &inputs.prepared.manifest.authority_sha_id,
    )) return error.AuditRowMismatch;
    if (!std.mem.eql(
        u8,
        &inputs.prepared.outer_relation_context_sha_id,
        &boundaryRelationContextIdentity(relations),
    )) return error.BoundaryRelationContextMismatch;

    const closure = inputs.prepared.closure;
    try closure.validate();
    var statement_values = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    statement_values[@intFromEnum(relation.Domain.recursion_statement_word)] =
        closure.statement_emit;
    var public_values = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    public_values[@intFromEnum(relation.Domain.recursion_verifier_input_word)] =
        closure.verifier_input_consume;
    public_values[@intFromEnum(relation.Domain.recursion_wire)] =
        closure.publication_bridge_emit;
    audits.* = .{
        .{
            .values = statement_values,
            .total = closure.statement_emit,
            .logical_rows = inputs.prepared.statement_event_count,
            .event_terms = inputs.prepared.statement_event_count *
                boundary_air.Statement.RELATION_EVENT_COUNT,
        },
        .{
            .values = public_values,
            .total = closure.publicLogUpClaim(),
            .logical_rows = inputs.prepared.public_logup_word_count,
            .event_terms = inputs.prepared.public_logup_word_count *
                boundary_air.PublicLogUp.RELATION_EVENT_COUNT,
        },
    };
    claims.* = .{
        inputs.prepared.statement_claim,
        inputs.prepared.public_logup_claim,
    };
}

pub fn rebuildVerifierInputProvider(
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    boundary: BoundaryInputsV2,
    inputs: VerifierInputProviderInputsV2,
    audit: *relation_interaction.DomainAudit,
    claim: *QM31,
) !void {
    try inputs.authority.validate();
    try inputs.prepared.validateAgainst(.{
        .capture = boundary.prepared,
        .vm_context = inputs.vm_context,
    }, relations);
    if (!std.mem.eql(
        u8,
        &manifest.provider_authority_sha_id,
        &inputs.prepared.source_authority_sha_id,
    ) or !std.mem.eql(
        u8,
        &inputs.authority.source_authority_sha_id,
        &inputs.prepared.source_authority_sha_id,
    )) return error.AuditRowMismatch;

    var values = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    values[@intFromEnum(relation.Domain.recursion_verifier_input_word)] =
        inputs.prepared.claimed_sum;
    audit.* = .{
        .values = values,
        .total = inputs.prepared.claimed_sum,
        .logical_rows = input_provider_authority.LOGICAL_ROW_COUNT,
        .event_terms = input_provider_authority.LOGICAL_ROW_COUNT *
            input_provider_air.RELATION_EVENT_COUNT,
    };
    claim.* = inputs.prepared.claimed_sum;
}

/// Compatibility check against the already-sealed boundary authority receipt.
/// This copies its documented encoding exactly; it does not create a second
/// protocol identity and is used only to reject a mismatched challenge bundle.
pub fn boundaryRelationContextIdentity(
    relations: *const universal.UniversalRelations,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_RELATION_CONTEXT_DOMAIN);
    hashInt(&hash, u16, relations.format_version);
    hashInt(&hash, u32, relations.registry_order_digest.len);
    hash.update(&relations.registry_order_digest);
    hashInt(&hash, u16, relations.elements.len);
    for (relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQM31(&hash, element.z);
        hashQM31(&hash, element.alpha);
    }
    return hash.finalResult();
}

comptime {
    if (COMPONENT_COUNT != 39 or DOMAIN_COUNT != 47 or
        NONCORE_ROW_COUNT != 22 or CORE_ROW_COUNT != 17 or
        NONCORE_ROW_MASK | CORE_ROW_MASK != ALL_ROW_MASK or
        NONCORE_ROW_MASK & CORE_ROW_MASK != 0 or
        transcript_components.FIRST_ROW != 0 or
        transcript_components.ROW_COUNT != 10 or
        statement_components.FIRST_ROW != 10 or
        statement_components.ROW_COUNT != 2 or
        public_components.FIRST_ROW != 12 or
        public_components.ROW_COUNT != 6 or
        !range_authority.ROW_35_COMPLETE or
        boundary_authority.COMPONENT_COUNT != 2 or
        input_provider_authority.PROPOSED_ROSTER_ROW != 38 or
        input_provider_authority.LOGICAL_ROW_COUNT != 139 or
        input_provider_witness.DETAILED_CLAIM_COUNT != 21 or
        COLD_TYPED_AUDIT_ALLOCATION_CALLS != 36 or
        ROW17_LOGICAL_ROWS != 71 or ROW17_TYPED_EVENT_TERMS != 142 or
        ROW17_ACTIVE_RELATION_EVENTS != 72 or
        HOT_AUDIT_HEAP_ALLOCATIONS != 0 or HOT_INSTALL_HEAP_ALLOCATIONS != 0 or
        REBUILD_AND_INSTALL_REDUNDANT_AUDIT_PASSES != 0 or
        !NONCORE_AUDITS_AVAILABLE or WHOLE_COHORT_AUDITS_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("SegmentV2 non-core audit custody drifted");
    }
}
