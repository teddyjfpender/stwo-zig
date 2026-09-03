//! Genuine q193-ready cohort for one canonical-empty wrapper.
//!
//! Placement zero emits one authenticated `recursion_statement_word` tuple
//! per byte of the fixed NodePublic ABI under a wrapper-specific scope. The
//! exact aggregate is reconstructed by the cold verifier from the canonical
//! empty source. Placements 1..35 use the same reviewed AIR with canonical
//! zero preprocessing, main, interaction, and claims. No proofless empty row
//! is relabeled as a verified recursive child.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const input_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_wrapper_manifest_v1.zig");
const artifact_mod =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

const recursion = frontend.recursion;
const air = recursion.air;
const statement_air = air.statement_input;
const statement_relation = air.statement_input_relation;
const framework = air.framework_interaction;
const universal = air.universal_challenges;
const shared_provider = air.universal_shared_provider;
const relation = @import("../../frontends/riscv/air/lang/relation.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const StatementFramework = framework.Runtime(statement_relation.Runtime);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4345_5743; // "CEWC"
pub const NODE_PUBLIC_TUPLE_COUNT = input_mod.NODE_PUBLIC_SCALAR_BYTE_COUNT;
pub const COMPONENT_COUNT = manifest_mod.COMPONENT_COUNT;
pub const STATEMENT_DOMAIN_INDEX = @intFromEnum(
    relation.Domain.recursion_statement_word,
);

const COHORT_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-cohort/v1\x00";
const INTERACTION_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-interactions/v1\x00";
const AUDIT_DOMAIN =
    "stwo-zig/common-canonical-empty-wrapper-audit/v1\x00";

pub const Error = input_mod.Error || manifest_mod.Error || error{
    CanonicalEmptyWrapperAuditMismatch,
    CanonicalEmptyWrapperAuthorityMismatch,
    CanonicalEmptyWrapperClaimMismatch,
    CanonicalEmptyWrapperInteractionMismatch,
    CanonicalEmptyWrapperTreeMismatch,
};

pub const AuthorityInputs = struct {
    source_bytes: []const u8,
};

pub const BoundaryEvidenceV1 = struct {
    domain: relation.Domain,
    tuple_count: u64,
    claimed_sum: QM31,
    tuple_provenance_sha256: [32]u8,

    pub fn zero(domain: relation.Domain) BoundaryEvidenceV1 {
        return .{
            .domain = domain,
            .tuple_count = 0,
            .claimed_sum = QM31.zero(),
            .tuple_provenance_sha256 = boundaryIdentity(
                domain,
                0,
                QM31.zero(),
            ),
        };
    }

    pub fn validate(self: BoundaryEvidenceV1) Error!void {
        if (!std.mem.eql(
            u8,
            &self.tuple_provenance_sha256,
            &boundaryIdentity(self.domain, self.tuple_count, self.claimed_sum),
        )) return error.CanonicalEmptyWrapperAuditMismatch;
    }
};

pub const ClosureReceiptV1 = struct {
    closure_id: [32]u8,
};

pub const AuditedInteractionsV2 = struct {
    wire_boundary: BoundaryEvidenceV1,
    verifier_input_boundary: BoundaryEvidenceV1,
    closure: ClosureReceiptV1,
    identity_sha256: [32]u8,

    pub fn validate(self: *const AuditedInteractionsV2) Error!void {
        try self.wire_boundary.validate();
        try self.verifier_input_boundary.validate();
        if (self.wire_boundary.domain != .recursion_statement_word or
            self.wire_boundary.tuple_count != NODE_PUBLIC_TUPLE_COUNT or
            self.verifier_input_boundary.domain !=
                .recursion_verifier_input_word or
            self.verifier_input_boundary.tuple_count != 0 or
            !self.verifier_input_boundary.claimed_sum.isZero() or
            std.mem.allEqual(u8, &self.closure.closure_id, 0) or
            !std.mem.eql(u8, &self.identity_sha256, &auditIdentity(self)))
        {
            return error.CanonicalEmptyWrapperAuditMismatch;
        }
    }
};

pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    manifest_seal: [32]u8,
    cohort_identity_sha256: [32]u8,
    relations_identity_sha256: [32]u8,
    claims: [COMPONENT_COUNT]QM31,
    domain_totals: [universal.RELATION_COUNT]QM31,
    identity_sha256: [32]u8,

    pub fn validate(self: *const GeneratedInteractionsV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            std.mem.allEqual(u8, &self.manifest_seal, 0) or
            std.mem.allEqual(u8, &self.cohort_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.relations_identity_sha256, 0))
        {
            return error.CanonicalEmptyWrapperInteractionMismatch;
        }
        for (self.claims[1..]) |claim| if (!claim.isZero())
            return error.CanonicalEmptyWrapperClaimMismatch;
        for (self.domain_totals, 0..) |claim, domain| {
            if (domain == STATEMENT_DOMAIN_INDEX) {
                if (!claim.eql(self.claims[0]))
                    return error.CanonicalEmptyWrapperClaimMismatch;
            } else if (!claim.isZero()) {
                return error.CanonicalEmptyWrapperClaimMismatch;
            }
        }
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &interactionIdentity(self),
        )) return error.CanonicalEmptyWrapperInteractionMismatch;
    }
};

pub const CohortV1 = struct {
    allocator: std.mem.Allocator,
    source_bytes: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8,
    cold: input_mod.ColdInputV1,
    manifest_value: manifest_mod.Manifest,
    definition: statement_air.Definition,
    relation_plan: statement_relation.Plan,
    rows: []StatementFramework.Row,
    interaction_workspace: StatementFramework.Workspace,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        inputs: AuthorityInputs,
    ) !CohortV1 {
        if (inputs.source_bytes.len != input_mod.SOURCE_ENCODED_BYTE_COUNT)
            return error.CanonicalEmptyWrapperAuthorityMismatch;
        var source_bytes: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8 = undefined;
        @memcpy(&source_bytes, inputs.source_bytes);
        const cold = try input_mod.ColdInputV1.open(&source_bytes);
        const manifest_value = try manifest_mod.build();
        var definition = try statement_air.build(allocator);
        errdefer definition.deinit();
        const relation_plan = try statement_relation.authenticate(&definition);
        const rows = try allocator.alloc(
            StatementFramework.Row,
            NODE_PUBLIC_TUPLE_COUNT,
        );
        errdefer allocator.free(rows);
        try fillRows(rows, &cold);
        var interaction_workspace = try StatementFramework.Workspace.init(
            allocator,
            manifest_mod.LOG_SIZE,
        );
        errdefer interaction_workspace.deinit();
        var result = CohortV1{
            .allocator = allocator,
            .source_bytes = source_bytes,
            .cold = cold,
            .manifest_value = manifest_value,
            .definition = definition,
            .relation_plan = relation_plan,
            .rows = rows,
            .interaction_workspace = interaction_workspace,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = cohortIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn deinit(self: *CohortV1) void {
        self.interaction_workspace.deinit();
        self.allocator.free(self.rows);
        self.definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *CohortV1) !void {
        try self.cold.validate(&self.source_bytes);
        try manifest_mod.validateExact(&self.manifest_value);
        try self.definition.validate();
        try self.relation_plan.validateAgainst(
            &self.definition.arena,
            statement_air.SEMANTIC_DIGEST,
            statement_relation.events(&self.definition),
        );
        if (self.rows.len != NODE_PUBLIC_TUPLE_COUNT or
            !std.mem.eql(u8, &self.authority_sha256, &cohortIdentity(self)))
        {
            return error.CanonicalEmptyWrapperAuthorityMismatch;
        }
        const expected = try self.allocator.alloc(
            StatementFramework.Row,
            NODE_PUBLIC_TUPLE_COUNT,
        );
        defer self.allocator.free(expected);
        try fillRows(expected, &self.cold);
        if (!rowsEqual(self.rows, expected))
            return error.CanonicalEmptyWrapperAuthorityMismatch;
    }

    pub fn manifest(self: *const CohortV1) *const manifest_mod.Manifest {
        return &self.manifest_value;
    }

    pub fn recursiveStatementWords(
        self: *const CohortV1,
    ) !*const recursion.span_statement.StatementWords {
        try self.cold.leaf.validate();
        return &self.cold.leaf.child().statement_words;
    }

    pub fn publicationAuthority(
        self: *const CohortV1,
    ) *const input_mod.ColdInputV1 {
        return &self.cold;
    }

    pub fn sessionAuthority(
        self: *const CohortV1,
    ) !artifact_mod.CanonicalEmptySessionAuthorityV1 {
        try self.cold.validate(&self.source_bytes);
        return .{
            .ingress_identity_sha256 = self.cold.identity_sha256,
            .parent_statement_words = self.cold.leaf.child().statement_words,
            .profile_identity_sha256 = try manifest_mod.profileIdentity(),
            .child_composition_manifest_sha256 = try manifest_mod.contractIdentity(),
            .parent_outer_manifest_sha256 = try manifest_mod.contractIdentity(),
            .verification_key_id = try manifest_mod.verificationKeyId(),
            .next_parent_vk_id = try manifest_mod.nextParentVkId(),
            .air_program_id = try manifest_mod.airProgramId(),
        };
    }

    pub fn session(self: *const CohortV1) !artifact_mod.SessionV1 {
        return artifact_mod.SessionV1.initCanonicalEmptyWrapper(
            try self.sessionAuthority(),
        );
    }

    pub fn validateSession(
        self: *const CohortV1,
        session_value: *const artifact_mod.SessionV1,
    ) !void {
        const expected = try self.session();
        if (!std.meta.eql(session_value.*, expected))
            return error.CanonicalEmptyWrapperAuthorityMismatch;
    }

    pub fn mixAuthority(self: *CohortV1, transcript: anytype) !void {
        try self.validate();
        transcript.mixU32s(&.{
            AUTHORITY_TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            SCHEMA_VERSION,
            COMPONENT_COUNT,
            NODE_PUBLIC_TUPLE_COUNT,
            manifest_mod.NODE_PUBLIC_SCOPE,
        });
        transcript.mixU32s(&digestWords(self.authority_sha256));
        transcript.mixU32s(&digestWords(self.cold.identity_sha256));
        transcript.mixU32s(&digestWords(
            self.cold.node_public.output_identity_sha256,
        ));
        const public_bytes = try input_mod.encodeNodePublic(
            &self.cold.node_public,
        );
        var public_words: [NODE_PUBLIC_TUPLE_COUNT]u32 = undefined;
        for (&public_words, public_bytes) |*word, byte| word.* = byte;
        transcript.mixU32s(&public_words);
    }

    pub fn fillPreprocessedInto(
        self: *CohortV1,
        active_manifest: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try self.validate();
        try requireManifest(active_manifest, &self.manifest_value);
        try preflightFreshTree(
            active_manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
        errdefer clearTree(destination);
        const placement = try active_manifest.placement(
            manifest_mod.COMPONENT_KEYS[0],
        );
        for (self.rows, 0..) |row, logical_row| {
            const committed = framework.committedRow(
                logical_row,
                placement.geometry.log_size,
            );
            inline for (0..statement_air.PREPROCESSED_COLUMN_COUNT) |column| {
                destination[placement.preprocessed_offset + column][committed] =
                    row[statement_air.PHYSICAL_MAIN_COLUMN_COUNT + column];
            }
        }
    }

    pub fn fillMainInto(
        self: *CohortV1,
        active_manifest: *const manifest_mod.Manifest,
        destination: [][]M31,
    ) !void {
        try self.validate();
        try requireManifest(active_manifest, &self.manifest_value);
        try preflightFreshTree(
            active_manifest,
            manifest_mod.MAIN_TREE_INDEX,
            destination,
        );
        errdefer clearTree(destination);
        const placement = try active_manifest.placement(
            manifest_mod.COMPONENT_KEYS[0],
        );
        for (self.rows, 0..) |row, logical_row| {
            const committed = framework.committedRow(
                logical_row,
                placement.geometry.log_size,
            );
            inline for (0..statement_air.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
                destination[placement.main_offset + column][committed] =
                    row[column];
            }
        }
    }

    pub fn fillInteractionInto(
        self: *CohortV1,
        active_manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        destination: [][]M31,
    ) !GeneratedInteractionsV1 {
        try self.validate();
        try requireManifest(active_manifest, &self.manifest_value);
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        try preflightFreshTree(
            active_manifest,
            manifest_mod.INTERACTION_TREE_INDEX,
            destination,
        );
        errdefer clearTree(destination);
        var claims = [_]QM31{QM31.zero()} ** COMPONENT_COUNT;
        var domain_totals = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
        inline for (manifest_mod.COMPONENT_KEYS, 0..) |key, ordinal| {
            const placement = try active_manifest.placement(key);
            var columns: [StatementFramework.INTERACTION_COLUMN_COUNT][]M31 =
                undefined;
            for (
                &columns,
                destination[placement.interaction_offset..][0..columns.len],
            ) |*bound, column| bound.* = column;
            const active_rows: []const StatementFramework.Row = if (ordinal == manifest_mod.NODE_PUBLIC_COMPONENT) self.rows else &.{};
            const generated = try StatementFramework
                .generatePreparedIntoWithDomainSums(
                &self.interaction_workspace,
                &self.relation_plan,
                active_rows,
                placement.geometry.log_size,
                relations,
                &columns,
            );
            claims[ordinal] = generated.claimed_sum;
            for (&domain_totals, generated.by_domain) |*total, item|
                total.* = total.add(item);
        }
        var result = GeneratedInteractionsV1{
            .manifest_seal = active_manifest.seal,
            .cohort_identity_sha256 = self.authority_sha256,
            .relations_identity_sha256 = relationsIdentity(relations),
            .claims = claims,
            .domain_totals = domain_totals,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = interactionIdentity(&result);
        try self.validateGenerated(
            &result,
            relations,
            provider_relations,
        );
        return result;
    }

    pub fn validateGenerated(
        self: *CohortV1,
        generated: *const GeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validate();
        try generated.validate();
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        if (!std.mem.eql(
            u8,
            &generated.manifest_seal,
            &self.manifest_value.seal,
        ) or !std.mem.eql(
            u8,
            &generated.cohort_identity_sha256,
            &self.authority_sha256,
        ) or !std.mem.eql(
            u8,
            &generated.relations_identity_sha256,
            &relationsIdentity(relations),
        )) return error.CanonicalEmptyWrapperInteractionMismatch;
        const audit = try self.relation_plan.auditPreparedDomainSums(
            self.allocator,
            self.rows,
            relations,
            generated.claims[0],
        );
        if (!audit.total.eql(generated.claims[0]) or
            audit.logical_rows != NODE_PUBLIC_TUPLE_COUNT or
            audit.event_terms !=
                NODE_PUBLIC_TUPLE_COUNT * statement_air.RELATION_EVENT_COUNT)
        {
            return error.CanonicalEmptyWrapperInteractionMismatch;
        }
        for (audit.values, generated.domain_totals) |expected, actual|
            if (!expected.eql(actual))
                return error.CanonicalEmptyWrapperInteractionMismatch;
    }

    pub fn claimVector(
        self: *CohortV1,
        generated: *const GeneratedInteractionsV1,
    ) !manifest_mod.ClaimVector {
        try generated.validate();
        var result = try manifest_mod.ClaimVector.init(&self.manifest_value);
        inline for (manifest_mod.COMPONENT_KEYS, 0..) |key, ordinal|
            try result.bind(key, generated.claims[ordinal]);
        try result.sealClaims(&self.manifest_value);
        return result;
    }

    pub fn auditGlobalClosureV2(
        self: *CohortV1,
        generated: *const GeneratedInteractionsV1,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !AuditedInteractionsV2 {
        try self.validateGenerated(generated, relations, provider_relations);
        const expected_claims = try self.claimVector(generated);
        if (!std.meta.eql(claims.*, expected_claims))
            return error.CanonicalEmptyWrapperClaimMismatch;
        var result = AuditedInteractionsV2{
            .wire_boundary = .{
                .domain = .recursion_statement_word,
                .tuple_count = NODE_PUBLIC_TUPLE_COUNT,
                .claimed_sum = generated.domain_totals[STATEMENT_DOMAIN_INDEX],
                .tuple_provenance_sha256 = boundaryIdentity(
                    .recursion_statement_word,
                    NODE_PUBLIC_TUPLE_COUNT,
                    generated.domain_totals[STATEMENT_DOMAIN_INDEX],
                ),
            },
            .verifier_input_boundary = BoundaryEvidenceV1.zero(
                .recursion_verifier_input_word,
            ),
            .closure = .{ .closure_id = generated.identity_sha256 },
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = auditIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn auditGlobalClosure(
        self: *CohortV1,
        generated: *const GeneratedInteractionsV1,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !AuditedInteractionsV2 {
        return self.auditGlobalClosureV2(
            generated,
            claims,
            relations,
            provider_relations,
        );
    }

    pub fn validateAuditedInteractions(
        self: *CohortV1,
        audited: *const AuditedInteractionsV2,
        claims: *const manifest_mod.ClaimVector,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try audited.validate();
        const generated = try self.rebuildGeneratedInteractions(
            relations,
            provider_relations,
        );
        const expected = try self.auditGlobalClosureV2(
            &generated,
            claims,
            relations,
            provider_relations,
        );
        if (!std.meta.eql(audited.*, expected))
            return error.CanonicalEmptyWrapperAuditMismatch;
    }

    pub fn rebuildGeneratedInteractions(
        self: *CohortV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !GeneratedInteractionsV1 {
        var tree = try InteractionTreeV1.init(
            self.allocator,
            &self.manifest_value,
        );
        defer tree.deinit();
        return self.fillInteractionInto(
            &self.manifest_value,
            relations,
            provider_relations,
            tree.columns,
        );
    }

    pub fn initComponents(
        self: *CohortV1,
        generated: *const GeneratedInteractionsV1,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !ComponentSetV1 {
        try self.validateGenerated(generated, relations, provider_relations);
        var values: [COMPONENT_COUNT]manifest_mod.StatementAdapter = undefined;
        inline for (manifest_mod.COMPONENT_KEYS, 0..) |key, ordinal| {
            values[ordinal] = try manifest_mod.StatementAdapter.init(
                &self.definition,
                self.relation_plan,
                &self.manifest_value,
                key,
                manifest_mod.LOG_SIZE,
                parameters(ordinal == manifest_mod.NODE_PUBLIC_COMPONENT),
                relations,
                generated.claims[ordinal],
            );
        }
        return .{ .values = values };
    }
};

pub const ComponentSetV1 = struct {
    values: [COMPONENT_COUNT]manifest_mod.StatementAdapter,

    pub fn appendToGate(
        self: *const ComponentSetV1,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0) return error.AdapterOrderMismatch;
        inline for (&self.values) |*component|
            try gate.append(manifest, try component.binding(manifest));
        if (gate.count != COMPONENT_COUNT)
            return error.AdapterCountMismatch;
    }

    pub fn deinit(self: *ComponentSetV1) void {
        self.* = undefined;
    }
};

const InteractionTreeV1 = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
    ) !InteractionTreeV1 {
        try manifest_mod.validateExact(manifest);
        const columns = try allocator.alloc(
            []M31,
            manifest.total_interaction_columns,
        );
        errdefer allocator.free(columns);
        const storage = try allocator.alloc(
            M31,
            columns.len * manifest_mod.TRACE_SIZE,
        );
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        for (columns, 0..) |*column, ordinal|
            column.* = storage[ordinal * manifest_mod.TRACE_SIZE ..][0..manifest_mod.TRACE_SIZE];
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    fn deinit(self: *InteractionTreeV1) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

fn fillRows(
    rows: []StatementFramework.Row,
    cold: *const input_mod.ColdInputV1,
) !void {
    if (rows.len != NODE_PUBLIC_TUPLE_COUNT)
        return error.CanonicalEmptyWrapperAuthorityMismatch;
    const bytes = try input_mod.encodeNodePublic(&cold.node_public);
    for (rows, bytes, 0..) |*row, byte, index| {
        row.* = .{
            M31.one(),
            M31.fromCanonical(byte),
            M31.one(),
            M31.zero(),
            M31.zero(),
            M31.one(),
            M31.fromCanonical(3),
            M31.fromCanonical(manifest_mod.NODE_PUBLIC_SCOPE),
            M31.fromCanonical(@intCast(index)),
            M31.zero(),
            M31.one(),
            M31.fromCanonical(statement_air.STATEMENT_INPUT_KIND),
            M31.fromCanonical(statement_air.STATEMENT_INPUT_ITEM),
            M31.fromCanonical(statement_air.VM_CLAIM_STATEMENT_SCOPE),
        };
    }
}

fn parameters(active: bool) [statement_air.PARAMETER_COUNT]M31 {
    return .{
        M31.zero(),
        if (active) M31.one() else M31.zero(),
        M31.fromCanonical(statement_air.STATEMENT_INPUT_KIND),
        M31.fromCanonical(statement_air.STATEMENT_INPUT_ITEM),
        M31.fromCanonical(statement_air.VM_CLAIM_STATEMENT_SCOPE),
    };
}

fn requireManifest(
    actual: *const manifest_mod.Manifest,
    expected: *const manifest_mod.Manifest,
) !void {
    try manifest_mod.validateExact(actual);
    if (!std.meta.eql(actual.*, expected.*))
        return error.CanonicalEmptyWrapperAuthorityMismatch;
}

fn preflightFreshTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: [][]M31,
) !void {
    try manifest_mod.validateExact(manifest);
    const expected_count: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => return error.CanonicalEmptyWrapperTreeMismatch,
    };
    if (destination.len != expected_count)
        return error.CanonicalEmptyWrapperTreeMismatch;
    for (destination, 0..) |column, ordinal| {
        if (column.len != manifest_mod.TRACE_SIZE)
            return error.CanonicalEmptyWrapperTreeMismatch;
        for (column) |value| if (!value.isZero())
            return error.CanonicalEmptyWrapperTreeMismatch;
        for (destination[ordinal + 1 ..]) |other|
            if (slicesOverlap(column, other))
                return error.CanonicalEmptyWrapperTreeMismatch;
    }
}

fn clearTree(destination: [][]M31) void {
    for (destination) |column| @memset(column, M31.zero());
}

fn slicesOverlap(left: []const M31, right: []const M31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len * @sizeOf(M31);
    const right_end = right_start + right.len * @sizeOf(M31);
    return left_start < right_end and right_start < left_end;
}

fn rowsEqual(
    left: []const StatementFramework.Row,
    right: []const StatementFramework.Row,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_row, right_row| {
        for (left_row, right_row) |left_value, right_value|
            if (!left_value.eql(right_value)) return false;
    }
    return true;
}

fn cohortIdentity(value: *const CohortV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(COHORT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.cold.identity_sha256);
    hash.update(&value.manifest_value.seal);
    hash.update(&statement_air.SEMANTIC_DIGEST);
    return hash.finalResult();
}

fn interactionIdentity(value: *const GeneratedInteractionsV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(INTERACTION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.manifest_seal);
    hash.update(&value.cohort_identity_sha256);
    hash.update(&value.relations_identity_sha256);
    for (value.claims) |claim| hashQm31(&hash, claim);
    for (value.domain_totals) |claim| hashQm31(&hash, claim);
    return hash.finalResult();
}

fn boundaryIdentity(
    domain: relation.Domain,
    tuple_count: u64,
    claim: QM31,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUDIT_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(domain));
    hashInt(&hash, u64, tuple_count);
    hashQm31(&hash, claim);
    return hash.finalResult();
}

fn auditIdentity(value: *const AuditedInteractionsV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUDIT_DOMAIN);
    hash.update(&value.wire_boundary.tuple_provenance_sha256);
    hash.update(&value.verifier_input_boundary.tuple_provenance_sha256);
    hash.update(&value.closure.closure_id);
    return hash.finalResult();
}

fn relationsIdentity(
    relations: *const universal.UniversalRelations,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/common-canonical-empty-wrapper-relations/v1\x00");
    hashInt(&hash, u16, relations.format_version);
    hash.update(&relations.registry_order_digest);
    for (relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
    }
    return hash.finalResult();
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        word.* = std.mem.readInt(
            u32,
            value[index * 4 ..][0..4],
            .little,
        );
    }
    return result;
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        COMPONENT_COUNT != 36 or NODE_PUBLIC_TUPLE_COUNT != 1816 or
        statement_air.LOGICAL_INPUT_COUNT != 14 or
        statement_air.PREPROCESSED_COLUMN_COUNT != 7 or
        statement_air.PHYSICAL_MAIN_COLUMN_COUNT != 2 or
        PRODUCTION_ACTIVATION)
    {
        @compileError("canonical-empty wrapper cohort contract drifted");
    }
}
