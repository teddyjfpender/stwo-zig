//! Internal segment leaf outer authority v2 authority shard; use segment_leaf_outer_authority_v2.zig publicly.

const dependency_0 = @import("segment_leaf_outer_authority_v2_contract.zig");

const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const NATIVE_CAPTURE_PREPARED_ID_DOMAIN = dependency_0.NATIVE_CAPTURE_PREPARED_ID_DOMAIN;
const NativeDigest = dependency_0.NativeDigest;
const NativeHasher = dependency_0.NativeHasher;
const OuterManifestV2 = dependency_0.OuterManifestV2;
const PREPARED_ID_DOMAIN = dependency_0.PREPARED_ID_DOMAIN;
const PUBLIC_LOGUP_TRACE_ROWS = dependency_0.PUBLIC_LOGUP_TRACE_ROWS;
const PublicLogUpFramework = dependency_0.PublicLogUpFramework;
const PublicLogUpTraceV2 = dependency_0.PublicLogUpTraceV2;
const QM31 = dependency_0.QM31;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const Sha256Digest = dependency_0.Sha256Digest;
const ShaHasher = dependency_0.ShaHasher;
const StatementFramework = dependency_0.StatementFramework;
const StatementTraceV2 = dependency_0.StatementTraceV2;
const TracesV2 = dependency_0.TracesV2;
const VERIFICATION_ID_DOMAIN = dependency_0.VERIFICATION_ID_DOMAIN;
const air_v2 = dependency_0.air_v2;
const native_relations = dependency_0.native_relations;
const public_data_v2 = dependency_0.public_data_v2;
const relation = dependency_0.relation;
const requireNativeDigest = dependency_0.requireNativeDigest;
const requireShaDigest = dependency_0.requireShaDigest;
const source_v2 = dependency_0.source_v2;
const statement_v1 = dependency_0.statement_v1;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const universal = dependency_0.universal;

/// Cold, worker-private reusable storage. All arrays are exact-capacity for
/// one authenticated manifest; no resize or fallback allocation exists.
pub const WorkspaceV2 = struct {
    allocator: std.mem.Allocator,
    manifest_id: NativeDigest,
    statement_trace_rows: usize,
    statement_logical_rows: usize,

    source_logical_storage: []M31,
    statement_committed_storage: []M31,
    statement_interaction_storage: []M31,
    statement_rows: []air_v2.Statement.Row,
    statement_events: []source_v2.StatementRelationEventV2,

    public_logup_committed_storage: [
        PUBLIC_LOGUP_TRACE_ROWS *
            (air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
                air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT)
    ]M31 = undefined,
    public_logup_interaction_storage: [
        PUBLIC_LOGUP_TRACE_ROWS *
            air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT
    ]M31 = undefined,
    public_logup_rows: [source_v2.LOGUP_PUBLICATION_WORD_COUNT]air_v2.PublicLogUp.Row = undefined,
    public_logup_events: [source_v2.LOGUP_PUBLICATION_WORD_COUNT]source_v2.VerifierInputEventV2 = undefined,

    statement_interaction: StatementFramework.Workspace,
    public_logup_interaction: PublicLogUpFramework.Workspace,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const OuterManifestV2,
    ) Error!WorkspaceV2 {
        try manifest.validate();
        const statement_rows: usize = manifest.components[0].trace_rows;
        const statement_logical: usize = manifest.components[0].logical_rows;
        const source_logical_storage = try allocator.alloc(
            M31,
            std.math.mul(usize, statement_rows, 4) catch
                return error.ArithmeticOverflow,
        );
        errdefer allocator.free(source_logical_storage);
        const statement_committed_storage = try allocator.alloc(
            M31,
            std.math.mul(usize, statement_rows, 4) catch
                return error.ArithmeticOverflow,
        );
        errdefer allocator.free(statement_committed_storage);
        const statement_interaction_storage = try allocator.alloc(
            M31,
            std.math.mul(
                usize,
                statement_rows,
                air_v2.Statement.INTERACTION_COLUMN_COUNT,
            ) catch return error.ArithmeticOverflow,
        );
        errdefer allocator.free(statement_interaction_storage);
        const statement_rows_storage = try allocator.alloc(
            air_v2.Statement.Row,
            statement_logical,
        );
        errdefer allocator.free(statement_rows_storage);
        const statement_events = try allocator.alloc(
            source_v2.StatementRelationEventV2,
            statement_logical,
        );
        errdefer allocator.free(statement_events);
        var statement_interaction = try StatementFramework.Workspace.init(
            allocator,
            manifest.components[0].trace_log_size,
        );
        errdefer statement_interaction.deinit();
        var public_logup_interaction = try PublicLogUpFramework.Workspace.init(
            allocator,
            manifest.components[1].trace_log_size,
        );
        errdefer public_logup_interaction.deinit();
        return .{
            .allocator = allocator,
            .manifest_id = manifest.identity,
            .statement_trace_rows = statement_rows,
            .statement_logical_rows = statement_logical,
            .source_logical_storage = source_logical_storage,
            .statement_committed_storage = statement_committed_storage,
            .statement_interaction_storage = statement_interaction_storage,
            .statement_rows = statement_rows_storage,
            .statement_events = statement_events,
            .statement_interaction = statement_interaction,
            .public_logup_interaction = public_logup_interaction,
        };
    }

    pub fn deinit(self: *WorkspaceV2) void {
        self.public_logup_interaction.deinit();
        self.statement_interaction.deinit();
        self.allocator.free(self.statement_events);
        self.allocator.free(self.statement_rows);
        self.allocator.free(self.statement_interaction_storage);
        self.allocator.free(self.statement_committed_storage);
        self.allocator.free(self.source_logical_storage);
        self.* = undefined;
    }

    pub fn validateFor(
        self: *const WorkspaceV2,
        manifest: *const OuterManifestV2,
    ) Error!void {
        try manifest.validate();
        const statement_rows: usize = manifest.components[0].trace_rows;
        const statement_logical: usize = manifest.components[0].logical_rows;
        if (!std.meta.eql(self.manifest_id, manifest.identity) or
            self.statement_trace_rows != statement_rows or
            self.statement_logical_rows != statement_logical or
            self.source_logical_storage.len != 4 * statement_rows or
            self.statement_committed_storage.len != 4 * statement_rows or
            self.statement_interaction_storage.len !=
                air_v2.Statement.INTERACTION_COLUMN_COUNT * statement_rows or
            self.statement_rows.len != statement_logical or
            self.statement_events.len != statement_logical or
            self.statement_interaction.capacity_log_size !=
                manifest.components[0].trace_log_size or
            self.public_logup_interaction.capacity_log_size !=
                manifest.components[1].trace_log_size)
        {
            return error.WorkspaceShapeMismatch;
        }
    }

    pub fn logicalSourceTrace(self: *WorkspaceV2) source_v2.TraceColumnsV2 {
        const rows = self.statement_trace_rows;
        return .{
            .active = self.source_logical_storage[0..rows],
            .scope = self.source_logical_storage[rows .. 2 * rows],
            .index = self.source_logical_storage[2 * rows .. 3 * rows],
            .value = self.source_logical_storage[3 * rows .. 4 * rows],
        };
    }

    pub fn statementStage(self: *WorkspaceV2) StatementTraceV2 {
        const rows = self.statement_trace_rows;
        var interaction: [air_v2.Statement.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&interaction, 0..) |*column, index|
            column.* = self.statement_interaction_storage[index * rows ..][0..rows];
        return .{
            .preprocessed = .{
                self.statement_committed_storage[0..rows],
                self.statement_committed_storage[rows .. 2 * rows],
                self.statement_committed_storage[2 * rows .. 3 * rows],
            },
            .main = .{
                self.statement_committed_storage[3 * rows .. 4 * rows],
            },
            .interaction = interaction,
        };
    }

    pub fn publicLogUpStage(self: *WorkspaceV2) PublicLogUpTraceV2 {
        const rows: usize = PUBLIC_LOGUP_TRACE_ROWS;
        var interaction: [air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&interaction, 0..) |*column, index|
            column.* = self.public_logup_interaction_storage[index * rows ..][0..rows];
        return .{
            .preprocessed = .{
                self.public_logup_committed_storage[0..rows],
                self.public_logup_committed_storage[rows .. 2 * rows],
            },
            .main = .{
                self.public_logup_committed_storage[2 * rows .. 3 * rows],
            },
            .interaction = interaction,
        };
    }
};

/// The two V2 components expose open boundaries in three universal relation
/// domains. They may be closed only against same-domain counterpart claims;
/// aggregate cancellation across domains is never accepted as custody.
pub const BoundaryClosureV2 = struct {
    checked_domain_mask: u64 = relationBit(.recursion_statement_word) |
        relationBit(.recursion_verifier_input_word) |
        relationBit(.recursion_wire),
    statement_emit: QM31,
    verifier_input_consume: QM31,
    publication_bridge_emit: QM31,
    aggregate: QM31,
    locally_closed: bool = false,

    pub fn init(
        statement_emit: QM31,
        verifier_input_consume: QM31,
        publication_bridge_emit: QM31,
    ) BoundaryClosureV2 {
        return .{
            .statement_emit = statement_emit,
            .verifier_input_consume = verifier_input_consume,
            .publication_bridge_emit = publication_bridge_emit,
            .aggregate = statement_emit.add(verifier_input_consume)
                .add(publication_bridge_emit),
        };
    }

    pub fn publicLogUpClaim(self: BoundaryClosureV2) QM31 {
        return self.verifier_input_consume.add(self.publication_bridge_emit);
    }

    pub fn validate(self: BoundaryClosureV2) Error!void {
        if (self.checked_domain_mask !=
            relationBit(.recursion_statement_word) |
                relationBit(.recursion_verifier_input_word) |
                relationBit(.recursion_wire) or
            self.locally_closed or
            !self.aggregate.eql(
                self.statement_emit.add(self.publicLogUpClaim()),
            ))
        {
            return error.CrossDomainClosureMismatch;
        }
    }

    /// Same-domain closure gate for the future complete V2 roster. An
    /// aggregate-zero pair whose individual domains do not close is rejected.
    pub fn validateCounterparts(
        self: BoundaryClosureV2,
        statement_consume: QM31,
        verifier_input_emit: QM31,
        publication_bridge_consume: QM31,
    ) Error!void {
        try self.validate();
        if (!self.statement_emit.add(statement_consume).isZero() or
            !self.verifier_input_consume.add(verifier_input_emit).isZero() or
            !self.publication_bridge_emit.add(publication_bridge_consume).isZero())
        {
            return error.CrossDomainClosureMismatch;
        }
    }
};

/// Pointer-free result of trace preparation. SHA trace/evidence identities and
/// native temporal identities remain in separately typed fields.
pub const PreparedOuterAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest: OuterManifestV2,
    source: source_v2.PreparedV2,
    public_logup: source_v2.PublicLogUpPublicationV2,
    statement_event_count: u32,
    public_logup_word_count: u32 = source_v2.LOGUP_PUBLICATION_WORD_COUNT,
    statement_claim: QM31,
    public_logup_claim: QM31,
    closure: BoundaryClosureV2,
    outer_relation_context_sha_id: Sha256Digest,
    /// Full relation-bound custody of Trees 0, 1, and 2.
    committed_trace_sha_id: Sha256Digest,
    identity: NativeDigest,

    pub fn validate(self: *const PreparedOuterAuthorityV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.statement_event_count !=
                self.manifest.components[0].logical_rows or
            self.public_logup_word_count !=
                source_v2.LOGUP_PUBLICATION_WORD_COUNT or
            !self.statement_claim.eql(self.closure.statement_emit) or
            !self.public_logup_claim.eql(
                self.closure.publicLogUpClaim(),
            ))
        {
            return error.InvalidPublication;
        }
        try self.manifest.validate();
        try self.public_logup.validate();
        try self.closure.validate();
        try requireShaDigest(self.outer_relation_context_sha_id);
        try requireShaDigest(self.committed_trace_sha_id);
        try requireNativeDigest(self.identity);
        if (!std.meta.eql(self.identity, preparedIdentity(self)))
            return error.InvalidPublication;
    }

    pub fn validateAgainst(
        self: *const PreparedOuterAuthorityV2,
        data: *const public_data_v2.PublicDataV2,
        keys: *const source_v2.VerifierKeyAuthorityV2,
        native: *const native_relations.Relations,
        outer: *const universal.UniversalRelations,
    ) Error!void {
        try self.validate();
        try self.source.validateAgainst(data, keys);
        try self.public_logup.validateAgainst(&self.source, data, native);
        try outer.validate();
        const expected_manifest = try OuterManifestV2.init(self.source.manifest);
        if (!std.meta.eql(self.manifest, expected_manifest) or
            !std.meta.eql(
                self.outer_relation_context_sha_id,
                outerRelationContextShaId(outer),
            ))
        {
            return error.InvalidPublication;
        }
    }

    pub fn productionReady(_: *const PreparedOuterAuthorityV2) bool {
        return false;
    }
};

/// Same two typed authority rows, but populated exclusively from a successful
/// native V2 verifier capture.  Compensated public sums, the sealed receipt,
/// the independently recomputed statement authority and its exact row-34
/// provider request plan cross this boundary as one value.
///
/// This still is not a recursive-proof receipt.  The authority-hash request
/// AIR and whole 36-row closure must consume this plan before production can
/// be enabled.
pub const PreparedNativeVerifierOuterAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest: OuterManifestV2,
    source: source_v2.PreparedV2,
    public_logup: source_v2.VerifiedNativePublicLogUpPublicationV2,
    authority_hash_plan: source_v2.AuthorityHashPoseidonPlanV2,
    statement_event_count: u32,
    public_logup_word_count: u32 = source_v2.LOGUP_PUBLICATION_WORD_COUNT,
    statement_claim: QM31,
    public_logup_claim: QM31,
    closure: BoundaryClosureV2,
    outer_relation_context_sha_id: Sha256Digest,
    /// Full relation-bound custody of Trees 0, 1, and 2.
    committed_trace_sha_id: Sha256Digest,
    identity: NativeDigest,

    pub fn validate(
        self: *const PreparedNativeVerifierOuterAuthorityV2,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.statement_event_count !=
                self.manifest.components[0].logical_rows or
            self.public_logup_word_count !=
                source_v2.LOGUP_PUBLICATION_WORD_COUNT or
            !self.statement_claim.eql(self.closure.statement_emit) or
            !self.public_logup_claim.eql(self.closure.publicLogUpClaim()))
        {
            return error.InvalidPublication;
        }
        try self.manifest.validate();
        try self.public_logup.validate();
        try self.authority_hash_plan.validate();
        try self.closure.validate();
        try requireShaDigest(self.outer_relation_context_sha_id);
        try requireShaDigest(self.committed_trace_sha_id);
        try requireNativeDigest(self.identity);
        if (!std.meta.eql(self.source.context.segment_wire_id, self.public_logup.statement_wire_id) or
            !std.meta.eql(
                self.public_logup.statement_authority_id,
                self.authority_hash_plan.statement_authority_id,
            ) or !std.meta.eql(
            self.public_logup.receipt.identity,
            self.authority_hash_plan.receipt_id,
        ) or !std.meta.eql(self.identity, nativeCapturePreparedIdentity(self))) {
            return error.InvalidPublication;
        }
    }

    pub fn validateAgainst(
        self: *const PreparedNativeVerifierOuterAuthorityV2,
        data: *const public_data_v2.PublicDataV2,
        keys: *const source_v2.VerifierKeyAuthorityV2,
        native: *const native_relations.Relations,
        native_sums: *const statement_v2.NativePublicSums,
        receipt: *const statement_v2.VerifiedReceipt,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
        outer: *const universal.UniversalRelations,
    ) Error!void {
        try self.validate();
        try self.source.validateAgainst(data, keys);
        try self.public_logup.validateAgainst(
            &self.source,
            data,
            native,
            native_sums,
            receipt,
            component_descs,
            infra_descs,
        );
        try self.authority_hash_plan.validateAgainst(
            data,
            receipt,
            component_descs,
            infra_descs,
        );
        try outer.validate();
        const expected_manifest = try OuterManifestV2.init(self.source.manifest);
        if (!std.meta.eql(self.manifest, expected_manifest) or
            !std.meta.eql(
                self.outer_relation_context_sha_id,
                outerRelationContextShaId(outer),
            ))
        {
            return error.InvalidPublication;
        }
    }

    pub fn authorityPoseidonCallCount(
        self: *const PreparedNativeVerifierOuterAuthorityV2,
    ) Error!usize {
        try self.validate();
        return self.authority_hash_plan.poseidonCallCount();
    }

    pub fn appendAuthorityPoseidonCallsInto(
        self: *const PreparedNativeVerifierOuterAuthorityV2,
        destination: []@import("../air/memory_commitment/poseidon2_air.zig").Call,
        data: *const public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!void {
        return self.authority_hash_plan.appendPoseidonCallsInto(
            destination,
            data,
            receipt,
            component_descs,
            infra_descs,
        );
    }

    pub fn productionReady(_: *const PreparedNativeVerifierOuterAuthorityV2) bool {
        return false;
    }
};

/// Independent authority-trace verifier receipt. `outer_stark_verified` is
/// fixed false: this is the exact landing point a future native V2 verifier
/// must extend, never a substitute for its proof receipt.
pub const AuthorityVerificationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    typed_components_verified: bool = true,
    all_authority_events_verified: bool = true,
    all_public_logup_words_verified: bool = true,
    exact_domain_boundaries_verified: bool = true,
    outer_stark_verified: bool = false,
    production_capability: bool = false,
    prepared_identity: NativeDigest,
    manifest_id: NativeDigest,
    committed_trace_sha_id: Sha256Digest,
    statement_event_count: u32,
    public_logup_word_count: u32,
    identity: NativeDigest,

    pub fn validateAgainst(
        self: *const AuthorityVerificationV2,
        prepared: *const PreparedOuterAuthorityV2,
    ) Error!void {
        try prepared.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !self.typed_components_verified or
            !self.all_authority_events_verified or
            !self.all_public_logup_words_verified or
            !self.exact_domain_boundaries_verified or
            self.outer_stark_verified or self.production_capability or
            !std.meta.eql(self.prepared_identity, prepared.identity) or
            !std.meta.eql(self.manifest_id, prepared.manifest.identity) or
            !std.meta.eql(
                self.committed_trace_sha_id,
                prepared.committed_trace_sha_id,
            ) or self.statement_event_count != prepared.statement_event_count or
            self.public_logup_word_count != prepared.public_logup_word_count or
            !std.meta.eql(self.identity, verificationIdentity(self)))
        {
            return error.InvalidVerification;
        }
        try requireNativeDigest(self.identity);
    }

    pub fn productionReady(_: *const AuthorityVerificationV2) bool {
        return false;
    }
};

pub fn validateTraceShape(traces: TracesV2, statement_rows: usize) Error!void {
    for (traces.statement.preprocessed) |column|
        if (column.len != statement_rows) return error.InvalidTraceShape;
    for (traces.statement.main) |column|
        if (column.len != statement_rows) return error.InvalidTraceShape;
    for (traces.statement.interaction) |column|
        if (column.len != statement_rows) return error.InvalidTraceShape;
    for (traces.public_logup.preprocessed) |column|
        if (column.len != PUBLIC_LOGUP_TRACE_ROWS)
            return error.InvalidTraceShape;
    for (traces.public_logup.main) |column|
        if (column.len != PUBLIC_LOGUP_TRACE_ROWS)
            return error.InvalidTraceShape;
    for (traces.public_logup.interaction) |column|
        if (column.len != PUBLIC_LOGUP_TRACE_ROWS)
            return error.InvalidTraceShape;
}

pub const TRACE_SLICE_COUNT =
    air_v2.Statement.PREPROCESSED_COLUMN_COUNT +
    air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT +
    air_v2.Statement.INTERACTION_COLUMN_COUNT +
    air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
    air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT +
    air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT;

pub fn outerRelationContextShaId(
    outer: *const universal.UniversalRelations,
) Sha256Digest {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-leaf-outer-v2/relations/v1\x00",
    );
    hash.u16Value(outer.format_version);
    hash.rawBytes(&outer.registry_order_digest);
    hash.u16Value(outer.elements.len);
    for (outer.elements) |element| {
        hash.u8Value(element.arity);
        hash.qm31(element.z);
        hash.qm31(element.alpha);
    }
    return hash.finalize();
}

pub fn preparedIdentity(prepared: *const PreparedOuterAuthorityV2) NativeDigest {
    var hash = NativeHasher.init(PREPARED_ID_DOMAIN);
    hash.scalar(prepared.format_version);
    hash.scalar(prepared.schema_version);
    hash.digest(prepared.manifest.identity);
    hash.digest(prepared.source.source_id);
    hash.digest(prepared.public_logup.identity);
    hash.scalar(prepared.statement_event_count);
    hash.scalar(prepared.public_logup_word_count);
    hash.qm31(prepared.statement_claim);
    hash.qm31(prepared.public_logup_claim);
    hash.scalar(prepared.closure.checked_domain_mask);
    hash.qm31(prepared.closure.statement_emit);
    hash.qm31(prepared.closure.verifier_input_consume);
    hash.qm31(prepared.closure.publication_bridge_emit);
    hash.qm31(prepared.closure.aggregate);
    hash.scalar(@intFromBool(prepared.closure.locally_closed));
    hash.sha256(prepared.outer_relation_context_sha_id);
    hash.sha256(prepared.committed_trace_sha_id);
    return hash.finalize();
}

pub fn nativeCapturePreparedIdentity(
    prepared: *const PreparedNativeVerifierOuterAuthorityV2,
) NativeDigest {
    var hash = NativeHasher.init(NATIVE_CAPTURE_PREPARED_ID_DOMAIN);
    hash.scalar(prepared.format_version);
    hash.scalar(prepared.schema_version);
    hash.digest(prepared.manifest.identity);
    hash.digest(prepared.source.source_id);
    hash.digest(prepared.public_logup.identity);
    hash.digest(prepared.public_logup.receipt.identity);
    hash.digest(prepared.public_logup.native_public_sums_identity);
    hash.digest(prepared.authority_hash_plan.identity);
    hash.scalar(prepared.statement_event_count);
    hash.scalar(prepared.public_logup_word_count);
    hash.qm31(prepared.statement_claim);
    hash.qm31(prepared.public_logup_claim);
    hash.scalar(prepared.closure.checked_domain_mask);
    hash.qm31(prepared.closure.statement_emit);
    hash.qm31(prepared.closure.verifier_input_consume);
    hash.qm31(prepared.closure.publication_bridge_emit);
    hash.qm31(prepared.closure.aggregate);
    hash.scalar(@intFromBool(prepared.closure.locally_closed));
    hash.sha256(prepared.outer_relation_context_sha_id);
    hash.sha256(prepared.committed_trace_sha_id);
    return hash.finalize();
}

pub fn verificationIdentity(
    verification: *const AuthorityVerificationV2,
) NativeDigest {
    var hash = NativeHasher.init(VERIFICATION_ID_DOMAIN);
    hash.scalar(verification.format_version);
    hash.scalar(verification.schema_version);
    hash.scalar(@intFromBool(verification.typed_components_verified));
    hash.scalar(@intFromBool(verification.all_authority_events_verified));
    hash.scalar(@intFromBool(verification.all_public_logup_words_verified));
    hash.scalar(@intFromBool(verification.exact_domain_boundaries_verified));
    hash.scalar(@intFromBool(verification.outer_stark_verified));
    hash.scalar(@intFromBool(verification.production_capability));
    hash.digest(verification.prepared_identity);
    hash.digest(verification.manifest_id);
    hash.sha256(verification.committed_trace_sha_id);
    hash.scalar(verification.statement_event_count);
    hash.scalar(verification.public_logup_word_count);
    return hash.finalize();
}

pub fn relationBit(domain: relation.Domain) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}
