//! Internal segment leaf outer authority v2 authority shard; use segment_leaf_outer_authority_v2.zig publicly.

const dependency_0 = @import("segment_leaf_outer_authority_v2_contract.zig");
const dependency_1 = @import("segment_leaf_outer_authority_v2_workspace_v2.zig");

const AuthorityV2 = dependency_0.AuthorityV2;
const AuthorityVerificationV2 = dependency_1.AuthorityVerificationV2;
const BoundaryClosureV2 = dependency_1.BoundaryClosureV2;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const NativeDigest = dependency_0.NativeDigest;
const NativeHasher = dependency_0.NativeHasher;
const OuterManifestV2 = dependency_0.OuterManifestV2;
const PUBLICATION_ID_DOMAIN = dependency_0.PUBLICATION_ID_DOMAIN;
const PUBLIC_LOGUP_TRACE_LOG_SIZE = dependency_0.PUBLIC_LOGUP_TRACE_LOG_SIZE;
const PUBLIC_LOGUP_TRACE_ROWS = dependency_0.PUBLIC_LOGUP_TRACE_ROWS;
const PreparedNativeVerifierOuterAuthorityV2 = dependency_1.PreparedNativeVerifierOuterAuthorityV2;
const PreparedOuterAuthorityV2 = dependency_1.PreparedOuterAuthorityV2;
const PublicLogUpFramework = dependency_0.PublicLogUpFramework;
const QM31 = dependency_0.QM31;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const Sha256Digest = dependency_0.Sha256Digest;
const ShaHasher = dependency_0.ShaHasher;
const StatementFramework = dependency_0.StatementFramework;
const TRACE_SLICE_COUNT = dependency_1.TRACE_SLICE_COUNT;
const TracesV2 = dependency_0.TracesV2;
const WorkspaceV2 = dependency_1.WorkspaceV2;
const air_v2 = dependency_0.air_v2;
const direct_program = dependency_0.direct_program;
const framework_interaction = dependency_0.framework_interaction;
const nativeCapturePreparedIdentity = dependency_1.nativeCapturePreparedIdentity;
const native_relations = dependency_0.native_relations;
const outerRelationContextShaId = dependency_1.outerRelationContextShaId;
const overlap = dependency_1.overlap;
const preflight = dependency_0.preflight;
const preparedIdentity = dependency_1.preparedIdentity;
const public_data_v2 = dependency_0.public_data_v2;
const relation = dependency_0.relation;
const requireNativeDigest = dependency_0.requireNativeDigest;
const source_v2 = dependency_0.source_v2;
const statement_v1 = dependency_0.statement_v1;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const universal = dependency_0.universal;
const validateTraceShape = dependency_1.validateTraceShape;
const verificationIdentity = dependency_1.verificationIdentity;

/// Publication permitted only after `verifyAuthorityInto` has independently
/// rebuilt and compared every trace cell. It is useful integration substrate,
/// but its capability bits prevent reinterpretation as a native proof.
pub const VerifiedAuthorityPublicationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    outer_stark_verified: bool = false,
    production_capability: bool = false,
    verification: AuthorityVerificationV2,
    cohort: source_v2.CohortHandoffV2,
    identity: NativeDigest,

    pub fn validateAgainst(
        self: *const VerifiedAuthorityPublicationV2,
        prepared: *const PreparedOuterAuthorityV2,
        data: *const public_data_v2.PublicDataV2,
        native: *const native_relations.Relations,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.outer_stark_verified or self.production_capability)
        {
            return error.ProductionCapabilityEscalation;
        }
        try self.verification.validateAgainst(prepared);
        try self.cohort.validateAgainst(
            &prepared.source,
            &prepared.public_logup,
            data,
            native,
        );
        try requireNativeDigest(self.identity);
        if (!std.meta.eql(self.identity, publicationIdentity(self)))
            return error.InvalidPublication;
    }

    pub fn productionReady(_: *const VerifiedAuthorityPublicationV2) bool {
        return false;
    }
};

/// Generates both typed component traces and their framework interaction
/// columns into caller-owned final storage. All fallible work targets retained
/// workspace staging; destinations and receipt commit only after both
/// components and both exact-domain claims succeed.
pub fn prepareInto(
    destination: *PreparedOuterAuthorityV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    traces: TracesV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
    native: *const native_relations.Relations,
    outer: *const universal.UniversalRelations,
) Error!void {
    try validateMutableBoundary(
        std.mem.asBytes(destination),
        workspace,
        traces,
        authority,
        data,
        keys,
        native,
        outer,
    );
    const staged = try rebuildStages(
        workspace,
        authority,
        data,
        keys,
        native,
        outer,
    );
    copyTraces(workspace, traces);
    destination.* = staged;
}

/// Independent allocation-free verifier for an already prepared component
/// pair. The destination is untouched on every source, trace, claim, event,
/// relation-context, or identity failure.
pub fn verifyAuthorityInto(
    destination: *AuthorityVerificationV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    traces: TracesV2,
    prepared: *const PreparedOuterAuthorityV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
    native: *const native_relations.Relations,
    outer: *const universal.UniversalRelations,
) Error!void {
    try validateMutableBoundary(
        std.mem.asBytes(destination),
        workspace,
        traces,
        authority,
        data,
        keys,
        native,
        outer,
    );
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(prepared)) or
        tracesOverlap(std.mem.asBytes(prepared), traces) or
        workspaceOverlaps(workspace, std.mem.asBytes(prepared)))
    {
        return error.AliasedDestination;
    }
    const expected = try rebuildStages(
        workspace,
        authority,
        data,
        keys,
        native,
        outer,
    );
    if (!std.meta.eql(expected, prepared.*))
        return error.InvalidPublication;
    try compareTraces(workspace, traces);
    var staged = AuthorityVerificationV2{
        .prepared_identity = prepared.identity,
        .manifest_id = prepared.manifest.identity,
        .committed_trace_sha_id = prepared.committed_trace_sha_id,
        .statement_event_count = prepared.statement_event_count,
        .public_logup_word_count = prepared.public_logup_word_count,
        .identity = undefined,
    };
    staged.identity = verificationIdentity(&staged);
    try staged.validateAgainst(prepared);
    destination.* = staged;
}

pub fn rebuildStages(
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
    native: *const native_relations.Relations,
    outer: *const universal.UniversalRelations,
) Error!PreparedOuterAuthorityV2 {
    try authority.validate();
    try outer.validate();
    const source_preflight = try source_v2.preflight(data, keys);
    const manifest = try OuterManifestV2.init(source_preflight.manifest);
    try workspace.validateFor(&manifest);

    var prepared_source: source_v2.PreparedV2 = undefined;
    try source_v2.prepareInto(
        &prepared_source,
        workspace.logicalSourceTrace(),
        data,
        keys,
    );
    try source_v2.writeStatementRelationEventsInto(
        &prepared_source,
        workspace.statement_events,
        data,
    );
    var public_logup: source_v2.PublicLogUpPublicationV2 = undefined;
    try source_v2.preparePublicLogUpInto(
        &public_logup,
        &prepared_source,
        data,
        native,
    );
    try source_v2.writeVerifierInputEventsInto(
        &public_logup,
        &workspace.public_logup_events,
    );

    try materializeStatementRows(workspace, authority, &prepared_source);
    try materializePublicLogUpRows(workspace, authority, &public_logup);
    var statement_stage = workspace.statementStage();
    const statement_claim = try StatementFramework.generatePreparedInto(
        &workspace.statement_interaction,
        &authority.statement_plan,
        workspace.statement_rows,
        manifest.components[0].trace_log_size,
        outer,
        &statement_stage.interaction,
    );
    var logup_stage = workspace.publicLogUpStage();
    const public_logup_domains =
        try PublicLogUpFramework.generatePreparedIntoWithDomainSums(
            &workspace.public_logup_interaction,
            &authority.public_logup_plan,
            &workspace.public_logup_rows,
            manifest.components[1].trace_log_size,
            outer,
            &logup_stage.interaction,
        );
    const public_logup_claim = public_logup_domains.claimed_sum;

    const closure = try boundaryClosureFromPublicLogUp(
        statement_claim,
        public_logup_domains,
    );
    var staged = PreparedOuterAuthorityV2{
        .manifest = manifest,
        .source = prepared_source,
        .public_logup = public_logup,
        .statement_event_count = manifest.components[0].logical_rows,
        .statement_claim = statement_claim,
        .public_logup_claim = public_logup_claim,
        .closure = closure,
        .outer_relation_context_sha_id = outerRelationContextShaId(outer),
        .committed_trace_sha_id = committedTraceShaId(workspace, &manifest),
        .identity = undefined,
    };
    staged.identity = preparedIdentity(&staged);
    try staged.validateAgainst(data, keys, native, outer);
    return staged;
}

pub fn rebuildNativeVerifierStages(
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
    native: *const native_relations.Relations,
    native_sums: *const statement_v2.NativePublicSums,
    receipt: *const statement_v2.VerifiedReceipt,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
    outer: *const universal.UniversalRelations,
) Error!PreparedNativeVerifierOuterAuthorityV2 {
    try authority.validate();
    try outer.validate();
    const source_preflight = try source_v2.preflight(data, keys);
    const manifest = try OuterManifestV2.init(source_preflight.manifest);
    try workspace.validateFor(&manifest);

    var prepared_source: source_v2.PreparedV2 = undefined;
    try source_v2.prepareInto(
        &prepared_source,
        workspace.logicalSourceTrace(),
        data,
        keys,
    );
    try source_v2.writeStatementRelationEventsInto(
        &prepared_source,
        workspace.statement_events,
        data,
    );
    var public_logup: source_v2.VerifiedNativePublicLogUpPublicationV2 = undefined;
    try source_v2.prepareVerifiedNativePublicLogUpInto(
        &public_logup,
        &prepared_source,
        data,
        native,
        native_sums,
        receipt,
        component_descs,
        infra_descs,
    );
    try source_v2.writeVerifiedNativeVerifierInputEventsInto(
        &public_logup,
        &workspace.public_logup_events,
    );
    const authority_hash_plan = try source_v2.AuthorityHashPoseidonPlanV2.init(
        data,
        receipt,
        component_descs,
        infra_descs,
    );

    try materializeStatementRows(workspace, authority, &prepared_source);
    try materializePublicLogUpRows(workspace, authority, &public_logup);
    var statement_stage = workspace.statementStage();
    const statement_claim = try StatementFramework.generatePreparedInto(
        &workspace.statement_interaction,
        &authority.statement_plan,
        workspace.statement_rows,
        manifest.components[0].trace_log_size,
        outer,
        &statement_stage.interaction,
    );
    var logup_stage = workspace.publicLogUpStage();
    const public_logup_domains =
        try PublicLogUpFramework.generatePreparedIntoWithDomainSums(
            &workspace.public_logup_interaction,
            &authority.public_logup_plan,
            &workspace.public_logup_rows,
            manifest.components[1].trace_log_size,
            outer,
            &logup_stage.interaction,
        );
    const public_logup_claim = public_logup_domains.claimed_sum;
    const closure = try boundaryClosureFromPublicLogUp(
        statement_claim,
        public_logup_domains,
    );
    var staged = PreparedNativeVerifierOuterAuthorityV2{
        .manifest = manifest,
        .source = prepared_source,
        .public_logup = public_logup,
        .authority_hash_plan = authority_hash_plan,
        .statement_event_count = manifest.components[0].logical_rows,
        .statement_claim = statement_claim,
        .public_logup_claim = public_logup_claim,
        .closure = closure,
        .outer_relation_context_sha_id = outerRelationContextShaId(outer),
        .committed_trace_sha_id = committedTraceShaId(workspace, &manifest),
        .identity = undefined,
    };
    staged.identity = nativeCapturePreparedIdentity(&staged);
    try staged.validateAgainst(
        data,
        keys,
        native,
        native_sums,
        receipt,
        component_descs,
        infra_descs,
        outer,
    );
    return staged;
}

pub fn boundaryClosureFromPublicLogUp(
    statement_claim: QM31,
    public_logup: PublicLogUpFramework.DomainClaims,
) Error!BoundaryClosureV2 {
    const verifier_index = @intFromEnum(relation.Domain.recursion_verifier_input_word);
    const bridge_index = @intFromEnum(relation.Domain.recursion_wire);
    for (public_logup.by_domain, 0..) |claim, index| {
        if (index != verifier_index and index != bridge_index and !claim.isZero())
            return error.CrossDomainClosureMismatch;
    }
    const closure = BoundaryClosureV2.init(
        statement_claim,
        public_logup.by_domain[verifier_index],
        public_logup.by_domain[bridge_index],
    );
    try closure.validate();
    if (!closure.publicLogUpClaim().eql(public_logup.claimed_sum))
        return error.CrossDomainClosureMismatch;
    return closure;
}

pub fn materializeStatementRows(
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    prepared: *const source_v2.PreparedV2,
) Error!void {
    const logical = workspace.logicalSourceTrace();
    var committed = workspace.statementStage();
    var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
    var direct_roots: [air_v2.Statement.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (0..workspace.statement_trace_rows) |logical_row| {
        const active = logical.active[logical_row];
        const scope = logical.scope[logical_row];
        const index = logical.index[logical_row];
        const value = logical.value[logical_row];
        const row = air_v2.Statement.logicalRow(value, active, scope, index);
        try authority.statement_direct.evaluateBaseInto(
            &row,
            &direct_scratch,
            &direct_roots,
        );
        for (direct_roots) |root| if (!root.eql(M31.zero()))
            return error.DirectConstraintMismatch;

        if (logical_row < workspace.statement_logical_rows) {
            const event = workspace.statement_events[logical_row];
            if (event.domain != .recursion_statement_word or
                event.role != .emit or !active.eql(M31.one()) or
                !scope.eql(event.tuple[0]) or
                !index.eql(event.tuple[1]) or
                !value.eql(event.tuple[2]))
            {
                return error.AuthorityEventMismatch;
            }
            workspace.statement_rows[logical_row] = row;
        } else if (!active.eql(M31.zero()) or !scope.eql(M31.zero()) or
            !index.eql(M31.zero()) or !value.eql(M31.zero()))
        {
            return error.AuthorityEventMismatch;
        }

        const destination = framework_interaction.committedRow(
            logical_row,
            prepared.manifest.trace_log_size,
        );
        committed.preprocessed[0][destination] = active;
        committed.preprocessed[1][destination] = scope;
        committed.preprocessed[2][destination] = index;
        committed.main[0][destination] = value;
    }
}

pub fn materializePublicLogUpRows(
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    publication: anytype,
) Error!void {
    const words = try publication.canonicalWords();
    var committed = workspace.publicLogUpStage();
    var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
    var direct_roots: [air_v2.PublicLogUp.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (0..PUBLIC_LOGUP_TRACE_ROWS) |logical_row| {
        const active = M31.fromCanonical(@intFromBool(
            logical_row < source_v2.LOGUP_PUBLICATION_WORD_COUNT,
        ));
        const index = if (logical_row < source_v2.LOGUP_PUBLICATION_WORD_COUNT)
            M31.fromCanonical(@intCast(logical_row))
        else
            M31.zero();
        const value = if (logical_row < source_v2.LOGUP_PUBLICATION_WORD_COUNT)
            words[logical_row]
        else
            M31.zero();
        const row = air_v2.PublicLogUp.logicalRow(value, active, index);
        try authority.public_logup_direct.evaluateBaseInto(
            &row,
            &direct_scratch,
            &direct_roots,
        );
        for (direct_roots) |root| if (!root.eql(M31.zero()))
            return error.DirectConstraintMismatch;

        if (logical_row < source_v2.LOGUP_PUBLICATION_WORD_COUNT) {
            const event = workspace.public_logup_events[logical_row];
            if (event.domain != .recursion_verifier_input_word or
                event.role != .consume or
                !event.tuple[0].eql(M31.fromCanonical(
                    source_v2.SEGMENT_V2_VERIFIER_ID,
                )) or !event.tuple[1].eql(M31.fromCanonical(
                source_v2.PUBLIC_LOGUP_V2_KIND,
            )) or !event.tuple[2].eql(index) or
                !event.tuple[3].eql(M31.zero()) or
                !event.tuple[4].eql(value))
            {
                return error.AuthorityEventMismatch;
            }
            workspace.public_logup_rows[logical_row] = row;
        }
        const destination = framework_interaction.committedRow(
            logical_row,
            PUBLIC_LOGUP_TRACE_LOG_SIZE,
        );
        committed.preprocessed[0][destination] = active;
        committed.preprocessed[1][destination] = index;
        committed.main[0][destination] = value;
    }
}

pub fn validateMutableBoundary(
    destination: []const u8,
    workspace: *WorkspaceV2,
    traces: TracesV2,
    authority: *const AuthorityV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
    native: *const native_relations.Relations,
    outer: *const universal.UniversalRelations,
) Error!void {
    try validateTraceShape(traces, workspace.statement_trace_rows);
    const immutable = [_][]const u8{
        std.mem.asBytes(authority),
        std.mem.asBytes(data),
        std.mem.sliceAsBytes(data.words()),
        std.mem.asBytes(keys),
        std.mem.asBytes(native),
        std.mem.asBytes(outer),
    };
    for (immutable) |input| {
        if (overlap(destination, input) or tracesOverlap(input, traces) or
            workspaceOverlaps(workspace, input))
        {
            return error.AliasedDestination;
        }
    }
    if (tracesOverlap(destination, traces) or
        workspaceOverlaps(workspace, destination))
    {
        return error.AliasedDestination;
    }
    const output_slices = traceSlices(traces);
    for (output_slices, 0..) |left, left_index| {
        for (output_slices[left_index + 1 ..]) |right| {
            if (overlap(left, right)) return error.AliasedDestination;
        }
        if (workspaceOverlaps(workspace, left))
            return error.AliasedDestination;
    }
}

pub fn traceSlices(traces: TracesV2) [TRACE_SLICE_COUNT][]const u8 {
    var result: [TRACE_SLICE_COUNT][]const u8 = undefined;
    var at: usize = 0;
    inline for (.{
        traces.statement.preprocessed,
        traces.statement.main,
        traces.statement.interaction,
        traces.public_logup.preprocessed,
        traces.public_logup.main,
        traces.public_logup.interaction,
    }) |columns| for (columns) |column| {
        result[at] = std.mem.sliceAsBytes(column);
        at += 1;
    };
    std.debug.assert(at == result.len);
    return result;
}

pub fn tracesOverlap(input: []const u8, traces: TracesV2) bool {
    for (traceSlices(traces)) |output| if (overlap(input, output)) return true;
    return false;
}

pub fn workspaceOverlaps(workspace: *const WorkspaceV2, input: []const u8) bool {
    inline for (.{
        std.mem.asBytes(workspace),
        std.mem.sliceAsBytes(workspace.source_logical_storage),
        std.mem.sliceAsBytes(workspace.statement_committed_storage),
        std.mem.sliceAsBytes(workspace.statement_interaction_storage),
        std.mem.sliceAsBytes(workspace.statement_rows),
        std.mem.sliceAsBytes(workspace.statement_events),
        std.mem.asBytes(&workspace.public_logup_committed_storage),
        std.mem.asBytes(&workspace.public_logup_interaction_storage),
        std.mem.asBytes(&workspace.public_logup_rows),
        std.mem.asBytes(&workspace.public_logup_events),
        std.mem.sliceAsBytes(workspace.statement_interaction.scratch),
        std.mem.sliceAsBytes(workspace.public_logup_interaction.scratch),
    }) |storage| if (overlap(storage, input)) return true;
    return false;
}

pub fn copyTraces(workspace: *WorkspaceV2, destination: TracesV2) void {
    const statement = workspace.statementStage();
    const logup = workspace.publicLogUpStage();
    copyColumnSet(destination.statement.preprocessed, statement.preprocessed);
    copyColumnSet(destination.statement.main, statement.main);
    copyColumnSet(destination.statement.interaction, statement.interaction);
    copyColumnSet(destination.public_logup.preprocessed, logup.preprocessed);
    copyColumnSet(destination.public_logup.main, logup.main);
    copyColumnSet(destination.public_logup.interaction, logup.interaction);
}

pub fn compareTraces(workspace: *WorkspaceV2, actual: TracesV2) Error!void {
    const statement = workspace.statementStage();
    const logup = workspace.publicLogUpStage();
    try compareColumnSet(actual.statement.preprocessed, statement.preprocessed);
    try compareColumnSet(actual.statement.main, statement.main);
    try compareColumnSet(actual.statement.interaction, statement.interaction);
    try compareColumnSet(actual.public_logup.preprocessed, logup.preprocessed);
    try compareColumnSet(actual.public_logup.main, logup.main);
    try compareColumnSet(actual.public_logup.interaction, logup.interaction);
}

pub fn copyColumnSet(destination: anytype, source: anytype) void {
    for (destination, source) |output, input| @memcpy(output, input);
}

pub fn compareColumnSet(actual: anytype, expected: anytype) Error!void {
    for (actual, expected) |got, wanted| {
        for (got, wanted) |got_word, wanted_word| {
            if (!got_word.eql(wanted_word)) return error.TraceMismatch;
        }
    }
}

pub fn committedTraceShaId(
    workspace: *WorkspaceV2,
    manifest: *const OuterManifestV2,
) Sha256Digest {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-leaf-outer-v2/committed-traces/v1\x00",
    );
    hash.nativeDigest(manifest.identity);
    const statement = workspace.statementStage();
    const logup = workspace.publicLogUpStage();
    inline for (.{
        statement.preprocessed,
        statement.main,
        statement.interaction,
        logup.preprocessed,
        logup.main,
        logup.interaction,
    }) |columns| {
        hash.u16Value(columns.len);
        for (columns) |column| {
            hash.u32Value(column.len);
            for (column) |word| hash.u32Value(word.toU32());
        }
    }
    return hash.finalize();
}

pub fn publicationIdentity(
    publication: *const VerifiedAuthorityPublicationV2,
) NativeDigest {
    var hash = NativeHasher.init(PUBLICATION_ID_DOMAIN);
    hash.scalar(publication.format_version);
    hash.scalar(publication.schema_version);
    hash.scalar(@intFromBool(publication.outer_stark_verified));
    hash.scalar(@intFromBool(publication.production_capability));
    hash.digest(publication.verification.identity);
    hash.digest(publication.cohort.native.identity);
    hash.sha256(publication.cohort.sha_closure.statement_relation.snapshot_id);
    hash.sha256(publication.cohort.sha_closure.verifier_input.snapshot_id);
    return hash.finalize();
}
