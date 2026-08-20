//! Distinct committed authority for the SegmentV2 publication-input publisher.
//!
//! The source is rebuilt from the capture-backed boundary publication and the
//! verifier-owned VM leaf context, but it owns a separate typed AIR, relation
//! plan, committed columns, claimed sum, trace digest, and receipt. The sole
//! emitted domain is `recursion_verifier_input_word`; rows 37 and 18 remain
//! independent consumers. No host claim or same-component event can cancel
//! either boundary.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;

const relation = @import("../air/lang/relation.zig");
const air = @import("air/segment_publication_input_provider_v2.zig");
const binding = @import("air/segment_publication_input_provider_relation_v2.zig");
const witness = @import("air/segment_publication_input_provider_witness_v2.zig");
const direct_program = @import("air/direct_constraint_program.zig");
const framework_interaction = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");
const boundary = @import("segment_leaf_outer_authority_v2.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const LOGICAL_ROW_COUNT: usize = witness.LOGICAL_ROW_COUNT;
pub const TRACE_LOG_SIZE: u32 = witness.TRACE_LOG_SIZE;
pub const TRACE_ROW_COUNT: usize = witness.TRACE_ROW_COUNT;
pub const PROPOSED_ROSTER_ROW: u8 = witness.PROPOSED_ROSTER_ROW;
pub const HOT_PREPARE_HEAP_ALLOCATIONS: usize = 0;
pub const SOURCE_AIR_AUTHORITY_AVAILABLE = true;
pub const COMMITTED_SOURCE_AVAILABLE = true;
pub const ROSTER_INTEGRATION_AVAILABLE = true;
pub const PRODUCTION_ACTIVATION = false;

pub const Framework = framework_interaction.Runtime(binding.Runtime);

pub const Error = boundary.Error || witness.Error ||
    direct_program.Error || framework_interaction.Error || universal.Error ||
    std.mem.Allocator.Error || error{
    AliasedDestination,
    AuthorityMismatch,
    CaptureMismatch,
    ClaimClosureMismatch,
    InvalidPreparedAuthority,
    InvalidPublicationInputProviderDefinition,
    InvalidTraceShape,
    RelationContextMismatch,
    TraceConstraintViolation,
    TraceMutation,
    WorkspaceMismatch,
};

/// Cold, stable-address program owner. The capture never supplies equations,
/// event roles, tuple coordinates, or proof geometry.
pub const AuthorityV2 = struct {
    definition: air.Definition,
    relation_plan: binding.Plan,
    direct: direct_program.Program,
    source_authority_sha_id: [32]u8,

    pub fn init(allocator: std.mem.Allocator) Error!AuthorityV2 {
        var definition = try air.build(allocator);
        errdefer definition.deinit();
        const relation_plan = try binding.authenticate(&definition);
        const direct = try direct_program.authenticate(
            &definition.arena,
            air.SEMANTIC_DIGEST,
            air.LOGICAL_INPUT_COUNT,
        );
        var result = AuthorityV2{
            .definition = definition,
            .relation_plan = relation_plan,
            .direct = direct,
            .source_authority_sha_id = sourceAuthorityShaId(),
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *AuthorityV2) void {
        self.definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const AuthorityV2) Error!void {
        try self.definition.validate();
        try self.relation_plan.validateAgainst(
            &self.definition.arena,
            air.SEMANTIC_DIGEST,
            binding.events(&self.definition),
        );
        const expected_direct = try direct_program.authenticate(
            &self.definition.arena,
            air.SEMANTIC_DIGEST,
            air.LOGICAL_INPUT_COUNT,
        );
        if (!std.meta.eql(self.direct, expected_direct) or
            self.direct.constraint_count != air.DIRECT_CONSTRAINT_COUNT or
            !std.mem.eql(
                u8,
                &self.source_authority_sha_id,
                &sourceAuthorityShaId(),
            ))
        {
            return error.AuthorityMismatch;
        }
    }
};

pub const TraceV2 = struct {
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    interaction: [air.INTERACTION_COLUMN_COUNT][]M31,
};

/// Reusable worker-private staging. All heap allocation is confined to init;
/// repeated capture preparation performs one bulk inversion and zero allocs.
pub const WorkspaceV2 = struct {
    interaction_workspace: Framework.Workspace,
    main_storage: [air.PHYSICAL_MAIN_COLUMN_COUNT * TRACE_ROW_COUNT]M31 = undefined,
    preprocessed_storage: [air.PREPROCESSED_COLUMN_COUNT * TRACE_ROW_COUNT]M31 = undefined,
    interaction_storage: [air.INTERACTION_COLUMN_COUNT * TRACE_ROW_COUNT]M31 = undefined,
    logical_rows: [LOGICAL_ROW_COUNT]binding.Row = undefined,
    relation_events: [witness.ACTIVE_RELATION_EVENT_COUNT]witness.RelationEventV2 = undefined,

    pub fn init(allocator: std.mem.Allocator) Error!WorkspaceV2 {
        return .{
            .interaction_workspace = try Framework.Workspace.init(
                allocator,
                TRACE_LOG_SIZE,
            ),
        };
    }

    pub fn deinit(self: *WorkspaceV2) void {
        self.interaction_workspace.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const WorkspaceV2) Error!void {
        if (self.interaction_workspace.capacity_log_size != TRACE_LOG_SIZE or
            self.interaction_workspace.scratch.len !=
                try Framework.requiredScratchElementCount(TRACE_LOG_SIZE))
        {
            return error.WorkspaceMismatch;
        }
    }

    pub fn stagedTrace(self: *WorkspaceV2) TraceV2 {
        var preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&preprocessed, 0..) |*column, index|
            column.* = self.preprocessed_storage[index * TRACE_ROW_COUNT ..][0..TRACE_ROW_COUNT];
        var main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&main, 0..) |*column, index|
            column.* = self.main_storage[index * TRACE_ROW_COUNT ..][0..TRACE_ROW_COUNT];
        var interaction: [air.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&interaction, 0..) |*column, index|
            column.* = self.interaction_storage[index * TRACE_ROW_COUNT ..][0..TRACE_ROW_COUNT];
        return .{
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
        };
    }

    fn sourceDestinations(self: *WorkspaceV2) witness.DestinationsV2 {
        const trace = self.stagedTrace();
        return .{
            .main = trace.main,
            .preprocessed = trace.preprocessed,
            .logical_rows = &self.logical_rows,
            .relation_events = &self.relation_events,
        };
    }
};

/// Pointer-free receipt for the independently committed publisher component.
pub const PreparedAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    roster_row: u8 = PROPOSED_ROSTER_ROW,
    trace_log_size: u8 = TRACE_LOG_SIZE,
    logical_row_count: u16 = LOGICAL_ROW_COUNT,
    relation_event_count: u16 = witness.ACTIVE_RELATION_EVENT_COUNT,
    semantic_digest: [32]u8 = air.SEMANTIC_DIGEST,
    source_authority_sha_id: [32]u8,
    source_snapshot_id: [32]u8,
    capture_identity: boundary.NativeDigest,
    publication_id: boundary.NativeDigest,
    context_identity_digest: boundary.Sha256Digest,
    context_profile_manifest_digest: boundary.Sha256Digest,
    relation_context_sha_id: boundary.Sha256Digest,
    committed_trace_sha_id: boundary.Sha256Digest,
    claimed_sum: QM31,
    lup2_publisher_claim: QM31,
    detailed_publisher_claim: QM31,
    row37_consumer_claim: QM31,
    identity: [32]u8,

    pub fn validate(self: *const PreparedAuthorityV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.roster_row != PROPOSED_ROSTER_ROW or
            self.trace_log_size != TRACE_LOG_SIZE or
            self.logical_row_count != LOGICAL_ROW_COUNT or
            self.relation_event_count != witness.ACTIVE_RELATION_EVENT_COUNT or
            !std.mem.eql(u8, &self.semantic_digest, &air.SEMANTIC_DIGEST) or
            !std.mem.eql(
                u8,
                &self.source_authority_sha_id,
                &sourceAuthorityShaId(),
            ) or !self.claimed_sum.eql(
            self.lup2_publisher_claim.add(self.detailed_publisher_claim),
        ) or !self.lup2_publisher_claim.add(
            self.row37_consumer_claim,
        ).isZero() or
            !std.mem.eql(u8, &self.identity, &preparedAuthorityId(self)))
        {
            return error.InvalidPreparedAuthority;
        }
        try requireShaDigest(self.source_authority_sha_id);
        try requireShaDigest(self.source_snapshot_id);
        try requireNativeDigest(self.capture_identity);
        try requireNativeDigest(self.publication_id);
        try requireShaDigest(self.context_identity_digest);
        try requireShaDigest(self.context_profile_manifest_digest);
        try requireShaDigest(self.relation_context_sha_id);
        try requireShaDigest(self.committed_trace_sha_id);
        try requireCanonical(self.claimed_sum);
        try requireCanonical(self.lup2_publisher_claim);
        try requireCanonical(self.detailed_publisher_claim);
        try requireCanonical(self.row37_consumer_claim);
    }

    pub fn validateAgainst(
        self: *const PreparedAuthorityV2,
        inputs: witness.InputsV2,
        relations: *const universal.UniversalRelations,
    ) Error!void {
        try self.validate();
        try inputs.validate();
        try relations.validate();
        const source = try witness.preflight(inputs);
        if (!std.mem.eql(u8, &self.source_snapshot_id, &source.identity) or
            !std.meta.eql(self.capture_identity, inputs.capture.identity) or
            !std.meta.eql(
                self.publication_id,
                inputs.capture.public_logup.identity,
            ) or !std.mem.eql(
            u8,
            &self.context_identity_digest,
            &inputs.vm_context.identity_digest,
        ) or !std.mem.eql(
            u8,
            &self.context_profile_manifest_digest,
            &inputs.vm_context.profile.manifest_digest,
        ) or
            !std.mem.eql(
                u8,
                &self.relation_context_sha_id,
                &outerRelationContextShaId(relations),
            ) or !std.mem.eql(
            u8,
            &self.relation_context_sha_id,
            &inputs.capture.outer_relation_context_sha_id,
        ) or !self.row37_consumer_claim.eql(
            inputs.capture.closure.verifier_input_consume,
        )) {
            return error.CaptureMismatch;
        }
    }

    pub fn productionReady(_: *const PreparedAuthorityV2) bool {
        return PRODUCTION_ACTIVATION;
    }
};

/// Builds the typed committed source into caller-owned trace columns. All
/// fallible capture, authority, relation, shape, direct-constraint, inversion,
/// and closure checks complete in worker-private staging before the first
/// caller-owned trace or receipt byte changes.
pub fn prepareInto(
    destination: *PreparedAuthorityV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    traces: TraceV2,
    inputs: witness.InputsV2,
    relations: *const universal.UniversalRelations,
) Error!void {
    // Authenticate and snapshot both verifier-owned inputs exactly once on the
    // hot path. All later work consumes this pointer-free source value.
    const source = try witness.preflight(inputs);
    try validateBoundary(destination, workspace, authority, traces, inputs, relations);
    if (!std.mem.eql(
        u8,
        &source.outer_relation_context_sha_id,
        &outerRelationContextShaId(relations),
    )) return error.RelationContextMismatch;

    try witness.writeInto(&source, workspace.sourceDestinations());
    try validateDirectRows(workspace, authority);
    var staged_trace = workspace.stagedTrace();
    const domain_claims = try Framework.generatePreparedIntoWithDomainSums(
        &workspace.interaction_workspace,
        &authority.relation_plan,
        &workspace.logical_rows,
        TRACE_LOG_SIZE,
        relations,
        &staged_trace.interaction,
    );
    const verifier_domain = @intFromEnum(
        relation.Domain.recursion_verifier_input_word,
    );
    for (domain_claims.by_domain, 0..) |claim, domain| if (domain != verifier_domain and !claim.isZero()) return error.ClaimClosureMismatch;
    if (!domain_claims.by_domain[verifier_domain].eql(
        domain_claims.claimed_sum,
    )) return error.ClaimClosureMismatch;

    // The first 55 source-exact rows are byte-for-byte the opposite of row
    // 37's capture-backed consumers. The residual therefore belongs solely to
    // row 18's 84 detailed-claim limbs without a second inversion pass.
    const row37_consumer_claim =
        inputs.capture.closure.verifier_input_consume;
    const lup2_publisher_claim = row37_consumer_claim.neg();
    const detailed_publisher_claim =
        domain_claims.claimed_sum.sub(lup2_publisher_claim);

    var staged = PreparedAuthorityV2{
        .source_authority_sha_id = authority.source_authority_sha_id,
        .source_snapshot_id = source.identity,
        .capture_identity = inputs.capture.identity,
        .publication_id = inputs.capture.public_logup.identity,
        .context_identity_digest = inputs.vm_context.identity_digest,
        .context_profile_manifest_digest = inputs.vm_context.profile.manifest_digest,
        .relation_context_sha_id = outerRelationContextShaId(relations),
        .committed_trace_sha_id = committedTraceShaId(
            &source,
            authority,
            staged_trace,
        ),
        .claimed_sum = domain_claims.claimed_sum,
        .lup2_publisher_claim = lup2_publisher_claim,
        .detailed_publisher_claim = detailed_publisher_claim,
        .row37_consumer_claim = row37_consumer_claim,
        .identity = undefined,
    };
    staged.identity = preparedAuthorityId(&staged);
    try staged.validate();

    copyTrace(traces, staged_trace);
    destination.* = staged;
}

pub fn verifyTrace(
    prepared: *const PreparedAuthorityV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    traces: TraceV2,
    inputs: witness.InputsV2,
    relations: *const universal.UniversalRelations,
) Error!void {
    try prepared.validateAgainst(inputs, relations);
    var rebuilt: PreparedAuthorityV2 = undefined;
    var expected_storage: [
        (air.PREPROCESSED_COLUMN_COUNT + air.PHYSICAL_MAIN_COLUMN_COUNT +
            air.INTERACTION_COLUMN_COUNT) * TRACE_ROW_COUNT
    ]M31 = undefined;
    const expected = traceFromStorage(&expected_storage);
    try prepareInto(
        &rebuilt,
        workspace,
        authority,
        expected,
        inputs,
        relations,
    );
    if (!std.meta.eql(prepared.*, rebuilt)) return error.TraceMutation;
    try compareTrace(traces, expected);
}

fn validateDirectRows(
    workspace: *const WorkspaceV2,
    authority: *const AuthorityV2,
) Error!void {
    const trace = @constCast(workspace).stagedTrace();
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (0..TRACE_ROW_COUNT) |row_index| {
        var row: binding.Row = undefined;
        row[0] = trace.main[0][row_index];
        inline for (0..air.PREPROCESSED_COLUMN_COUNT) |column|
            row[column + air.PHYSICAL_MAIN_COLUMN_COUNT] =
                trace.preprocessed[column][row_index];
        try authority.direct.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero())
            return error.TraceConstraintViolation;
    }
}

fn validateBoundary(
    destination: *PreparedAuthorityV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    traces: TraceV2,
    inputs: witness.InputsV2,
    relations: *const universal.UniversalRelations,
) Error!void {
    try workspace.validate();
    try authority.validate();
    try relations.validate();
    try validateTraceShape(traces);

    var outputs: [
        air.PREPROCESSED_COLUMN_COUNT + air.PHYSICAL_MAIN_COLUMN_COUNT +
            air.INTERACTION_COLUMN_COUNT + 1
    ][]u8 = undefined;
    var at: usize = 0;
    for (traces.preprocessed) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    for (traces.main) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    for (traces.interaction) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    outputs[at] = std.mem.asBytes(destination);
    at += 1;
    std.debug.assert(at == outputs.len);
    const input_ranges = [_][]const u8{
        std.mem.asBytes(workspace),
        std.mem.sliceAsBytes(workspace.interaction_workspace.scratch),
        std.mem.asBytes(authority),
        std.mem.asBytes(inputs.capture),
        std.mem.asBytes(inputs.vm_context),
        std.mem.sliceAsBytes(inputs.vm_context.component_descs),
        std.mem.sliceAsBytes(inputs.vm_context.infra_descs),
        std.mem.sliceAsBytes(inputs.vm_context.detailed_claims),
        std.mem.asBytes(relations),
    };
    for (outputs, 0..) |left, left_index| {
        for (outputs[left_index + 1 ..]) |right| if (overlap(left, right))
            return error.AliasedDestination;
        for (input_ranges) |input| if (overlap(left, input))
            return error.AliasedDestination;
    }
}

fn validateTraceShape(traces: TraceV2) Error!void {
    for (traces.preprocessed) |column| if (column.len != TRACE_ROW_COUNT)
        return error.InvalidTraceShape;
    for (traces.main) |column| if (column.len != TRACE_ROW_COUNT)
        return error.InvalidTraceShape;
    for (traces.interaction) |column| if (column.len != TRACE_ROW_COUNT)
        return error.InvalidTraceShape;
}

fn copyTrace(destination: TraceV2, source: TraceV2) void {
    for (destination.preprocessed, source.preprocessed) |target, values|
        @memcpy(target, values);
    for (destination.main, source.main) |target, values| @memcpy(target, values);
    for (destination.interaction, source.interaction) |target, values|
        @memcpy(target, values);
}

fn compareTrace(actual: TraceV2, expected: TraceV2) Error!void {
    for (actual.preprocessed, expected.preprocessed) |left, right|
        if (!m31SliceEqual(left, right)) return error.TraceMutation;
    for (actual.main, expected.main) |left, right|
        if (!m31SliceEqual(left, right)) return error.TraceMutation;
    for (actual.interaction, expected.interaction) |left, right|
        if (!m31SliceEqual(left, right)) return error.TraceMutation;
}

fn traceFromStorage(storage: []M31) TraceV2 {
    std.debug.assert(storage.len ==
        (air.PREPROCESSED_COLUMN_COUNT + air.PHYSICAL_MAIN_COLUMN_COUNT +
            air.INTERACTION_COLUMN_COUNT) * TRACE_ROW_COUNT);
    var at: usize = 0;
    var result: TraceV2 = undefined;
    for (&result.preprocessed) |*column| {
        column.* = storage[at..][0..TRACE_ROW_COUNT];
        at += TRACE_ROW_COUNT;
    }
    for (&result.main) |*column| {
        column.* = storage[at..][0..TRACE_ROW_COUNT];
        at += TRACE_ROW_COUNT;
    }
    for (&result.interaction) |*column| {
        column.* = storage[at..][0..TRACE_ROW_COUNT];
        at += TRACE_ROW_COUNT;
    }
    std.debug.assert(at == storage.len);
    return result;
}

fn committedTraceShaId(
    source: *const witness.PreparedV2,
    authority: *const AuthorityV2,
    traces: TraceV2,
) boundary.Sha256Digest {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-publication-input-provider/traces/v1\x00",
    );
    hash.rawBytes(&source.identity);
    hash.rawBytes(&authority.source_authority_sha_id);
    inline for (.{ traces.preprocessed, traces.main, traces.interaction }) |columns| {
        hash.u16Value(columns.len);
        for (columns) |column| {
            hash.u32Value(column.len);
            for (column) |word| hash.u32Value(word.toU32());
        }
    }
    return hash.finalize();
}

/// Stable allocation-free seal for manifest geometry/authorship binding.
/// Per-proof snapshot identities and claims deliberately do not enter it.
pub fn sourceAuthorityShaId() [32]u8 {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-publication-input-provider/authority/v1\x00",
    );
    hash.u16Value(FORMAT_VERSION);
    hash.u16Value(SCHEMA_VERSION);
    hash.u8Value(PROPOSED_ROSTER_ROW);
    hash.u16Value(LOGICAL_ROW_COUNT);
    hash.u8Value(TRACE_LOG_SIZE);
    hash.u16Value(air.PREPROCESSED_COLUMN_COUNT);
    hash.u16Value(air.PHYSICAL_MAIN_COLUMN_COUNT);
    hash.u16Value(air.INTERACTION_COLUMN_COUNT);
    hash.u16Value(air.DIRECT_CONSTRAINT_COUNT);
    hash.u16Value(air.RELATION_EVENT_COUNT);
    hash.u8Value(@intFromEnum(relation.Domain.recursion_verifier_input_word));
    hash.u8Value(@intFromEnum(relation.Role.emit));
    hash.rawBytes(&air.SEMANTIC_DIGEST);
    hash.rawBytes(&relation.registryOrderDigest());
    return hash.finalize();
}

/// Byte-identical to the capture-backed boundary authority's relation-context
/// seal, so a publisher cannot be generated under different denominators.
fn outerRelationContextShaId(
    relations: *const universal.UniversalRelations,
) boundary.Sha256Digest {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-leaf-outer-v2/relations/v1\x00",
    );
    hash.u16Value(relations.format_version);
    hash.rawBytes(&relations.registry_order_digest);
    hash.u16Value(relations.elements.len);
    for (relations.elements) |element| {
        hash.u8Value(element.arity);
        hash.qm31(element.z);
        hash.qm31(element.alpha);
    }
    return hash.finalize();
}

fn preparedAuthorityId(prepared: *const PreparedAuthorityV2) [32]u8 {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-publication-input-provider/receipt/v1\x00",
    );
    hash.u16Value(prepared.format_version);
    hash.u16Value(prepared.schema_version);
    hash.u8Value(prepared.roster_row);
    hash.u8Value(prepared.trace_log_size);
    hash.u16Value(prepared.logical_row_count);
    hash.u16Value(prepared.relation_event_count);
    hash.rawBytes(&prepared.semantic_digest);
    hash.rawBytes(&prepared.source_authority_sha_id);
    hash.rawBytes(&prepared.source_snapshot_id);
    hash.nativeDigest(prepared.capture_identity);
    hash.nativeDigest(prepared.publication_id);
    hash.rawBytes(&prepared.context_identity_digest);
    hash.rawBytes(&prepared.context_profile_manifest_digest);
    hash.rawBytes(&prepared.relation_context_sha_id);
    hash.rawBytes(&prepared.committed_trace_sha_id);
    hash.qm31(prepared.claimed_sum);
    hash.qm31(prepared.lup2_publisher_claim);
    hash.qm31(prepared.detailed_publisher_claim);
    hash.qm31(prepared.row37_consumer_claim);
    return hash.finalize();
}

const ShaHasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    fn init(domain: []const u8) ShaHasher {
        var inner = std.crypto.hash.sha2.Sha256.init(.{});
        inner.update(domain);
        return .{ .inner = inner };
    }

    fn u8Value(self: *ShaHasher, value: anytype) void {
        self.inner.update(&.{@intCast(value)});
    }

    fn u16Value(self: *ShaHasher, value: anytype) void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(value), .little);
        self.inner.update(&bytes);
    }

    fn u32Value(self: *ShaHasher, value: anytype) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(value), .little);
        self.inner.update(&bytes);
    }

    fn rawBytes(self: *ShaHasher, value: []const u8) void {
        self.u32Value(value.len);
        self.inner.update(value);
    }

    fn nativeDigest(self: *ShaHasher, value: boundary.NativeDigest) void {
        for (value) |word| self.u32Value(word);
    }

    fn qm31(self: *ShaHasher, value: QM31) void {
        for (value.toM31Array()) |word| self.u32Value(word.toU32());
    }

    fn finalize(self: *ShaHasher) [32]u8 {
        return self.inner.finalResult();
    }
};

fn requireNativeDigest(value: boundary.NativeDigest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidPreparedAuthority;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidPreparedAuthority;
}

fn requireShaDigest(value: [32]u8) Error!void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidPreparedAuthority;
}

fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word| if (word.toU32() >= m31.Modulus)
        return error.InvalidPreparedAuthority;
}

fn m31SliceEqual(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (LOGICAL_ROW_COUNT != 139 or TRACE_ROW_COUNT != 256 or
        PROPOSED_ROSTER_ROW != 38 or air.RELATION_EVENT_COUNT != 1 or
        air.PREPROCESSED_COLUMN_COUNT != 4 or
        air.INTERACTION_COLUMN_COUNT != 4 or
        binding.Runtime.INTERACTION_COLUMN_COUNT != 4 or
        HOT_PREPARE_HEAP_ALLOCATIONS != 0 or !SOURCE_AIR_AUTHORITY_AVAILABLE or
        !COMMITTED_SOURCE_AVAILABLE or !ROSTER_INTEGRATION_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("SegmentV2 publication-input provider authority drifted");
    }
}
