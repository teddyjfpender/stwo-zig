//! Internal segment leaf authority v2 authority shard; use segment_leaf_authority_v2.zig publicly.

const dependency_0 = @import("segment_leaf_authority_v2_contract.zig");

const CONTEXT_SCOPE = dependency_0.CONTEXT_SCOPE;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const LOGUP_PUBLICATION_ID_DOMAIN = dependency_0.LOGUP_PUBLICATION_ID_DOMAIN;
const LOGUP_PUBLICATION_WORD_COUNT = dependency_0.LOGUP_PUBLICATION_WORD_COUNT;
const LOGUP_RELATION_ID_DOMAIN = dependency_0.LOGUP_RELATION_ID_DOMAIN;
const LOGUP_TAG = dependency_0.LOGUP_TAG;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const ManifestV2 = dependency_0.ManifestV2;
const NativeTemporalContextV2 = dependency_0.NativeTemporalContextV2;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const PUBLIC_LOGUP_V2_KIND = dependency_0.PUBLIC_LOGUP_V2_KIND;
const PerformanceV2 = dependency_0.PerformanceV2;
const QM31 = dependency_0.QM31;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const SEGMENT_V2_VERIFIER_ID = dependency_0.SEGMENT_V2_VERIFIER_ID;
const SOURCE_ID_DOMAIN = dependency_0.SOURCE_ID_DOMAIN;
const STATEMENT_RELATION_ARITY = dependency_0.STATEMENT_RELATION_ARITY;
const STATEMENT_RELATION_DOMAIN = dependency_0.STATEMENT_RELATION_DOMAIN;
const VERIFIER_INPUT_RELATION_ARITY = dependency_0.VERIFIER_INPUT_RELATION_ARITY;
const VERIFIER_INPUT_RELATION_DOMAIN = dependency_0.VERIFIER_INPUT_RELATION_DOMAIN;
const VerifierKeyAuthorityV2 = dependency_0.VerifierKeyAuthorityV2;
const WIRE_SCOPE = dependency_0.WIRE_SCOPE;
const WordWriter = dependency_0.WordWriter;
const channel = dependency_0.channel;
const formatId = dependency_0.formatId;
const isZeroBytes = dependency_0.isZeroBytes;
const nativeContext = dependency_0.nativeContext;
const native_relations = dependency_0.native_relations;
const public_data_v2 = dependency_0.public_data_v2;
const public_logup_v2 = dependency_0.public_logup_v2;
const relation = dependency_0.relation;
const requireDigest = dependency_0.requireDigest;
const std = dependency_0.std;
const temporal = dependency_0.temporal;

/// SHA identities consumed by global-closure plumbing.  These byte values are
/// never accepted where a native temporal `Digest` is required.
pub const ShaTupleEvidenceV2 = struct {
    source_authority_id: [32]u8,
    snapshot_id: [32]u8,
    tuple_provenance_id: [32]u8,
    tuple_count: u32,

    pub fn validate(self: *const ShaTupleEvidenceV2) Error!void {
        if (self.tuple_count == 0 or isZeroBytes(&self.source_authority_id) or
            isZeroBytes(&self.snapshot_id) or
            isZeroBytes(&self.tuple_provenance_id))
        {
            return error.InvalidPublication;
        }
    }
};

/// Pointer-free source receipt.  The full wire is retained in the caller's
/// `PublicDataV2`; this receipt binds it transitively through `segment_wire_id`
/// and is re-derived before every hot write.
pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest: ManifestV2,
    verifier_keys: VerifierKeyAuthorityV2,
    context: NativeTemporalContextV2,
    source_id: Digest,
    statement_relation_evidence: ShaTupleEvidenceV2,
    performance: PerformanceV2,

    pub fn validateAgainst(
        self: *const PreparedV2,
        data: *const public_data_v2.PublicDataV2,
        keys: *const VerifierKeyAuthorityV2,
    ) Error!void {
        const expected = try derivePrepared(data, keys);
        if (!std.meta.eql(self.*, expected)) return error.SourceMismatch;
    }
};

/// SoA trace destinations for the new V2 statement-source row.
pub const TraceColumnsV2 = struct {
    active: []M31,
    scope: []M31,
    index: []M31,
    value: []M31,
};

pub const StatementRelationEventV2 = struct {
    domain: relation.Domain = STATEMENT_RELATION_DOMAIN,
    role: relation.Role = .emit,
    tuple: [3]M31,
};

/// Allocation geometry obtained only after authenticating the borrowed wire.
/// Drivers use this cold preflight before allocating reusable trace/event slabs;
/// hot publication remains allocation-free.
pub const PreflightV2 = struct {
    manifest: ManifestV2,
    source_trace_column_words: usize,
    source_trace_storage_bytes: usize,
    statement_event_count: usize,
};

pub fn preflight(
    data: *const public_data_v2.PublicDataV2,
    keys: *const VerifierKeyAuthorityV2,
) Error!PreflightV2 {
    try keys.validate();
    _ = try data.metadata();
    const manifest = try ManifestV2.init(data.words().len);
    const column_words = std.math.mul(
        usize,
        manifest.trace_row_count,
        PREPROCESSED_COLUMN_COUNT + MAIN_COLUMN_COUNT,
    ) catch return error.ArithmeticOverflow;
    const storage_bytes = std.math.mul(
        usize,
        column_words,
        @sizeOf(M31),
    ) catch return error.ArithmeticOverflow;
    return .{
        .manifest = manifest,
        .source_trace_column_words = column_words,
        .source_trace_storage_bytes = storage_bytes,
        .statement_event_count = manifest.logical_row_count,
    };
}

/// Derive and publish one complete V2 source and its trace transactionally.
/// Every validation, alias check and size check completes before any output is
/// modified.  No allocation occurs.
pub fn prepareInto(
    destination: *PreparedV2,
    trace: TraceColumnsV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const VerifierKeyAuthorityV2,
) Error!void {
    try rejectPrepareAliases(destination, trace, data, keys);
    const staged = try derivePrepared(data, keys);
    try validateTraceShape(trace, staged.manifest.trace_row_count);
    writeTraceAssumeValid(trace, data.words(), &staged.context, &staged.manifest);
    destination.* = staged;
}

/// Revalidated trace refill for a reusable preallocated worker slab.
pub fn writeTraceInto(
    prepared: *const PreparedV2,
    trace: TraceColumnsV2,
    data: *const public_data_v2.PublicDataV2,
) Error!void {
    try rejectTraceAliases(prepared, trace, data);
    try prepared.validateAgainst(data, &prepared.verifier_keys);
    try validateTraceShape(trace, prepared.manifest.trace_row_count);
    writeTraceAssumeValid(trace, data.words(), &prepared.context, &prepared.manifest);
}

/// Exact logical relation multiset for closure/audit consumers.  Padding rows
/// are inactive and intentionally absent from this compact publication.
pub fn writeStatementRelationEventsInto(
    prepared: *const PreparedV2,
    destination: []StatementRelationEventV2,
    data: *const public_data_v2.PublicDataV2,
) Error!void {
    if (overlap(std.mem.sliceAsBytes(destination), std.mem.asBytes(prepared)) or
        overlap(std.mem.sliceAsBytes(destination), std.mem.asBytes(data)) or
        overlap(std.mem.sliceAsBytes(destination), std.mem.sliceAsBytes(data.words())))
    {
        return error.AliasedDestination;
    }
    try prepared.validateAgainst(data, &prepared.verifier_keys);
    if (destination.len != prepared.manifest.logical_row_count)
        return error.DestinationLengthMismatch;

    const context_words = try prepared.context.canonicalWords();
    var at: usize = 0;
    for (data.words(), 0..) |word, index| {
        destination[at] = statementEvent(WIRE_SCOPE, index, word);
        at += 1;
    }
    for (context_words, 0..) |word, index| {
        destination[at] = statementEvent(CONTEXT_SCOPE, index, word);
        at += 1;
    }
    std.debug.assert(at == destination.len);
}

/// Allocation-free source preflight over the uncompensated public boundary.
///
/// This value is useful for typed-AIR authoring and trace-shape validation,
/// but it is not evidence that a native proof verified.  Production callers
/// must use the separately typed capture-backed publication below; retaining
/// this explicit name prevents a bare recomputation from acquiring verifier
/// custody by accident.
pub const SourcePreflightPublicLogUpPublicationV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    wire_tag: u32 = LOGUP_TAG,
    source_id: Digest,
    authenticated_context_id: Digest,
    relation_context_id: Digest,
    sums: public_logup_v2.Sums,
    total: QM31,
    identity: Digest,
    verifier_input_evidence: ShaTupleEvidenceV2,

    pub fn validate(self: *const SourcePreflightPublicLogUpPublicationV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.wire_tag != LOGUP_TAG)
        {
            return error.UnsupportedVersion;
        }
        inline for (.{
            self.source_id,
            self.authenticated_context_id,
            self.relation_context_id,
            self.identity,
        }) |digest| try requireDigest(digest);
        if (!self.total.eql(self.sums.total()) or
            !std.meta.eql(self.identity, logupPublicationId(self)))
        {
            return error.InvalidPublication;
        }
        try self.verifier_input_evidence.validate();
        const expected_evidence = verifierInputEvidence(self);
        if (!std.meta.eql(expected_evidence, self.verifier_input_evidence))
            return error.InvalidPublication;
    }

    pub fn validateAgainst(
        self: *const SourcePreflightPublicLogUpPublicationV2,
        prepared: *const PreparedV2,
        data: *const public_data_v2.PublicDataV2,
        relations: *const native_relations.Relations,
    ) Error!void {
        const expected = try derivePublicLogUp(prepared, data, relations);
        if (!std.meta.eql(self.*, expected)) return error.InvalidPublication;
    }

    pub fn canonicalWords(
        self: *const SourcePreflightPublicLogUpPublicationV2,
    ) Error![LOGUP_PUBLICATION_WORD_COUNT]M31 {
        try self.validate();
        var result: [LOGUP_PUBLICATION_WORD_COUNT]M31 = undefined;
        writeLogUpWordsAssumeValid(self, &result);
        return result;
    }

    pub fn productionReady(_: *const SourcePreflightPublicLogUpPublicationV2) bool {
        return false;
    }
};

/// Compatibility spelling for existing source-preflight callers.  New code
/// should name the provenance explicitly and must not treat this alias as a
/// successful native-verifier receipt.
pub const PublicLogUpPublicationV2 = SourcePreflightPublicLogUpPublicationV2;

pub fn derivePrepared(
    data: *const public_data_v2.PublicDataV2,
    keys: *const VerifierKeyAuthorityV2,
) Error!PreparedV2 {
    try keys.validate();
    const metadata = try data.metadata();
    const manifest = try ManifestV2.init(data.words().len);
    const context = try nativeContext(&metadata, keys, &manifest);
    const source_id = sourceId(&manifest, keys, &context);
    const evidence = statementRelationEvidence(
        data.words(),
        &context,
        &manifest,
        source_id,
    );
    return .{
        .manifest = manifest,
        .verifier_keys = keys.*,
        .context = context,
        .source_id = source_id,
        .statement_relation_evidence = evidence,
        .performance = .{
            .wire_words = manifest.wire_word_count,
            .context_words = manifest.context_word_count,
            .logical_rows = manifest.logical_row_count,
            .padded_rows = manifest.trace_row_count,
            .padding_rows = manifest.trace_row_count - manifest.logical_row_count,
            .prepared_bytes = @sizeOf(PreparedV2),
            .authority_identity_poseidon_permutations = authorityIdentityPoseidonPermutationCount(),
        },
    };
}

pub fn derivePublicLogUp(
    prepared: *const PreparedV2,
    data: *const public_data_v2.PublicDataV2,
    relations: *const native_relations.Relations,
) Error!SourcePreflightPublicLogUpPublicationV2 {
    try prepared.validateAgainst(data, &prepared.verifier_keys);
    const sums = try public_logup_v2.relationSums(data, relations);
    var result = SourcePreflightPublicLogUpPublicationV2{
        .source_id = prepared.source_id,
        .authenticated_context_id = prepared.context.authenticated_context_id,
        .relation_context_id = relationContextId(relations),
        .sums = sums,
        .total = sums.total(),
        .identity = undefined,
        .verifier_input_evidence = undefined,
    };
    result.identity = logupPublicationId(&result);
    result.verifier_input_evidence = verifierInputEvidence(&result);
    try result.validate();
    return result;
}

pub fn writeTraceAssumeValid(
    trace: TraceColumnsV2,
    wire: []const M31,
    context: *const NativeTemporalContextV2,
    manifest: *const ManifestV2,
) void {
    const context_words = context.canonicalWords() catch unreachable;
    var row: usize = 0;
    for (wire, 0..) |word, index| {
        writeTraceRow(trace, row, true, WIRE_SCOPE, index, word);
        row += 1;
    }
    for (context_words, 0..) |word, index| {
        writeTraceRow(trace, row, true, CONTEXT_SCOPE, index, word);
        row += 1;
    }
    while (row < manifest.trace_row_count) : (row += 1)
        writeTraceRow(trace, row, false, 0, 0, M31.zero());
}

pub fn writeTraceRow(
    trace: TraceColumnsV2,
    row: usize,
    active: bool,
    scope: u32,
    index: usize,
    value: M31,
) void {
    trace.active[row] = M31.fromCanonical(@intFromBool(active));
    trace.scope[row] = M31.fromCanonical(scope);
    trace.index[row] = M31.fromCanonical(@intCast(index));
    trace.value[row] = value;
}

pub fn statementEvent(scope: u32, index: usize, value: M31) StatementRelationEventV2 {
    return .{ .tuple = .{
        M31.fromCanonical(scope),
        M31.fromCanonical(@intCast(index)),
        value,
    } };
}

pub fn validateTraceShape(trace: TraceColumnsV2, expected: u32) Error!void {
    const len: usize = expected;
    if (trace.active.len != len or trace.scope.len != len or
        trace.index.len != len or trace.value.len != len)
    {
        return error.InvalidTraceShape;
    }
    const slices = [_][]M31{ trace.active, trace.scope, trace.index, trace.value };
    for (slices, 0..) |left, left_index| {
        for (slices[left_index + 1 ..]) |right| {
            if (overlap(std.mem.sliceAsBytes(left), std.mem.sliceAsBytes(right)))
                return error.AliasedDestination;
        }
    }
}

pub fn rejectPrepareAliases(
    destination: *PreparedV2,
    trace: TraceColumnsV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const VerifierKeyAuthorityV2,
) Error!void {
    const destination_bytes = std.mem.asBytes(destination);
    if (overlap(destination_bytes, std.mem.asBytes(data)) or
        overlap(destination_bytes, std.mem.sliceAsBytes(data.words())) or
        overlap(destination_bytes, std.mem.asBytes(keys)))
    {
        return error.AliasedDestination;
    }
    try rejectTraceInputAliases(trace, destination_bytes, data, std.mem.asBytes(keys));
}

pub fn rejectTraceAliases(
    prepared: *const PreparedV2,
    trace: TraceColumnsV2,
    data: *const public_data_v2.PublicDataV2,
) Error!void {
    try rejectTraceInputAliases(trace, std.mem.asBytes(prepared), data, &.{});
}

pub fn rejectTraceInputAliases(
    trace: TraceColumnsV2,
    authority_bytes: []const u8,
    data: *const public_data_v2.PublicDataV2,
    extra: []const u8,
) Error!void {
    const inputs = [_][]const u8{
        authority_bytes,
        std.mem.asBytes(data),
        std.mem.sliceAsBytes(data.words()),
        extra,
    };
    for ([_][]M31{ trace.active, trace.scope, trace.index, trace.value }) |column| {
        const bytes = std.mem.sliceAsBytes(column);
        for (inputs) |input| if (overlap(bytes, input))
            return error.AliasedDestination;
    }
}

pub fn sourceId(
    manifest: *const ManifestV2,
    keys: *const VerifierKeyAuthorityV2,
    context: *const NativeTemporalContextV2,
) Digest {
    var hash = IdentityHasher.init(SOURCE_ID_DOMAIN);
    hash.scalar(FORMAT_VERSION);
    hash.scalar(SCHEMA_VERSION);
    hash.digest(formatId());
    hash.digest(manifest.identity);
    hash.digest(keys.identity);
    hash.digest(context.segment_wire_id);
    hash.digest(context.authenticated_context_id);
    return hash.finalize();
}

pub fn relationContextId(relations: *const native_relations.Relations) Digest {
    var draws: [native_relations.DRAW_COUNT]QM31 = undefined;
    relations.writeDraws(&draws) catch unreachable;
    var hash = IdentityHasher.init(LOGUP_RELATION_ID_DOMAIN);
    hash.scalar(FORMAT_VERSION);
    hash.scalar(native_relations.RELATION_COUNT);
    for (draws) |draw| hash.qm31(draw);
    return hash.finalize();
}

pub fn logupPublicationId(publication: anytype) Digest {
    var hash = IdentityHasher.init(LOGUP_PUBLICATION_ID_DOMAIN);
    hash.scalar(publication.format_version);
    hash.scalar(publication.schema_version);
    hash.digest(publication.source_id);
    hash.digest(publication.authenticated_context_id);
    hash.digest(publication.relation_context_id);
    hash.qm31(publication.sums.registers_state);
    hash.qm31(publication.sums.memory_access);
    hash.qm31(publication.sums.program_access);
    hash.qm31(publication.sums.merkle);
    hash.qm31(publication.total);
    return hash.finalize();
}

pub fn writeLogUpWordsAssumeValid(
    publication: anytype,
    destination: *[LOGUP_PUBLICATION_WORD_COUNT]M31,
) void {
    var writer = WordWriter{ .words = destination };
    writer.scalar(publication.wire_tag);
    writer.scalar(publication.format_version);
    writer.scalar(publication.schema_version);
    writer.digest(publication.source_id);
    writer.digest(publication.authenticated_context_id);
    writer.digest(publication.relation_context_id);
    writer.qm31(publication.sums.registers_state);
    writer.qm31(publication.sums.memory_access);
    writer.qm31(publication.sums.program_access);
    writer.qm31(publication.sums.merkle);
    writer.qm31(publication.total);
    writer.digest(publication.identity);
    std.debug.assert(writer.at == destination.len);
}

pub fn statementRelationEvidence(
    wire: []const M31,
    context: *const NativeTemporalContextV2,
    manifest: *const ManifestV2,
    source_id: Digest,
) ShaTupleEvidenceV2 {
    const context_words = context.canonicalWords() catch unreachable;

    var authority = ShaHasher.init("stwo-zig/segment-leaf-v2/statement-authority/v1\x00");
    authority.u16Value(FORMAT_VERSION);
    authority.u16Value(SCHEMA_VERSION);
    authority.u8Value(@intFromEnum(STATEMENT_RELATION_DOMAIN));
    authority.u32Value(WIRE_SCOPE);
    authority.u32Value(CONTEXT_SCOPE);
    authority.u8Value(STATEMENT_RELATION_ARITY);
    authority.rawBytes(&relation.registryOrderDigest());
    authority.digestWords(manifest.schema_id);
    authority.digestWords(manifest.identity);

    var snapshot = ShaHasher.init("stwo-zig/segment-leaf-v2/statement-snapshot/v1\x00");
    snapshot.digestWords(source_id);
    snapshot.digestWords(context.segment_wire_id);
    snapshot.digestWords(context.authenticated_context_id);
    snapshot.u32Value(manifest.logical_row_count);

    var provenance = ShaHasher.init("stwo-zig/segment-leaf-v2/statement-tuples/v1\x00");
    provenance.u8Value(@intFromEnum(STATEMENT_RELATION_DOMAIN));
    provenance.u8Value(@intFromEnum(relation.Role.emit));
    provenance.u32Value(manifest.logical_row_count);
    for (wire, 0..) |word, index|
        provenance.statementTuple(WIRE_SCOPE, @intCast(index), word);
    for (context_words, 0..) |word, index|
        provenance.statementTuple(CONTEXT_SCOPE, @intCast(index), word);
    return .{
        .source_authority_id = authority.finalize(),
        .snapshot_id = snapshot.finalize(),
        .tuple_provenance_id = provenance.finalize(),
        .tuple_count = manifest.logical_row_count,
    };
}

pub fn verifierInputEvidence(
    publication: anytype,
) ShaTupleEvidenceV2 {
    const words = blk: {
        var encoded: [LOGUP_PUBLICATION_WORD_COUNT]M31 = undefined;
        writeLogUpWordsAssumeValid(publication, &encoded);
        break :blk encoded;
    };
    var authority = ShaHasher.init("stwo-zig/segment-leaf-v2/logup-authority/v1\x00");
    authority.u16Value(FORMAT_VERSION);
    authority.u16Value(SCHEMA_VERSION);
    authority.u8Value(@intFromEnum(VERIFIER_INPUT_RELATION_DOMAIN));
    authority.u32Value(SEGMENT_V2_VERIFIER_ID);
    authority.u32Value(PUBLIC_LOGUP_V2_KIND);
    authority.u8Value(VERIFIER_INPUT_RELATION_ARITY);
    authority.rawBytes(&relation.registryOrderDigest());

    var snapshot = ShaHasher.init("stwo-zig/segment-leaf-v2/logup-snapshot/v1\x00");
    snapshot.digestWords(publication.source_id);
    snapshot.digestWords(publication.relation_context_id);
    snapshot.digestWords(publication.identity);

    var provenance = ShaHasher.init("stwo-zig/segment-leaf-v2/logup-tuples/v1\x00");
    provenance.u8Value(@intFromEnum(VERIFIER_INPUT_RELATION_DOMAIN));
    provenance.u8Value(@intFromEnum(relation.Role.consume));
    provenance.u32Value(LOGUP_PUBLICATION_WORD_COUNT);
    for (words, 0..) |word, index| provenance.verifierInputTuple(
        SEGMENT_V2_VERIFIER_ID,
        PUBLIC_LOGUP_V2_KIND,
        @intCast(index),
        0,
        word,
    );
    return .{
        .source_authority_id = authority.finalize(),
        .snapshot_id = snapshot.finalize(),
        .tuple_provenance_id = provenance.finalize(),
        .tuple_count = LOGUP_PUBLICATION_WORD_COUNT,
    };
}

pub fn authorityIdentityPoseidonPermutationCount() usize {
    // Exact canonical words for format, manifest, VK authority, authenticated
    // context, source ID, and the upstream segment-format identity embedded in
    // that context.  Each identity is counted once; strict revalidation may
    // intentionally recompute one to detect a mutated receipt.
    return channel.canonicalWordPermutationCount(38) +
        channel.canonicalWordPermutationCount(28) +
        channel.canonicalWordPermutationCount(27) +
        channel.canonicalWordPermutationCount(129) +
        channel.canonicalWordPermutationCount(42) +
        channel.canonicalWordPermutationCount(36);
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len;
    const right_end = right_start + right.len;
    return left_start < right_end and right_start < left_end;
}

pub const ShaHasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    fn init(domain: []const u8) ShaHasher {
        var inner = std.crypto.hash.sha2.Sha256.init(.{});
        inner.update(domain);
        return .{ .inner = inner };
    }

    fn u8Value(self: *ShaHasher, value: u8) void {
        self.inner.update(&.{value});
    }

    fn u16Value(self: *ShaHasher, value: u16) void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .little);
        self.inner.update(&bytes);
    }

    fn u32Value(self: *ShaHasher, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        self.inner.update(&bytes);
    }

    fn rawBytes(self: *ShaHasher, value: []const u8) void {
        self.u32Value(@intCast(value.len));
        self.inner.update(value);
    }

    fn digestWords(self: *ShaHasher, value: Digest) void {
        for (value) |word| self.u32Value(word);
    }

    fn statementTuple(self: *ShaHasher, scope: u32, index: u32, value: M31) void {
        self.u32Value(scope);
        self.u32Value(index);
        self.u32Value(value.toU32());
    }

    fn verifierInputTuple(
        self: *ShaHasher,
        verifier: u32,
        kind: u32,
        index0: u32,
        index1: u32,
        value: M31,
    ) void {
        self.u32Value(verifier);
        self.u32Value(kind);
        self.u32Value(index0);
        self.u32Value(index1);
        self.u32Value(value.toU32());
    }

    fn finalize(self: *ShaHasher) [32]u8 {
        return self.inner.finalResult();
    }
};
