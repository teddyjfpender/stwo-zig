//! Internal segment leaf authority v2 authority shard; use segment_leaf_authority_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const public_logup_v2 = @import("../air/public_logup_v2.zig");
pub const native_relations = @import("../air/relation_challenges.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const statement_v2 = @import("../air/statement_v2.zig");
pub const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
pub const poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const protocol = @import("protocol.zig");
pub const segment_v2 = @import("segment_statement_v2.zig");
pub const temporal = @import("temporal_pair_node.zig");
pub const roster = @import("air/universal_roster.zig");

pub const Digest = channel.Digest;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_VERSION: u16 = 2;
pub const KNOWN_FLAGS: u16 = 0;

pub const WIRE_SCOPE: u32 = 0x5332_5752; // "S2WR"
pub const CONTEXT_SCOPE: u32 = 0x5332_4358; // "S2CX"
pub const SEGMENT_V2_VERIFIER_ID: u32 = 2;
pub const PUBLIC_LOGUP_V2_KIND: u32 = 0x4c55_5032; // "LUP2"
/// Recursion-local custody bridge from source component 37 to rows 12--14.
pub const PUBLICATION_BRIDGE_CIRCUIT_ID: u32 = 44;
pub const CONTEXT_TAG: u32 = 0x534c_4332; // "SLC2"
pub const LOGUP_TAG: u32 = 0x534c_4c32; // "SLL2"
pub const VERIFIED_NATIVE_LOGUP_TAG: u32 = 0x534c_5632; // "SLV2"

pub const FORMAT_ID_DOMAIN: u32 = 0x534c_464d; // "SLFM"
pub const MANIFEST_ID_DOMAIN: u32 = 0x534c_4d46; // "SLMF"
pub const VK_AUTHORITY_ID_DOMAIN: u32 = 0x534c_564b; // "SLVK"
pub const CONTEXT_ID_DOMAIN: u32 = 0x534c_4354; // "SLCT"
pub const SOURCE_ID_DOMAIN: u32 = 0x534c_5352; // "SLSR"
pub const LOGUP_RELATION_ID_DOMAIN: u32 = 0x534c_524c; // "SLRL"
pub const LOGUP_PUBLICATION_ID_DOMAIN: u32 = 0x534c_4c50; // "SLLP"
pub const VERIFIED_NATIVE_LOGUP_ID_DOMAIN: u32 = 0x534c_564c; // "SLVL"
pub const AUTHORITY_HASH_PLAN_ID_DOMAIN: u32 = 0x534c_4841; // "SLHA"
pub const NATIVE_PUBLICATION_ID_DOMAIN: u32 = 0x534c_4e50; // "SLNP"

pub const STATEMENT_RELATION_DOMAIN: relation.Domain =
    .recursion_statement_word;
pub const VERIFIER_INPUT_RELATION_DOMAIN: relation.Domain =
    .recursion_verifier_input_word;
pub const STATEMENT_RELATION_ARITY: u8 = 3;
pub const VERIFIER_INPUT_RELATION_ARITY: u8 = 5;
pub const FROZEN_V1_ROSTER_ROW: u8 =
    @intFromEnum(roster.Component.statement_input);

pub const CONTEXT_WORD_COUNT: usize = 137;
pub const CONTEXT_PREFIX_WORD_COUNT: usize = 17;
pub const CONTEXT_SEGMENT_WIRE_ID_DIGEST_ORDINAL: usize = 4;
pub const CONTEXT_SEGMENT_WIRE_ID_START: usize =
    CONTEXT_PREFIX_WORD_COUNT +
    CONTEXT_SEGMENT_WIRE_ID_DIGEST_ORDINAL * channel.RATE;
pub const LOGUP_PUBLICATION_WORD_COUNT: usize = 55;
pub const PREPROCESSED_COLUMN_COUNT: u16 = 3;
pub const MAIN_COLUMN_COUNT: u16 = 1;
pub const INTERACTION_COLUMN_COUNT: u16 = 4;
pub const DIRECT_CONSTRAINT_COUNT: u16 = 4;
pub const INTERACTION_BATCH_COUNT: u16 = 1;
pub const PROTOCOL_CONSTRAINT_DEGREE: u8 = 3;

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const FROZEN_V1_ROW_COMPATIBLE = false;
pub const REQUIRES_VERSIONED_OUTER_MANIFEST = true;
pub const PRODUCTION_ACTIVATION = false;
pub const AUTHORITY_HASH_SHARED_PROVIDER_REQUESTS_AVAILABLE = true;
pub const AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE = false;

pub const AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT: usize = 22;
pub const AUTHORITY_HASH_WORDS_PER_DESCRIPTOR: usize = 8;

comptime {
    if (FORMAT_VERSION == 1 or MANIFEST_VERSION == 1)
        @compileError("segment-leaf V2 must not alias the frozen V1 schema");
    if (WIRE_SCOPE >= m31.Modulus or CONTEXT_SCOPE >= m31.Modulus or
        SEGMENT_V2_VERIFIER_ID >= m31.Modulus or
        PUBLIC_LOGUP_V2_KIND >= m31.Modulus or
        PUBLICATION_BRIDGE_CIRCUIT_ID >= m31.Modulus)
    {
        @compileError("segment-leaf V2 relation tags must be canonical M31 words");
    }
    if (FROZEN_V1_ROSTER_ROW != 10)
        @compileError("frozen statement-input row moved");
    if (CONTEXT_WORD_COUNT != 17 + 15 * channel.RATE)
        @compileError("segment-leaf V2 context geometry drifted");
    if (CONTEXT_SEGMENT_WIRE_ID_START != 49 or
        CONTEXT_SEGMENT_WIRE_ID_START + channel.RATE > CONTEXT_WORD_COUNT)
    {
        @compileError("segment-leaf V2 context wire-id position drifted");
    }
    if (LOGUP_PUBLICATION_WORD_COUNT != 3 + 3 * channel.RATE + 5 * 4 + channel.RATE)
        @compileError("segment-leaf V2 public LogUp geometry drifted");
    if (relation.universalDescriptor(STATEMENT_RELATION_DOMAIN).arity !=
        STATEMENT_RELATION_ARITY or
        relation.universalDescriptor(VERIFIER_INPUT_RELATION_DOMAIN).arity !=
            VERIFIER_INPUT_RELATION_ARITY)
    {
        @compileError("segment-leaf V2 universal relation ABI drifted");
    }
}

pub const Error = public_data_v2.Error || public_logup_v2.Error ||
    statement_v2.Error || error{
    AliasedDestination,
    ArithmeticOverflow,
    AuthorityMismatch,
    ContextMismatch,
    DestinationLengthMismatch,
    InvalidManifest,
    InvalidPublication,
    InvalidTraceShape,
    NonCanonicalDigest,
    EmptyDigest,
    SourceMismatch,
    NativeVerifierCustodyMismatch,
    PoseidonCallCountMismatch,
    UnsupportedVersion,
};

pub const Activation = enum(u8) {
    requires_v2_outer_manifest = 1,
};

/// Cold verifier-key authority.  The outer driver constructs this from its
/// admitted leaf and recursive-parent verification keys; both native digests
/// become proof-visible context words.
pub const VerifierKeyAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    flags: u16 = KNOWN_FLAGS,
    segment_leaf_vk_id: Digest,
    recursive_parent_vk_id: Digest,
    identity: Digest,

    pub fn init(
        segment_leaf_vk_id: Digest,
        recursive_parent_vk_id: Digest,
    ) Error!VerifierKeyAuthorityV2 {
        try requireDigest(segment_leaf_vk_id);
        try requireDigest(recursive_parent_vk_id);
        var result = VerifierKeyAuthorityV2{
            .segment_leaf_vk_id = segment_leaf_vk_id,
            .recursive_parent_vk_id = recursive_parent_vk_id,
            .identity = undefined,
        };
        result.identity = verifierKeyAuthorityId(&result);
        return result;
    }

    pub fn validate(self: *const VerifierKeyAuthorityV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.flags != KNOWN_FLAGS)
        {
            return error.UnsupportedVersion;
        }
        try requireDigest(self.segment_leaf_vk_id);
        try requireDigest(self.recursive_parent_vk_id);
        try requireDigest(self.identity);
        if (!std.meta.eql(self.identity, verifierKeyAuthorityId(self)))
            return error.AuthorityMismatch;
    }
};

/// Geometry for a new V2 statement-source row.  `frozen_v1_row_compatible` is
/// deliberately false even when a small wire happens to fit in 2^11 rows.
pub const ManifestV2 = struct {
    format_version: u16 = MANIFEST_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    flags: u16 = KNOWN_FLAGS,
    activation: Activation = .requires_v2_outer_manifest,
    frozen_v1_roster_row: u8 = FROZEN_V1_ROSTER_ROW,
    frozen_v1_row_compatible: bool = FROZEN_V1_ROW_COMPATIBLE,
    statement_relation_domain: relation.Domain = STATEMENT_RELATION_DOMAIN,
    wire_scope: u32 = WIRE_SCOPE,
    context_scope: u32 = CONTEXT_SCOPE,
    wire_word_count: u32,
    context_word_count: u32 = CONTEXT_WORD_COUNT,
    logical_row_count: u32,
    trace_log_size: u8,
    trace_row_count: u32,
    preprocessed_columns: u16 = PREPROCESSED_COLUMN_COUNT,
    main_columns: u16 = MAIN_COLUMN_COUNT,
    interaction_columns: u16 = INTERACTION_COLUMN_COUNT,
    direct_constraints: u16 = DIRECT_CONSTRAINT_COUNT,
    interaction_batches: u16 = INTERACTION_BATCH_COUNT,
    protocol_constraint_degree: u8 = PROTOCOL_CONSTRAINT_DEGREE,
    schema_id: Digest,
    identity: Digest,

    pub fn init(wire_word_count: usize) Error!ManifestV2 {
        const wire_count = std.math.cast(u32, wire_word_count) orelse
            return error.ArithmeticOverflow;
        const logical = std.math.add(
            u32,
            wire_count,
            CONTEXT_WORD_COUNT,
        ) catch return error.ArithmeticOverflow;
        const log_size = ceilLog2(logical);
        if (log_size >= 31) return error.InvalidManifest;
        const trace_rows = @as(u32, 1) << @intCast(log_size);
        var result = ManifestV2{
            .wire_word_count = wire_count,
            .logical_row_count = logical,
            .trace_log_size = log_size,
            .trace_row_count = trace_rows,
            .schema_id = formatId(),
            .identity = undefined,
        };
        result.identity = manifestId(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const ManifestV2) Error!void {
        if (self.format_version != MANIFEST_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.flags != KNOWN_FLAGS or
            self.activation != .requires_v2_outer_manifest or
            self.frozen_v1_roster_row != FROZEN_V1_ROSTER_ROW or
            self.frozen_v1_row_compatible or
            self.statement_relation_domain != STATEMENT_RELATION_DOMAIN or
            self.wire_scope != WIRE_SCOPE or self.context_scope != CONTEXT_SCOPE or
            self.context_word_count != CONTEXT_WORD_COUNT or
            self.preprocessed_columns != PREPROCESSED_COLUMN_COUNT or
            self.main_columns != MAIN_COLUMN_COUNT or
            self.interaction_columns != INTERACTION_COLUMN_COUNT or
            self.direct_constraints != DIRECT_CONSTRAINT_COUNT or
            self.interaction_batches != INTERACTION_BATCH_COUNT or
            self.protocol_constraint_degree != PROTOCOL_CONSTRAINT_DEGREE)
        {
            return error.InvalidManifest;
        }
        const logical = std.math.add(
            u32,
            self.wire_word_count,
            self.context_word_count,
        ) catch return error.InvalidManifest;
        if (logical != self.logical_row_count or logical == 0 or
            self.trace_log_size >= 31 or
            self.trace_row_count != @as(u32, 1) << @intCast(self.trace_log_size) or
            self.trace_row_count < logical or
            (self.trace_log_size != 0 and self.trace_row_count / 2 >= logical) or
            !std.meta.eql(self.schema_id, formatId()) or
            !std.meta.eql(self.identity, manifestId(self)))
        {
            return error.InvalidManifest;
        }
    }
};

/// Native temporal preimage retained separately from every SHA closure ID.
pub const NativeTemporalContextV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    statement_version: u32 = public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
    is_first: bool,
    is_final: bool,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    segment_format_id: Digest,
    protocol_id: Digest = protocol.PROTOCOL_ID_WORDS,
    manifest_id: Digest,
    /// Frozen base span-statement identity retained by the V2 wrapper.
    statement_id: Digest,
    /// Identity of the complete variable V2 statement wire.
    segment_wire_id: Digest,
    session_id: Digest,
    job_id: Digest,
    position_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    lineage_id: Digest,
    verifier_key_authority_id: Digest,
    segment_leaf_vk_id: Digest,
    recursive_parent_vk_id: Digest,
    authenticated_context_id: Digest,

    pub fn validate(
        self: *const NativeTemporalContextV2,
        metadata: *const public_data_v2.Metadata,
        keys: *const VerifierKeyAuthorityV2,
        manifest: *const ManifestV2,
    ) Error!void {
        try keys.validate();
        try manifest.validate();
        const expected = try nativeContext(metadata, keys, manifest);
        if (!std.meta.eql(self.*, expected)) return error.ContextMismatch;
    }

    pub fn canonicalWords(
        self: *const NativeTemporalContextV2,
    ) Error![CONTEXT_WORD_COUNT]M31 {
        try validateNativeContextSelf(self);
        var result: [CONTEXT_WORD_COUNT]M31 = undefined;
        writeContextWordsAssumeValid(self, &result);
        return result;
    }
};

pub const PerformanceV2 = struct {
    wire_words: u32,
    context_words: u32,
    logical_rows: u32,
    padded_rows: u32,
    padding_rows: u32,
    prepared_bytes: usize,
    /// Exact cost of constructing each authority identity once.  This excludes
    /// upstream `PublicDataV2` wire authentication, whose cost belongs to the
    /// segment-statement protocol and depends on its retained section sizes.
    authority_identity_poseidon_permutations: usize,
    heap_allocations: usize = HOT_HEAP_ALLOCATIONS,
};

pub fn formatId() Digest {
    var hash = IdentityHasher.init(FORMAT_ID_DOMAIN);
    hash.scalar(FORMAT_VERSION);
    hash.scalar(SCHEMA_VERSION);
    hash.scalar(MANIFEST_VERSION);
    hash.scalar(KNOWN_FLAGS);
    hash.scalar(WIRE_SCOPE);
    hash.scalar(CONTEXT_SCOPE);
    hash.scalar(SEGMENT_V2_VERIFIER_ID);
    hash.scalar(PUBLIC_LOGUP_V2_KIND);
    hash.scalar(PUBLICATION_BRIDGE_CIRCUIT_ID);
    hash.scalar(CONTEXT_WORD_COUNT);
    hash.scalar(LOGUP_PUBLICATION_WORD_COUNT);
    hash.scalar(PREPROCESSED_COLUMN_COUNT);
    hash.scalar(MAIN_COLUMN_COUNT);
    hash.scalar(INTERACTION_COLUMN_COUNT);
    hash.scalar(DIRECT_CONSTRAINT_COUNT);
    hash.scalar(INTERACTION_BATCH_COUNT);
    hash.scalar(PROTOCOL_CONSTRAINT_DEGREE);
    hash.scalar(@intFromEnum(STATEMENT_RELATION_DOMAIN));
    hash.scalar(STATEMENT_RELATION_ARITY);
    hash.scalar(@intFromEnum(VERIFIER_INPUT_RELATION_DOMAIN));
    hash.scalar(VERIFIER_INPUT_RELATION_ARITY);
    hash.scalar(relation.REGISTRY_ORDER_FORMAT_VERSION);
    hash.scalar(relation.UNIVERSAL_RELATION_COUNT);
    hash.digest(segment_v2.formatId());
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    return hash.finalize();
}

pub fn nativeContext(
    metadata: *const public_data_v2.Metadata,
    keys: *const VerifierKeyAuthorityV2,
    manifest: *const ManifestV2,
) Error!NativeTemporalContextV2 {
    try keys.validate();
    try manifest.validate();
    var result = NativeTemporalContextV2{
        .segment_index = metadata.segment_index,
        .segment_count = metadata.segment_count,
        .global_cycle_start = metadata.global_cycle_start,
        .global_cycle_end = metadata.global_cycle_end,
        .is_first = metadata.is_first,
        .is_final = metadata.is_final,
        .entry_continuation_root = metadata.entry_continuation_root,
        .exit_continuation_root = metadata.exit_continuation_root,
        .segment_format_id = segment_v2.formatId(),
        .manifest_id = manifest.identity,
        .statement_id = metadata.base_statement_id,
        .segment_wire_id = metadata.wire_id,
        .session_id = metadata.session_id,
        .job_id = metadata.job_id,
        .position_id = metadata.position_id,
        .entry_lineage_id = metadata.entry_lineage_id,
        .exit_lineage_id = metadata.exit_lineage_id,
        .lineage_id = metadata.lineage_id,
        .verifier_key_authority_id = keys.identity,
        .segment_leaf_vk_id = keys.segment_leaf_vk_id,
        .recursive_parent_vk_id = keys.recursive_parent_vk_id,
        .authenticated_context_id = undefined,
    };
    result.authenticated_context_id = contextId(&result);
    try validateNativeContextSelf(&result);
    return result;
}

pub fn validateNativeContextSelf(context: *const NativeTemporalContextV2) Error!void {
    if (context.format_version != FORMAT_VERSION or
        context.schema_version != SCHEMA_VERSION or
        context.statement_version != public_data_v2.STATEMENT_TRANSCRIPT_VERSION or
        context.global_cycle_end <= context.global_cycle_start or
        context.segment_index >= context.segment_count or
        context.is_first != (context.segment_index == 0) or
        context.is_final != (context.segment_index == context.segment_count - 1))
    {
        return error.ContextMismatch;
    }
    inline for (.{
        context.segment_format_id,
        context.protocol_id,
        context.manifest_id,
        context.statement_id,
        context.segment_wire_id,
        context.session_id,
        context.job_id,
        context.position_id,
        context.entry_lineage_id,
        context.exit_lineage_id,
        context.lineage_id,
        context.verifier_key_authority_id,
        context.segment_leaf_vk_id,
        context.recursive_parent_vk_id,
        context.authenticated_context_id,
    }) |digest| try requireDigest(digest);
    if (!std.meta.eql(context.segment_format_id, segment_v2.formatId()) or
        !std.meta.eql(context.protocol_id, protocol.PROTOCOL_ID_WORDS) or
        !std.meta.eql(context.authenticated_context_id, contextId(context)))
    {
        return error.ContextMismatch;
    }
}

pub fn verifierKeyAuthorityId(keys: *const VerifierKeyAuthorityV2) Digest {
    var hash = IdentityHasher.init(VK_AUTHORITY_ID_DOMAIN);
    hash.scalar(FORMAT_VERSION);
    hash.scalar(SCHEMA_VERSION);
    hash.scalar(keys.flags);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(keys.segment_leaf_vk_id);
    hash.digest(keys.recursive_parent_vk_id);
    return hash.finalize();
}

pub fn manifestId(manifest: *const ManifestV2) Digest {
    var hash = IdentityHasher.init(MANIFEST_ID_DOMAIN);
    hash.scalar(manifest.format_version);
    hash.scalar(manifest.schema_version);
    hash.scalar(manifest.flags);
    hash.scalar(@intFromEnum(manifest.activation));
    hash.scalar(manifest.frozen_v1_roster_row);
    hash.scalar(@intFromBool(manifest.frozen_v1_row_compatible));
    hash.scalar(@intFromEnum(manifest.statement_relation_domain));
    hash.scalar(manifest.wire_scope);
    hash.scalar(manifest.context_scope);
    hash.scalar(manifest.wire_word_count);
    hash.scalar(manifest.context_word_count);
    hash.scalar(manifest.logical_row_count);
    hash.scalar(manifest.trace_log_size);
    hash.scalar(manifest.trace_row_count);
    hash.scalar(manifest.preprocessed_columns);
    hash.scalar(manifest.main_columns);
    hash.scalar(manifest.interaction_columns);
    hash.scalar(manifest.direct_constraints);
    hash.scalar(manifest.interaction_batches);
    hash.scalar(manifest.protocol_constraint_degree);
    hash.digest(manifest.schema_id);
    return hash.finalize();
}

pub fn contextId(context: *const NativeTemporalContextV2) Digest {
    var hash = IdentityHasher.init(CONTEXT_ID_DOMAIN);
    hash.scalar(context.format_version);
    hash.scalar(context.schema_version);
    hash.scalar(context.statement_version);
    hash.u32Value(context.segment_index);
    hash.u32Value(context.segment_count);
    hash.u32Value(context.global_cycle_start);
    hash.u32Value(context.global_cycle_end);
    hash.scalar(@intFromBool(context.is_first));
    hash.scalar(@intFromBool(context.is_final));
    hash.u32Value(context.entry_continuation_root);
    hash.u32Value(context.exit_continuation_root);
    hash.digest(context.segment_format_id);
    hash.digest(context.protocol_id);
    hash.digest(context.manifest_id);
    hash.digest(context.statement_id);
    hash.digest(context.segment_wire_id);
    hash.digest(context.session_id);
    hash.digest(context.job_id);
    hash.digest(context.position_id);
    hash.digest(context.entry_lineage_id);
    hash.digest(context.exit_lineage_id);
    hash.digest(context.lineage_id);
    hash.digest(context.verifier_key_authority_id);
    hash.digest(context.segment_leaf_vk_id);
    hash.digest(context.recursive_parent_vk_id);
    return hash.finalize();
}

pub fn writeContextWordsAssumeValid(
    context: *const NativeTemporalContextV2,
    destination: *[CONTEXT_WORD_COUNT]M31,
) void {
    var writer = WordWriter{ .words = destination };
    writer.scalar(CONTEXT_TAG);
    writer.scalar(context.format_version);
    writer.scalar(context.schema_version);
    writer.scalar(public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN);
    writer.scalar(context.statement_version);
    writer.u32Value(context.segment_index);
    writer.u32Value(context.segment_count);
    writer.u32Value(context.global_cycle_start);
    writer.u32Value(context.global_cycle_end);
    writer.scalar(@intFromBool(context.is_first));
    writer.scalar(@intFromBool(context.is_final));
    writer.scalar(context.entry_continuation_root);
    writer.scalar(context.exit_continuation_root);
    writer.digest(context.segment_format_id);
    writer.digest(context.protocol_id);
    writer.digest(context.manifest_id);
    writer.digest(context.statement_id);
    writer.digest(context.segment_wire_id);
    writer.digest(context.session_id);
    writer.digest(context.job_id);
    writer.digest(context.position_id);
    writer.digest(context.entry_lineage_id);
    writer.digest(context.exit_lineage_id);
    writer.digest(context.lineage_id);
    writer.digest(context.verifier_key_authority_id);
    writer.digest(context.segment_leaf_vk_id);
    writer.digest(context.recursive_parent_vk_id);
    writer.digest(context.authenticated_context_id);
    std.debug.assert(writer.at == destination.len);
}

pub fn ceilLog2(value: u32) u8 {
    std.debug.assert(value != 0);
    if (value <= 1) return 0;
    return @intCast(32 - @clz(value - 1));
}

pub fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.EmptyDigest;
}

pub fn isZeroBytes(value: *const [32]u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub const WordWriter = struct {
    words: []M31,
    at: usize = 0,

    pub fn scalar(self: *WordWriter, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        self.words[self.at] = M31.fromCanonical(canonical);
        self.at += 1;
    }

    pub fn u32Value(self: *WordWriter, value: u32) void {
        self.scalar(value & 0xffff);
        self.scalar(value >> 16);
    }

    pub fn digest(self: *WordWriter, value: Digest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn qm31(self: *WordWriter, value: QM31) void {
        for (value.toM31Array()) |word| {
            self.words[self.at] = word;
            self.at += 1;
        }
    }
};

pub const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *IdentityHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(canonical)};
        self.inner.update(&words);
    }

    pub fn u32Value(self: *IdentityHasher, value: u32) void {
        self.scalar(value & 0xffff);
        self.scalar(value >> 16);
    }

    pub fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn qm31(self: *IdentityHasher, value: QM31) void {
        const words = value.toM31Array();
        self.inner.update(&words);
    }

    pub fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};
