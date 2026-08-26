//! Internal segment leaf outer authority v2 authority shard; use segment_leaf_outer_authority_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const native_relations = @import("../air/relation_challenges.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const statement_v2 = @import("../air/statement_v2.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const air_v2 = @import("segment_leaf_outer_air_v2.zig");
pub const source_v2 = @import("segment_leaf_authority_v2.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const direct_program = @import("air/direct_constraint_program.zig");
pub const framework_interaction = @import("air/framework_interaction.zig");
pub const universal = @import("air/universal_challenges.zig");

pub const NativeDigest = source_v2.Digest;
pub const Sha256Digest = [32]u8;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_VERSION: u16 = 2;
pub const COMPONENT_COUNT: u8 = 2;
pub const PUBLIC_LOGUP_LOGICAL_ROWS: u32 = source_v2.LOGUP_PUBLICATION_WORD_COUNT;
pub const PUBLIC_LOGUP_TRACE_LOG_SIZE: u8 = 6;
pub const PUBLIC_LOGUP_TRACE_ROWS: u32 = 1 << PUBLIC_LOGUP_TRACE_LOG_SIZE;

pub const STATEMENT_COMPONENT_TAG: u32 = 0x5332_5354; // "S2ST"
pub const PUBLIC_LOGUP_COMPONENT_TAG: u32 = 0x5332_4c55; // "S2LU"
pub const MANIFEST_ID_DOMAIN: u32 = 0x5332_4f4d; // "S2OM"
pub const PREPARED_ID_DOMAIN: u32 = 0x5332_5052; // "S2PR"
pub const NATIVE_CAPTURE_PREPARED_ID_DOMAIN: u32 = 0x5332_4350; // "S2CP"
pub const VERIFICATION_ID_DOMAIN: u32 = 0x5332_5652; // "S2VR"
pub const PUBLICATION_ID_DOMAIN: u32 = 0x5332_5055; // "S2PU"
pub const SHA256_ENCODING_TAG: u32 = 0x5348_4132; // "SHA2"

pub const HOT_PREPARE_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_VERIFY_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_PUBLISH_HEAP_ALLOCATIONS: usize = 0;
pub const INTERACTION_BULK_INVERSIONS: usize = COMPONENT_COUNT;
pub const ALL_AUTHORITY_EVENTS_CHECKED = true;
pub const ALL_PUBLIC_LOGUP_WORDS_CHECKED = true;
pub const NATIVE_V2_PROOF_API_AVAILABLE = true;
pub const OUTER_STARK_VERIFICATION_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPLETE_TEMPORAL_PARENT = false;

pub const StatementFramework = framework_interaction.Runtime(air_v2.Statement.Runtime);
pub const PublicLogUpFramework = framework_interaction.Runtime(air_v2.PublicLogUp.Runtime);
pub const StatementAirError = @typeInfo(@typeInfo(@TypeOf(
    air_v2.Statement.build,
)).@"fn".return_type.?).error_union.error_set;
pub const PublicLogUpAirError = @typeInfo(@typeInfo(@TypeOf(
    air_v2.PublicLogUp.build,
)).@"fn".return_type.?).error_union.error_set;
pub const StatementAuthenticationError = @typeInfo(@typeInfo(@TypeOf(
    air_v2.Statement.authenticate,
)).@"fn".return_type.?).error_union.error_set;
pub const PublicLogUpAuthenticationError = @typeInfo(@typeInfo(@TypeOf(
    air_v2.PublicLogUp.authenticate,
)).@"fn".return_type.?).error_union.error_set;

pub const Error = source_v2.Error || framework_interaction.Error ||
    direct_program.Error || universal.Error || StatementAirError ||
    PublicLogUpAirError || StatementAuthenticationError ||
    PublicLogUpAuthenticationError || std.mem.Allocator.Error || error{
    AliasedDestination,
    ArithmeticOverflow,
    AuthorityEventMismatch,
    AuthorityMismatch,
    CrossDomainClosureMismatch,
    DestinationLengthMismatch,
    DirectConstraintMismatch,
    EmptyDigest,
    InvalidManifest,
    InvalidPublication,
    InvalidTraceShape,
    InvalidVerification,
    NativeV2ProofApiUnavailable,
    NonCanonicalDigest,
    ProductionCapabilityEscalation,
    SourceMismatch,
    TraceMismatch,
    WorkspaceShapeMismatch,
};

pub const ComponentKindV2 = enum(u8) {
    statement_source = 0,
    public_logup_source = 1,
};

pub const ComponentGeometryV2 = struct {
    kind: ComponentKindV2,
    component_tag: u32,
    logical_rows: u32,
    trace_log_size: u8,
    trace_rows: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    protocol_constraint_degree: u8,
    semantic_digest: Sha256Digest,

    pub fn validate(self: ComponentGeometryV2) Error!void {
        if (self.logical_rows == 0 or self.trace_log_size >= 31 or
            self.trace_rows != @as(u32, 1) << @intCast(self.trace_log_size) or
            self.trace_rows < self.logical_rows or
            (self.trace_log_size != 0 and
                self.trace_rows / 2 >= self.logical_rows))
        {
            return error.InvalidManifest;
        }
        switch (self.kind) {
            .statement_source => {
                if (self.component_tag != STATEMENT_COMPONENT_TAG or
                    self.preprocessed_columns !=
                        air_v2.Statement.PREPROCESSED_COLUMN_COUNT or
                    self.main_columns !=
                        air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT or
                    self.interaction_columns !=
                        air_v2.Statement.INTERACTION_COLUMN_COUNT or
                    self.direct_constraints !=
                        air_v2.Statement.DIRECT_CONSTRAINT_COUNT or
                    self.interaction_batches !=
                        air_v2.Statement.INTERACTION_BATCH_COUNT or
                    self.protocol_constraint_degree !=
                        air_v2.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE or
                    !std.mem.eql(
                        u8,
                        &self.semantic_digest,
                        &air_v2.Statement.SEMANTIC_DIGEST,
                    ))
                {
                    return error.InvalidManifest;
                }
            },
            .public_logup_source => {
                if (self.component_tag != PUBLIC_LOGUP_COMPONENT_TAG or
                    self.logical_rows != PUBLIC_LOGUP_LOGICAL_ROWS or
                    self.trace_log_size != PUBLIC_LOGUP_TRACE_LOG_SIZE or
                    self.trace_rows != PUBLIC_LOGUP_TRACE_ROWS or
                    self.preprocessed_columns !=
                        air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT or
                    self.main_columns !=
                        air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT or
                    self.interaction_columns !=
                        air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT or
                    self.direct_constraints !=
                        air_v2.PublicLogUp.DIRECT_CONSTRAINT_COUNT or
                    self.interaction_batches !=
                        air_v2.PublicLogUp.INTERACTION_BATCH_COUNT or
                    self.protocol_constraint_degree !=
                        air_v2.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE or
                    !std.mem.eql(
                        u8,
                        &self.semantic_digest,
                        &air_v2.PublicLogUp.SEMANTIC_DIGEST,
                    ))
                {
                    return error.InvalidManifest;
                }
            },
        }
    }
};

/// V2-only component manifest. Its native identity binds the SHA typed-AIR
/// authority through an explicit byte encoding; the two digest types remain
/// distinct fields and are never bit-cast or substituted.
pub const OuterManifestV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest_version: u16 = MANIFEST_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    frozen_v1_compatible: bool = false,
    source_manifest: source_v2.ManifestV2,
    components: [COMPONENT_COUNT]ComponentGeometryV2,
    authority_sha_id: Sha256Digest,
    identity: NativeDigest,

    pub fn init(source_manifest: source_v2.ManifestV2) Error!OuterManifestV2 {
        try source_manifest.validate();
        const statement = ComponentGeometryV2{
            .kind = .statement_source,
            .component_tag = STATEMENT_COMPONENT_TAG,
            .logical_rows = source_manifest.logical_row_count,
            .trace_log_size = source_manifest.trace_log_size,
            .trace_rows = source_manifest.trace_row_count,
            .preprocessed_columns = air_v2.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = air_v2.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = air_v2.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = air_v2.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = air_v2.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = air_v2.Statement.SEMANTIC_DIGEST,
        };
        const logup = ComponentGeometryV2{
            .kind = .public_logup_source,
            .component_tag = PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = air_v2.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = air_v2.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = air_v2.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = air_v2.PublicLogUp.SEMANTIC_DIGEST,
        };
        var result = OuterManifestV2{
            .source_manifest = source_manifest,
            .components = .{ statement, logup },
            .authority_sha_id = airAuthorityShaId(),
            .identity = undefined,
        };
        result.identity = outerManifestId(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const OuterManifestV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.manifest_version != MANIFEST_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.frozen_v1_compatible)
        {
            return error.InvalidManifest;
        }
        try self.source_manifest.validate();
        for (self.components, 0..) |component, index| {
            if (@intFromEnum(component.kind) != index)
                return error.InvalidManifest;
            try component.validate();
        }
        const statement = self.components[
            @intFromEnum(
                ComponentKindV2.statement_source,
            )
        ];
        if (statement.logical_rows != self.source_manifest.logical_row_count or
            statement.trace_log_size != self.source_manifest.trace_log_size or
            statement.trace_rows != self.source_manifest.trace_row_count or
            statement.preprocessed_columns !=
                self.source_manifest.preprocessed_columns or
            statement.main_columns != self.source_manifest.main_columns or
            statement.interaction_columns !=
                self.source_manifest.interaction_columns or
            statement.direct_constraints !=
                self.source_manifest.direct_constraints or
            statement.interaction_batches !=
                self.source_manifest.interaction_batches or
            statement.protocol_constraint_degree !=
                self.source_manifest.protocol_constraint_degree or
            !std.mem.eql(u8, &self.authority_sha_id, &airAuthorityShaId()) or
            !std.meta.eql(self.identity, outerManifestId(self)))
        {
            return error.InvalidManifest;
        }
        try requireNativeDigest(self.identity);
        try requireShaDigest(self.authority_sha_id);
    }

    pub fn totalLogicalEvents(self: *const OuterManifestV2) Error!u32 {
        try self.validate();
        return std.math.add(
            u32,
            self.components[0].logical_rows,
            self.components[1].logical_rows,
        ) catch return error.ArithmeticOverflow;
    }
};

pub const PreflightV2 = struct {
    source: source_v2.PreflightV2,
    manifest: OuterManifestV2,
    statement_row_scratch: usize,
    statement_event_scratch: usize,
    committed_m31_words: usize,
    interaction_qm31_scratch: usize,
    hot_heap_allocations: usize = HOT_PREPARE_HEAP_ALLOCATIONS,
};

pub fn preflight(
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
) Error!PreflightV2 {
    const source = try source_v2.preflight(data, keys);
    const manifest = try OuterManifestV2.init(source.manifest);
    const statement_rows: usize = manifest.components[0].trace_rows;
    const logup_rows: usize = manifest.components[1].trace_rows;
    const committed_words = std.math.add(
        usize,
        std.math.mul(usize, statement_rows, 8) catch
            return error.ArithmeticOverflow,
        std.math.mul(usize, logup_rows, 7) catch
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
    const interaction_scratch = std.math.add(
        usize,
        try StatementFramework.requiredScratchElementCount(
            manifest.components[0].trace_log_size,
        ),
        try PublicLogUpFramework.requiredScratchElementCount(
            manifest.components[1].trace_log_size,
        ),
    ) catch return error.ArithmeticOverflow;
    return .{
        .source = source,
        .manifest = manifest,
        .statement_row_scratch = manifest.components[0].logical_rows,
        .statement_event_scratch = manifest.components[0].logical_rows,
        .committed_m31_words = committed_words,
        .interaction_qm31_scratch = interaction_scratch,
    };
}

/// Cold typed-program owner. Hot paths revalidate the immutable programs but
/// never allocate; all digest and plan recomputation is stack-only.
pub const AuthorityV2 = struct {
    allocator: std.mem.Allocator,
    statement_definition: air_v2.Statement.Definition,
    statement_plan: air_v2.Statement.Plan,
    statement_direct: direct_program.Program,
    public_logup_definition: air_v2.PublicLogUp.Definition,
    public_logup_plan: air_v2.PublicLogUp.Plan,
    public_logup_direct: direct_program.Program,
    authority_sha_id: Sha256Digest,

    pub fn init(allocator: std.mem.Allocator) Error!AuthorityV2 {
        var statement_definition = try air_v2.Statement.build(allocator);
        errdefer statement_definition.deinit();
        const statement_plan = try air_v2.Statement.authenticate(
            &statement_definition,
        );
        const statement_direct = try direct_program.authenticate(
            &statement_definition.arena,
            air_v2.Statement.SEMANTIC_DIGEST,
            air_v2.Statement.LOGICAL_INPUT_COUNT,
        );
        var public_logup_definition = try air_v2.PublicLogUp.build(allocator);
        errdefer public_logup_definition.deinit();
        const public_logup_plan = try air_v2.PublicLogUp.authenticate(
            &public_logup_definition,
        );
        const public_logup_direct = try direct_program.authenticate(
            &public_logup_definition.arena,
            air_v2.PublicLogUp.SEMANTIC_DIGEST,
            air_v2.PublicLogUp.LOGICAL_INPUT_COUNT,
        );
        const result = AuthorityV2{
            .allocator = allocator,
            .statement_definition = statement_definition,
            .statement_plan = statement_plan,
            .statement_direct = statement_direct,
            .public_logup_definition = public_logup_definition,
            .public_logup_plan = public_logup_plan,
            .public_logup_direct = public_logup_direct,
            .authority_sha_id = airAuthorityShaId(),
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *AuthorityV2) void {
        self.public_logup_definition.deinit();
        self.statement_definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const AuthorityV2) Error!void {
        try self.statement_definition.validate();
        try self.public_logup_definition.validate();
        const statement_plan = try air_v2.Statement.authenticate(
            &self.statement_definition,
        );
        const public_logup_plan = try air_v2.PublicLogUp.authenticate(
            &self.public_logup_definition,
        );
        const statement_direct = try direct_program.authenticate(
            &self.statement_definition.arena,
            air_v2.Statement.SEMANTIC_DIGEST,
            air_v2.Statement.LOGICAL_INPUT_COUNT,
        );
        const public_logup_direct = try direct_program.authenticate(
            &self.public_logup_definition.arena,
            air_v2.PublicLogUp.SEMANTIC_DIGEST,
            air_v2.PublicLogUp.LOGICAL_INPUT_COUNT,
        );
        if (!std.meta.eql(statement_plan, self.statement_plan) or
            !std.meta.eql(public_logup_plan, self.public_logup_plan) or
            !std.meta.eql(statement_direct, self.statement_direct) or
            !std.meta.eql(public_logup_direct, self.public_logup_direct) or
            !std.mem.eql(u8, &self.authority_sha_id, &airAuthorityShaId()))
        {
            return error.AuthorityMismatch;
        }
    }
};

pub const StatementTraceV2 = struct {
    preprocessed: [air_v2.Statement.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    interaction: [air_v2.Statement.INTERACTION_COLUMN_COUNT][]M31,
};

pub const PublicLogUpTraceV2 = struct {
    preprocessed: [air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    interaction: [air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31,
};

pub const TracesV2 = struct {
    statement: StatementTraceV2,
    public_logup: PublicLogUpTraceV2,
};

pub fn airAuthorityShaId() Sha256Digest {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-leaf-outer-v2/air-authority/v1\x00",
    );
    hash.u16Value(FORMAT_VERSION);
    hash.u16Value(SCHEMA_VERSION);
    hash.rawBytes(&relation.registryOrderDigest());
    hash.rawBytes(&air_v2.Statement.SEMANTIC_DIGEST);
    hash.rawBytes(&air_v2.PublicLogUp.SEMANTIC_DIGEST);
    hash.u32Value(STATEMENT_COMPONENT_TAG);
    hash.u32Value(PUBLIC_LOGUP_COMPONENT_TAG);
    return hash.finalize();
}

pub fn outerManifestId(manifest: *const OuterManifestV2) NativeDigest {
    var hash = NativeHasher.init(MANIFEST_ID_DOMAIN);
    hash.scalar(manifest.format_version);
    hash.scalar(manifest.schema_version);
    hash.scalar(manifest.manifest_version);
    hash.scalar(manifest.component_count);
    hash.scalar(@intFromBool(manifest.frozen_v1_compatible));
    hash.digest(manifest.source_manifest.identity);
    for (manifest.components) |component| {
        hash.scalar(@intFromEnum(component.kind));
        hash.scalar(component.component_tag);
        hash.scalar(component.logical_rows);
        hash.scalar(component.trace_log_size);
        hash.scalar(component.trace_rows);
        hash.scalar(component.preprocessed_columns);
        hash.scalar(component.main_columns);
        hash.scalar(component.interaction_columns);
        hash.scalar(component.direct_constraints);
        hash.scalar(component.interaction_batches);
        hash.scalar(component.protocol_constraint_degree);
        hash.sha256(component.semantic_digest);
    }
    hash.sha256(manifest.authority_sha_id);
    return hash.finalize();
}

pub fn requireNativeDigest(value: NativeDigest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.EmptyDigest;
}

pub fn requireShaDigest(value: Sha256Digest) Error!void {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    if (aggregate == 0) return error.EmptyDigest;
}

pub const NativeHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) NativeHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *NativeHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(canonical)};
        self.inner.update(&words);
    }

    pub fn digest(self: *NativeHasher, value: NativeDigest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn sha256(self: *NativeHasher, value: Sha256Digest) void {
        self.scalar(SHA256_ENCODING_TAG);
        self.scalar(value.len);
        for (value) |byte| self.scalar(byte);
    }

    pub fn qm31(self: *NativeHasher, value: QM31) void {
        const words = value.toM31Array();
        self.inner.update(&words);
    }

    pub fn finalize(self: *NativeHasher) NativeDigest {
        return self.inner.finalize();
    }
};

pub const ShaHasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    pub fn init(domain: []const u8) ShaHasher {
        var inner = std.crypto.hash.sha2.Sha256.init(.{});
        inner.update(domain);
        return .{ .inner = inner };
    }

    pub fn u8Value(self: *ShaHasher, value: u8) void {
        self.inner.update(&.{value});
    }

    pub fn u16Value(self: *ShaHasher, value: anytype) void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(value), .little);
        self.inner.update(&bytes);
    }

    pub fn u32Value(self: *ShaHasher, value: anytype) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(value), .little);
        self.inner.update(&bytes);
    }

    pub fn rawBytes(self: *ShaHasher, value: []const u8) void {
        self.u32Value(value.len);
        self.inner.update(value);
    }

    pub fn nativeDigest(self: *ShaHasher, value: NativeDigest) void {
        for (value) |word| self.u32Value(word);
    }

    pub fn qm31(self: *ShaHasher, value: QM31) void {
        for (value.toM31Array()) |word| self.u32Value(word.toU32());
    }

    pub fn finalize(self: *ShaHasher) Sha256Digest {
        return self.inner.finalResult();
    }
};
