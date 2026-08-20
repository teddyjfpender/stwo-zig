//! Internal segment statement outer source v2 authority shard; use segment_statement_outer_source_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const direct_program = @import("air/direct_constraint_program.zig");
pub const framework_interaction = @import("air/framework_interaction.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const row10_air = @import("air/statement_input.zig");
pub const transcript_payload_air = @import("air/transcript_payload.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const roster = @import("air/universal_roster.zig");
pub const span_statement = @import("span_statement.zig");
pub const segment_statement_v2 = @import("segment_statement_v2.zig");
pub const source_v2 = @import("segment_leaf_authority_v2.zig");
pub const air_v2 = @import("segment_leaf_outer_air_v2.zig");
pub const public_source_v2 = @import("segment_public_outer_source_v2.zig");
pub const transcript_source_v2 = @import("segment_transcript_outer_source_v2.zig");
pub const channel = @import("poseidon2_channel.zig");

pub const Digest = channel.Digest;
pub const Sha256Digest = [32]u8;
pub const Air = air_v2.StatementSemanticsV2;
pub const Framework = framework_interaction.Runtime(Air.Runtime);
pub const AirError = @typeInfo(@typeInfo(@TypeOf(
    Air.build,
)).@"fn".return_type.?).error_union.error_set;
pub const AirAuthenticationError = @typeInfo(@typeInfo(@TypeOf(
    Air.authenticate,
)).@"fn".return_type.?).error_union.error_set;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 2;
pub const MANIFEST_VERSION: u16 = 3;
pub const FROZEN_ROW_10: u8 = @intFromEnum(roster.Component.statement_input);
pub const ROUTING_ROW_11: u8 =
    @intFromEnum(roster.Component.statement_semantics_input);
pub const RANGE_PROVIDER_ROW_35: u8 =
    @intFromEnum(roster.Component.range_check_8_8);
pub const STATEMENT_SOURCE_COMPONENT_36: u8 = roster.COMPONENT_COUNT;
pub const PUBLIC_LOGUP_SOURCE_COMPONENT_37: u8 = roster.COMPONENT_COUNT + 1;
pub const VM_PUBLIC_LOGUP_ROW_16: u8 =
    @intFromEnum(roster.Component.vm_public_logup_input);
pub const HEADER_LIMB_COUNT: usize = 8;
pub const WIRE_ID_WORD_COUNT: usize = channel.RATE;
pub const WIRE_ID_LIMB_COUNT: usize = 2 * WIRE_ID_WORD_COUNT;
pub const EVENT_COUNT_PER_ROW: usize = Air.RELATION_EVENT_COUNT;

pub const MANIFEST_ID_DOMAIN: u32 = 0x5353_5632; // "SSV2"
pub const PREPARED_ID_DOMAIN: u32 = 0x5350_5632; // "SPV2"
pub const TRACE_SHA_DOMAIN =
    "stwo-zig/typed-air/segment-statement-spine-v2/trace/v1\x00";
pub const ROW_SHA_DOMAIN =
    "stwo-zig/typed-air/segment-statement-spine-v2/rows/v1\x00";

pub const HOT_PREPARE_HEAP_ALLOCATIONS: usize = 0;
pub const FROZEN_ROW_10_ACTIVE = false;
pub const FROZEN_ROW_10_CLAIM_IS_ZERO = true;
pub const ROW_11_SOURCE_TUPLES_CLOSED = true;
pub const ROW_11_TRANSCRIPT_STATEMENT_INPUTS_CLOSED = true;
pub const ROW_11_BOUNDARY_BRIDGE_CLOSED = true;
pub const ROW_35_REQUEST_SET_COMPLETE = true;
pub const WIRE_HASH_AIR_VERIFIED = false;
pub const AUTHORITY_HASH_AIR_VERIFIED = false;
pub const PRODUCTION_ACTIVATION = false;

pub const OverrideActivationV2 = enum(u8) {
    explicitly_inactive = 0,
    active_v2_override = 1,
    appended_boundary_source = 2,
};

/// Exact manifest handoff for the central 38-component V2 roster. Geometry is
/// exported from each authoritative AIR and is never transcribed by callers.
pub const ComponentOverrideV2 = struct {
    component_index: u8,
    activation: OverrideActivationV2,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    relation_events: u16,
    protocol_constraint_degree: u8,
    profiled_constraint_degree: u8,
    semantic_digest: Sha256Digest,
};

pub const COMPONENT_OVERRIDE_TABLE_V2 = [_]ComponentOverrideV2{
    overrideFor(
        row10_air,
        FROZEN_ROW_10,
        .explicitly_inactive,
    ),
    overrideFor(
        Air,
        ROUTING_ROW_11,
        .active_v2_override,
    ),
    overrideFor(
        air_v2.Statement,
        STATEMENT_SOURCE_COMPONENT_36,
        .appended_boundary_source,
    ),
};

/// Auditable producer/consumer multiplicities for the V2 statement boundary.
/// Source 37 now publishes its exact circuit-44 bridge into rows 12--14. Its
/// custom verifier-input namespace remains disjoint from row 16's standard
/// claimed-sum input, so the two consumers cannot cancel or double-consume an
/// edge accidentally.
pub const ClosureLedgerV2 = struct {
    row10_statement_emits: u32 = 0,
    row10_verifier_input_consumes: u32 = 0,
    source36_statement_emits: u32,
    row11_statement_consumes: u32,
    program_statement_payload_emits: u32,
    row11_statement_payload_consumes: u32,
    row11_boundary_wire_emits: u32,
    row15_boundary_wire_consumes: u32,
    boundary_bridge_circuit_id: u32 = Air.BOUNDARY_BRIDGE_CIRCUIT_ID,
    source37_custom_logup_consumes: u32 = source_v2.LOGUP_PUBLICATION_WORD_COUNT,
    source37_verifier_id: u32 = source_v2.SEGMENT_V2_VERIFIER_ID,
    source37_kind: u32 = source_v2.PUBLIC_LOGUP_V2_KIND,
    row16_verifier_id: u32 = 0,
    row16_kind: u32 =
        @intFromEnum(transcript_payload_air.VerifierInputKind.claimed_sum),
    source37_row16_namespaces_disjoint: bool = true,
    source37_custom_producer_closed: bool =
        public_source_v2.SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE,

    pub fn validate(self: ClosureLedgerV2) Error!void {
        if (self.row10_statement_emits != 0 or
            self.row10_verifier_input_consumes != 0 or
            self.source36_statement_emits == 0 or
            self.source36_statement_emits != self.row11_statement_consumes or
            self.program_statement_payload_emits !=
                self.row11_statement_payload_consumes or
            self.row11_boundary_wire_emits == 0 or
            self.row11_boundary_wire_emits !=
                self.row15_boundary_wire_consumes or
            self.boundary_bridge_circuit_id !=
                public_source_v2.BOUNDARY_BRIDGE_CIRCUIT_ID or
            self.source37_custom_logup_consumes !=
                source_v2.LOGUP_PUBLICATION_WORD_COUNT or
            self.source37_verifier_id != source_v2.SEGMENT_V2_VERIFIER_ID or
            self.source37_kind != source_v2.PUBLIC_LOGUP_V2_KIND or
            self.row16_verifier_id != 0 or
            self.row16_kind !=
                @intFromEnum(transcript_payload_air.VerifierInputKind.claimed_sum) or
            !self.source37_row16_namespaces_disjoint or
            !self.source37_custom_producer_closed or
            self.source37_custom_producer_closed !=
                public_source_v2.SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE or
            (self.source37_verifier_id == self.row16_verifier_id and
                self.source37_kind == self.row16_kind))
        {
            return error.SourceMismatch;
        }
    }
};

comptime {
    if (FROZEN_ROW_10 != 10 or ROUTING_ROW_11 != 11 or
        RANGE_PROVIDER_ROW_35 != 35 or STATEMENT_SOURCE_COMPONENT_36 != 36 or
        PUBLIC_LOGUP_SOURCE_COMPONENT_37 != 37 or
        VM_PUBLIC_LOGUP_ROW_16 != 16 or
        HEADER_LIMB_COUNT != 8 or
        WIRE_ID_LIMB_COUNT != 16 or Air.RELATION_EVENT_COUNT != 7 or
        Air.INTERACTION_BATCH_COUNT != 4 or Air.INTERACTION_COLUMN_COUNT != 16 or
        Air.BOUNDARY_BRIDGE_CIRCUIT_ID !=
            public_source_v2.BOUNDARY_BRIDGE_CIRCUIT_ID)
    {
        @compileError("V2 statement-spine protocol geometry drifted");
    }
}

pub const Error = public_data_v2.Error || source_v2.Error ||
    transcript_source_v2.Error || direct_program.Error ||
    framework_interaction.Error || universal.Error || AirError ||
    AirAuthenticationError || error{
    AliasedDestination,
    ArithmeticOverflow,
    AuthorityMismatch,
    DestinationLengthMismatch,
    DirectConstraintFailure,
    InvalidManifest,
    InvalidRelationEvent,
    InvalidTraceShape,
    NonCanonicalRangeWord,
    SourceMismatch,
    TraceMutation,
    UnsupportedVersion,
};

pub const ManifestV2 = struct {
    format_version: u16 = MANIFEST_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    frozen_row_10: u8 = FROZEN_ROW_10,
    frozen_row_10_active: bool = FROZEN_ROW_10_ACTIVE,
    routing_row_11: u8 = ROUTING_ROW_11,
    range_provider_row_35: u8 = RANGE_PROVIDER_ROW_35,
    wire_word_count: u32,
    context_word_count: u32 = source_v2.CONTEXT_WORD_COUNT,
    header_limb_count: u32 = HEADER_LIMB_COUNT,
    logical_row_count: u32,
    trace_log_size: u8,
    trace_row_count: u32,
    relation_event_count: u32,
    wire_u16_request_count: u32,
    wire_id_limb_request_count: u32 = WIRE_ID_LIMB_COUNT,
    range_request_count: u32,
    range_request_source_complete: bool = ROW_35_REQUEST_SET_COMPLETE,
    source_manifest_id: Digest,
    transcript_manifest_id: Digest,
    wire_id: Digest,
    statement_authority_id: Digest,
    semantic_digest: Sha256Digest = Air.SEMANTIC_DIGEST,
    identity: Digest,

    pub fn validate(self: *const ManifestV2) Error!void {
        if (self.format_version != MANIFEST_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.frozen_row_10 != FROZEN_ROW_10 or self.frozen_row_10_active or
            self.routing_row_11 != ROUTING_ROW_11 or
            self.range_provider_row_35 != RANGE_PROVIDER_ROW_35 or
            self.context_word_count != source_v2.CONTEXT_WORD_COUNT or
            self.header_limb_count != HEADER_LIMB_COUNT or
            self.wire_id_limb_request_count != WIRE_ID_LIMB_COUNT or
            !self.range_request_source_complete or
            !std.mem.eql(u8, &self.semantic_digest, &Air.SEMANTIC_DIGEST))
        {
            return error.InvalidManifest;
        }
        const source_rows = addU32(self.wire_word_count, self.context_word_count) catch
            return error.InvalidManifest;
        const logical_rows = addU32(source_rows, self.header_limb_count) catch
            return error.InvalidManifest;
        const event_count = mulU32(logical_rows, EVENT_COUNT_PER_ROW) catch
            return error.InvalidManifest;
        const range_count = addU32(
            self.wire_u16_request_count,
            self.wire_id_limb_request_count,
        ) catch return error.InvalidManifest;
        if (self.logical_row_count != logical_rows or
            self.relation_event_count != event_count or
            self.range_request_count != range_count or
            self.trace_log_size >= 31 or
            self.trace_row_count != @as(u32, 1) << @intCast(self.trace_log_size) or
            self.trace_row_count < self.logical_row_count or
            (self.trace_log_size != 0 and
                self.trace_row_count / 2 >= self.logical_row_count) or
            !std.meta.eql(self.identity, manifestId(self)))
        {
            return error.InvalidManifest;
        }
        inline for (.{
            self.source_manifest_id,
            self.transcript_manifest_id,
            self.wire_id,
            self.statement_authority_id,
            self.identity,
        }) |value| try requireDigest(value);
    }
};

pub const PreprocessedRowV2 = struct {
    row_mask: u32,
    source_mask: u32,
    verifier_a_mask: u32,
    verifier_b_mask: u32,
    header_mask: u32,
    recombine_mask: u32,
    source_u16_mask: u32,
    verifier_a_u16_mask: u32,
    verifier_b_u16_mask: u32,
    source_scope: u32,
    source_index: u32,
    verifier_item: u32,
    verifier_a_index: u32,
    verifier_b_index: u32,
    expected_header: u32,
    boundary_bridge_mask: u32,

    pub fn values(self: PreprocessedRowV2) [Air.PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            felt(self.row_mask),
            felt(self.source_mask),
            felt(self.verifier_a_mask),
            felt(self.verifier_b_mask),
            felt(self.header_mask),
            felt(self.recombine_mask),
            felt(self.source_u16_mask),
            felt(self.verifier_a_u16_mask),
            felt(self.verifier_b_u16_mask),
            felt(self.source_scope),
            felt(self.source_index),
            felt(self.verifier_item),
            felt(self.verifier_a_index),
            felt(self.verifier_b_index),
            felt(self.expected_header),
            felt(self.boundary_bridge_mask),
        };
    }
};

pub const MainRowV2 = struct {
    enabler: M31,
    source_value: M31,
    verifier_a: M31,
    verifier_b: M31,
    source_low_byte: M31,
    source_high_byte: M31,
    verifier_a_low_byte: M31,
    verifier_a_high_byte: M31,
    verifier_b_low_byte: M31,
    verifier_b_high_byte: M31,

    pub fn values(self: MainRowV2) [Air.PHYSICAL_MAIN_COLUMN_COUNT]M31 {
        return .{
            self.enabler,
            self.source_value,
            self.verifier_a,
            self.verifier_b,
            self.source_low_byte,
            self.source_high_byte,
            self.verifier_a_low_byte,
            self.verifier_a_high_byte,
            self.verifier_b_low_byte,
            self.verifier_b_high_byte,
        };
    }
};

pub const LogicalRowV2 = struct {
    preprocessing: PreprocessedRowV2,
    main: MainRowV2,

    pub fn runtime(self: LogicalRowV2) Air.Row {
        return self.main.values() ++ self.preprocessing.values();
    }
};

pub const RelationEventV2 = struct {
    logical_row: u32,
    ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    multiplicity: u32,
    arity: u8,
    tuple: [6]M31,

    pub fn validate(self: RelationEventV2) Error!void {
        if (self.ordinal >= EVENT_COUNT_PER_ROW or
            self.arity != relation.universalDescriptor(self.domain).arity or
            self.arity > self.tuple.len)
        {
            return error.InvalidRelationEvent;
        }
        for (self.tuple[self.arity..]) |value| if (!value.isZero())
            return error.InvalidRelationEvent;
    }
};

pub const RangeRequestV2 = struct {
    logical_row: u32,
    event_ordinal: u8,
    low_byte: M31,
    high_byte: M31,

    pub fn value(self: RangeRequestV2) u16 {
        return @intCast(self.low_byte.toU32() |
            (self.high_byte.toU32() << 8));
    }
};

pub const TraceColumnsV2 = struct {
    preprocessed: [Air.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
};

pub const DestinationsV2 = struct {
    trace: TraceColumnsV2,
    logical_rows: []Air.Row,
    relation_events: []RelationEventV2,
    range_requests: []RangeRequestV2,
};

pub const AuthorityV2 = struct {
    definition: Air.Definition,
    relation_plan: Air.Plan,
    direct: direct_program.Program,

    pub fn init(allocator: std.mem.Allocator) !AuthorityV2 {
        var definition = try Air.build(allocator);
        errdefer definition.deinit();
        const relation_plan = try Air.authenticate(&definition);
        const direct = try direct_program.authenticate(
            &definition.arena,
            Air.SEMANTIC_DIGEST,
            Air.LOGICAL_INPUT_COUNT,
        );
        var result = AuthorityV2{
            .definition = definition,
            .relation_plan = relation_plan,
            .direct = direct,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *AuthorityV2) void {
        self.definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const AuthorityV2) !void {
        try self.definition.validate();
        try self.relation_plan.validateAgainst(
            &self.definition.arena,
            Air.SEMANTIC_DIGEST,
            self.definition.events,
        );
        const expected = try direct_program.authenticate(
            &self.definition.arena,
            Air.SEMANTIC_DIGEST,
            Air.LOGICAL_INPUT_COUNT,
        );
        if (!std.meta.eql(self.direct, expected))
            return error.AuthorityMismatch;
    }
};

/// Stack-only direct-constraint scratch. Interaction inversion storage is
/// separately retained by `Framework.Workspace` and shared across proofs.
pub const WorkspaceV2 = struct {
    direct_scratch: [direct_program.MAX_NODES]M31 =
        [_]M31{M31.zero()} ** direct_program.MAX_NODES,
    roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 =
        [_]M31{M31.zero()} ** Air.DIRECT_CONSTRAINT_COUNT,
};

pub fn manifestId(manifest: *const ManifestV2) Digest {
    var hash = NativeHasher.init(MANIFEST_ID_DOMAIN);
    hash.scalar(manifest.format_version);
    hash.scalar(manifest.schema_version);
    hash.scalar(manifest.frozen_row_10);
    hash.scalar(@intFromBool(manifest.frozen_row_10_active));
    hash.scalar(manifest.routing_row_11);
    hash.scalar(manifest.range_provider_row_35);
    hash.u32Value(manifest.wire_word_count);
    hash.u32Value(manifest.context_word_count);
    hash.u32Value(manifest.header_limb_count);
    hash.u32Value(manifest.logical_row_count);
    hash.scalar(manifest.trace_log_size);
    hash.u32Value(manifest.trace_row_count);
    hash.u32Value(manifest.relation_event_count);
    hash.u32Value(manifest.wire_u16_request_count);
    hash.u32Value(manifest.wire_id_limb_request_count);
    hash.u32Value(manifest.range_request_count);
    hash.scalar(@intFromBool(manifest.range_request_source_complete));
    hash.digest(manifest.source_manifest_id);
    hash.digest(manifest.transcript_manifest_id);
    hash.digest(manifest.wire_id);
    hash.digest(manifest.statement_authority_id);
    hash.bytesDigest(manifest.semantic_digest);
    return hash.finalize();
}

pub const NativeHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) NativeHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *NativeHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < stwo_core.fields.m31.Modulus);
        self.inner.update(&.{felt(canonical)});
    }

    pub fn u32Value(self: *NativeHasher, value: u32) void {
        self.inner.update(&.{ felt(value & 0xffff), felt(value >> 16) });
    }

    pub fn digest(self: *NativeHasher, value: Digest) void {
        var words: [channel.RATE]M31 = undefined;
        for (&words, value) |*target, word| target.* = felt(word);
        self.inner.update(&words);
    }

    pub fn qm31(self: *NativeHasher, value: QM31) void {
        self.inner.update(&value.toM31Array());
    }

    pub fn bytesDigest(self: *NativeHasher, value: Sha256Digest) void {
        for (0..8) |index| self.u32Value(std.mem.readInt(
            u32,
            value[index * 4 ..][0..4],
            .little,
        ));
    }

    pub fn finalize(self: *NativeHasher) Digest {
        return self.inner.finalize();
    }
};

pub fn felt(value: anytype) M31 {
    return M31.fromCanonical(@intCast(value));
}

pub fn add(lhs: usize, rhs: usize) error{ArithmeticOverflow}!usize {
    return std.math.add(usize, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn addU32(lhs: u32, rhs: anytype) error{ArithmeticOverflow}!u32 {
    return std.math.add(u32, lhs, @intCast(rhs)) catch error.ArithmeticOverflow;
}

pub fn mulU32(lhs: u32, rhs: anytype) error{ArithmeticOverflow}!u32 {
    return std.math.mul(u32, lhs, @intCast(rhs)) catch error.ArithmeticOverflow;
}

pub fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.AuthorityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.AuthorityMismatch;
}

pub fn overrideFor(
    comptime ComponentAir: type,
    comptime component_index: u8,
    comptime activation: OverrideActivationV2,
) ComponentOverrideV2 {
    return .{
        .component_index = component_index,
        .activation = activation,
        .preprocessed_columns = ComponentAir.PREPROCESSED_COLUMN_COUNT,
        .main_columns = ComponentAir.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = ComponentAir.INTERACTION_COLUMN_COUNT,
        .direct_constraints = ComponentAir.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = ComponentAir.INTERACTION_BATCH_COUNT,
        .relation_events = ComponentAir.RELATION_EVENT_COUNT,
        .protocol_constraint_degree = ComponentAir.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = ComponentAir.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = ComponentAir.SEMANTIC_DIGEST,
    };
}

pub fn isZeroSha(value: Sha256Digest) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}
