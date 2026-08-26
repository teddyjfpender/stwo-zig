//! Internal outer parent statement air source authority shard; use outer_parent_statement_air_source.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const fields = stwo_core.fields;
pub const M31 = fields.m31.M31;
pub const QM31 = fields.qm31.QM31;

pub const channel = @import("poseidon2_channel.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const parent_source = @import("outer_parent_statement_source.zig");
pub const pair_node = @import("pair_node.zig");
pub const protocol = @import("protocol.zig");
pub const span_statement = @import("span_statement.zig");
pub const statement_circuit = @import("statement_semantics_circuit.zig");
pub const range_owner = @import("outer_parent_range_authority.zig");
pub const segment_source = @import("segment_statement_outer_source.zig");
pub const relation = @import("../air/lang/relation.zig");

pub const row10_air = @import("air/statement_input.zig");
pub const row10_relation = @import("air/statement_input_relation.zig");
pub const row10_witness = @import("air/statement_input_witness.zig");
pub const row11_air = @import("air/statement_semantics_input.zig");
pub const row11_relation = @import("air/statement_semantics_input_relation.zig");
pub const row11_witness = @import("air/statement_semantics_input_witness.zig");
pub const range_bridge = @import("air/range_check_8_8_bridge.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const lowering = @import("air/verifier_arithmetic_lowering.zig");
pub const manifest_mod = @import("air/universal_adapter_manifest.zig");
pub const roster = @import("air/universal_roster.zig");
pub const shared_provider = @import("air/universal_shared_provider.zig");
pub const typed_component = @import("air/universal_typed_component.zig");
pub const universal = @import("air/universal_challenges.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const STATEMENT_PUBLICATION_FORMAT_VERSION: u16 = 1;
pub const STATEMENT_PUBLICATION_ID_DOMAIN: u32 = 0x4f50_4253; // "OPBS"
pub const SOURCE_ID_DOMAIN: u32 = 0x4f50_4153; // "OPAS"
pub const CHILD_COUNT: usize = parent_source.CHILD_COUNT;
pub const STATEMENT_CIRCUIT_ID = segment_source.STATEMENT_CIRCUIT_ID;

pub const STATEMENT_INPUT_LOG_SIZE = segment_source.STATEMENT_INPUT_LOG_SIZE;
pub const STATEMENT_SEMANTICS_LOG_SIZE =
    segment_source.STATEMENT_SEMANTICS_LOG_SIZE;
pub const RANGE_CHECK_LOG_SIZE = segment_source.RANGE_CHECK_LOG_SIZE;
pub const STATEMENT_INPUT_TRACE_SIZE = segment_source.STATEMENT_INPUT_TRACE_SIZE;
pub const STATEMENT_SEMANTICS_TRACE_SIZE =
    segment_source.STATEMENT_SEMANTICS_TRACE_SIZE;
pub const RANGE_CHECK_TRACE_SIZE = segment_source.RANGE_CHECK_TRACE_SIZE;

pub const STATEMENT_INPUT_PARAMETERS = [row10_air.PARAMETER_COUNT]M31{
    M31.zero(),
    M31.one(),
    M31.fromCanonical(row10_air.STATEMENT_INPUT_KIND),
    M31.fromCanonical(row10_air.STATEMENT_INPUT_ITEM),
    M31.fromCanonical(row10_air.VM_CLAIM_STATEMENT_SCOPE),
};
pub const STATEMENT_SEMANTICS_PARAMETERS = [row11_air.PARAMETER_COUNT]M31{
    M31.zero(),
    M31.one(),
    M31.zero(),
    M31.zero(),
};

pub const ProductionStatus = enum(u8) {
    verifier_published_statement_words = 1,
};

pub const CURRENT_STATUS: ProductionStatus =
    .verifier_published_statement_words;
pub const NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS = true;
pub const COMPLETE_PARENT_STARK_VERIFIED = false;
pub const HOT_TRACE_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL: usize = 0;
pub const COLD_HEAP_ALLOCATIONS_PER_PREPARED: usize = 3;
/// A fresh end-to-end preparation authenticates the pair once, in the parent
/// source constructor. The statement publication and AIR construction remain
/// in the same transaction and consume that already authenticated local.
pub const FUSED_PAIR_AUTHENTICATIONS_PER_PREPARE: usize = 1;
/// The formerly composed parent -> publication -> AIR path authenticated the
/// same retained pair three more times. The fused entry point removes those
/// redundant walks; each walk is the measured prepared-root cost below.
pub const FUSED_PAIR_REAUTHENTICATIONS_AVOIDED: usize = 3;
pub const FUSED_PAIR_PERMUTATIONS_AVOIDED: usize =
    FUSED_PAIR_REAUTHENTICATIONS_AVOIDED *
    pair_node.AuthenticationPermutationCostV1.successful_prepared_root;

pub const Error = parent_source.Error || span_statement.Error ||
    statement_circuit.Error || range_owner.Error || segment_source.Error ||
    error{
        AliasedDestination,
        AliasedInput,
        AliasedWorkspace,
        AuthorityMismatch,
        StatementPublicationMismatch,
        ChildIndexOutOfRange,
        DuplicatePublication,
        InvalidTraceShape,
        NonBaseCircuitInput,
        ParentStatementIdMismatch,
        PrefixClosureMismatch,
        ProductionStatusMismatch,
        SourceIdentityMismatch,
        ZeroDenominator,
    };

/// Canonical statement words published by one successful native verifier and
/// cryptographically bound to one exact child of one authenticated parent.
pub const VerifiedStatementPublicationV1 = struct {
    format_version: u16 = STATEMENT_PUBLICATION_FORMAT_VERSION,
    status: ProductionStatus = CURRENT_STATUS,
    child_index: u8,
    position: pair_node.ChildPosition,
    role: pair_node.ChildRole,
    parent_source_id: channel.Digest,
    profile_id: channel.Digest,
    capture_id: channel.Digest,
    receipt_id: channel.Digest,
    preprocessed_root: channel.Digest,
    statement_id: channel.Digest,
    proof_id: channel.Digest,
    transcript_id: channel.Digest,
    summary_id: channel.Digest,
    statement: span_statement.SpanStatement,
    words: span_statement.StatementWords,
    binding_id: channel.Digest,

    pub fn validateAgainst(
        self: *const VerifiedStatementPublicationV1,
        parent: anytype,
    ) Error!void {
        if (self.format_version != STATEMENT_PUBLICATION_FORMAT_VERSION or
            self.status != CURRENT_STATUS)
        {
            return error.ProductionStatusMismatch;
        }
        const index: usize = self.child_index;
        if (index >= CHILD_COUNT) return error.ChildIndexOutOfRange;
        const public = parent.statement.children[index];
        const transcript = parent.transcript.children[index];
        const custody = parent.witness.custody[index];
        if (self.position != public.position or self.role != public.role or
            !std.meta.eql(self.parent_source_id, parent.source_id) or
            !std.meta.eql(self.profile_id, custody.profile_id) or
            !std.meta.eql(self.capture_id, custody.capture_id) or
            !std.meta.eql(self.receipt_id, custody.receipt_id) or
            !std.meta.eql(self.preprocessed_root, public.preprocessed_root) or
            !std.meta.eql(self.preprocessed_root, transcript.preprocessed_root) or
            !std.meta.eql(self.statement_id, public.statement_id) or
            !std.meta.eql(self.proof_id, public.proof_id) or
            !std.meta.eql(self.transcript_id, public.transcript_id) or
            !std.meta.eql(self.summary_id, public.summary_id) or
            !m31SlicesEql(&self.words, &transcript.statement_words))
        {
            return error.StatementPublicationMismatch;
        }
        const expected_words = try self.statement.canonicalWords();
        if (!m31SlicesEql(&expected_words, &self.words) or
            !std.meta.eql(statementId(&expected_words), self.statement_id))
        {
            return error.StatementPublicationMismatch;
        }
        const expected_binding = statementPublicationId(self);
        if (!std.meta.eql(expected_binding, self.binding_id))
            return error.StatementPublicationMismatch;
    }
};

pub const ParentAirPublicV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    status: ProductionStatus = CURRENT_STATUS,
    parent_source_id: channel.Digest,
    parent_vk_id: channel.Digest,
    child_preprocessed_roots: [CHILD_COUNT]channel.Digest,
    child_statement_ids: [CHILD_COUNT]channel.Digest,
    child_publication_ids: [CHILD_COUNT]channel.Digest,
    execution_statement_id: channel.Digest,
};

pub const Workspace = struct {
    allocator: std.mem.Allocator,
    range: range_owner.Workspace,
    logical_storage: []M31,
    secure_storage: []QM31,

    pub fn init(allocator: std.mem.Allocator) Error!Workspace {
        var range = try range_owner.Workspace.init(allocator);
        errdefer range.deinit(allocator);
        const logical_storage = try allocator.alloc(M31, LOGICAL_SCRATCH_COUNT);
        errdefer allocator.free(logical_storage);
        const secure_storage = try allocator.alloc(QM31, SECURE_SCRATCH_COUNT);
        return .{
            .allocator = allocator,
            .range = range,
            .logical_storage = logical_storage,
            .secure_storage = secure_storage,
        };
    }

    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.secure_storage);
        self.allocator.free(self.logical_storage);
        self.range.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn validate(self: *const Workspace) Error!void {
        try self.range.validateGeometry();
        if (self.logical_storage.len != LOGICAL_SCRATCH_COUNT or
            self.secure_storage.len != SECURE_SCRATCH_COUNT)
        {
            return error.InvalidTraceShape;
        }
    }
};

pub fn validatePublications(parent: anytype, publications: anytype) Error!void {
    for (publications, 0..) |*publication, index| {
        if (publication.child_index != index)
            return error.StatementPublicationMismatch;
        try publication.validateAgainst(parent);
    }
    if (std.meta.eql(publications[0].binding_id, publications[1].binding_id))
        return error.DuplicatePublication;
}

pub fn validatePublicRecord(public: *const ParentAirPublicV1) Error!void {
    const direct = [_]channel.Digest{
        public.parent_source_id,
        public.parent_vk_id,
        public.execution_statement_id,
    };
    for (direct) |value| try validateDigest(value);
    for (public.child_preprocessed_roots) |value| try validateDigest(value);
    for (public.child_statement_ids) |value| try validateDigest(value);
    for (public.child_publication_ids) |value| try validateDigest(value);
}

pub fn validateDigest(value: channel.Digest) Error!void {
    var nonzero = false;
    for (value) |word| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.SourceIdentityMismatch;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.SourceIdentityMismatch;
}

pub fn publicFromParent(parent: anytype, publications: anytype) ParentAirPublicV1 {
    var roots: [CHILD_COUNT]channel.Digest = undefined;
    var statement_ids: [CHILD_COUNT]channel.Digest = undefined;
    var publication_ids: [CHILD_COUNT]channel.Digest = undefined;
    for (&roots, &statement_ids, &publication_ids, parent.statement.children, publications) |
        *root,
        *statement_id,
        *publication_id,
        child,
        publication,
    | {
        root.* = child.preprocessed_root;
        statement_id.* = child.statement_id;
        publication_id.* = publication.binding_id;
    }
    return .{
        .parent_source_id = parent.source_id,
        .parent_vk_id = parent.statement.parent_vk_id,
        .child_preprocessed_roots = roots,
        .child_statement_ids = statement_ids,
        .child_publication_ids = publication_ids,
        .execution_statement_id = parent.statement.execution_statement_id,
    };
}

pub fn statementPublicationId(
    publication: *const VerifiedStatementPublicationV1,
) channel.Digest {
    var hasher = CanonicalHasher.init(STATEMENT_PUBLICATION_ID_DOMAIN);
    hasher.addU32(STATEMENT_PUBLICATION_FORMAT_VERSION);
    hasher.addU32(@intFromEnum(CURRENT_STATUS));
    hasher.addU32(publication.child_index);
    hasher.addU32(@intFromEnum(publication.position));
    hasher.addU32(@intFromEnum(publication.role));
    hasher.digest(publication.parent_source_id);
    hasher.digest(publication.profile_id);
    hasher.digest(publication.capture_id);
    hasher.digest(publication.receipt_id);
    hasher.digest(publication.preprocessed_root);
    hasher.digest(publication.statement_id);
    hasher.digest(publication.proof_id);
    hasher.digest(publication.transcript_id);
    hasher.digest(publication.summary_id);
    hasher.words(&publication.words);
    return hasher.finalize();
}

pub fn sourceId(prepared: anytype) channel.Digest {
    var hasher = CanonicalHasher.init(SOURCE_ID_DOMAIN);
    hasher.addU32(FORMAT_VERSION);
    hasher.addU32(@intFromEnum(CURRENT_STATUS));
    hasher.digest(prepared.public.parent_source_id);
    hasher.digest(prepared.public.parent_vk_id);
    for (prepared.public.child_preprocessed_roots) |value| hasher.digest(value);
    for (prepared.public.child_statement_ids) |value| hasher.digest(value);
    for (prepared.public.child_publication_ids) |value| hasher.digest(value);
    hasher.digest(prepared.public.execution_statement_id);
    hasher.words(&prepared.left_words);
    hasher.words(&prepared.right_words);
    hasher.words(&prepared.parent_words);
    hasher.bytes(&prepared.range.source_authority_digest);
    hasher.addU64(prepared.range.request_count);
    return hasher.finalize();
}

pub fn statementId(words: *const span_statement.StatementWords) channel.Digest {
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (words, &canonical) |word, *destination| destination.* = word.toU32();
    return protocol.statementId(&canonical);
}

pub const CanonicalHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) CanonicalHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *CanonicalHasher, value: u32) void {
        const encoded = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&encoded);
    }

    fn addU64(self: *CanonicalHasher, value: u64) void {
        self.addU32(@truncate(value & 0xffff));
        self.addU32(@truncate((value >> 16) & 0xffff));
        self.addU32(@truncate((value >> 32) & 0xffff));
        self.addU32(@truncate(value >> 48));
    }

    fn digest(self: *CanonicalHasher, value: channel.Digest) void {
        var encoded: [channel.RATE]M31 = undefined;
        for (value, &encoded) |word, *destination|
            destination.* = M31.fromCanonical(word);
        self.inner.update(&encoded);
    }

    fn words(self: *CanonicalHasher, value: []const M31) void {
        self.inner.update(value);
    }

    fn bytes(self: *CanonicalHasher, value: []const u8) void {
        self.addU32(@intCast(value.len));
        var index: usize = 0;
        while (index + 1 < value.len) : (index += 2) {
            self.addU32(@as(u32, value[index]) |
                (@as(u32, value[index + 1]) << 8));
        }
        if (index < value.len) self.addU32(value[index]);
    }

    fn finalize(self: *CanonicalHasher) channel.Digest {
        return self.inner.finalize();
    }
};

pub fn baseInputs(inputs: []const QM31, destination: []M31) Error!void {
    if (inputs.len != destination.len) return error.InvalidTraceShape;
    for (inputs, destination) |input, *output| {
        const words = input.toM31Array();
        if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero())
            return error.NonBaseCircuitInput;
        output.* = words[0];
    }
}

pub fn m31SlicesEql(lhs: []const M31, rhs: []const M31) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |a, b| if (!a.eql(b)) return false;
    return true;
}

pub fn secureSlicesEql(lhs: []const QM31, rhs: []const QM31) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |a, b| if (!a.eql(b)) return false;
    return true;
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    pub fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn rejectWorkspaceAliases(prepared: anytype, workspace: *const Workspace) Error!void {
    const destinations = [_]AddressRange{
        try sliceRange(M31, workspace.logical_storage),
        try sliceRange(QM31, workspace.secure_storage),
        try sliceRange(M31, workspace.range.counter.values),
    };
    const sources = [_]AddressRange{
        try objectRange(prepared),
        try sliceRange(M31, prepared.statement_values),
        try sliceRange(QM31, prepared.circuit_evaluation.storage),
        try sliceRange(M31, prepared.range.provider().counter.values),
    };
    for (destinations, 0..) |destination, index| {
        for (destinations[0..index]) |prior| if (destination.overlaps(prior))
            return error.AliasedWorkspace;
        for (sources) |source| if (destination.overlaps(source))
            return error.AliasedWorkspace;
    }
}

pub fn sliceRange(comptime T: type, values: []const T) Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.ArithmeticOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.ArithmeticOverflow,
    };
}

pub fn objectRange(pointer: anytype) Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected source must be a single-item pointer");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.ArithmeticOverflow,
    };
}

pub const ROW10_PREPROCESSED_CELLS =
    row10_witness.PREPROCESSED_COLUMN_COUNT * STATEMENT_INPUT_TRACE_SIZE;
pub const ROW11_PREPROCESSED_CELLS =
    row11_witness.PREPROCESSED_COLUMN_COUNT * STATEMENT_SEMANTICS_TRACE_SIZE;
pub const TREE0_LOGICAL_CELLS = ROW10_PREPROCESSED_CELLS + ROW11_PREPROCESSED_CELLS;
pub const TREE1_LOGICAL_CELLS =
    row10_witness.MAIN_COLUMN_COUNT * STATEMENT_INPUT_TRACE_SIZE +
    row11_witness.MAIN_COLUMN_COUNT * STATEMENT_SEMANTICS_TRACE_SIZE;
pub const LOGICAL_SCRATCH_COUNT = @max(
    statement_circuit.INPUT_COUNT,
    @max(TREE0_LOGICAL_CELLS, TREE1_LOGICAL_CELLS),
);
pub const ROW10_INTERACTION_TERMS =
    row10_relation.Runtime.BATCH_COUNT * STATEMENT_INPUT_TRACE_SIZE;
pub const ROW11_INTERACTION_TERMS =
    row11_relation.Runtime.BATCH_COUNT * STATEMENT_SEMANTICS_TRACE_SIZE;
pub const TOTAL_INTERACTION_TERMS =
    ROW10_INTERACTION_TERMS + ROW11_INTERACTION_TERMS + RANGE_CHECK_TRACE_SIZE;
pub const CIRCUIT_REPLAY_CELLS =
    statement_circuit.INPUT_COUNT + statement_circuit.NODE_COUNT;
pub const SECURE_SCRATCH_COUNT = @max(
    CIRCUIT_REPLAY_CELLS,
    3 * TOTAL_INTERACTION_TERMS,
);
