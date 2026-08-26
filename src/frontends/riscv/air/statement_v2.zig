//! Versioned native statement envelope for one authenticated execution segment.
//!
//! The opcode and infrastructure geometry remains the existing
//! `RiscVStatement`: those descriptors are already the single source of truth
//! for committed columns and AIR components.  The public boundary is replaced
//! by `PublicDataV2`, however, and may never be admitted through V1 validation.
//! This envelope pins the legacy-shaped geometry to one canonical projection
//! of the authenticated V2 wire so internal helpers cannot observe a second,
//! contradictory set of PCs, roots, registers, clocks, or completion data.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const public_data_v1 = @import("public_data.zig");
const public_data_v2 = @import("public_data_v2.zig");
const public_logup_v2 = @import("public_logup_v2.zig");
const relation_challenges = @import("relation_challenges.zig");
const sparse_merkle = @import("memory_commitment/sparse_merkle.zig");
const statement_v1 = @import("statement.zig");
const channel = @import("../recursion/poseidon2_channel.zig");
const segment_v2 = @import("../recursion/segment_statement_v2.zig");
const runner_result = @import("../runner/result.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const AUTHORITY_ID_DOMAIN: u32 = 0x5253_5632; // "RSV2"
pub const RECEIPT_ID_DOMAIN: u32 = 0x5253_5250; // "RSRP"
pub const NATIVE_SUMS_ID_DOMAIN: u32 = 0x5253_4c32; // "RSL2"
pub const RELATION_CONTEXT_ID_DOMAIN: u32 = 0x5253_5243; // "RSRC"
pub const PRODUCTION_ACTIVATION = false;

pub const Error = public_logup_v2.Error || error{
    GeometryBoundaryMismatch,
    InvalidComponentGeometry,
    InvalidNativePublicSums,
    InvalidVerifiedReceipt,
    MerkleBoundaryMismatch,
    NonScalarProgramRoot,
    SegmentResultMismatch,
    UnsupportedVersion,
    ZeroDenominator,
};

/// Value-only receipt published together with a verifier capture.  It carries
/// no borrowed wire pointer, so it remains valid after the caller releases the
/// canonical statement allocation.
pub const VerifiedReceipt = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    authority_id: channel.Digest,
    wire_id: channel.Digest,
    session_id: channel.Digest,
    job_id: channel.Digest,
    position_id: channel.Digest,
    lineage_id: channel.Digest,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
    is_first: bool,
    is_final: bool,
    identity: channel.Digest,

    /// Re-authenticates the owned wire and detects accidental mutation of any
    /// receipt field.  This deterministic identity is defensive custody, not
    /// adversarial authenticity: recursive admission must also recompute the
    /// authority ID from verifier-owned VM geometry with
    /// `authorityIdentityFromGeometry`.
    pub fn validateAgainst(
        self: *const VerifiedReceipt,
        data: *const public_data_v2.PublicDataV2,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.identity, verifiedReceiptIdentity(self)))
        {
            return error.InvalidVerifiedReceipt;
        }
        const metadata = try data.metadata();
        if (!std.meta.eql(self.wire_id, metadata.wire_id) or
            !std.meta.eql(self.session_id, metadata.session_id) or
            !std.meta.eql(self.job_id, metadata.job_id) or
            !std.meta.eql(self.position_id, metadata.position_id) or
            !std.meta.eql(self.lineage_id, metadata.lineage_id) or
            self.segment_index != metadata.segment_index or
            self.segment_count != metadata.segment_count or
            self.global_cycle_start != metadata.global_cycle_start or
            self.global_cycle_end != metadata.global_cycle_end or
            self.is_first != metadata.is_first or
            self.is_final != metadata.is_final)
        {
            return error.InvalidVerifiedReceipt;
        }
    }
};

/// Owned verifier-authenticated V2 wire.  Recursive consumers receive this
/// value from successful native verification rather than re-parsing caller
/// bytes or retaining a pointer into caller-owned statement storage.
pub const OwnedPublicDataV2 = struct {
    allocator: std.mem.Allocator,
    canonical_words: []M31,
    data: public_data_v2.PublicDataV2,

    pub fn initVerified(
        allocator: std.mem.Allocator,
        source: *const public_data_v2.PublicDataV2,
    ) !OwnedPublicDataV2 {
        try source.validate();
        const words = try allocator.dupe(M31, source.words());
        errdefer allocator.free(words);
        const data = try public_data_v2.PublicDataV2.authenticate(words);
        if (!std.meta.eql(data.wireId(), source.wireId()))
            return error.SourceMutation;
        return .{
            .allocator = allocator,
            .canonical_words = words,
            .data = data,
        };
    }

    pub fn deinit(self: *OwnedPublicDataV2) void {
        self.allocator.free(self.canonical_words);
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedPublicDataV2) Error!void {
        if (self.data.words().ptr != self.canonical_words.ptr or
            self.data.words().len != self.canonical_words.len)
        {
            return error.SourceMutation;
        }
        try self.data.validate();
    }
};

/// Sealed split public compensation used by the native V2 verifier.  Its
/// concrete sums type intentionally remains `public_logup_v2.Sums`, with the
/// Merkle member extended by authenticated continuation-leaf/empty-root terms.
pub const NativePublicSums = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    wire_id: channel.Digest,
    relation_context_id: channel.Digest,
    sums: public_logup_v2.Sums,
    total: QM31,
    identity: channel.Digest,

    pub fn init(
        data: *const public_data_v2.PublicDataV2,
        relations: *const relation_challenges.Relations,
    ) Error!NativePublicSums {
        var result = NativePublicSums{
            .wire_id = (try authenticatedView(data)).wire_id,
            .relation_context_id = relationContextIdentity(relations),
            .sums = try nativeRelationSums(data, relations),
            .total = undefined,
            .identity = undefined,
        };
        result.total = result.sums.total();
        result.identity = nativeSumsIdentity(&result);
        return result;
    }

    pub fn validateAgainst(
        self: *const NativePublicSums,
        data: *const public_data_v2.PublicDataV2,
        relations: *const relation_challenges.Relations,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !self.total.eql(self.sums.total()) or
            !std.meta.eql(self.identity, nativeSumsIdentity(self)))
        {
            return error.InvalidNativePublicSums;
        }
        const expected = try NativePublicSums.init(data, relations);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidNativePublicSums;
    }
};

pub const RiscVStatementV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    /// Existing component geometry and its exact V2-derived compatibility
    /// projection.  V2 proof code consumes only the geometry methods on this
    /// value; transcript and public compensation consume `public_data` below.
    core: statement_v1.RiscVStatement,
    public_data: public_data_v2.PublicDataV2,
    authority_id: channel.Digest,

    const Self = @This();

    pub fn init(
        core: statement_v1.RiscVStatement,
        public_data: public_data_v2.PublicDataV2,
    ) Error!Self {
        var result = Self{
            .core = core,
            .public_data = public_data,
            .authority_id = undefined,
        };
        try result.validatePayload();
        result.authority_id = try authorityIdentityFromGeometry(
            &result.public_data,
            result.core.component_descs[0..result.core.n_components],
            result.core.infra_descs[0..result.core.n_infra],
        );
        return result;
    }

    /// Re-authenticates the borrowed wire and checks every compatibility field
    /// before the statement can reach a transcript, commitment, or verifier.
    pub fn validate(self: *const Self) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.UnsupportedVersion;
        }
        try self.validatePayload();
        const expected_authority = try authorityIdentityFromGeometry(
            &self.public_data,
            self.core.component_descs[0..self.core.n_components],
            self.core.infra_descs[0..self.core.n_infra],
        );
        if (!std.meta.eql(self.authority_id, expected_authority))
            return error.GeometryBoundaryMismatch;
    }

    pub fn metadata(self: *const Self) Error!public_data_v2.Metadata {
        try self.validate();
        return self.public_data.metadata();
    }

    pub fn declaresPublicIo(self: *const Self) Error!bool {
        const value = try self.metadata();
        return value.public_input != null or value.public_output != null;
    }

    pub fn verifiedReceipt(self: *const Self) Error!VerifiedReceipt {
        const value = try self.metadata();
        var result = VerifiedReceipt{
            .authority_id = self.authority_id,
            .wire_id = value.wire_id,
            .session_id = value.session_id,
            .job_id = value.job_id,
            .position_id = value.position_id,
            .lineage_id = value.lineage_id,
            .segment_index = value.segment_index,
            .segment_count = value.segment_count,
            .global_cycle_start = value.global_cycle_start,
            .global_cycle_end = value.global_cycle_end,
            .is_first = value.is_first,
            .is_final = value.is_final,
            .identity = undefined,
        };
        result.identity = verifiedReceiptIdentity(&result);
        return result;
    }

    /// Reconstructs the canonical segment statement directly from the runner
    /// result and compares the full retained wire payload.  This is the native
    /// proof ingress: a caller cannot pair an authenticated statement from one
    /// segment with the execution trace or commitment snapshot of another.
    pub fn validateSegmentResult(
        self: *const Self,
        result: *const runner_result.SegmentResult,
    ) Error!void {
        try self.validate();
        const view = try authenticatedView(&self.public_data);
        const base_statement = try view.statement.base();
        const source = try segment_v2.SourceV2.fromSegmentResult(
            view.statement.session_id,
            base_statement,
            result,
        );
        const expected = try source.statement();
        if (!std.meta.eql(expected, view.statement))
            return error.SegmentResultMismatch;
        if (!snapshotMatches(
            &view,
            view.entry_snapshot,
            result.rw_memory.words,
            .initial_word,
        ) or !snapshotMatches(
            &view,
            view.exit_snapshot,
            result.rw_memory.words,
            .final_word,
        ) or !clockSectionMatches(
            &view,
            view.entry_memory_clocks,
            result.entry_access_clocks.memory_clocks,
        ) or !clockSectionMatches(
            &view,
            view.exit_memory_clocks,
            result.exit_access_clocks.memory_clocks,
        )) return error.SegmentResultMismatch;

        const rows = result.execution_trace.rows.items;
        const first_clock = std.math.cast(u32, result.global_first_cycle) orelse
            return error.SegmentResultMismatch;
        const last_clock = std.math.add(
            u32,
            first_clock,
            std.math.cast(u32, result.cycle_count -| 1) orelse
                return error.SegmentResultMismatch,
        ) catch return error.SegmentResultMismatch;
        if (result.execution_trace.step_count != result.cycle_count or
            rows.len != result.cycle_count or rows.len == 0 or
            result.execution_trace.initial_pc != result.entry_cpu.pc or
            result.execution_trace.final_pc != result.exit_cpu.pc or
            rows[0].pc != result.entry_cpu.pc or
            rows[rows.len - 1].next_pc != result.exit_cpu.pc or
            rows[0].clk != first_clock or rows[rows.len - 1].clk != last_clock)
        {
            return error.SegmentResultMismatch;
        }
    }

    fn validatePayload(self: *const Self) Error!void {
        if (self.core.n_components > statement_v1.MAX_COMPONENTS or
            self.core.n_infra > statement_v1.MAX_INFRA_COMPONENTS)
        {
            return error.InvalidComponentGeometry;
        }
        const expected = try canonicalCorePublicData(&self.public_data);
        if (!publicDataProjectionEql(&self.core.public_data, &expected))
            return error.GeometryBoundaryMismatch;
        if (self.core.initial_pc != expected.initial_pc or
            self.core.final_pc != expected.final_pc or
            self.core.total_steps != expected.clock)
        {
            return error.GeometryBoundaryMismatch;
        }
    }
};

/// V2 verifier-side relation sums for the existing component set.
///
/// V2's public memory transition already closes every opcode access chain, so
/// its commitment witness intentionally has no V1 memory-boundary rows.  The
/// authenticated continuation trees still run through the existing Merkle and
/// Poseidon components; these extra public terms consume their retained
/// nonzero byte leaves.  An empty tree has neither leaves nor nodes, hence its
/// otherwise-unmatched root anchor is neutralized exactly once.
pub fn nativeRelationSums(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
) Error!public_logup_v2.Sums {
    const view = try authenticatedView(data);
    var sums = try public_logup_v2.relationSums(data, relations);
    try addContinuationTreeCompensation(
        &sums.merkle,
        &view,
        view.entry_snapshot,
        view.statement.entry_continuation_root,
        &relations.merkle,
    );
    try addContinuationTreeCompensation(
        &sums.merkle,
        &view,
        view.exit_snapshot,
        view.statement.exit_continuation_root,
        &relations.merkle,
    );
    return sums;
}

pub fn nativeRelationSum(
    data: *const public_data_v2.PublicDataV2,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    return (try nativeRelationSums(data, relations)).total();
}

/// Native transcript binding with the same frame as `PublicDataV2.mixInto`.
/// Blake channels already absorb canonical M31 values as their u32
/// representatives; Poseidon-native channels use their typed bulk method.
/// Both paths are allocation-free and one-shot, so variable wire length cannot
/// alter framing through chunk boundaries.
pub fn mixIntoNativeTranscript(
    data: *const public_data_v2.PublicDataV2,
    transcript: anytype,
) Error!void {
    const view = try authenticatedView(data);
    const word_count = std.math.cast(u32, view.words.len) orelse
        return error.TranscriptWordCountOverflow;
    transcript.mixU32s(&.{
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
        word_count,
    });
    transcript.mixU32s(&view.wire_id);
    if (comptime @hasDecl(@TypeOf(transcript.*), "mixCanonicalM31Words")) {
        view.mixInto(transcript);
    } else {
        comptime {
            if (@sizeOf(M31) != @sizeOf(u32) or @alignOf(M31) != @alignOf(u32))
                @compileError("native V2 transcript requires canonical M31/u32 layout");
        }
        const canonical: []const u32 = @as(
            [*]const u32,
            @ptrCast(view.words.ptr),
        )[0..view.words.len];
        transcript.mixU32s(canonical);
    }
}

/// Exact number of V2 public terms used by coefficient-lift admission.
pub fn nativePublicTermCounts(
    data: *const public_data_v2.PublicDataV2,
) Error!struct { memory: u64, merkle: u64 } {
    const view = try authenticatedView(data);
    const events = try data.eventCounts();
    var merkle: u64 = 3; // program, entry-continuation and exit-continuation roots
    merkle += nonzeroByteCount(&view, view.entry_snapshot);
    merkle += nonzeroByteCount(&view, view.exit_snapshot);
    merkle += @intFromBool(view.entry_snapshot.count == 0);
    merkle += @intFromBool(view.exit_snapshot.count == 0);
    return .{
        .memory = @intCast(events.register_memory + events.rw_memory),
        .merkle = merkle,
    };
}

/// Canonical compatibility projection used only by existing geometry, witness,
/// and commitment helpers.  It is never transcript-mixed and never supplies
/// public LogUp compensation in a V2 proof.
pub fn canonicalCorePublicData(
    data: *const public_data_v2.PublicDataV2,
) Error!public_data_v1.PublicData {
    const metadata = try data.metadata();
    const cycle_count = metadata.global_cycle_end - metadata.global_cycle_start;
    const completion: ?public_data_v1.Completion = if (metadata.completion) |value|
        .{
            .kind = @enumFromInt(@intFromEnum(value.kind)),
            .address = value.address,
            .value = value.value,
            .clock = value.clock,
        }
    else
        null;

    return .{
        .initial_pc = metadata.entry_cpu.pc,
        .final_pc = metadata.exit_cpu.pc,
        .clock = cycle_count,
        .initial_regs = metadata.entry_cpu.registers,
        .final_regs = metadata.exit_cpu.registers,
        .reg_last_clock = metadata.exit_cpu.predecessor_clocks,
        .program_root = try scalarProgramRoot(metadata.program),
        .initial_rw_root = metadata.entry_continuation_root,
        .final_rw_root = metadata.exit_continuation_root,
        .completion = completion,
        .io_entries = .{
            .input_start = 0,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_words = &.{},
        },
    };
}

fn scalarProgramRoot(program: public_data_v2.Digest) Error!u32 {
    for (program[1..]) |word| if (word != 0)
        return error.NonScalarProgramRoot;
    return program[0];
}

fn authenticatedView(
    data: *const public_data_v2.PublicDataV2,
) Error!segment_v2.CanonicalWireViewV2 {
    const view = try segment_v2.authenticateCanonicalWire(data.words());
    if (!std.meta.eql(view.wire_id, data.wireId())) return error.SourceMutation;
    return view;
}

const SnapshotSide = enum { initial_word, final_word };

fn snapshotMatches(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    words: []const @import("../runner/memory_state.zig").WordState,
    comptime side: SnapshotSide,
) bool {
    var section_at: usize = 0;
    for (words) |word| {
        const value = @field(word, @tagName(side));
        if (value == 0) continue;
        if (section_at == section.count) return false;
        const entry = view.sparseEntry(section, section_at);
        if (entry.address != word.addr or entry.value != value) return false;
        section_at += 1;
    }
    return section_at == section.count;
}

fn clockSectionMatches(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    clocks: []const runner_result.MemoryAccessClock,
) bool {
    if (section.count != clocks.len) return false;
    for (clocks, 0..) |clock, index| {
        const entry = view.clockEntry(section, index);
        if (entry.address != clock.addr or entry.clock != clock.clock) return false;
    }
    return true;
}

fn addContinuationTreeCompensation(
    sum: *QM31,
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    root: u32,
    relation: *const relation_challenges.RelationElements(4),
) Error!void {
    if (section.count == 0) {
        try subtractMerkleInverse(sum, relation, .{ 0, 0, root, root });
        return;
    }
    for (0..section.count) |index| {
        const entry = view.sparseEntry(section, index);
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const value: u8 = @truncate(entry.value >> shift);
            if (value == 0) continue;
            try subtractMerkleInverse(sum, relation, .{
                entry.address + @as(u32, @intCast(limb)),
                sparse_merkle.LEAF_DEPTH,
                value,
                root,
            });
        }
    }
}

fn subtractMerkleInverse(
    sum: *QM31,
    relation: *const relation_challenges.RelationElements(4),
    tuple: [4]u32,
) Error!void {
    const denominator = relation.combineBase(.{
        base(tuple[0]),
        base(tuple[1]),
        base(tuple[2]),
        base(tuple[3]),
    });
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    sum.* = sum.sub(inverse);
}

fn nonzeroByteCount(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
) u64 {
    var result: u64 = 0;
    for (0..section.count) |index| {
        const entry = view.sparseEntry(section, index);
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const value: u8 = @truncate(entry.value >> shift);
            result += @intFromBool(value != 0);
        }
    }
    return result;
}

fn base(value: anytype) M31 {
    return M31.fromU64(@as(u64, value));
}

fn publicDataProjectionEql(
    actual: *const public_data_v1.PublicData,
    expected: *const public_data_v1.PublicData,
) bool {
    return actual.initial_pc == expected.initial_pc and
        actual.final_pc == expected.final_pc and
        actual.clock == expected.clock and
        std.mem.eql(u32, &actual.initial_regs, &expected.initial_regs) and
        std.mem.eql(u32, &actual.final_regs, &expected.final_regs) and
        std.mem.eql(u32, &actual.reg_last_clock, &expected.reg_last_clock) and
        actual.program_root == expected.program_root and
        actual.initial_rw_root == expected.initial_rw_root and
        actual.final_rw_root == expected.final_rw_root and
        std.meta.eql(actual.completion, expected.completion) and
        actual.io_entries.input_start == 0 and
        actual.io_entries.input_len == 0 and
        actual.io_entries.input_words.len == 0 and
        actual.io_entries.output_len == 0 and
        actual.io_entries.output_len_addr == 0 and
        actual.io_entries.output_data_addr == 0 and
        actual.io_entries.output_words.len == 0;
}

/// Recomputes the native V2 statement authority from the authenticated wire
/// and the exact verifier-owned rows-10--18 component geometry.  Recursive
/// authorities use this function instead of trusting the receipt's defensive
/// identity seal.
pub fn authorityIdentityFromGeometry(
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!channel.Digest {
    if (component_descs.len > statement_v1.MAX_COMPONENTS or
        infra_descs.len > statement_v1.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidComponentGeometry;
    }
    const core_public = try canonicalCorePublicData(data);
    var hash = channel.CanonicalWordHasher.init(AUTHORITY_ID_DOMAIN);
    updateScalars(&hash, &.{
        FORMAT_VERSION,
        SCHEMA_VERSION,
        @as(u32, @intCast(component_descs.len)),
        @as(u32, @intCast(infra_descs.len)),
        core_public.initial_pc,
        core_public.final_pc,
        core_public.clock,
    });
    updateDigest(&hash, data.wireId());
    for (component_descs) |desc| {
        updateScalars(&hash, &.{
            @intFromEnum(desc.family),
            desc.log_size,
            desc.n_rows,
            desc.n_columns,
        });
    }
    for (infra_descs) |desc| {
        updateScalars(&hash, &.{
            @intFromEnum(desc.kind),
            desc.log_size,
            desc.n_rows,
            desc.n_columns,
        });
    }
    return hash.finalize();
}

fn relationContextIdentity(
    relations: *const relation_challenges.Relations,
) channel.Digest {
    var draws: [relation_challenges.DRAW_COUNT]QM31 = undefined;
    relations.writeDraws(&draws) catch unreachable;
    var hash = channel.CanonicalWordHasher.init(RELATION_CONTEXT_ID_DOMAIN);
    updateScalars(&hash, &.{
        FORMAT_VERSION,
        SCHEMA_VERSION,
        relation_challenges.RELATION_COUNT,
        relation_challenges.DRAW_COUNT,
    });
    for (draws) |value| updateQm31(&hash, value);
    return hash.finalize();
}

fn verifiedReceiptIdentity(receipt: *const VerifiedReceipt) channel.Digest {
    var hash = channel.CanonicalWordHasher.init(RECEIPT_ID_DOMAIN);
    updateScalars(&hash, &.{
        receipt.format_version,
        receipt.schema_version,
        receipt.segment_index,
        receipt.segment_count,
        receipt.global_cycle_start,
        receipt.global_cycle_end,
        @intFromBool(receipt.is_first),
    });
    updateScalars(&hash, &.{@intFromBool(receipt.is_final)});
    updateDigest(&hash, receipt.authority_id);
    updateDigest(&hash, receipt.wire_id);
    updateDigest(&hash, receipt.session_id);
    updateDigest(&hash, receipt.job_id);
    updateDigest(&hash, receipt.position_id);
    updateDigest(&hash, receipt.lineage_id);
    return hash.finalize();
}

fn nativeSumsIdentity(publication: *const NativePublicSums) channel.Digest {
    var hash = channel.CanonicalWordHasher.init(NATIVE_SUMS_ID_DOMAIN);
    updateScalars(&hash, &.{
        publication.format_version,
        publication.schema_version,
    });
    updateDigest(&hash, publication.wire_id);
    updateDigest(&hash, publication.relation_context_id);
    updateQm31(&hash, publication.sums.registers_state);
    updateQm31(&hash, publication.sums.memory_access);
    updateQm31(&hash, publication.sums.program_access);
    updateQm31(&hash, publication.sums.merkle);
    updateQm31(&hash, publication.total);
    return hash.finalize();
}

fn updateScalars(
    hash: *channel.CanonicalWordHasher,
    values: []const u32,
) void {
    var words: [14]M31 = undefined;
    std.debug.assert(values.len * 2 <= words.len);
    for (values, 0..) |value, index| {
        words[2 * index] = M31.fromCanonical(value & 0xffff);
        words[2 * index + 1] = M31.fromCanonical(value >> 16);
    }
    hash.update(words[0 .. values.len * 2]);
}

fn updateDigest(
    hash: *channel.CanonicalWordHasher,
    digest: channel.Digest,
) void {
    var words: [channel.RATE]M31 = undefined;
    for (digest, &words) |value, *word| word.* = M31.fromCanonical(value);
    hash.update(&words);
}

fn updateQm31(hash: *channel.CanonicalWordHasher, value: QM31) void {
    const words = value.toM31Array();
    hash.update(&words);
}

comptime {
    if (FORMAT_VERSION == public_data_v1.STATEMENT_TRANSCRIPT_VERSION or
        FORMAT_VERSION != public_data_v2.STATEMENT_TRANSCRIPT_VERSION)
    {
        @compileError("native segment statement version drifted");
    }
}
