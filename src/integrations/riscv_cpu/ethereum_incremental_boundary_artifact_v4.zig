//! Canonical custody for a full-state incremental memory transition.
//!
//! STWIMT04 embeds one canonical STWIMT02 transition and adds the exact entry
//! clock aligned with each retained touched word.  The entry clocks are
//! derived from an authenticated SegmentV2 public wire at creation time; they
//! are not caller-selected.  Cold validation re-authenticates that wire,
//! reconstructs `WordBoundarySourceV4`, derives every role/public link from a
//! `SegmentPublicAuthorityV4`, and requires the reconstructed inventory to be
//! byte-for-byte/order-for-order equivalent to the embedded V2 transition.
//!
//! This is transport and diagnostic authority only.  It serializes neither a
//! role bit nor a verifier-owned fresh capability, and it does not admit a
//! proof or activate the incremental native profile.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const access_clock = frontend.access_clock;
const public_data_v2 = frontend.air.public_data_v2;
const m31 = @import("stwo_core").fields.m31;
const authority_v2 = @import("ethereum_incremental_boundary_authority_v1.zig");
const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'M', 'T', '0', '4' };
pub const CONTENT_DOMAIN =
    "stwo.ethereum.incremental-boundary-artifact.v4\x00";
pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;

const public_wire_word_count: usize = 8;
const header_bytes: usize = 8 + 2 + 2 + 4 + 5 * 4 + 8 +
    public_wire_word_count * 4 + 32 + 8;
const seal_bytes: usize = 32;

pub const Limits = struct {
    max_bytes: usize,
    max_touched_words: usize,
    max_transition_bytes: usize,
    transition: artifact_v2.Limits,

    pub fn validate(self: Limits) !void {
        try self.transition.validate();
        if (self.max_bytes < header_bytes + seal_bytes or
            self.max_touched_words == 0 or
            self.max_transition_bytes < 1 or
            self.max_transition_bytes > self.transition.max_bytes)
        {
            return error.InvalidIncrementalBoundaryArtifactV4Limits;
        }
    }
};

pub const default_limits = Limits{
    .max_bytes = 768 * 1024 * 1024,
    .max_touched_words = 8 * 1024 * 1024,
    .max_transition_bytes = artifact_v2.default_limits.max_bytes,
    .transition = artifact_v2.default_limits,
};

comptime {
    if (@sizeOf(public_data_v2.Digest) != public_wire_word_count * @sizeOf(u32))
        @compileError("unexpected SegmentV2 public-wire identity width");
}

pub const OwnedArtifactV4 = struct {
    allocator: std.mem.Allocator,
    policy: boundary_v4.BoundaryPolicyV4,
    coordinate: boundary_v4.CoordinateV4,
    continuation_roots: boundary_v4.FullStateRootsV4,
    segment_public_wire_id: public_data_v2.Digest,
    entry_clocks: []u32,
    transition_v2: artifact_v2.OwnedArtifactV2,
    content_sha256: [32]u8,

    pub fn deinit(self: *OwnedArtifactV4) void {
        self.transition_v2.deinit();
        self.allocator.free(self.entry_clocks);
        self.* = undefined;
    }

    /// Rebuild both nested and outer canonical bytes.  This makes mutation of
    /// any decoded field detectable before it reaches cold reconstruction.
    pub fn validateCanonical(self: *const OwnedArtifactV4, limits: Limits) !void {
        const validated = try authority_v2
            .ValidatedIncrementalBoundaryAuthorityV1.init(
            &self.transition_v2.authority,
        );
        return validateCanonicalWithAuthority(self, &validated, limits);
    }
};

fn validateCanonicalWithAuthority(
    self: *const OwnedArtifactV4,
    validated: *const authority_v2.ValidatedIncrementalBoundaryAuthorityV1,
    limits: Limits,
) !void {
    const encoded = try encodeOwnedValidatedAlloc(
        self.allocator,
        self,
        validated,
        limits,
    );
    defer self.allocator.free(encoded);
    const retained = encoded[encoded.len - seal_bytes ..];
    if (!std.mem.eql(u8, retained, &self.content_sha256))
        return error.IncrementalBoundaryArtifactV4ContentMismatch;
}

/// Process-local reconstruction only.  The canonical transport never contains
/// this value and therefore cannot serialize roles or fresh verifier state.
pub const ColdReconstructionV4 = struct {
    allocator: std.mem.Allocator,
    coordinate: boundary_v4.CoordinateV4,
    segment_public_wire_id: public_data_v2.Digest,
    artifact_content_sha256: [32]u8,
    sources: []boundary_v4.WordBoundarySourceV4,
    transitions: []boundary_v4.OpenedTransitionV4,

    pub fn deinit(self: *ColdReconstructionV4) void {
        self.allocator.free(self.transitions);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};

/// Mint STWIMT04 only from an authenticated public wire.  Entry clocks and raw
/// word boundaries are read back from that wire and matched against STWIMT02.
pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    transition_v2_bytes: []const u8,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    limits: Limits,
) ![]u8 {
    try limits.validate();
    if (transition_v2_bytes.len > limits.max_transition_bytes)
        return error.IncrementalBoundaryArtifactV4ResourceLimitExceeded;

    var decoded_transition = try artifact_v2.decodeValidatedAlloc(
        allocator,
        transition_v2_bytes,
        limits.transition,
    );
    defer decoded_transition.artifact.deinit();
    const transition = &decoded_transition.artifact;
    const metadata = try segment_public_wire.metadata();
    const coordinate = boundary_v4.CoordinateV4{
        .segment_index = metadata.segment_index,
        .segment_count = metadata.segment_count,
    };
    const roots = boundary_v4.FullStateRootsV4{
        .entry = metadata.entry_continuation_root,
        .exit = metadata.exit_continuation_root,
    };
    const validated_authority = try boundary_v4
        .ValidatedSegmentPublicAuthorityV4.init(public_authority);
    try requireAuthorityBinding(
        coordinate,
        roots,
        metadata,
        validated_authority,
    );
    try requireTransitionBindingValidated(
        &decoded_transition.validated,
        coordinate,
        roots,
    );
    if (transition.authority.touched_words.len > limits.max_touched_words)
        return error.IncrementalBoundaryArtifactV4ResourceLimitExceeded;

    const entry_clocks = try allocator.alloc(
        u32,
        transition.authority.touched_words.len,
    );
    defer allocator.free(entry_clocks);
    try deriveRetainedEntryClocks(
        segment_public_wire,
        validated_authority,
        transition.authority.touched_words,
        entry_clocks,
    );
    const sources = try allocator.alloc(
        boundary_v4.WordBoundarySourceV4,
        transition.authority.touched_words.len,
    );
    defer allocator.free(sources);
    try reconstructExactInventory(
        segment_public_wire,
        validated_authority,
        transition.authority.touched_words,
        entry_clocks,
        sources,
    );
    try validated_authority.validateInventory(sources);
    return encodeFieldsAlloc(
        allocator,
        coordinate,
        roots,
        segment_public_wire.wireId(),
        entry_clocks,
        transition_v2_bytes,
        transition.content_sha256,
        limits,
    );
}

pub fn encodeOwnedAlloc(
    allocator: std.mem.Allocator,
    artifact: *const OwnedArtifactV4,
    limits: Limits,
) ![]u8 {
    const validated = try authority_v2
        .ValidatedIncrementalBoundaryAuthorityV1.init(
        &artifact.transition_v2.authority,
    );
    return encodeOwnedValidatedAlloc(
        allocator,
        artifact,
        &validated,
        limits,
    );
}

fn encodeOwnedValidatedAlloc(
    allocator: std.mem.Allocator,
    artifact: *const OwnedArtifactV4,
    validated: *const authority_v2.ValidatedIncrementalBoundaryAuthorityV1,
    limits: Limits,
) ![]u8 {
    try limits.validate();
    try requireOwnedShapeValidated(artifact, validated, limits);
    const nested = try artifact_v2.encodeValidatedAlloc(
        allocator,
        validated,
        limits.transition,
    );
    defer allocator.free(nested);
    const nested_content = nested[nested.len - seal_bytes ..];
    if (!std.mem.eql(
        u8,
        nested_content,
        &artifact.transition_v2.content_sha256,
    )) return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    return encodeFieldsAlloc(
        allocator,
        artifact.coordinate,
        artifact.continuation_roots,
        artifact.segment_public_wire_id,
        artifact.entry_clocks,
        nested,
        artifact.transition_v2.content_sha256,
        limits,
    );
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !OwnedArtifactV4 {
    try limits.validate();
    if (bytes.len < header_bytes + seal_bytes or bytes.len > limits.max_bytes)
        return error.InvalidIncrementalBoundaryArtifactV4Length;

    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, reader.readBytes(8), &MAGIC) or
        reader.readInt(u16) != FORMAT_VERSION or
        reader.readInt(u16) != SCHEMA_VERSION or
        reader.readInt(u32) !=
            @intFromEnum(boundary_v4.BoundaryPolicyV4.full_state_split_public_input_exit))
    {
        return error.InvalidIncrementalBoundaryArtifactV4Header;
    }
    const coordinate = boundary_v4.CoordinateV4{
        .segment_index = reader.readInt(u32),
        .segment_count = reader.readInt(u32),
    };
    const roots = boundary_v4.FullStateRootsV4{
        .entry = reader.readInt(u32),
        .exit = reader.readInt(u32),
    };
    const touched_count: usize = reader.readInt(u32);
    const transition_byte_count: usize = std.math.cast(
        usize,
        reader.readInt(u64),
    ) orelse return error.IncrementalBoundaryArtifactV4SizeOverflow;
    var wire_id: public_data_v2.Digest = undefined;
    for (&wire_id) |*word| word.* = reader.readInt(u32);
    const nested_content_sha256 = reader.readArray(32);
    if (!allZero(reader.readBytes(8)))
        return error.InvalidIncrementalBoundaryArtifactV4Header;

    const expected_size = try encodedSize(touched_count, transition_byte_count);
    if (reader.failed or expected_size != bytes.len or
        touched_count > limits.max_touched_words or
        transition_byte_count > limits.max_transition_bytes)
    {
        return error.IncrementalBoundaryArtifactV4ResourceLimitExceeded;
    }
    if (coordinate.segment_count == 0 or
        coordinate.segment_index >= coordinate.segment_count)
    {
        return error.InvalidIncrementalBoundaryArtifactV4Coordinate;
    }
    for (wire_id) |word| if (word >= m31.Modulus)
        return error.InvalidIncrementalBoundaryArtifactV4PublicWireIdentity;

    const clocks = try allocator.alloc(u32, touched_count);
    errdefer allocator.free(clocks);
    for (clocks) |*clock| clock.* = reader.readInt(u32);
    const nested_bytes = reader.readBytes(transition_byte_count);
    if (reader.failed or reader.at + seal_bytes != bytes.len)
        return error.InvalidIncrementalBoundaryArtifactV4Length;
    const expected_content = contentIdentity(bytes[0..reader.at]);
    const retained_content = reader.readArray(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected_content, &retained_content))
    {
        return error.IncrementalBoundaryArtifactV4ContentMismatch;
    }

    var decoded_transition = try artifact_v2.decodeValidatedAlloc(
        allocator,
        nested_bytes,
        limits.transition,
    );
    errdefer decoded_transition.artifact.deinit();
    const transition = &decoded_transition.artifact;
    if (!std.mem.eql(
        u8,
        &transition.content_sha256,
        &nested_content_sha256,
    )) return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    try requireTransitionBindingValidated(
        &decoded_transition.validated,
        coordinate,
        roots,
    );
    if (transition.authority.touched_words.len != clocks.len)
        return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    for (transition.authority.touched_words, clocks) |word, entry_clock| {
        if (entry_clock > word.final_clock or
            (entry_clock != 0 and !access_clock.isCanonical(entry_clock)))
        {
            return error.InvalidIncrementalBoundaryArtifactV4EntryClock;
        }
    }

    return .{
        .allocator = allocator,
        .policy = .full_state_split_public_input_exit,
        .coordinate = coordinate,
        .continuation_roots = roots,
        .segment_public_wire_id = wire_id,
        .entry_clocks = clocks,
        .transition_v2 = decoded_transition.artifact,
        .content_sha256 = retained_content,
    };
}

/// Coldly reconstruct the V4 boundary source and semantic transitions.  The
/// authenticated wire is the clock/value/order authority; V4 public authority
/// is the role/public-link authority.  Neither can substitute for the other.
pub fn coldReconstruct(
    allocator: std.mem.Allocator,
    artifact: *const OwnedArtifactV4,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    limits: Limits,
) !ColdReconstructionV4 {
    const validated_transition = try authority_v2
        .ValidatedIncrementalBoundaryAuthorityV1.init(
        &artifact.transition_v2.authority,
    );
    try validateCanonicalWithAuthority(
        artifact,
        &validated_transition,
        limits,
    );
    const validated_authority = try boundary_v4
        .ValidatedSegmentPublicAuthorityV4.init(public_authority);
    const metadata = try segment_public_wire.metadata();
    try requirePublicBinding(artifact, metadata, validated_authority);

    const touched = artifact.transition_v2.authority.touched_words;
    const sources = try allocator.alloc(
        boundary_v4.WordBoundarySourceV4,
        touched.len,
    );
    errdefer allocator.free(sources);
    try reconstructExactInventory(
        segment_public_wire,
        validated_authority,
        touched,
        artifact.entry_clocks,
        sources,
    );

    const transitions = try allocator.alloc(
        boundary_v4.OpenedTransitionV4,
        sources.len,
    );
    errdefer allocator.free(transitions);
    try validated_authority.writeOpenedTransitions(
        sources,
        transitions,
    );
    for (transitions, touched) |transition, word| {
        if (transition.source.word.addr != word.address or
            transition.merkle_words.entry != word.old_word or
            transition.merkle_words.exit != word.new_word or
            transition.source.word.final_clock != word.final_clock)
        {
            return error.IncrementalBoundaryArtifactV4TransitionMismatch;
        }
    }
    return .{
        .allocator = allocator,
        .coordinate = artifact.coordinate,
        .segment_public_wire_id = artifact.segment_public_wire_id,
        .artifact_content_sha256 = artifact.content_sha256,
        .sources = sources,
        .transitions = transitions,
    };
}

fn requireOwnedShape(artifact: *const OwnedArtifactV4, limits: Limits) !void {
    const validated = try authority_v2
        .ValidatedIncrementalBoundaryAuthorityV1.init(
        &artifact.transition_v2.authority,
    );
    return requireOwnedShapeValidated(artifact, &validated, limits);
}

fn requireOwnedShapeValidated(
    artifact: *const OwnedArtifactV4,
    validated: *const authority_v2.ValidatedIncrementalBoundaryAuthorityV1,
    limits: Limits,
) !void {
    if (artifact.policy != .full_state_split_public_input_exit)
        return error.InvalidIncrementalBoundaryArtifactV4Policy;
    if (artifact.entry_clocks.len > limits.max_touched_words)
        return error.IncrementalBoundaryArtifactV4ResourceLimitExceeded;
    if (artifact.coordinate.segment_count == 0 or
        artifact.coordinate.segment_index >= artifact.coordinate.segment_count)
    {
        return error.InvalidIncrementalBoundaryArtifactV4Coordinate;
    }
    for (artifact.segment_public_wire_id) |word| if (word >= m31.Modulus)
        return error.InvalidIncrementalBoundaryArtifactV4PublicWireIdentity;
    try requireTransitionBindingValidated(
        validated,
        artifact.coordinate,
        artifact.continuation_roots,
    );
    if (artifact.entry_clocks.len !=
        artifact.transition_v2.authority.touched_words.len)
    {
        return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    }
    for (
        artifact.transition_v2.authority.touched_words,
        artifact.entry_clocks,
    ) |word, clock| {
        if (clock > word.final_clock or
            (clock != 0 and !access_clock.isCanonical(clock)))
        {
            return error.InvalidIncrementalBoundaryArtifactV4EntryClock;
        }
    }
}

fn requireTransitionBinding(
    transition: *const artifact_v2.OwnedArtifactV2,
    coordinate: boundary_v4.CoordinateV4,
    roots: boundary_v4.FullStateRootsV4,
) !void {
    const validated = try authority_v2
        .ValidatedIncrementalBoundaryAuthorityV1.init(&transition.authority);
    return requireTransitionBindingValidated(&validated, coordinate, roots);
}

fn requireTransitionBindingValidated(
    validated: *const authority_v2.ValidatedIncrementalBoundaryAuthorityV1,
    coordinate: boundary_v4.CoordinateV4,
    roots: boundary_v4.FullStateRootsV4,
) !void {
    const authority = validated.authority();
    if (authority.segment_index != coordinate.segment_index or
        authority.entry_root != roots.entry or
        authority.exit_root != roots.exit)
    {
        return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    }
}

fn requirePublicBinding(
    artifact: *const OwnedArtifactV4,
    metadata: public_data_v2.Metadata,
    validated: boundary_v4.ValidatedSegmentPublicAuthorityV4,
) !void {
    const authority = validated.authority();
    if (!std.meta.eql(artifact.segment_public_wire_id, metadata.wire_id) or
        artifact.coordinate.segment_index != metadata.segment_index or
        artifact.coordinate.segment_count != metadata.segment_count or
        artifact.continuation_roots.entry != metadata.entry_continuation_root or
        artifact.continuation_roots.exit != metadata.exit_continuation_root or
        !std.meta.eql(artifact.coordinate, authority.coordinate) or
        !std.meta.eql(artifact.continuation_roots, authority.continuation_roots) or
        authority.segment_role.is_first != metadata.is_first or
        authority.segment_role.is_last != metadata.is_final)
    {
        return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
    }
    try requireAuthorityBinding(
        artifact.coordinate,
        artifact.continuation_roots,
        metadata,
        validated,
    );
}

fn requireAuthorityBinding(
    coordinate: boundary_v4.CoordinateV4,
    roots: boundary_v4.FullStateRootsV4,
    metadata: public_data_v2.Metadata,
    validated: boundary_v4.ValidatedSegmentPublicAuthorityV4,
) !void {
    const authority = validated.authority();
    if (!std.meta.eql(coordinate, authority.coordinate) or
        !std.meta.eql(roots, authority.continuation_roots) or
        authority.segment_role.is_first != metadata.is_first or
        authority.segment_role.is_last != metadata.is_final)
    {
        return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
    }
    const data = authority.public_data;
    const cycle_count = metadata.global_cycle_end - metadata.global_cycle_start;
    if (data.initial_pc != metadata.entry_cpu.pc or
        data.final_pc != metadata.exit_cpu.pc or
        data.clock != cycle_count or
        !std.meta.eql(data.initial_regs, metadata.entry_cpu.registers) or
        !std.meta.eql(data.final_regs, metadata.exit_cpu.registers) or
        !std.meta.eql(
            data.reg_last_clock,
            metadata.exit_cpu.predecessor_clocks,
        ))
    {
        return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
    }
    const program_root = data.program_root orelse
        return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
    if (metadata.program[0] != program_root)
        return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
    for (metadata.program[1..]) |word| if (word != 0)
        return error.IncrementalBoundaryArtifactV4NonScalarProgram;
    if (metadata.is_final) {
        const expected = metadata.completion orelse
            return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
        const retained = data.completion orelse
            return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
        if (@intFromEnum(retained.kind) != @intFromEnum(expected.kind) or
            retained.address != expected.address or
            retained.value != expected.value or
            retained.clock != expected.clock)
        {
            return error.IncrementalBoundaryArtifactV4PublicWireMismatch;
        }
    }
}

fn deriveRetainedEntryClocks(
    wire: *const public_data_v2.PublicDataV2,
    authority: boundary_v4.ValidatedSegmentPublicAuthorityV4,
    touched: []const authority_v2.TouchedWordV1,
    destination: []u32,
) !void {
    if (destination.len != touched.len)
        return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    var cursor = try wire.eventCursor();
    const metadata = cursor.metadata();
    const wire_boundary_count = cursor.counts.memory_address_count;
    var touched_at: usize = 0;
    var boundary_at: usize = 0;
    var last_boundary: ?RwBoundary = null;
    while (try nextRwBoundary(&cursor)) |boundary| : (boundary_at += 1) {
        last_boundary = boundary;
        if (touched_at == touched.len) continue;
        while (touched_at < touched.len and
            touched[touched_at].address < boundary.address)
        {
            const sparse_word = touched[touched_at];
            _ = requireSparseZeroPublicInput(authority, sparse_word) catch {
                reportEntryClockInventoryMismatch(
                    .transition_address_before_wire,
                    metadata.segment_index,
                    touched_at,
                    touched.len,
                    sparse_word,
                    boundary_at,
                    wire_boundary_count,
                    boundary,
                );
                return error.IncrementalBoundaryArtifactV4InventoryMismatch;
            };
            destination[touched_at] = 0;
            touched_at += 1;
        }
        if (touched_at == touched.len) continue;
        const word = touched[touched_at];
        if (word.address != boundary.address) continue;
        try requireRawWord(word, boundary);
        destination[touched_at] = boundary.entry_clock;
        touched_at += 1;
    }
    while (touched_at < touched.len) : (touched_at += 1) {
        const sparse_word = touched[touched_at];
        _ = requireSparseZeroPublicInput(authority, sparse_word) catch {
            reportEntryClockInventoryMismatch(
                .wire_exhausted,
                metadata.segment_index,
                touched_at,
                touched.len,
                sparse_word,
                boundary_at,
                wire_boundary_count,
                last_boundary,
            );
            return error.IncrementalBoundaryArtifactV4InventoryMismatch;
        };
        destination[touched_at] = 0;
    }
}

const EntryClockInventoryMismatchReason = enum {
    transition_address_before_wire,
    wire_exhausted,
};

/// Failure-only custody diagnostic.  It does not classify, normalize, or
/// change the accepted inventory; the same mismatch is returned immediately
/// after this exact transition-versus-public-wire context is emitted.
fn reportEntryClockInventoryMismatch(
    reason: EntryClockInventoryMismatchReason,
    segment_index: u32,
    touched_index: usize,
    touched_count: usize,
    touched_word: authority_v2.TouchedWordV1,
    wire_boundary_index: usize,
    wire_boundary_count: usize,
    wire_boundary: ?RwBoundary,
) void {
    if (wire_boundary) |boundary| {
        std.debug.print(
            "incremental_boundary_artifact_v4_inventory_mismatch " ++
                "phase=derive_entry_clocks reason={s} segment_index={d} " ++
                "transition_index={d} transition_count={d} " ++
                "transition_address=0x{x:0>8} " ++
                "transition_old_word=0x{x:0>8} " ++
                "transition_new_word=0x{x:0>8} " ++
                "transition_final_clock={d} wire_index={d} wire_count={d} " ++
                "wire_address=0x{x:0>8} wire_entry_clock={d} " ++
                "wire_exit_clock={d} wire_entry_value=0x{x:0>8} " ++
                "wire_exit_value=0x{x:0>8}\n",
            .{
                @tagName(reason),
                segment_index,
                touched_index,
                touched_count,
                touched_word.address,
                touched_word.old_word,
                touched_word.new_word,
                touched_word.final_clock,
                wire_boundary_index,
                wire_boundary_count,
                boundary.address,
                boundary.entry_clock,
                boundary.exit_clock,
                boundary.entry_value,
                boundary.exit_value,
            },
        );
    } else {
        std.debug.print(
            "incremental_boundary_artifact_v4_inventory_mismatch " ++
                "phase=derive_entry_clocks reason={s} segment_index={d} " ++
                "transition_index={d} transition_count={d} " ++
                "transition_address=0x{x:0>8} " ++
                "transition_old_word=0x{x:0>8} " ++
                "transition_new_word=0x{x:0>8} " ++
                "transition_final_clock={d} wire_index={d} wire_count={d} " ++
                "wire_boundary=none\n",
            .{
                @tagName(reason),
                segment_index,
                touched_index,
                touched_count,
                touched_word.address,
                touched_word.old_word,
                touched_word.new_word,
                touched_word.final_clock,
                wire_boundary_index,
                wire_boundary_count,
            },
        );
    }
}

fn reconstructExactInventory(
    wire: *const public_data_v2.PublicDataV2,
    authority: boundary_v4.ValidatedSegmentPublicAuthorityV4,
    touched: []const authority_v2.TouchedWordV1,
    entry_clocks: []const u32,
    destination: []boundary_v4.WordBoundarySourceV4,
) !void {
    if (touched.len != entry_clocks.len or destination.len != touched.len)
        return error.IncrementalBoundaryArtifactV4TransitionMismatch;
    var cursor = try wire.eventCursor();
    var touched_at: usize = 0;
    var pending = try nextRwBoundary(&cursor);
    while (touched_at < touched.len) {
        const word = touched[touched_at];
        while (pending != null and pending.?.address < word.address)
            pending = try nextRwBoundary(&cursor);
        if (pending == null or word.address < pending.?.address) {
            const role = try requireSparseZeroPublicInput(authority, word);
            if (entry_clocks[touched_at] != 0)
                return error.IncrementalBoundaryArtifactV4EntryClockMismatch;
            destination[touched_at] = sourceFor(word, 0, role);
            touched_at += 1;
            continue;
        }
        const boundary = pending.?;
        const role = try authority.expectedRole(boundary.address);
        const role_selected = role.is_public_input or
            role.is_public_output or role.is_public_completion;
        const should_open = boundary.entry_clock != boundary.exit_clock or
            role_selected;
        if (!should_open) {
            return error.IncrementalBoundaryArtifactV4InventoryMismatch;
        }
        if (word.address != boundary.address) {
            return error.IncrementalBoundaryArtifactV4InventoryMismatch;
        }
        try requireRawWord(word, boundary);
        if (entry_clocks[touched_at] != boundary.entry_clock)
            return error.IncrementalBoundaryArtifactV4EntryClockMismatch;
        destination[touched_at] = sourceFor(word, boundary.entry_clock, role);
        touched_at += 1;
        pending = try nextRwBoundary(&cursor);
    }
}

fn sourceFor(
    word: authority_v2.TouchedWordV1,
    entry_clock: u32,
    role: frontend.runner.memory_state.WordRole,
) boundary_v4.WordBoundarySourceV4 {
    return .{
        .word = .{
            .addr = word.address,
            .initial_word = word.old_word,
            .final_word = word.new_word,
            .final_clock = word.final_clock,
            .role = role,
        },
        .entry_clock = entry_clock,
    };
}

/// The SegmentV2 wire canonically omits exactly `(value=0,clock=0)`.  V4 may
/// bridge that sparse omission only when the independently reconstructed ABI
/// proves the address is an exact first-segment public-input word whose value
/// is also zero.  No output, completion, layout padding, or caller role bit is
/// accepted through this path.
fn requireSparseZeroPublicInput(
    authority: boundary_v4.ValidatedSegmentPublicAuthorityV4,
    word: authority_v2.TouchedWordV1,
) !frontend.runner.memory_state.WordRole {
    const input_value = authority.publicInputWord(word.address) orelse
        return error.IncrementalBoundaryArtifactV4InventoryMismatch;
    if (input_value != 0 or word.old_word != 0 or word.new_word != 0 or
        word.final_clock != 0)
    {
        return error.IncrementalBoundaryArtifactV4InventoryMismatch;
    }
    const role = try authority.expectedRole(word.address);
    if (!role.is_public_input or role.is_public_output or
        role.is_public_completion)
    {
        return error.IncrementalBoundaryArtifactV4InventoryMismatch;
    }
    return role;
}

const RwBoundary = struct {
    address: u32,
    entry_clock: u32,
    exit_clock: u32,
    entry_value: u32,
    exit_value: u32,
};

fn nextRwBoundary(cursor: *public_data_v2.EventCursor) !?RwBoundary {
    while (cursor.next()) |event| switch (event) {
        .registers_state => {},
        .memory_access => |entry| {
            if (entry.address_space == 0) continue;
            if (entry.direction != .consume)
                return error.InvalidIncrementalBoundaryArtifactV4PublicWireOrder;
            const next = cursor.next() orelse
                return error.InvalidIncrementalBoundaryArtifactV4PublicWireOrder;
            const exit = switch (next) {
                .memory_access => |value| value,
                else => return error.InvalidIncrementalBoundaryArtifactV4PublicWireOrder,
            };
            if (exit.address_space != 1 or exit.direction != .produce or
                exit.address != entry.address)
            {
                return error.InvalidIncrementalBoundaryArtifactV4PublicWireOrder;
            }
            return .{
                .address = entry.address,
                .entry_clock = entry.predecessor_clock,
                .exit_clock = exit.predecessor_clock,
                .entry_value = entry.value,
                .exit_value = exit.value,
            };
        },
    };
    return null;
}

fn requireRawWord(word: authority_v2.TouchedWordV1, boundary: RwBoundary) !void {
    if (word.address != boundary.address or
        word.old_word != boundary.entry_value or
        word.new_word != boundary.exit_value or
        word.final_clock != boundary.exit_clock)
    {
        return error.IncrementalBoundaryArtifactV4RawWordMismatch;
    }
}

fn encodeFieldsAlloc(
    allocator: std.mem.Allocator,
    coordinate: boundary_v4.CoordinateV4,
    roots: boundary_v4.FullStateRootsV4,
    wire_id: public_data_v2.Digest,
    clocks: []const u32,
    nested: []const u8,
    nested_content_sha256: [32]u8,
    limits: Limits,
) ![]u8 {
    if (clocks.len > limits.max_touched_words or
        nested.len > limits.max_transition_bytes)
    {
        return error.IncrementalBoundaryArtifactV4ResourceLimitExceeded;
    }
    const size = try encodedSize(clocks.len, nested.len);
    if (size > limits.max_bytes)
        return error.IncrementalBoundaryArtifactV4ResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writer.writeBytes(&MAGIC);
    writer.writeInt(u16, FORMAT_VERSION);
    writer.writeInt(u16, SCHEMA_VERSION);
    writer.writeInt(
        u32,
        @intFromEnum(boundary_v4.BoundaryPolicyV4.full_state_split_public_input_exit),
    );
    writer.writeInt(u32, coordinate.segment_index);
    writer.writeInt(u32, coordinate.segment_count);
    writer.writeInt(u32, roots.entry);
    writer.writeInt(u32, roots.exit);
    writer.writeInt(u32, try countU32(clocks.len));
    writer.writeInt(u64, try countU64(nested.len));
    for (wire_id) |word| writer.writeInt(u32, word);
    writer.writeBytes(&nested_content_sha256);
    writer.writeBytes(&([_]u8{0} ** 8));
    for (clocks) |clock| writer.writeInt(u32, clock);
    writer.writeBytes(nested);
    if (writer.at + seal_bytes != bytes.len)
        return error.InvalidIncrementalBoundaryArtifactV4Length;
    const seal = contentIdentity(bytes[0..writer.at]);
    writer.writeBytes(&seal);
    if (writer.at != bytes.len)
        return error.InvalidIncrementalBoundaryArtifactV4Length;
    return bytes;
}

fn encodedSize(touched_count: usize, transition_bytes: usize) !usize {
    const clocks = std.math.mul(usize, touched_count, 4) catch
        return error.IncrementalBoundaryArtifactV4SizeOverflow;
    const with_clocks = std.math.add(usize, header_bytes, clocks) catch
        return error.IncrementalBoundaryArtifactV4SizeOverflow;
    const with_transition = std.math.add(
        usize,
        with_clocks,
        transition_bytes,
    ) catch return error.IncrementalBoundaryArtifactV4SizeOverflow;
    return std.math.add(usize, with_transition, seal_bytes) catch
        error.IncrementalBoundaryArtifactV4SizeOverflow;
}

fn countU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse
        error.IncrementalBoundaryArtifactV4SizeOverflow;
}

fn countU64(value: usize) !u64 {
    return std.math.cast(u64, value) orelse
        error.IncrementalBoundaryArtifactV4SizeOverflow;
}

fn contentIdentity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(bytes);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn writeBytes(self: *Writer, values: []const u8) void {
        @memcpy(self.bytes[self.at..][0..values.len], values);
        self.at += values.len;
    }

    fn writeInt(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.at..][0..@sizeOf(T)], value, .little);
        self.at += @sizeOf(T);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    failed: bool = false,

    fn take(self: *Reader, count: usize) []const u8 {
        const end = std.math.add(usize, self.at, count) catch {
            self.failed = true;
            return &.{};
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return &.{};
        }
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }

    fn readBytes(self: *Reader, count: usize) []const u8 {
        return self.take(count);
    }

    fn readArray(self: *Reader, comptime count: usize) [count]u8 {
        var result = [_]u8{0} ** count;
        const value = self.take(count);
        if (value.len == count) @memcpy(&result, value);
        return result;
    }

    fn readInt(self: *Reader, comptime T: type) T {
        const value = self.take(@sizeOf(T));
        return if (value.len == @sizeOf(T))
            std.mem.readInt(T, value[0..@sizeOf(T)], .little)
        else
            0;
    }
};

pub const testing = struct {
    pub const HEADER_BYTES = header_bytes;
    pub const POLICY_OFFSET: usize = 12;
    pub const SEGMENT_INDEX_OFFSET: usize = 16;
    pub const SEGMENT_COUNT_OFFSET: usize = 20;
    pub const ENTRY_ROOT_OFFSET: usize = 24;
    pub const EXIT_ROOT_OFFSET: usize = 28;
    pub const TOUCHED_COUNT_OFFSET: usize = 32;
    pub const PUBLIC_WIRE_ID_OFFSET: usize = 44;
    pub const RESERVED_OFFSET: usize = 108;
    pub const ENTRY_CLOCKS_OFFSET: usize = header_bytes;

    pub fn reseal(bytes: []u8) !void {
        if (bytes.len < header_bytes + seal_bytes)
            return error.InvalidIncrementalBoundaryArtifactV4Length;
        const at = bytes.len - seal_bytes;
        const seal = contentIdentity(bytes[0..at]);
        @memcpy(bytes[at..], &seal);
    }
};
