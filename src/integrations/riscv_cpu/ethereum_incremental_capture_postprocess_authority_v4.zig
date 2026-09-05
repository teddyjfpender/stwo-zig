//! Cold authority adapter from retained raw capture to VM-free V4 mint input.
//!
//! Every call reopens create-only STWEMT01/STWIPW04, authenticates the public
//! wire with retained STWESG31 roots (never recomputing the sparse Poseidon
//! root), binds the local projection/journal coordinate, and reconstructs the
//! exact full-state/public-role inventory.  No VM continuation is restored.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const boundary_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const postprocess = @import("ethereum_incremental_capture_postprocess_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const raw_transport =
    @import("ethereum_incremental_capture_raw_transport_v4.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");

const memory_state = frontend.runner.memory_state;
const minimal = frontend.runner.minimal_trace;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const segment_v2 = frontend.recursion.segment_statement_v2;
const source_wire = support.source_wire;

pub const PRODUCTION_ACTIVE = false;
pub const VM_REEXECUTION_REQUIRED = false;
pub const RETAINED_ROOT_REUSE_REQUIRED = true;

/// Exact sorted declared-program authority retained from the admitted ELF.
/// The slice is borrowed; its owner must outlive every derived completion.
pub const ProgramSourceV4 = struct {
    words: []const minimal.ProgramWord,
    identity: [32]u8,

    pub fn init(words: []const minimal.ProgramWord) !ProgramSourceV4 {
        const source = try minimal.SliceProgram.init(words);
        const result = ProgramSourceV4{
            .words = words,
            .identity = source.identity,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: ProgramSourceV4) !void {
        const source = try minimal.SliceProgram.init(self.words);
        if (!std.mem.eql(u8, &self.identity, &source.identity))
            return error.IncrementalPostprocessProgramSourceMismatchV4;
    }

    pub fn fetch(self: ProgramSourceV4, address: u32) !u32 {
        try self.validate();
        return self.fetchUnchecked(address);
    }

    fn fetchUnchecked(self: ProgramSourceV4, address: u32) !u32 {
        var low: usize = 0;
        var high: usize = self.words.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.words[mid];
            if (candidate.address < address) {
                low = mid + 1;
            } else if (candidate.address > address) {
                high = mid;
            } else {
                return candidate.word;
            }
        }
        return error.ProgramWordUnavailable;
    }
};

/// Journal/STWESG31-derived authorities passed to independent compact replay.
/// These values are deliberately retained outside the decoded STWEMT01 leaf:
/// the replay verifier must never treat the tape as its own expected source.
pub const ReplayAuthorityV4 = struct {
    source: minimal.ethereum_types.SourceIdentityV1,
    entry_cpu_sha256: [32]u8,
    exit_cpu_sha256: [32]u8,
    completion: ?minimal.ethereum_types.CompletionV1,

    pub fn validate(self: ReplayAuthorityV4) !void {
        try self.source.validate();
        if (std.mem.allEqual(u8, &self.entry_cpu_sha256, 0) or
            std.mem.allEqual(u8, &self.exit_cpu_sha256, 0))
        {
            return error.InvalidIncrementalPostprocessReplayAuthorityV4;
        }
    }
};

/// Segment-role derivation used by both the cold constructor and replay
/// validation. Final SegmentV2 completion remains unchanged; only a nonfinal
/// absent completion is filled from the admitted ELF program word.
pub fn deriveRoleCompletionV4(
    program: ProgramSourceV4,
    segment_index: u32,
    segment_count: u32,
    final_pc: u32,
    retained: ?public_data.Completion,
) !public_data.Completion {
    try program.validate();
    if (segment_count < 2 or segment_index >= segment_count)
        return error.IncrementalPostprocessSegmentRoleMismatchV4;
    if (segment_index + 1 == segment_count) {
        const completion = retained orelse return error.MissingCompletion;
        if (completion.kind == .unretired_program_fetch)
            return error.IncrementalPostprocessSegmentRoleMismatchV4;
        return completion;
    }
    if (retained != null)
        return error.IncrementalPostprocessSegmentRoleMismatchV4;
    return public_data.Completion.unretiredProgramFetch(
        final_pc,
        try program.fetchUnchecked(final_pc),
    );
}

pub const AuthorityV4 = struct {
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    root: []u8,
    execution: publication.ExecutionAuthorityV4,
    layout: memory_state.MemoryLayout,
    program_identity: [32]u8,
    program_words: []minimal.ProgramWord,

    pub fn init(
        allocator: std.mem.Allocator,
        retained: *const retained_mod.RetainedAuthorityV4,
        root_path: []const u8,
    ) !AuthorityV4 {
        const execution = try retained.executionAuthority();
        const root = try artifact_io.resolveAbsolute(allocator, root_path);
        errdefer allocator.free(root);
        const manifest_path = try publication.manifestPathAlloc(allocator, root);
        defer allocator.free(manifest_path);
        const public_manifest_path = try wire_publication.manifestPathAlloc(
            allocator,
            root,
        );
        defer allocator.free(public_manifest_path);
        try publication.requireAbsent(manifest_path);
        try publication.requireAbsent(public_manifest_path);

        const program = try programAuthority(allocator, retained.elf_bytes);
        return .{
            .allocator = allocator,
            .retained = retained,
            .root = root,
            .execution = execution,
            .layout = program.layout,
            .program_identity = program.identity,
            .program_words = program.words,
        };
    }

    pub fn deinit(self: *AuthorityV4) void {
        self.allocator.free(self.program_words);
        self.allocator.free(self.root);
        self.* = undefined;
    }

    pub fn openSegment(
        self: *const AuthorityV4,
        segment_index: u32,
    ) !OwnedMintInputV4 {
        return self.openSegmentWithAllocator(self.allocator, segment_index);
    }

    /// Segment-disjoint cold open for bounded parallel postprocessing. The
    /// returned owner retains `allocator`; callers must keep that allocator
    /// valid through `OwnedMintInputV4.deinit`.
    pub fn openSegmentWithAllocator(
        self: *const AuthorityV4,
        allocator: std.mem.Allocator,
        segment_index: u32,
    ) !OwnedMintInputV4 {
        if (segment_index >= self.retained.sources.len)
            return error.SegmentIndexMismatch;
        const retained_source = &self.retained.sources[segment_index];
        const compact_path = try publication.compactTapePathAlloc(
            allocator,
            self.root,
            segment_index,
        );
        defer allocator.free(compact_path);
        const compact_bytes = try artifact_io.readFileBounded(
            allocator,
            compact_path,
            minimal.ethereum_wire.MAX_ENCODED_BYTES,
        );
        defer allocator.free(compact_bytes);
        const wire_path = try wire_publication.wirePathAlloc(
            allocator,
            self.root,
            segment_index,
        );
        defer allocator.free(wire_path);
        const wire_bytes = try artifact_io.readFileBounded(
            allocator,
            wire_path,
            wire_publication.max_wire_bytes,
        );
        defer allocator.free(wire_bytes);
        return openCanonicalBytesWithProgram(
            allocator,
            self.execution,
            self.layout,
            .{ .words = self.program_words, .identity = self.program_identity },
            self.retained.input_bytes,
            self.retained.output_bytes,
            &retained_source.value,
            retained_source.identity,
            compact_bytes,
            wire_bytes,
        );
    }
};

pub const OwnedMintInputV4 = struct {
    allocator: std.mem.Allocator,
    compact: minimal.EthereumMinimalArtifactV1,
    wire: wire_publication.OwnedWireV4,
    role_public: OwnedRolePublicV4,
    touched_words: []boundary_v1.TouchedWordV1,
    initial_words: []boundary_v1.SparseWordV1,
    compact_identity: publication.ArtifactIdentityV4,
    wire_identity: publication.ArtifactIdentityV4,
    source_identity: publication.ArtifactIdentityV4,
    journal_record_sha256: [32]u8,
    layout: memory_state.MemoryLayout,
    segment_index: u32,
    segment_count: u32,
    program_source: ProgramSourceV4,
    replay_authority: ReplayAuthorityV4,
    owned_program_words: ?[]minimal.ProgramWord = null,

    /// Path-free stage-101 admission. Every byte slice is caller-owned and
    /// borrowed only for this transaction; the result owns all decoded state.
    /// The retained source is canonically re-encoded to mint its exact
    /// identity, and ELF/input/output bytes must reproduce `execution` before
    /// any compact or public-wire value is decoded.
    pub fn openCanonicalBytes(
        allocator: std.mem.Allocator,
        execution: publication.ExecutionAuthorityV4,
        elf_bytes: []const u8,
        input_bytes: []const u8,
        output_bytes: []const u8,
        retained_source: *const source_wire.Source,
        compact_bytes: []const u8,
        public_wire_bytes: []const u8,
    ) !OwnedMintInputV4 {
        try execution.validate();
        try retained_source.validate();
        if (!std.meta.eql(
            execution.elf,
            publication.ArtifactIdentityV4.fromBytes(elf_bytes),
        ) or !std.meta.eql(
            execution.input,
            publication.ArtifactIdentityV4.fromBytes(input_bytes),
        ) or !std.meta.eql(
            execution.expected_output,
            publication.ArtifactIdentityV4.fromBytes(output_bytes),
        ) or !std.mem.eql(
            u8,
            &execution.execution_profile_semantic_sha256,
            &frontend.isa.execution_profile.ethereum_semantic_digest,
        ) or retained_source.metadata.segment_count != execution.segment_count) {
            return error.IncrementalPostprocessCanonicalBytesMismatchV4;
        }
        var program = try programAuthority(allocator, elf_bytes);
        errdefer program.deinit(allocator);
        const source_bytes = try source_wire.encodeValue(retained_source);
        var result = try openCanonicalBytesWithProgram(
            allocator,
            execution,
            program.layout,
            program.source(),
            input_bytes,
            output_bytes,
            retained_source,
            publication.ArtifactIdentityV4.fromBytes(&source_bytes),
            compact_bytes,
            public_wire_bytes,
        );
        result.owned_program_words = program.words;
        program.words = &.{};
        return result;
    }

    pub fn deinit(self: *OwnedMintInputV4) void {
        if (self.owned_program_words) |words| self.allocator.free(words);
        self.allocator.free(self.initial_words);
        self.allocator.free(self.touched_words);
        self.role_public.deinit();
        self.wire.deinit();
        self.compact.deinit();
        self.* = undefined;
    }

    pub fn input(self: *const OwnedMintInputV4) postprocess.MintInputV4 {
        return .{
            .segment_index = self.segment_index,
            .compact_tape = self.compact_identity,
            .public_wire = self.wire_identity,
            .source = self.source_identity,
            .journal_record_sha256 = self.journal_record_sha256,
            .touched_words = self.touched_words,
            .segment_public_wire = &self.wire.data,
            .public_authority = self.publicAuthority(),
        };
    }

    pub fn publicAuthority(
        self: *const OwnedMintInputV4,
    ) boundary_v4.SegmentPublicAuthorityV4 {
        return .{
            .coordinate = .{
                .segment_index = self.segment_index,
                .segment_count = self.segment_count,
            },
            .segment_role = .{
                .is_first = self.segment_index == 0,
                .is_last = self.segment_index + 1 == self.segment_count,
            },
            .layout = self.layout,
            .public_data = &self.role_public.value,
            .continuation_roots = .{
                .entry = self.role_public.value.initial_rw_root.?,
                .exit = self.role_public.value.final_rw_root.?,
            },
        };
    }

    pub fn validate(
        self: *const OwnedMintInputV4,
        execution: publication.ExecutionAuthorityV4,
    ) !void {
        try self.compact.validate();
        try self.wire.validate();
        try self.role_public.value.validate();
        try self.replay_authority.validate();
        if (!std.meta.eql(
            self.compact.leaf.source,
            self.replay_authority.source,
        ) or !std.mem.eql(
            u8,
            &minimal.ethereumCpuIdentity(self.compact.leaf.entry_cpu),
            &self.replay_authority.entry_cpu_sha256,
        ) or !std.mem.eql(
            u8,
            &minimal.ethereumCpuIdentity(self.compact.leaf.exit_cpu),
            &self.replay_authority.exit_cpu_sha256,
        ) or !std.meta.eql(
            self.compact.leaf.completion,
            self.replay_authority.completion,
        )) return error.IncrementalPostprocessReplayAuthorityMismatchV4;
        if (!std.mem.eql(
            u8,
            &self.replay_authority.source.program,
            &self.program_source.identity,
        )) return error.IncrementalPostprocessProgramSourceMismatchV4;
        const native = try frontend.air.statement_v2.canonicalCorePublicData(
            &self.wire.data,
        );
        const expected_completion = try deriveRoleCompletionV4(
            self.program_source,
            self.segment_index,
            self.segment_count,
            native.final_pc,
            native.completion,
        );
        if (!std.meta.eql(
            self.role_public.value.completion,
            @as(?public_data.Completion, expected_completion),
        )) return error.IncrementalPostprocessProgramFetchMismatchV4;
        try self.input().validate(execution);
    }
};

const ProgramAuthorityV4 = struct {
    layout: memory_state.MemoryLayout,
    identity: [32]u8,
    words: []minimal.ProgramWord,

    fn source(self: *const ProgramAuthorityV4) ProgramSourceV4 {
        return .{ .words = self.words, .identity = self.identity };
    }

    fn deinit(self: *ProgramAuthorityV4, allocator: std.mem.Allocator) void {
        allocator.free(self.words);
        self.* = undefined;
    }
};

fn programAuthority(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
) !ProgramAuthorityV4 {
    var program_memory = try frontend.runner.Memory.initFallible(allocator);
    defer program_memory.deinit();
    const elf = try frontend.runner.elf_loader.loadElfForProfile(
        elf_bytes,
        &program_memory,
        .rv32im_zkvm_ethereum_v1,
    );
    const initialized = try program_memory.canonicalAlignedWordAddresses();
    var count: usize = 0;
    for (initialized) |address| count += @intFromBool(
        elf.memory_layout.isProgramAddr(address),
    );
    if (count == 0) return error.EmptyProgram;
    const words = try allocator.alloc(minimal.ProgramWord, count);
    errdefer allocator.free(words);
    var at: usize = 0;
    for (initialized) |address| {
        if (!elf.memory_layout.isProgramAddr(address)) continue;
        words[at] = .{ .address = address, .word = program_memory.readU32(address) };
        at += 1;
    }
    const program = try minimal.SliceProgram.init(words);
    return .{
        .layout = elf.memory_layout,
        .identity = program.identity,
        .words = words,
    };
}

fn openCanonicalBytesWithProgram(
    allocator: std.mem.Allocator,
    execution: publication.ExecutionAuthorityV4,
    layout: memory_state.MemoryLayout,
    program_source: ProgramSourceV4,
    input_bytes: []const u8,
    output_bytes: []const u8,
    retained_source: *const source_wire.Source,
    source_identity: publication.ArtifactIdentityV4,
    compact_bytes: []const u8,
    wire_bytes: []const u8,
) !OwnedMintInputV4 {
    try retained_source.validate();
    const segment_index = retained_source.metadata.segment_index;
    var compact = try minimal.decodeEthereumMinimalArtifactAlloc(
        allocator,
        compact_bytes,
    );
    errdefer compact.deinit();
    var wire = try wire_publication.decodeWireAllocAgainstRetainedMetadata(
        allocator,
        wire_bytes,
        &retained_source.metadata,
    );
    errdefer wire.deinit();
    const session_identity = try execution.sessionIdentity();
    _ = try raw_transport.validateWireAgainstRetainedMetadata(
        &wire.data,
        &retained_source.metadata,
        support.sessionDigest(session_identity),
    );
    const view = try segment_v2.authenticateCanonicalWireReusingRoots(
        wire.data.words(),
        snapshot(&retained_source.metadata.entry),
        snapshot(&retained_source.metadata.exit),
    );
    const full_words = try fullSnapshotWords(allocator, &view);
    defer allocator.free(full_words);
    const replay_authority = try validateCompact(
        &compact,
        &retained_source.metadata,
        layout,
        full_words,
        program_source.identity,
        publication.ArtifactIdentityV4.fromBytes(input_bytes).sha256,
        session_identity,
    );
    var role_public = try buildRolePublic(
        allocator,
        &wire.data,
        &view,
        layout,
        program_source,
        input_bytes,
        output_bytes,
    );
    errdefer role_public.deinit();
    const public_authority = boundary_v4.SegmentPublicAuthorityV4{
        .coordinate = .{
            .segment_index = segment_index,
            .segment_count = execution.segment_count,
        },
        .segment_role = .{
            .is_first = segment_index == 0,
            .is_last = segment_index + 1 == execution.segment_count,
        },
        .layout = layout,
        .public_data = &role_public.value,
        .continuation_roots = .{
            .entry = retained_source.metadata.entry.continuation_root,
            .exit = retained_source.metadata.exit.continuation_root,
        },
    };
    const validated_public = try boundary_v4.ValidatedSegmentPublicAuthorityV4
        .init(public_authority);
    const addresses = try openedAddresses(
        allocator,
        compact.boundary_words,
        validated_public,
    );
    defer allocator.free(addresses);
    const touched_words = try allocator.alloc(
        boundary_v1.TouchedWordV1,
        addresses.len,
    );
    errdefer allocator.free(touched_words);
    const sources = try allocator.alloc(
        boundary_v4.WordBoundarySourceV4,
        addresses.len,
    );
    defer allocator.free(sources);
    for (addresses, touched_words, sources) |address, *touched, *source| {
        const entry = sparseValue(&view, view.entry_snapshot, address);
        const exit = sparseValue(&view, view.exit_snapshot, address);
        const entry_clock = clockValue(&view, view.entry_memory_clocks, address);
        const exit_clock = clockValue(&view, view.exit_memory_clocks, address);
        touched.* = .{
            .address = address,
            .old_word = entry,
            .new_word = exit,
            .final_clock = exit_clock,
        };
        source.* = .{
            .word = .{
                .addr = address,
                .initial_word = entry,
                .final_word = exit,
                .final_clock = exit_clock,
                .role = try validated_public.expectedRole(address),
            },
            .entry_clock = entry_clock,
        };
    }
    try validated_public.validateInventory(sources);
    try requireCompactBoundary(compact.boundary_words, &view);
    const initial_words = if (segment_index == 0)
        try sparseWords(allocator, &view, view.entry_snapshot)
    else
        try allocator.alloc(boundary_v1.SparseWordV1, 0);
    errdefer allocator.free(initial_words);
    var result = OwnedMintInputV4{
        .allocator = allocator,
        .compact = compact,
        .wire = wire,
        .role_public = role_public,
        .touched_words = touched_words,
        .initial_words = initial_words,
        .compact_identity = publication.ArtifactIdentityV4.fromBytes(
            compact_bytes,
        ),
        .wire_identity = publication.ArtifactIdentityV4.fromBytes(wire_bytes),
        .source_identity = source_identity,
        .journal_record_sha256 = retained_source.journal_record_sha256,
        .layout = layout,
        .segment_index = segment_index,
        .segment_count = execution.segment_count,
        .program_source = program_source,
        .replay_authority = replay_authority,
    };
    try result.validate(execution);
    return result;
}

const OwnedRolePublicV4 = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,

    fn deinit(self: *OwnedRolePublicV4) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }
};

fn buildRolePublic(
    allocator: std.mem.Allocator,
    native: *const public_data_v2.PublicDataV2,
    view: *const segment_v2.CanonicalWireViewV2,
    layout: memory_state.MemoryLayout,
    program_source: ProgramSourceV4,
    retained_input: []const u8,
    retained_output: []const u8,
) !OwnedRolePublicV4 {
    const metadata = try native.metadata();
    const input_words = if (metadata.is_first)
        try public_data.packInputWords(allocator, retained_input)
    else
        try allocator.alloc(u32, 0);
    errdefer allocator.free(input_words);
    const output_words = if (metadata.is_final)
        try outputWords(allocator, view, layout, retained_output)
    else
        try allocator.alloc(public_data.OutputWord, 0);
    errdefer allocator.free(output_words);
    var value = try frontend.air.statement_v2.canonicalCorePublicData(native);
    value.completion = try deriveRoleCompletionV4(
        program_source,
        metadata.segment_index,
        metadata.segment_count,
        value.final_pc,
        value.completion,
    );
    value.io_entries = .{
        .input_start = layout.input_base,
        .input_len = if (metadata.is_first)
            std.math.cast(u32, retained_input.len) orelse
                return error.IncrementalPostprocessPublicInputTooLargeV4
        else
            0,
        .input_words = input_words,
        .output_len = if (metadata.is_final)
            std.math.cast(u32, retained_output.len) orelse
                return error.IncrementalPostprocessPublicOutputTooLargeV4
        else
            0,
        .output_len_addr = layout.output_len_addr,
        .output_data_addr = layout.output_data_addr,
        .output_words = output_words,
    };
    try value.validate();
    return .{
        .allocator = allocator,
        .input_words = input_words,
        .output_words = output_words,
        .value = value,
    };
}

fn outputWords(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
    layout: memory_state.MemoryLayout,
    retained: []const u8,
) ![]public_data.OutputWord {
    if (retained.len == 0) return allocator.alloc(public_data.OutputWord, 0);
    const data_count = std.math.divCeil(usize, retained.len, 4) catch
        return error.IncrementalPostprocessPublicOutputTooLargeV4;
    const result = try allocator.alloc(public_data.OutputWord, data_count + 1);
    errdefer allocator.free(result);
    result[0] = outputWord(view, layout.output_len_addr);
    for (result[1..], 0..) |*word, index| {
        const offset = std.math.mul(u32, @intCast(index), 4) catch
            return error.IncrementalPostprocessPublicOutputTooLargeV4;
        word.* = outputWord(
            view,
            std.math.add(u32, layout.output_data_addr, offset) catch
                return error.IncrementalPostprocessPublicOutputTooLargeV4,
        );
    }
    const retained_len = std.math.cast(u32, retained.len) orelse
        return error.IncrementalPostprocessPublicOutputTooLargeV4;
    if (result[0].value != retained_len)
        return error.IncrementalPostprocessPublicOutputMismatchV4;
    for (retained, 0..) |expected, index| {
        const actual: u8 = @truncate(
            result[1 + index / 4].value >> @intCast((index % 4) * 8),
        );
        if (actual != expected)
            return error.IncrementalPostprocessPublicOutputMismatchV4;
    }
    return result;
}

fn outputWord(
    view: *const segment_v2.CanonicalWireViewV2,
    address: u32,
) public_data.OutputWord {
    return .{
        .addr = address,
        .value = sparseValue(view, view.exit_snapshot, address),
        .clock = clockValue(view, view.exit_memory_clocks, address),
    };
}

fn validateCompact(
    compact: *const minimal.EthereumMinimalArtifactV1,
    retained: *const frontend.recursion.segment_leaf_local_authority_v3.MetadataV3,
    layout: memory_state.MemoryLayout,
    full_words: []memory_state.WordState,
    program_identity: [32]u8,
    input_identity: [32]u8,
    session_identity: [32]u8,
) !ReplayAuthorityV4 {
    const metadata = retained.*;
    const memory = memory_state.Snapshot{
        .layout = layout,
        .segment_role = .{
            .is_first = retained.segment_index == 0,
            .is_last = retained.segment_index + 1 == retained.segment_count,
        },
        .words = full_words,
    };
    const expected_entry = minimal.ethereum_capture.snapshotIdentity(
        memory,
        .entry,
    );
    const expected_exit = minimal.ethereum_capture.snapshotIdentity(
        memory,
        .exit,
    );
    const expected_first = std.math.add(u64, metadata.global_cycle_start, 1) catch
        return error.IncrementalPostprocessCompactMismatchV4;
    if (compact.leaf.segment_index != metadata.segment_index or
        compact.leaf.global_first_cycle != expected_first or
        compact.leaf.cycle_count != metadata.local_cycle_count or
        !std.mem.eql(u8, &compact.leaf.source.program, &program_identity) or
        !std.mem.eql(u8, &compact.leaf.source.input, &input_identity) or
        !std.mem.eql(u8, &compact.leaf.source.session, &session_identity) or
        !std.mem.eql(u8, &compact.leaf.source.entry_memory, &expected_entry) or
        !std.mem.eql(u8, &compact.leaf.source.exit_memory, &expected_exit) or
        !std.meta.eql(compact.leaf.entry_cpu, cpuFromMetadata(retained, .entry)) or
        !std.meta.eql(compact.leaf.exit_cpu, cpuFromMetadata(retained, .exit)) or
        !completionMatches(compact.leaf.completion, retained.completion))
    {
        return error.IncrementalPostprocessCompactMismatchV4;
    }
    const result = ReplayAuthorityV4{
        .source = .{
            .program = program_identity,
            .input = input_identity,
            .session = session_identity,
            .entry_memory = expected_entry,
            .exit_memory = expected_exit,
        },
        .entry_cpu_sha256 = minimal.ethereumCpuIdentity(
            cpuFromMetadata(retained, .entry),
        ),
        .exit_cpu_sha256 = minimal.ethereumCpuIdentity(
            cpuFromMetadata(retained, .exit),
        ),
        // SegmentV2 authenticates the four completion tuple fields. The
        // optional diagnostic exit code has no SegmentV2 representation, so
        // the already tuple-validated tape value is retained verbatim.
        .completion = compact.leaf.completion,
    };
    try result.validate();
    return result;
}

const Side = enum { entry, exit };

fn cpuFromMetadata(
    retained: *const frontend.recursion.segment_leaf_local_authority_v3.MetadataV3,
    side: Side,
) frontend.runner.Cpu {
    const base = frontend.recursion.span_statement.SpanStatement
        .fromCanonicalWords(&retained.base_statement_words) catch unreachable;
    const executed = switch (base.body) {
        .executed => |value| value,
        .empty => unreachable,
    };
    const state = if (side == .entry) executed.entry else executed.exit;
    return .{ .pc = state.pc, .regs = state.registers };
}

fn completionMatches(
    compact: ?minimal.ethereum_types.CompletionV1,
    retained: ?segment_v2.CompletionV2,
) bool {
    if ((compact == null) != (retained == null)) return false;
    if (compact) |left| {
        const right = retained.?;
        const kind: u8 = switch (right.kind) {
            .halt_flag => 1,
            .unretired_self_loop => 2,
        };
        return left.kind == kind and left.address == right.address and
            left.value == right.value and left.clock == right.clock;
    }
    return true;
}

fn fullSnapshotWords(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
) ![]memory_state.WordState {
    const capacity = std.math.add(
        usize,
        view.entry_snapshot.count,
        view.exit_snapshot.count,
    ) catch return error.IncrementalPostprocessInventoryTooLargeV4;
    var result: std.ArrayList(memory_state.WordState) = .empty;
    errdefer result.deinit(allocator);
    try result.ensureTotalCapacity(allocator, capacity);
    var left: usize = 0;
    var right: usize = 0;
    while (left < view.entry_snapshot.count or right < view.exit_snapshot.count) {
        const left_address: ?u32 = if (left < view.entry_snapshot.count)
            view.sparseEntry(view.entry_snapshot, left).address
        else
            null;
        const right_address: ?u32 = if (right < view.exit_snapshot.count)
            view.sparseEntry(view.exit_snapshot, right).address
        else
            null;
        const address = if (left_address == null)
            right_address.?
        else if (right_address == null)
            left_address.?
        else
            @min(left_address.?, right_address.?);
        result.appendAssumeCapacity(.{
            .addr = address,
            .initial_word = sparseValue(view, view.entry_snapshot, address),
            .final_word = sparseValue(view, view.exit_snapshot, address),
            .final_clock = clockValue(view, view.exit_memory_clocks, address),
        });
        if (left_address == address) left += 1;
        if (right_address == address) right += 1;
    }
    return result.toOwnedSlice(allocator);
}

fn openedAddresses(
    allocator: std.mem.Allocator,
    replay: []const minimal.BoundaryWord,
    public: boundary_v4.ValidatedSegmentPublicAuthorityV4,
) ![]u32 {
    var values: std.ArrayList(u32) = .empty;
    errdefer values.deinit(allocator);
    const authority = public.authority();
    try values.ensureTotalCapacity(
        allocator,
        replay.len + authority.public_data.io_entries.input_words.len +
            authority.public_data.io_entries.output_words.len + 1,
    );
    for (replay) |word| values.appendAssumeCapacity(word.address);
    if (authority.segment_role.is_first) {
        for (authority.public_data.io_entries.input_words, 0..) |_, index|
            values.appendAssumeCapacity(
                try authority.public_data.io_entries.inputWordAddress(index),
            );
    }
    if (authority.segment_role.is_last) {
        for (authority.public_data.io_entries.output_words) |word|
            values.appendAssumeCapacity(word.addr);
        if (authority.public_data.completion) |completion| {
            if (completion.kind == .halt_flag)
                values.appendAssumeCapacity(completion.address);
        }
    }
    std.mem.sort(u32, values.items, {}, std.sort.asc(u32));
    var write: usize = 0;
    for (values.items) |address| {
        if (write != 0 and values.items[write - 1] == address) continue;
        values.items[write] = address;
        write += 1;
    }
    values.shrinkRetainingCapacity(write);
    return values.toOwnedSlice(allocator);
}

fn requireCompactBoundary(
    words: []const minimal.BoundaryWord,
    view: *const segment_v2.CanonicalWireViewV2,
) !void {
    for (words) |word| {
        if (word.entry != sparseValue(view, view.entry_snapshot, word.address) or
            word.exit != sparseValue(view, view.exit_snapshot, word.address))
        {
            return error.IncrementalPostprocessCompactBoundaryMismatchV4;
        }
    }
}

fn sparseWords(
    allocator: std.mem.Allocator,
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
) ![]boundary_v1.SparseWordV1 {
    const result = try allocator.alloc(boundary_v1.SparseWordV1, section.count);
    errdefer allocator.free(result);
    for (result, 0..) |*destination, index| {
        const source = view.sparseEntry(section, index);
        destination.* = .{ .address = source.address, .value = source.value };
    }
    return result;
}

fn sparseValue(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    address: u32,
) u32 {
    var low: usize = 0;
    var high: usize = section.count;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const entry = view.sparseEntry(section, middle);
        if (entry.address < address) {
            low = middle + 1;
        } else if (entry.address > address) {
            high = middle;
        } else return entry.value;
    }
    return 0;
}

fn clockValue(
    view: *const segment_v2.CanonicalWireViewV2,
    section: segment_v2.RetainedSectionV2,
    address: u32,
) u32 {
    var low: usize = 0;
    var high: usize = section.count;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const entry = view.clockEntry(section, middle);
        if (entry.address < address) {
            low = middle + 1;
        } else if (entry.address > address) {
            high = middle;
        } else return entry.clock;
    }
    return 0;
}

fn snapshot(
    value: *const frontend.recursion.segment_leaf_local_authority_v3.BoundaryV3,
) segment_v2.SnapshotIdentity {
    return .{
        .id = value.snapshot_id,
        .count = value.snapshot_count,
        .root = value.continuation_root,
    };
}
