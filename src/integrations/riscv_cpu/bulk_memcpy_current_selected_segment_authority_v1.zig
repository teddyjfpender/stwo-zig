//! Sealed current-execution authority for one selected segment-zero memcpy call.
//!
//! This is candidate-only custody. The historical journal and aggregate
//! observation remain authenticated corpus/completion evidence, but neither is
//! treated as the current executable's segment-boundary authority.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const evidence = @import("ethereum_block_leaf_evidence.zig");
const replay = @import("bulk_memcpy_retained_replay_v1.zig");
const tape_artifact = @import("bulk_memcpy_tape_artifact_v1.zig");

const tape_mod = frontend.runner.guest_precompile.bulk_memcpy_session_tape_v1;
const call_buffer = frontend.runner.guest_precompile.bulk_memcpy_call_buffer_v1;
const CompletionReason = frontend.runner.CompletionReason;
const SegmentClockFrame = frontend.runner.result_mod.SegmentClockFrame;

pub const schema =
    "stwo.riscv.bulk-memcpy-current-selected-segment-authority.v1";
pub const status = "current-segment0-selected-diagnostic-only";
pub const historical_role = "historical-completion-corpus-custody-only";
pub const selection_rule =
    "first execution-ordered memcpy entry in complete current segment0 for which validateRunnerCall succeeds and expectedWordCount()<=max_word_rows";
pub const replay_caveat =
    "pass1 seals a genuine const-only pre-retirement projection at TraceRow.clk-1; pass2 reexecutes current ELF/input to the same boundary and must match its canonical tape bytes exactly; this authority is custody-only and is not an AIR public statement";
pub const maximum_word_rows: u32 = 16;
pub const maximum_bytes: usize = 1024 * 1024;

pub const FileIdentity = struct {
    bytes: u64,
    path: []const u8,
    sha256: []const u8,

    fn validate(self: FileIdentity, allow_empty: bool) !void {
        if ((!allow_empty and self.bytes == 0) or
            !std.fs.path.isAbsolute(self.path))
        {
            return error.InvalidCurrentSelectedSegmentAuthority;
        }
        try requireDigest(self.sha256);
    }
};

pub const Timing = struct {
    system_ns: u64,
    user_ns: u64,
    wall_ns: u64,
};

pub const CurrentAuthorities = struct {
    elf: FileIdentity,
    input: FileIdentity,
    producer_executable: FileIdentity,
    source_request: FileIdentity,
};

pub const HistoricalCustody = struct {
    journal: FileIdentity,
    observation: FileIdentity,
    observation_content_sha256: []const u8,
    role: []const u8,
};

pub const Boundary = struct {
    access_clocks_sha256: []const u8,
    cpu_sha256: []const u8,
    memory_access_clock_entries: u64,
    pc: u32,
    rw_memory_nonzero_words: u64,
    rw_memory_retained_words: u64,
    rw_memory_sha256: []const u8,
    rw_memory_zero_words: u64,
};

pub const SelectedBoundaryProjection = struct {
    boundary: Boundary,
    call_count: u32,
    canonical_tape_bytes: u64,
    canonical_tape_hex: []const u8,
    canonical_tape_sha256: []const u8,
    execution_row_count: u32,
    external_step_origin: u64,
    tape_identity_sha256: []const u8,
    word_row_count: u32,
};

pub const ExternalFamilyRows = struct {
    calls: u64,
    execution_rows: u64,
    family: []const u8,
};

pub const FamilyRows = struct {
    family: []const u8,
    rows: u64,
};

pub const Continuation = struct {
    access_clocks: u64,
    clock_frame: []const u8,
    cpu_sha256: []const u8,
    identity_sha256: []const u8,
    next_cycle: u64,
    next_segment_index: u32,
    rw_memory_fingerprint: u64,
    rw_memory_word_count: u32,
    schema_version: u32,
    session_tag: u64,
};

pub const CurrentSegment = struct {
    completion_address: u32,
    completion_clock: u32,
    completion_reason: ?[]const u8,
    completion_value: u32,
    continuation: Continuation,
    core_trace_rows: u64,
    cycle_count: u64,
    entry: Boundary,
    exit: Boundary,
    exit_code: ?u32,
    external_family_rows: []const ExternalFamilyRows,
    external_trace_rows: u64,
    global_first_cycle: u64,
    is_first: bool,
    is_last: bool,
    opcode_family_rows: []const FamilyRows,
    output_bytes: ?u64,
    output_sha256: ?[]const u8,
    segment_index: u32,
    unclassified_core_rows: u64,
};

pub const CallDescriptor = struct {
    call_index: u32,
    destination: u32,
    execution_clock: u32,
    length: u32,
    pc: u32,
    projected_inst_word: u32,
    return_pc: u32,
    software_inst_word: u32,
    source: u32,
};

pub const Selector = struct {
    descriptor: CallDescriptor,
    identity_sha256: []const u8,
    max_word_rows: u32,
    rule: []const u8,
    selected_execution_ordinal: u64,
    selected_word_rows: u32,
    trace_row_clk: u32,
};

pub const UnsignedAuthorityV1 = struct {
    current_authorities: CurrentAuthorities,
    current_segment: CurrentSegment,
    historical_custody: HistoricalCustody,
    pass1_timing: Timing,
    production: bool,
    replay_boundary_caveat: []const u8,
    schema: []const u8,
    selected_boundary_projection: SelectedBoundaryProjection,
    selector: Selector,
    status: []const u8,
};

pub const AuthorityV1 = struct {
    content_sha256: []const u8,
    current_authorities: CurrentAuthorities,
    current_segment: CurrentSegment,
    historical_custody: HistoricalCustody,
    pass1_timing: Timing,
    production: bool,
    replay_boundary_caveat: []const u8,
    schema: []const u8,
    selected_boundary_projection: SelectedBoundaryProjection,
    selector: Selector,
    status: []const u8,

    pub fn validate(self: AuthorityV1) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.historical_custody.role, historical_role) or
            !std.mem.eql(u8, self.selector.rule, selection_rule) or
            !std.mem.eql(u8, self.replay_boundary_caveat, replay_caveat) or
            self.production or self.current_segment.segment_index != 0 or
            self.current_segment.global_first_cycle != 1 or
            !self.current_segment.is_first or self.current_segment.is_last or
            self.current_segment.cycle_count == 0 or
            self.current_segment.core_trace_rows == 0 or
            self.current_segment.completion_reason != null or
            self.current_segment.exit_code != null or
            self.current_segment.output_bytes != null or
            self.current_segment.output_sha256 != null or
            self.current_segment.continuation.schema_version !=
                frontend.runner.result_mod.CONTINUATION_SCHEMA_VERSION or
            self.current_segment.continuation.session_tag == 0 or
            self.current_segment.continuation.next_segment_index != 1 or
            !std.mem.eql(
                u8,
                self.current_segment.continuation.clock_frame,
                @tagName(SegmentClockFrame.leaf_local),
            ) or
            self.selector.max_word_rows != maximum_word_rows or
            self.selector.selected_word_rows == 0 or
            self.selector.selected_word_rows > self.selector.max_word_rows or
            self.selector.trace_row_clk <= 1 or
            self.selector.trace_row_clk !=
                self.selector.descriptor.execution_clock or
            self.selector.descriptor.call_index != 0 or
            self.selector.descriptor.projected_inst_word != tape_mod.fixed_inst_word or
            self.selector.trace_row_clk > self.current_segment.cycle_count or
            self.selected_boundary_projection.boundary.pc !=
                self.selector.descriptor.pc or
            self.selected_boundary_projection.call_count != 1 or
            self.selected_boundary_projection.execution_row_count != 1 or
            self.selected_boundary_projection.word_row_count !=
                self.selector.selected_word_rows or
            self.selected_boundary_projection.external_step_origin >
                self.selector.trace_row_clk - 1 or
            self.pass1_timing.wall_ns == 0)
        {
            return error.InvalidCurrentSelectedSegmentAuthority;
        }
        const expected_next_cycle = std.math.add(
            u64,
            self.current_segment.global_first_cycle,
            self.current_segment.cycle_count,
        ) catch return error.InvalidCurrentSelectedSegmentAuthority;
        if (self.current_segment.continuation.next_cycle != expected_next_cycle)
            return error.InvalidCurrentSelectedSegmentAuthority;
        if (@as(u64, self.current_segment.continuation.rw_memory_word_count) !=
            self.current_segment.exit.rw_memory_retained_words or
            self.current_segment.entry.rw_memory_retained_words !=
                self.current_segment.exit.rw_memory_retained_words)
        {
            return error.InvalidCurrentSelectedSegmentAuthority;
        }
        try self.current_authorities.elf.validate(false);
        try self.current_authorities.input.validate(true);
        try self.current_authorities.producer_executable.validate(false);
        try self.current_authorities.source_request.validate(false);
        try self.historical_custody.journal.validate(false);
        try self.historical_custody.observation.validate(false);
        inline for (.{
            self.content_sha256,
            self.historical_custody.observation_content_sha256,
            self.current_segment.entry.access_clocks_sha256,
            self.current_segment.entry.cpu_sha256,
            self.current_segment.entry.rw_memory_sha256,
            self.current_segment.exit.access_clocks_sha256,
            self.current_segment.exit.cpu_sha256,
            self.current_segment.exit.rw_memory_sha256,
            self.current_segment.continuation.cpu_sha256,
            self.current_segment.continuation.identity_sha256,
            self.selected_boundary_projection.canonical_tape_sha256,
            self.selected_boundary_projection.tape_identity_sha256,
            self.selector.identity_sha256,
        }) |digest| try requireDigest(digest);
        try validateBoundary(self.current_segment.entry);
        try validateBoundary(self.current_segment.exit);
        try validateBoundary(self.selected_boundary_projection.boundary);
        try validateProjectionStructure(self.selected_boundary_projection);
        if (!std.mem.eql(
            u8,
            self.current_segment.continuation.cpu_sha256,
            self.current_segment.exit.cpu_sha256,
        )) return error.InvalidCurrentSelectedSegmentAuthority;
        if (self.current_segment.external_family_rows.len != 2 or
            self.current_segment.opcode_family_rows.len != replay.family_count)
        {
            return error.InvalidCurrentSelectedSegmentAuthority;
        }
        var external_rows: u64 = 0;
        for (self.current_segment.external_family_rows, 0..) |family, index| {
            if (!std.mem.eql(u8, family.family, externalFamilyName(index)))
                return error.InvalidCurrentSelectedSegmentAuthority;
            external_rows = try std.math.add(
                u64,
                external_rows,
                family.execution_rows,
            );
        }
        var core_rows = self.current_segment.unclassified_core_rows;
        for (self.current_segment.opcode_family_rows, 0..) |family, index| {
            if (!std.mem.eql(
                u8,
                family.family,
                @tagName(frontend.witness_layout.canonical_families[index]),
            )) return error.InvalidCurrentSelectedSegmentAuthority;
            core_rows = try std.math.add(u64, core_rows, family.rows);
        }
        if (external_rows != self.current_segment.external_trace_rows or
            core_rows != self.current_segment.core_trace_rows or
            try std.math.add(u64, core_rows, external_rows) !=
                self.current_segment.cycle_count)
        {
            return error.InvalidCurrentSelectedSegmentAuthority;
        }
        _ = try decodeSelection(self.selector);
    }
};

pub const EncodeInput = struct {
    producer_executable: evidence.FileIdentity,
    source_request: evidence.FileIdentity,
    elf: evidence.FileIdentity,
    input: evidence.FileIdentity,
    historical_journal: evidence.FileIdentity,
    historical_observation: evidence.FileIdentity,
    historical_observation_content_sha256: []const u8,
    max_word_rows: u32,
    pass1: replay.Pass1Result,
};

pub const AdmitExpected = struct {
    producer_executable: evidence.FileIdentity,
    source_request: evidence.FileIdentity,
    elf: evidence.FileIdentity,
    input: evidence.FileIdentity,
    historical_journal: evidence.FileIdentity,
    historical_observation: evidence.FileIdentity,
    historical_observation_content_sha256: []const u8,
    max_word_rows: u32,
    pass1: replay.Pass1Result,
};

pub const Admitted = struct {
    content_sha256: [32]u8,
    projection: replay.OwnedSelectedBoundaryProjection,
    selection: replay.Selection,
    selector_identity_sha256: [32]u8,
    segment: replay.CurrentSegment,

    pub fn deinit(self: *Admitted) void {
        self.projection.deinit();
        self.* = undefined;
    }
};

pub fn encode(allocator: std.mem.Allocator, input: EncodeInput) ![]u8 {
    try input.pass1.projection.value.validate();
    var family_rows: [replay.family_count]FamilyRows = undefined;
    for (frontend.witness_layout.canonical_families, 0..) |family, index| {
        family_rows[index] = .{
            .family = @tagName(family),
            .rows = input.pass1.segment.opcode_family_rows[@intFromEnum(family)],
        };
    }
    const external_rows = [2]ExternalFamilyRows{
        .{
            .calls = input.pass1.segment.external_calls[0],
            .execution_rows = input.pass1.segment.external_execution_rows[0],
            .family = externalFamilyName(0),
        },
        .{
            .calls = input.pass1.segment.external_calls[1],
            .execution_rows = input.pass1.segment.external_execution_rows[1],
            .family = externalFamilyName(1),
        },
    };
    const producer_hex = hex(input.producer_executable.sha256);
    const source_hex = hex(input.source_request.sha256);
    const elf_hex = hex(input.elf.sha256);
    const input_hex = hex(input.input.sha256);
    const journal_hex = hex(input.historical_journal.sha256);
    const observation_hex = hex(input.historical_observation.sha256);
    const selector_hex = hex(selectorIdentity(
        input.pass1.selection,
        input.max_word_rows,
    ));
    const projection_tape_hex = try encodeHexAlloc(
        allocator,
        input.pass1.projection.value.canonical_tape_bytes,
    );
    defer allocator.free(projection_tape_hex);
    const projection_tape_sha_hex = hex(
        input.pass1.projection.value.canonical_tape_sha256,
    );
    const projection_tape_identity_hex = hex(
        input.pass1.projection.value.tape_identity_sha256,
    );
    const projection_access_hex = hex(
        input.pass1.projection.value.boundary.access_clocks_sha256,
    );
    const projection_cpu_hex = hex(
        input.pass1.projection.value.boundary.cpu_sha256,
    );
    const projection_memory_hex = hex(
        input.pass1.projection.value.boundary.memory_sha256,
    );
    const entry_access_hex = hex(input.pass1.segment.entry.access_clocks_sha256);
    const entry_cpu_hex = hex(input.pass1.segment.entry.cpu_sha256);
    const entry_memory_hex = hex(input.pass1.segment.entry.memory_sha256);
    const exit_access_hex = hex(input.pass1.segment.exit.access_clocks_sha256);
    const exit_cpu_hex = hex(input.pass1.segment.exit.cpu_sha256);
    const exit_memory_hex = hex(input.pass1.segment.exit.memory_sha256);
    const continuation_cpu_hex = hex(input.pass1.segment.continuation.cpu_sha256);
    const continuation_identity_hex = hex(
        input.pass1.segment.continuation.identity_sha256,
    );
    const output_hex = if (input.pass1.segment.output_sha256) |digest|
        hex(digest)
    else
        undefined;
    const completion_reason: ?[]const u8 = if (input.pass1.segment.completion_reason) |reason| @tagName(reason) else null;
    return encodeUnsigned(allocator, .{
        .current_authorities = .{
            .elf = fileWire(input.elf, &elf_hex),
            .input = fileWire(input.input, &input_hex),
            .producer_executable = fileWire(
                input.producer_executable,
                &producer_hex,
            ),
            .source_request = fileWire(input.source_request, &source_hex),
        },
        .current_segment = .{
            .completion_address = input.pass1.segment.completion_address,
            .completion_clock = input.pass1.segment.completion_clock,
            .completion_reason = completion_reason,
            .completion_value = input.pass1.segment.completion_value,
            .continuation = .{
                .access_clocks = input.pass1.segment.continuation.access_clocks,
                .clock_frame = @tagName(input.pass1.segment.continuation.clock_frame),
                .cpu_sha256 = &continuation_cpu_hex,
                .identity_sha256 = &continuation_identity_hex,
                .next_cycle = input.pass1.segment.continuation.next_cycle,
                .next_segment_index = input.pass1.segment.continuation.next_segment_index,
                .rw_memory_fingerprint = input.pass1.segment.continuation.rw_memory_fingerprint,
                .rw_memory_word_count = input.pass1.segment.continuation.rw_memory_word_count,
                .schema_version = input.pass1.segment.continuation.schema_version,
                .session_tag = input.pass1.segment.continuation.session_tag,
            },
            .core_trace_rows = input.pass1.segment.core_trace_rows,
            .cycle_count = input.pass1.segment.cycle_count,
            .entry = .{
                .access_clocks_sha256 = &entry_access_hex,
                .cpu_sha256 = &entry_cpu_hex,
                .memory_access_clock_entries = input.pass1.segment.entry.memory_clock_entries,
                .pc = input.pass1.segment.entry.pc,
                .rw_memory_nonzero_words = input.pass1.segment.entry.nonzero_words,
                .rw_memory_retained_words = input.pass1.segment.entry.retained_words,
                .rw_memory_sha256 = &entry_memory_hex,
                .rw_memory_zero_words = input.pass1.segment.entry.zero_words,
            },
            .exit = .{
                .access_clocks_sha256 = &exit_access_hex,
                .cpu_sha256 = &exit_cpu_hex,
                .memory_access_clock_entries = input.pass1.segment.exit.memory_clock_entries,
                .pc = input.pass1.segment.exit.pc,
                .rw_memory_nonzero_words = input.pass1.segment.exit.nonzero_words,
                .rw_memory_retained_words = input.pass1.segment.exit.retained_words,
                .rw_memory_sha256 = &exit_memory_hex,
                .rw_memory_zero_words = input.pass1.segment.exit.zero_words,
            },
            .exit_code = input.pass1.segment.exit_code,
            .external_family_rows = &external_rows,
            .external_trace_rows = input.pass1.segment.external_trace_rows,
            .global_first_cycle = input.pass1.segment.global_first_cycle,
            .is_first = input.pass1.segment.is_first,
            .is_last = input.pass1.segment.is_last,
            .opcode_family_rows = &family_rows,
            .output_bytes = input.pass1.segment.output_bytes,
            .output_sha256 = if (input.pass1.segment.output_sha256 != null)
                &output_hex
            else
                null,
            .segment_index = input.pass1.segment.segment_index,
            .unclassified_core_rows = input.pass1.segment.unclassified_core_rows,
        },
        .historical_custody = .{
            .journal = fileWire(input.historical_journal, &journal_hex),
            .observation = fileWire(input.historical_observation, &observation_hex),
            .observation_content_sha256 = input.historical_observation_content_sha256,
            .role = historical_role,
        },
        .pass1_timing = timingWire(input.pass1.stats.timing),
        .production = false,
        .replay_boundary_caveat = replay_caveat,
        .schema = schema,
        .selected_boundary_projection = .{
            .boundary = .{
                .access_clocks_sha256 = &projection_access_hex,
                .cpu_sha256 = &projection_cpu_hex,
                .memory_access_clock_entries = input.pass1.projection.value.boundary.memory_clock_entries,
                .pc = input.pass1.projection.value.boundary.pc,
                .rw_memory_nonzero_words = input.pass1.projection.value.boundary.nonzero_words,
                .rw_memory_retained_words = input.pass1.projection.value.boundary.retained_words,
                .rw_memory_sha256 = &projection_memory_hex,
                .rw_memory_zero_words = input.pass1.projection.value.boundary.zero_words,
            },
            .call_count = input.pass1.projection.value.call_count,
            .canonical_tape_bytes = @intCast(
                input.pass1.projection.value.canonical_tape_bytes.len,
            ),
            .canonical_tape_hex = projection_tape_hex,
            .canonical_tape_sha256 = &projection_tape_sha_hex,
            .execution_row_count = input.pass1.projection.value.execution_row_count,
            .external_step_origin = input.pass1.projection.value.external_step_origin,
            .tape_identity_sha256 = &projection_tape_identity_hex,
            .word_row_count = input.pass1.projection.value.word_row_count,
        },
        .selector = selectorWire(
            input.pass1.selection,
            input.max_word_rows,
            &selector_hex,
        ),
        .status = status,
    });
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(AuthorityV1) {
    if (bytes.len == 0 or bytes.len > maximum_bytes or
        bytes[bytes.len - 1] != '\n')
    {
        return error.InvalidCurrentSelectedSegmentAuthority;
    }
    const body = bytes[0 .. bytes.len - 1];
    var parsed = try std.json.parseFromSlice(AuthorityV1, allocator, body, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, body))
        return error.NonCanonicalCurrentSelectedSegmentAuthority;
    try parsed.value.validate();
    const unsigned = try std.json.Stringify.valueAlloc(
        allocator,
        withoutSeal(parsed.value),
        .{},
    );
    defer allocator.free(unsigned);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const expected = hex(hash.finalResult());
    if (!std.mem.eql(u8, parsed.value.content_sha256, &expected))
        return error.InvalidCurrentSelectedSegmentAuthoritySeal;
    const selection = try decodeSelection(parsed.value.selector);
    var projection = try decodeProjection(
        allocator,
        parsed.value.selected_boundary_projection,
        selection,
    );
    projection.deinit();
    return parsed;
}

pub fn admit(
    allocator: std.mem.Allocator,
    value: AuthorityV1,
    expected: AdmitExpected,
) !Admitted {
    try value.validate();
    try requireFileMatch(value.current_authorities.source_request, expected.source_request);
    try requireFileMatch(value.current_authorities.elf, expected.elf);
    try requireFileMatch(value.current_authorities.input, expected.input);
    try requireFileMatch(
        value.current_authorities.producer_executable,
        expected.producer_executable,
    );
    try requireFileMatch(
        value.historical_custody.journal,
        expected.historical_journal,
    );
    try requireFileMatch(
        value.historical_custody.observation,
        expected.historical_observation,
    );
    if (!std.mem.eql(
        u8,
        value.historical_custody.observation_content_sha256,
        expected.historical_observation_content_sha256,
    ) or value.selector.max_word_rows != expected.max_word_rows or
        value.pass1_timing.wall_ns != expected.pass1.stats.timing.wall_ns or
        value.pass1_timing.user_ns != expected.pass1.stats.timing.user_ns or
        value.pass1_timing.system_ns != expected.pass1.stats.timing.system_ns or
        expected.pass1.stats.segments != 1 or
        expected.pass1.stats.cycles != expected.pass1.segment.cycle_count or
        expected.pass1.stats.core_rows != expected.pass1.segment.core_trace_rows)
    {
        return error.CurrentSelectedSegmentAuthorityMismatch;
    }
    const selection = try decodeSelection(value.selector);
    const segment = try decodeSegment(value.current_segment);
    var projection = try decodeProjection(
        allocator,
        value.selected_boundary_projection,
        selection,
    );
    errdefer projection.deinit();
    if (!std.meta.eql(selection, expected.pass1.selection) or
        !std.meta.eql(segment, expected.pass1.segment) or
        !replay.projectionsEqual(
            projection.value,
            expected.pass1.projection.value,
        ))
    {
        return error.CurrentSelectedSegmentAuthorityMismatch;
    }
    return .{
        .content_sha256 = try parseDigest(value.content_sha256),
        .projection = projection,
        .selection = selection,
        .selector_identity_sha256 = try parseDigest(value.selector.identity_sha256),
        .segment = segment,
    };
}

fn encodeUnsigned(
    allocator: std.mem.Allocator,
    value: UnsignedAuthorityV1,
) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const content = hex(hash.finalResult());
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"content_sha256\":\"{s}\",{s}\n",
        .{ &content, unsigned[1..] },
    );
    errdefer allocator.free(body);
    if (body.len > maximum_bytes)
        return error.InvalidCurrentSelectedSegmentAuthority;
    var parsed = try parse(allocator, body);
    parsed.deinit();
    return body;
}

fn withoutSeal(value: AuthorityV1) UnsignedAuthorityV1 {
    return .{
        .current_authorities = value.current_authorities,
        .current_segment = value.current_segment,
        .historical_custody = value.historical_custody,
        .pass1_timing = value.pass1_timing,
        .production = value.production,
        .replay_boundary_caveat = value.replay_boundary_caveat,
        .schema = value.schema,
        .selected_boundary_projection = value.selected_boundary_projection,
        .selector = value.selector,
        .status = value.status,
    };
}

fn decodeSelection(value: Selector) !replay.Selection {
    const selection = replay.Selection{
        .segment_index = 0,
        .execution_ordinal = value.selected_execution_ordinal,
        .trace_clock = value.trace_row_clk,
        .software_inst_word = value.descriptor.software_inst_word,
        .return_pc = value.descriptor.return_pc,
        .call = .{
            .execution_clock = value.descriptor.execution_clock,
            .call_index = value.descriptor.call_index,
            .pc = value.descriptor.pc,
            .source = value.descriptor.source,
            .destination = value.descriptor.destination,
            .length = value.descriptor.length,
        },
    };
    try call_buffer.validateRunnerCall(selection.call);
    if (selection.call.expectedWordCount() != value.selected_word_rows or
        !std.meta.eql(
            try parseDigest(value.identity_sha256),
            selectorIdentity(selection, value.max_word_rows),
        ))
    {
        return error.InvalidCurrentSelectedSegmentAuthority;
    }
    return selection;
}

fn decodeSegment(value: CurrentSegment) !replay.CurrentSegment {
    var family_rows: [replay.family_count]u64 = .{0} ** replay.family_count;
    for (value.opcode_family_rows, 0..) |family, index| {
        const expected_family = frontend.witness_layout.canonical_families[index];
        if (!std.mem.eql(u8, family.family, @tagName(expected_family)))
            return error.InvalidCurrentSelectedSegmentAuthority;
        family_rows[@intFromEnum(expected_family)] = family.rows;
    }
    var external_calls: [2]u64 = undefined;
    var external_rows: [2]u64 = undefined;
    for (value.external_family_rows, 0..) |family, index| {
        if (!std.mem.eql(u8, family.family, externalFamilyName(index)))
            return error.InvalidCurrentSelectedSegmentAuthority;
        external_calls[index] = family.calls;
        external_rows[index] = family.execution_rows;
    }
    const completion_reason: ?CompletionReason = if (value.completion_reason) |reason|
        std.meta.stringToEnum(CompletionReason, reason) orelse
            return error.InvalidCurrentSelectedSegmentAuthority
    else
        null;
    const clock_frame = std.meta.stringToEnum(
        SegmentClockFrame,
        value.continuation.clock_frame,
    ) orelse return error.InvalidCurrentSelectedSegmentAuthority;
    return .{
        .segment_index = value.segment_index,
        .global_first_cycle = value.global_first_cycle,
        .cycle_count = value.cycle_count,
        .is_first = value.is_first,
        .is_last = value.is_last,
        .entry = try decodeBoundary(value.entry),
        .exit = try decodeBoundary(value.exit),
        .core_trace_rows = value.core_trace_rows,
        .external_trace_rows = value.external_trace_rows,
        .external_calls = external_calls,
        .external_execution_rows = external_rows,
        .unclassified_core_rows = value.unclassified_core_rows,
        .opcode_family_rows = family_rows,
        .completion_reason = completion_reason,
        .completion_address = value.completion_address,
        .completion_value = value.completion_value,
        .completion_clock = value.completion_clock,
        .exit_code = value.exit_code,
        .output_bytes = value.output_bytes,
        .output_sha256 = if (value.output_sha256) |digest|
            try parseDigest(digest)
        else
            null,
        .continuation = .{
            .schema_version = value.continuation.schema_version,
            .clock_frame = clock_frame,
            .session_tag = value.continuation.session_tag,
            .next_segment_index = value.continuation.next_segment_index,
            .next_cycle = value.continuation.next_cycle,
            .cpu_sha256 = try parseDigest(value.continuation.cpu_sha256),
            .rw_memory_word_count = value.continuation.rw_memory_word_count,
            .rw_memory_fingerprint = value.continuation.rw_memory_fingerprint,
            .access_clocks = value.continuation.access_clocks,
            .identity_sha256 = try parseDigest(value.continuation.identity_sha256),
        },
    };
}

fn decodeBoundary(value: Boundary) !replay.CurrentBoundary {
    return .{
        .pc = value.pc,
        .cpu_sha256 = try parseDigest(value.cpu_sha256),
        .memory_sha256 = try parseDigest(value.rw_memory_sha256),
        .retained_words = value.rw_memory_retained_words,
        .nonzero_words = value.rw_memory_nonzero_words,
        .zero_words = value.rw_memory_zero_words,
        .access_clocks_sha256 = try parseDigest(value.access_clocks_sha256),
        .memory_clock_entries = value.memory_access_clock_entries,
    };
}

fn selectorWire(
    value: replay.Selection,
    max_word_rows: u32,
    identity: []const u8,
) Selector {
    return .{
        .descriptor = .{
            .call_index = value.call.call_index,
            .destination = value.call.destination,
            .execution_clock = value.call.execution_clock,
            .length = value.call.length,
            .pc = value.call.pc,
            .projected_inst_word = tape_mod.fixed_inst_word,
            .return_pc = value.return_pc,
            .software_inst_word = value.software_inst_word,
            .source = value.call.source,
        },
        .identity_sha256 = identity,
        .max_word_rows = max_word_rows,
        .rule = selection_rule,
        .selected_execution_ordinal = value.execution_ordinal,
        .selected_word_rows = value.call.expectedWordCount(),
        .trace_row_clk = value.trace_clock,
    };
}

fn selectorIdentity(selection: replay.Selection, max_word_rows: u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/bulk-memcpy-current-selector/v1\x00");
    hash.update(selection_rule);
    hashInt(&hash, u32, max_word_rows);
    hashInt(&hash, u32, selection.segment_index);
    hashInt(&hash, u64, selection.execution_ordinal);
    hashInt(&hash, u32, selection.trace_clock);
    hashInt(&hash, u32, selection.software_inst_word);
    hashInt(&hash, u32, selection.return_pc);
    hashInt(&hash, u32, selection.call.execution_clock);
    hashInt(&hash, u32, selection.call.call_index);
    hashInt(&hash, u32, selection.call.pc);
    hashInt(&hash, u32, selection.call.source);
    hashInt(&hash, u32, selection.call.destination);
    hashInt(&hash, u32, selection.call.length);
    return hash.finalResult();
}

fn validateBoundary(value: Boundary) !void {
    if (try std.math.add(
        u64,
        value.rw_memory_nonzero_words,
        value.rw_memory_zero_words,
    ) != value.rw_memory_retained_words) {
        return error.InvalidCurrentSelectedSegmentAuthority;
    }
}

fn validateProjectionStructure(value: SelectedBoundaryProjection) !void {
    const byte_count = std.math.cast(usize, value.canonical_tape_bytes) orelse
        return error.InvalidCurrentSelectedSegmentAuthority;
    if (value.canonical_tape_bytes == 0 or
        byte_count > tape_artifact.maximum_artifact_bytes or
        byte_count > std.math.maxInt(usize) / 2 or
        value.canonical_tape_hex.len != byte_count * 2 or
        value.call_count != 1 or value.execution_row_count != 1 or
        value.word_row_count == 0)
    {
        return error.InvalidCurrentSelectedSegmentAuthority;
    }
    try requireDigest(value.canonical_tape_sha256);
    try requireDigest(value.tape_identity_sha256);
}

fn decodeProjection(
    allocator: std.mem.Allocator,
    value: SelectedBoundaryProjection,
    selection: replay.Selection,
) !replay.OwnedSelectedBoundaryProjection {
    try validateProjectionStructure(value);
    const byte_count = std.math.cast(usize, value.canonical_tape_bytes) orelse
        return error.InvalidCurrentSelectedSegmentAuthority;
    const bytes = try allocator.alloc(u8, byte_count);
    errdefer allocator.free(bytes);
    _ = std.fmt.hexToBytes(bytes, value.canonical_tape_hex) catch
        return error.InvalidCurrentSelectedSegmentAuthority;
    const canonical_hex = try encodeHexAlloc(allocator, bytes);
    defer allocator.free(canonical_hex);
    if (!std.mem.eql(u8, canonical_hex, value.canonical_tape_hex))
        return error.NonCanonicalCurrentSelectedSegmentAuthority;
    var tape = try tape_artifact.decodeAlloc(allocator, bytes);
    defer tape.deinit();
    const projection = replay.SelectedBoundaryProjection{
        .boundary = try decodeBoundary(value.boundary),
        .canonical_tape_bytes = bytes,
        .canonical_tape_sha256 = try parseDigest(value.canonical_tape_sha256),
        .tape_identity_sha256 = try parseDigest(value.tape_identity_sha256),
        .external_step_origin = value.external_step_origin,
        .call_count = value.call_count,
        .word_row_count = value.word_row_count,
        .execution_row_count = value.execution_row_count,
    };
    try projection.validate();
    if (@as(u64, @intCast(tape.externalStepOrigin())) !=
        projection.external_step_origin or
        @as(u32, @intCast(tape.records().len)) != projection.call_count or
        @as(u32, @intCast(tape.wordRows().len)) != projection.word_row_count or
        @as(u32, @intCast(tape.rows().len)) != projection.execution_row_count or
        !std.meta.eql(tape.records()[0].caller.call(), selection.call) or
        tape.rows()[0].inst_word != tape_mod.fixed_inst_word or
        projection.boundary.pc != selection.call.pc)
    {
        return error.InvalidCurrentSelectedSegmentAuthority;
    }
    return .{ .value = projection, .allocator = allocator };
}

fn requireFileMatch(wire: FileIdentity, expected: evidence.FileIdentity) !void {
    if (wire.bytes != expected.bytes or
        !std.mem.eql(u8, wire.path, expected.path) or
        !std.meta.eql(try parseDigest(wire.sha256), expected.sha256))
    {
        return error.CurrentSelectedSegmentAuthorityMismatch;
    }
}

fn fileWire(value: evidence.FileIdentity, digest: []const u8) FileIdentity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = digest };
}

fn timingWire(value: evidence.Timing) Timing {
    return .{
        .system_ns = value.system_ns,
        .user_ns = value.user_ns,
        .wall_ns = value.wall_ns,
    };
}

fn externalFamilyName(index: usize) []const u8 {
    return switch (index) {
        0 => "stwo.keccakf-1600.permute-in-place@1",
        1 => "stwo.secp256k1.recover-signer@1",
        else => unreachable,
    };
}

fn requireDigest(value: []const u8) !void {
    _ = try parseDigest(value);
}

fn parseDigest(value: []const u8) ![32]u8 {
    if (value.len != 64)
        return error.InvalidCurrentSelectedSegmentAuthority;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch
        return error.InvalidCurrentSelectedSegmentAuthority;
    return result;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn encodeHexAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const output = try allocator.alloc(u8, try std.math.mul(usize, bytes.len, 2));
    errdefer allocator.free(output);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "current segment authority seals and cold-admits exact pass1 custody" {
    var family_rows: [replay.family_count]u64 = .{0} ** replay.family_count;
    const first_family = frontend.witness_layout.canonical_families[0];
    family_rows[@intFromEnum(first_family)] = 10;
    const entry = replay.CurrentBoundary{
        .pc = 0x1000,
        .cpu_sha256 = .{0x11} ** 32,
        .memory_sha256 = .{0x12} ** 32,
        .retained_words = 3,
        .nonzero_words = 2,
        .zero_words = 1,
        .access_clocks_sha256 = .{0x13} ** 32,
        .memory_clock_entries = 0,
    };
    const exit = replay.CurrentBoundary{
        .pc = 0x1004,
        .cpu_sha256 = .{0x21} ** 32,
        .memory_sha256 = .{0x22} ** 32,
        .retained_words = 3,
        .nonzero_words = 2,
        .zero_words = 1,
        .access_clocks_sha256 = .{0x23} ** 32,
        .memory_clock_entries = 1,
    };
    var projection_boundary = entry;
    projection_boundary.pc = 0x3000;
    var pass1 = replay.Pass1Result{
        .selection = .{
            .segment_index = 0,
            .execution_ordinal = 7,
            .trace_clock = 5,
            .software_inst_word = 0x0000_0013,
            .return_pc = 0x2000,
            .call = .{
                .execution_clock = 5,
                .call_index = 0,
                .pc = 0x3000,
                .source = 0x4000,
                .destination = 0x5000,
                .length = 32,
            },
        },
        .projection = try testProjection(
            std.testing.allocator,
            projection_boundary,
        ),
        .segment = .{
            .segment_index = 0,
            .global_first_cycle = 1,
            .cycle_count = 10,
            .is_first = true,
            .is_last = false,
            .entry = entry,
            .exit = exit,
            .core_trace_rows = 10,
            .external_trace_rows = 0,
            .external_calls = .{ 0, 0 },
            .external_execution_rows = .{ 0, 0 },
            .unclassified_core_rows = 0,
            .opcode_family_rows = family_rows,
            .completion_reason = null,
            .completion_address = 0,
            .completion_value = 0,
            .completion_clock = 0,
            .exit_code = null,
            .output_bytes = null,
            .output_sha256 = null,
            .continuation = .{
                .schema_version = 2,
                .clock_frame = .leaf_local,
                .session_tag = 9,
                .next_segment_index = 1,
                .next_cycle = 11,
                .cpu_sha256 = exit.cpu_sha256,
                .rw_memory_word_count = 3,
                .rw_memory_fingerprint = 10,
                .access_clocks = 11,
                .identity_sha256 = .{0x31} ** 32,
            },
        },
        .stats = .{
            .segments = 1,
            .cycles = 10,
            .core_rows = 10,
            .timing = .{ .wall_ns = 1, .user_ns = 2, .system_ns = 3 },
        },
    };
    defer pass1.deinit();
    const source = testFile("/tmp/current-source.json", 1, 10);
    const elf = testFile("/tmp/current.elf", 2, 11);
    const input = testFile("/tmp/current.input", 3, 0);
    const journal_file = testFile("/tmp/historical.journal", 4, 12);
    const observation = testFile("/tmp/historical-observation.json", 5, 13);
    const observation_content_hex = hex(.{0x44} ** 32);
    const producer = testFile("/tmp/current-producer", 0x55, 14);
    const encode_input = EncodeInput{
        .producer_executable = producer,
        .source_request = source,
        .elf = elf,
        .input = input,
        .historical_journal = journal_file,
        .historical_observation = observation,
        .historical_observation_content_sha256 = &observation_content_hex,
        .max_word_rows = 16,
        .pass1 = pass1,
    };
    const bytes = try encode(std.testing.allocator, encode_input);
    defer std.testing.allocator.free(bytes);
    var parsed = try parse(std.testing.allocator, bytes);
    defer parsed.deinit();
    var admitted = try admit(std.testing.allocator, parsed.value, .{
        .producer_executable = producer,
        .source_request = source,
        .elf = elf,
        .input = input,
        .historical_journal = journal_file,
        .historical_observation = observation,
        .historical_observation_content_sha256 = &observation_content_hex,
        .max_word_rows = 16,
        .pass1 = pass1,
    });
    defer admitted.deinit();
    try std.testing.expectEqualDeep(pass1.selection, admitted.selection);
    try std.testing.expectEqualDeep(pass1.segment, admitted.segment);
    try std.testing.expect(replay.projectionsEqual(
        pass1.projection.value,
        admitted.projection.value,
    ));

    var mutated = parsed.value;
    mutated.selected_boundary_projection.boundary.pc +%= 4;
    try std.testing.expectError(
        error.InvalidCurrentSelectedSegmentAuthority,
        mutated.validate(),
    );
    mutated = parsed.value;
    mutated.selected_boundary_projection.word_row_count +%= 1;
    try std.testing.expectError(
        error.InvalidCurrentSelectedSegmentAuthority,
        mutated.validate(),
    );

    const tampered_tape = try std.testing.allocator.dupe(
        u8,
        admitted.projection.value.canonical_tape_bytes,
    );
    defer std.testing.allocator.free(tampered_tape);
    tampered_tape[0] ^= 1;
    var mutated_projection = admitted.projection.value;
    mutated_projection.canonical_tape_bytes = tampered_tape;
    try std.testing.expectError(
        error.InvalidSelectedBoundaryProjection,
        mutated_projection.validate(),
    );
}

fn testFile(path: []const u8, fill: u8, bytes: u64) evidence.FileIdentity {
    return .{ .bytes = bytes, .path = path, .sha256 = .{fill} ** 32 };
}

fn testProjection(
    allocator: std.mem.Allocator,
    boundary: replay.CurrentBoundary,
) !replay.OwnedSelectedBoundaryProjection {
    const bulk_runner = frontend.runner.guest_precompile.bulk_memcpy_v1;
    var memory = try frontend.runner.Memory.initFallible(allocator);
    defer memory.deinit();
    const layout = frontend.runner.memory_state.MemoryLayout{
        .program_base = 0x3000,
        .program_end = 0x4000,
        .data_base = 0x4000,
        .data_end = 0x6000,
        .stack_bottom = 0x7000,
        .stack_top = 0x8000,
        .io_base = 0x9000,
        .io_end = 0xa000,
        .input_base = 0x9000,
        .input_end = 0x9100,
        .output_len_addr = 0x9200,
        .output_data_addr = 0x9300,
        .output_base = 0x9300,
        .output_end = 0x9400,
    };
    for (0..8) |index| {
        memory.writeU32(0x4000 + @as(u32, @intCast(index * 4)), @intCast(index + 1));
        memory.writeU32(0x5000 + @as(u32, @intCast(index * 4)), 0);
    }
    var cpu = frontend.runner.Cpu.init(0x3000, 0x7ffc);
    cpu.writeReg(1, 0x3010);
    cpu.writeReg(10, 0x5000);
    cpu.writeReg(11, 0x4000);
    cpu.writeReg(12, 32);
    var tracker = frontend.runner.state_chain.StateChainTracker.init(allocator);
    defer tracker.deinit();
    var builder = try tape_mod.Builder.init(allocator, 1, 8, 4);
    errdefer builder.deinit();
    try bulk_runner.projectIntoTape(
        5,
        cpu,
        &memory,
        layout,
        &tracker,
        &builder,
    );
    var frozen = builder.freeze();
    defer frozen.deinit();
    const bytes = try tape_artifact.encodeAlloc(allocator, &frozen);
    errdefer allocator.free(bytes);
    const value = replay.SelectedBoundaryProjection{
        .boundary = boundary,
        .canonical_tape_bytes = bytes,
        .canonical_tape_sha256 = sha256Bytes(bytes),
        .tape_identity_sha256 = tape_artifact.identity(bytes),
        .external_step_origin = 4,
        .call_count = 1,
        .word_row_count = 8,
        .execution_row_count = 1,
    };
    try value.validate();
    return .{ .value = value, .allocator = allocator };
}

fn sha256Bytes(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
