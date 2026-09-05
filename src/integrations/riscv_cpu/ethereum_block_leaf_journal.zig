//! Independent admission of the pinned V3 segmented-execution journal.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const contract = @import("ethereum_block_leaf_contract.zig");

const manifest = frontend.diagnostics.segment_manifest;
const execution_profile = frontend.isa.execution_profile;
const segment_v2 = frontend.recursion.segment_statement_v2;
const CompletionReason = frontend.runner.CompletionReason;
const family_count = frontend.witness_layout.canonical_families.len;
const max_record_bytes: usize = 64 * 1024;
const empty_access_clocks_sha256 =
    "a47dc44986396c65742cbb0b98565644df17436157e16870e743d7437704153a";

const Header = struct {
    schema: []const u8,
    profile: []const u8,
    clock_frame: []const u8,
    claim_boundary: []const u8,
    elf_bytes: u64,
    elf_sha256: []const u8,
    input_bytes: u64,
    input_sha256: []const u8,
    segment_step_budget: u64,
    strict_completion: bool,
    trace_retention: []const u8,
};

const FamilyRows = struct {
    family: []const u8,
    rows: u64,
};

const ExternalFamilyRows = struct {
    family: []const u8,
    calls: u64,
    execution_rows: u64,
};

const Boundary = struct {
    pc: u32,
    cpu_sha256: []const u8,
    rw_memory_sha256: []const u8,
    rw_memory_retained_words: u64,
    rw_memory_nonzero_words: u64,
    access_clocks_sha256: []const u8,
    memory_access_clock_entries: u64,
};

const Segment = struct {
    schema: []const u8,
    clock_frame: []const u8,
    previous_record_sha256: []const u8,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u64,
    is_first: bool,
    is_last: bool,
    entry: Boundary,
    exit: Boundary,
    core_trace_rows: u64,
    external_trace_rows: u64,
    external_family_rows: []const ExternalFamilyRows,
    unclassified_core_rows: u64,
    opcode_family_rows: []const FamilyRows,
    completion_reason: ?[]const u8,
    completion_address: u32,
    completion_value: u32,
    completion_clock: u32,
    exit_code: ?u32,
    output_bytes: ?u64,
    output_sha256: ?[]const u8,
    continuation_sha256: ?[]const u8,
};

const Summary = struct {
    schema: []const u8,
    clock_frame: []const u8,
    previous_record_sha256: []const u8,
    claim_boundary: []const u8,
    completed: bool,
    segment_count: u32,
    total_cycles: u64,
    total_core_trace_rows: u64,
    total_external_trace_rows: u64,
    external_family_rows: []const ExternalFamilyRows,
    total_unclassified_core_rows: u64,
    opcode_family_rows: []const FamilyRows,
    completion_reason: []const u8,
    exit_code: ?u32,
    output_bytes: ?u64,
    output_sha256: ?[]const u8,
    final_cpu_sha256: []const u8,
    final_rw_memory_sha256: []const u8,
    final_access_clocks_sha256: []const u8,
    max_segment_cycle_count: u64,
    leaf_local_clock_ranges_within_v3_limit: bool,
    segment_statement_v2_global_cycle_limit: u32,
    segment_statement_v2_admissible: bool,
};

fn Envelope(comptime T: type) type {
    return struct {
        payload: T,
        content_sha256: []const u8,
    };
}

pub fn validate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    source: anytype,
) ![][32]u8 {
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n')
        return error.InvalidJournalFraming;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    const header_line = lines.next() orelse return error.MissingJournalHeader;
    const header_digest = try validateHeader(allocator, header_line, source);
    var previous = header_digest;
    var expected_cycle: u64 = 1;
    var total_cycles: u64 = 0;
    var total_core: u64 = 0;
    var total_external: u64 = 0;
    var total_unclassified: u64 = 0;
    var total_families: [family_count]u64 = .{0} ** family_count;
    var total_extension: [2]u64 = .{ 0, 0 };
    var max_cycles: u64 = 0;
    var prior_exit: ?BoundaryAuthority = null;
    var last: ?SegmentSummary = null;
    const digests = try allocator.alloc([32]u8, source.segment_count);
    errdefer allocator.free(digests);

    for (0..source.segment_count) |index| {
        const line = lines.next() orelse return error.MissingJournalSegment;
        var parsed = try parseLine(Segment, allocator, line);
        defer parsed.deinit();
        const value = parsed.value.payload;
        prior_exit = try validateSegment(
            value,
            index,
            source.segment_count,
            source.segment_step_budget,
            previous,
            expected_cycle,
            prior_exit,
        );
        digests[index] = try contract.parseSha256(parsed.value.content_sha256);
        previous = digests[index];
        expected_cycle = try std.math.add(u64, expected_cycle, value.cycle_count);
        total_cycles = try std.math.add(u64, total_cycles, value.cycle_count);
        total_core = try std.math.add(u64, total_core, value.core_trace_rows);
        total_external = try std.math.add(
            u64,
            total_external,
            value.external_trace_rows,
        );
        total_unclassified = try std.math.add(
            u64,
            total_unclassified,
            value.unclassified_core_rows,
        );
        for (value.opcode_family_rows, 0..) |family, family_index|
            total_families[family_index] = try std.math.add(
                u64,
                total_families[family_index],
                family.rows,
            );
        for (value.external_family_rows, 0..) |family, family_index|
            total_extension[family_index] = try std.math.add(
                u64,
                total_extension[family_index],
                family.calls,
            );
        max_cycles = @max(max_cycles, value.cycle_count);
        last = try segmentSummary(value);
    }

    const summary_line = lines.next() orelse return error.MissingJournalSummary;
    var parsed_summary = try parseLine(Summary, allocator, summary_line);
    defer parsed_summary.deinit();
    const terminator = lines.next() orelse return error.InvalidJournalFraming;
    if (terminator.len != 0 or lines.next() != null)
        return error.TrailingJournalRecord;
    try validateSummary(
        parsed_summary.value.payload,
        source,
        previous,
        total_cycles,
        total_core,
        total_external,
        total_unclassified,
        total_families,
        total_extension,
        max_cycles,
        prior_exit orelse return error.MissingJournalSegment,
        last orelse return error.MissingJournalSegment,
    );
    return digests;
}

fn validateHeader(
    allocator: std.mem.Allocator,
    line: []const u8,
    source: anytype,
) ![32]u8 {
    var parsed = try parseLine(Header, allocator, line);
    defer parsed.deinit();
    const value = parsed.value.payload;
    if (!std.mem.eql(u8, value.schema, manifest.HEADER_SCHEMA) or
        !std.mem.eql(u8, value.profile, contract.profile_name) or
        !std.mem.eql(u8, value.clock_frame, contract.clock_frame) or
        !std.mem.eql(u8, value.claim_boundary, manifest.CLAIM_BOUNDARY) or
        !std.mem.eql(u8, value.trace_retention, "segment-owned") or
        value.elf_bytes != source.elf.bytes or
        !std.mem.eql(u8, value.elf_sha256, source.elf.sha256) or
        value.input_bytes != source.input.bytes or
        !std.mem.eql(u8, value.input_sha256, source.input.sha256) or
        value.segment_step_budget != source.segment_step_budget or
        !value.strict_completion)
    {
        return error.JournalHeaderMismatch;
    }
    return contract.parseSha256(parsed.value.content_sha256);
}

fn validateSegment(
    value: Segment,
    index: usize,
    count: u32,
    budget: usize,
    previous: [32]u8,
    expected_cycle: u64,
    prior_exit: ?BoundaryAuthority,
) !BoundaryAuthority {
    const previous_hex = std.fmt.bytesToHex(previous, .lower);
    if (!std.mem.eql(u8, value.schema, manifest.SEGMENT_SCHEMA) or
        !std.mem.eql(u8, value.clock_frame, contract.clock_frame) or
        !std.mem.eql(u8, value.previous_record_sha256, &previous_hex) or
        value.segment_index != index or value.global_first_cycle != expected_cycle or
        value.cycle_count == 0 or value.cycle_count > budget or
        value.is_first != (index == 0) or
        value.is_last != (index + 1 == count))
    {
        return error.JournalSegmentMismatch;
    }
    const entry = try decodeBoundary(value.entry);
    const exit = try decodeBoundary(value.exit);
    if (prior_exit) |prior| {
        if (!std.meta.eql(prior.cpu_sha256, entry.cpu_sha256) or
            !std.meta.eql(prior.rw_memory_sha256, entry.rw_memory_sha256))
        {
            return error.JournalBoundaryMismatch;
        }
    }
    const empty_access_clocks = try contract.parseSha256(
        empty_access_clocks_sha256,
    );
    if (value.entry.memory_access_clock_entries != 0 or
        !std.meta.eql(entry.access_clocks_sha256, empty_access_clocks))
    {
        return error.JournalBoundaryMismatch;
    }
    if (try std.math.add(
        u64,
        value.core_trace_rows,
        value.external_trace_rows,
    ) != value.cycle_count) return error.JournalInventoryMismatch;
    if (value.unclassified_core_rows > value.core_trace_rows)
        return error.JournalInventoryMismatch;
    try validateFamilies(
        value.opcode_family_rows,
        value.core_trace_rows - value.unclassified_core_rows,
    );
    try validateExternal(value.external_family_rows, value.external_trace_rows);
    if (value.is_last) {
        if (value.completion_reason == null or value.continuation_sha256 != null or
            value.output_bytes == null or value.output_sha256 == null)
        {
            return error.JournalCompletionMismatch;
        }
    } else if (value.completion_reason != null or
        value.continuation_sha256 == null or value.output_bytes != null or
        value.output_sha256 != null)
    {
        return error.JournalCompletionMismatch;
    }
    if (value.completion_reason) |reason| _ = try parseCompletionReason(reason);
    if (value.output_sha256) |digest| _ = try contract.parseSha256(digest);
    if (value.continuation_sha256) |digest| _ = try contract.parseSha256(digest);
    return exit;
}

fn validateSummary(
    value: Summary,
    source: anytype,
    previous: [32]u8,
    total_cycles: u64,
    total_core: u64,
    total_external: u64,
    total_unclassified: u64,
    total_families: [family_count]u64,
    total_extension: [2]u64,
    max_cycles: u64,
    final_boundary: BoundaryAuthority,
    last: SegmentSummary,
) !void {
    const previous_hex = std.fmt.bytesToHex(previous, .lower);
    const final_cpu = try contract.parseSha256(value.final_cpu_sha256);
    const final_memory = try contract.parseSha256(
        value.final_rw_memory_sha256,
    );
    const final_clocks = try contract.parseSha256(
        value.final_access_clocks_sha256,
    );
    const completion = try parseCompletionReason(value.completion_reason);
    const output = if (value.output_sha256) |digest|
        try contract.parseSha256(digest)
    else
        null;
    const expected_output = try contract.parseSha256(
        source.expected_output.sha256,
    );
    if (!std.mem.eql(u8, value.schema, manifest.SUMMARY_SCHEMA) or
        !std.mem.eql(u8, value.clock_frame, contract.clock_frame) or
        !std.mem.eql(u8, value.previous_record_sha256, &previous_hex) or
        !std.mem.eql(u8, value.claim_boundary, manifest.CLAIM_BOUNDARY) or
        !value.completed or value.segment_count != source.segment_count or
        value.total_cycles != total_cycles or
        value.total_core_trace_rows != total_core or
        value.total_external_trace_rows != total_external or
        value.total_unclassified_core_rows != total_unclassified or
        value.max_segment_cycle_count != max_cycles or
        !value.leaf_local_clock_ranges_within_v3_limit or
        value.segment_statement_v2_global_cycle_limit !=
            segment_v2.MAX_GLOBAL_CYCLES or
        value.segment_statement_v2_admissible !=
            (total_cycles <= segment_v2.MAX_GLOBAL_CYCLES) or
        !std.meta.eql(final_cpu, final_boundary.cpu_sha256) or
        !std.meta.eql(final_memory, final_boundary.rw_memory_sha256) or
        !std.meta.eql(final_clocks, final_boundary.access_clocks_sha256) or
        value.exit_code != last.exit_code or
        value.output_bytes != last.output_bytes or
        !std.meta.eql(output, last.output_sha256) or
        last.completion_reason == null or
        completion != last.completion_reason.? or
        value.output_bytes != source.expected_output.bytes or
        output == null or !std.meta.eql(output.?, expected_output))
    {
        return error.JournalSummaryMismatch;
    }
    try validateFamilies(value.opcode_family_rows, total_core - total_unclassified);
    for (value.opcode_family_rows, 0..) |family, index|
        if (family.rows != total_families[index])
            return error.JournalSummaryMismatch;
    try validateExternal(value.external_family_rows, total_external);
    for (value.external_family_rows, 0..) |family, index|
        if (family.calls != total_extension[index])
            return error.JournalSummaryMismatch;
}

fn parseLine(
    comptime T: type,
    allocator: std.mem.Allocator,
    line: []const u8,
) !std.json.Parsed(Envelope(T)) {
    if (line.len == 0 or line.len > max_record_bytes)
        return error.InvalidJournalFraming;
    var parsed = try std.json.parseFromSlice(Envelope(T), allocator, line, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, line)) return error.NonCanonicalJournalRecord;
    const payload = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value.payload,
        .{},
    );
    defer allocator.free(payload);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    if (!std.meta.eql(
        digest,
        try contract.parseSha256(parsed.value.content_sha256),
    )) return error.InvalidJournalRecordIdentity;
    return parsed;
}

fn decodeBoundary(value: Boundary) !BoundaryAuthority {
    if (value.rw_memory_nonzero_words > value.rw_memory_retained_words)
        return error.JournalBoundaryMismatch;
    return .{
        .cpu_sha256 = try contract.parseSha256(value.cpu_sha256),
        .rw_memory_sha256 = try contract.parseSha256(value.rw_memory_sha256),
        .access_clocks_sha256 = try contract.parseSha256(
            value.access_clocks_sha256,
        ),
    };
}

fn validateFamilies(rows: []const FamilyRows, expected: u64) !void {
    if (rows.len != family_count) return error.JournalInventoryMismatch;
    var total: u64 = 0;
    for (rows, frontend.witness_layout.canonical_families) |row, family| {
        if (!std.mem.eql(u8, row.family, @tagName(family)))
            return error.JournalInventoryMismatch;
        total = try std.math.add(u64, total, row.rows);
    }
    if (total != expected) return error.JournalInventoryMismatch;
}

fn validateExternal(rows: []const ExternalFamilyRows, expected: u64) !void {
    const names = [_][]const u8{
        execution_profile.keccakf_capability,
        execution_profile.secp256k1_recover_capability,
    };
    if (rows.len != names.len) return error.JournalInventoryMismatch;
    var total: u64 = 0;
    for (rows, names) |row, name| {
        if (!std.mem.eql(u8, row.family, name) or
            row.calls != row.execution_rows)
        {
            return error.JournalInventoryMismatch;
        }
        total = try std.math.add(u64, total, row.calls);
    }
    if (total != expected) return error.JournalInventoryMismatch;
}

const BoundaryAuthority = struct {
    cpu_sha256: [32]u8,
    rw_memory_sha256: [32]u8,
    access_clocks_sha256: [32]u8,
};

const SegmentSummary = struct {
    completion_reason: ?CompletionReason,
    exit_code: ?u32,
    output_bytes: ?u64,
    output_sha256: ?[32]u8,
};

fn segmentSummary(value: Segment) !SegmentSummary {
    return .{
        .completion_reason = if (value.completion_reason) |reason|
            try parseCompletionReason(reason)
        else
            null,
        .exit_code = value.exit_code,
        .output_bytes = value.output_bytes,
        .output_sha256 = if (value.output_sha256) |digest|
            try contract.parseSha256(digest)
        else
            null,
    };
}

fn parseCompletionReason(value: []const u8) !CompletionReason {
    return std.meta.stringToEnum(CompletionReason, value) orelse
        error.InvalidCompletionReason;
}

const TestMutation = enum { none, boundary, output, completion };

test "journal replay owns two-segment boundary and terminal authorities" {
    const allocator = std.testing.allocator;
    const source = testSource();
    const admitted = try buildTestJournal(allocator, .none);
    defer allocator.free(admitted);
    const digests = try validate(allocator, admitted, source);
    defer allocator.free(digests);
    try std.testing.expectEqual(@as(usize, 2), digests.len);

    const boundary = try buildTestJournal(allocator, .boundary);
    defer allocator.free(boundary);
    try std.testing.expectError(
        error.JournalBoundaryMismatch,
        validate(allocator, boundary, source),
    );
    const output = try buildTestJournal(allocator, .output);
    defer allocator.free(output);
    try std.testing.expectError(
        error.JournalSummaryMismatch,
        validate(allocator, output, source),
    );
    const completion = try buildTestJournal(allocator, .completion);
    defer allocator.free(completion);
    try std.testing.expectError(
        error.JournalSummaryMismatch,
        validate(allocator, completion, source),
    );
}

const TestSource = struct {
    elf: contract.Identity,
    input: contract.Identity,
    expected_output: contract.Identity,
    segment_count: u32,
    segment_step_budget: usize,
};

const test_sha_a = [_]u8{'a'} ** 64;
const test_sha_b = [_]u8{'b'} ** 64;
const test_sha_c = [_]u8{'c'} ** 64;
const test_sha_d = [_]u8{'d'} ** 64;
const test_sha_e = [_]u8{'e'} ** 64;
const test_sha_f = [_]u8{'f'} ** 64;
const test_empty_sha =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn testSource() TestSource {
    return .{
        .elf = .{ .bytes = 1, .path = "/elf", .sha256 = &test_sha_e },
        .input = .{ .bytes = 0, .path = "/input", .sha256 = test_empty_sha },
        .expected_output = .{
            .bytes = 1,
            .path = "/output",
            .sha256 = &test_sha_f,
        },
        .segment_count = 2,
        .segment_step_budget = 1,
    };
}

fn buildTestJournal(
    allocator: std.mem.Allocator,
    mutation: TestMutation,
) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    const family_one = testFamilyRows(1);
    const family_two = testFamilyRows(2);
    const external = testExternalRows();
    var previous = try appendTestEnvelope(allocator, &writer.writer, Header{
        .schema = manifest.HEADER_SCHEMA,
        .profile = contract.profile_name,
        .clock_frame = contract.clock_frame,
        .claim_boundary = manifest.CLAIM_BOUNDARY,
        .elf_bytes = 1,
        .elf_sha256 = &test_sha_e,
        .input_bytes = 0,
        .input_sha256 = test_empty_sha,
        .segment_step_budget = 1,
        .strict_completion = true,
        .trace_retention = "segment-owned",
    });
    var previous_hex = std.fmt.bytesToHex(previous, .lower);
    previous = try appendTestEnvelope(allocator, &writer.writer, Segment{
        .schema = manifest.SEGMENT_SCHEMA,
        .clock_frame = contract.clock_frame,
        .previous_record_sha256 = &previous_hex,
        .segment_index = 0,
        .global_first_cycle = 1,
        .cycle_count = 1,
        .is_first = true,
        .is_last = false,
        .entry = testBoundary(&test_sha_a, &test_sha_a, empty_access_clocks_sha256, 0),
        .exit = testBoundary(&test_sha_b, &test_sha_b, &test_sha_d, 1),
        .core_trace_rows = 1,
        .external_trace_rows = 0,
        .external_family_rows = &external,
        .unclassified_core_rows = 0,
        .opcode_family_rows = &family_one,
        .completion_reason = null,
        .completion_address = 0,
        .completion_value = 0,
        .completion_clock = 0,
        .exit_code = null,
        .output_bytes = null,
        .output_sha256 = null,
        .continuation_sha256 = &test_sha_d,
    });
    previous_hex = std.fmt.bytesToHex(previous, .lower);
    const entry_cpu = if (mutation == .boundary) &test_sha_c else &test_sha_b;
    const output_sha = if (mutation == .output) &test_sha_e else &test_sha_f;
    const completion = "ecall";
    const summary_completion = if (mutation == .completion)
        "self_loop"
    else
        completion;
    previous = try appendTestEnvelope(allocator, &writer.writer, Segment{
        .schema = manifest.SEGMENT_SCHEMA,
        .clock_frame = contract.clock_frame,
        .previous_record_sha256 = &previous_hex,
        .segment_index = 1,
        .global_first_cycle = 2,
        .cycle_count = 1,
        .is_first = false,
        .is_last = true,
        .entry = testBoundary(entry_cpu, &test_sha_b, empty_access_clocks_sha256, 0),
        .exit = testBoundary(&test_sha_c, &test_sha_c, &test_sha_d, 1),
        .core_trace_rows = 1,
        .external_trace_rows = 0,
        .external_family_rows = &external,
        .unclassified_core_rows = 0,
        .opcode_family_rows = &family_one,
        .completion_reason = completion,
        .completion_address = 0,
        .completion_value = 0,
        .completion_clock = 1,
        .exit_code = 0,
        .output_bytes = 1,
        .output_sha256 = output_sha,
        .continuation_sha256 = null,
    });
    previous_hex = std.fmt.bytesToHex(previous, .lower);
    _ = try appendTestEnvelope(allocator, &writer.writer, Summary{
        .schema = manifest.SUMMARY_SCHEMA,
        .clock_frame = contract.clock_frame,
        .previous_record_sha256 = &previous_hex,
        .claim_boundary = manifest.CLAIM_BOUNDARY,
        .completed = true,
        .segment_count = 2,
        .total_cycles = 2,
        .total_core_trace_rows = 2,
        .total_external_trace_rows = 0,
        .external_family_rows = &external,
        .total_unclassified_core_rows = 0,
        .opcode_family_rows = &family_two,
        .completion_reason = summary_completion,
        .exit_code = 0,
        .output_bytes = 1,
        .output_sha256 = output_sha,
        .final_cpu_sha256 = &test_sha_c,
        .final_rw_memory_sha256 = &test_sha_c,
        .final_access_clocks_sha256 = &test_sha_d,
        .max_segment_cycle_count = 1,
        .leaf_local_clock_ranges_within_v3_limit = true,
        .segment_statement_v2_global_cycle_limit = segment_v2.MAX_GLOBAL_CYCLES,
        .segment_statement_v2_admissible = true,
    });
    return allocator.dupe(u8, writer.written());
}

fn testBoundary(
    cpu: []const u8,
    memory: []const u8,
    clocks: []const u8,
    clock_entries: u64,
) Boundary {
    return .{
        .pc = 0,
        .cpu_sha256 = cpu,
        .rw_memory_sha256 = memory,
        .rw_memory_retained_words = 1,
        .rw_memory_nonzero_words = 1,
        .access_clocks_sha256 = clocks,
        .memory_access_clock_entries = clock_entries,
    };
}

fn testFamilyRows(total: u64) [family_count]FamilyRows {
    var result: [family_count]FamilyRows = undefined;
    for (&result, frontend.witness_layout.canonical_families, 0..) |*row, family, index| {
        row.* = .{ .family = @tagName(family), .rows = if (index == 0) total else 0 };
    }
    return result;
}

fn testExternalRows() [2]ExternalFamilyRows {
    return .{
        .{
            .family = execution_profile.keccakf_capability,
            .calls = 0,
            .execution_rows = 0,
        },
        .{
            .family = execution_profile.secp256k1_recover_capability,
            .calls = 0,
            .execution_rows = 0,
        },
    };
}

fn appendTestEnvelope(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    value: anytype,
) ![32]u8 {
    const payload = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(payload);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    const encoded = try std.json.Stringify.valueAlloc(
        allocator,
        Envelope(@TypeOf(value)){
            .payload = value,
            .content_sha256 = &digest_hex,
        },
        .{},
    );
    defer allocator.free(encoded);
    try writer.writeAll(encoded);
    try writer.writeByte('\n');
    return digest;
}
