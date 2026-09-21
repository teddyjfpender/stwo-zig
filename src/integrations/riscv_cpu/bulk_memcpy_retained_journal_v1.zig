//! Typed replay checks for the already-cold-validated V3 execution journal.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const contract = @import("ethereum_block_leaf_contract.zig");

const CompletionReason = frontend.runner.CompletionReason;
const Family = frontend.witness_layout.Family;
const family_count = frontend.witness_layout.canonical_families.len;

pub const ExpectedBoundary = struct {
    pc: u32,
    cpu_sha256: [32]u8,
    memory_sha256: [32]u8,
    retained_words: u64,
    nonzero_words: u64,
    access_clocks_sha256: [32]u8,
    memory_clock_entries: u64,
};

pub const BoundarySide = enum { entry, exit };

pub const BoundaryField = enum {
    pc,
    cpu_digest,
    memory_digest,
    retained_word_count,
    nonzero_word_count,
    access_clock_digest,
    access_clock_count,
};

pub const BoundaryDiagnostic = struct {
    segment_index: u32,
    side: BoundarySide,
    field: BoundaryField,
};

const ObservedBoundary = struct {
    pc: u32,
    cpu_sha256: [32]u8,
    memory_sha256: [32]u8,
    retained_words: u64,
    nonzero_words: u64,
    access_clocks_sha256: [32]u8,
    memory_clock_entries: u64,
};

pub const ExpectedSegment = struct {
    record_sha256: [32]u8,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u64,
    is_first: bool,
    is_last: bool,
    entry: ExpectedBoundary,
    exit: ExpectedBoundary,
    core_trace_rows: u64,
    external_trace_rows: u64,
    external_calls: [2]u64,
    external_execution_rows: [2]u64,
    unclassified_core_rows: u64,
    opcode_family_rows: [family_count]u64,
    completion_reason: ?CompletionReason,
    completion_address: u32,
    completion_value: u32,
    completion_clock: u32,
    exit_code: ?u32,
    output_bytes: ?u64,
    output_sha256: ?[32]u8,
    continuation_sha256: ?[32]u8,
};

pub const ExpectedSegments = struct {
    items: []ExpectedSegment,

    pub fn deinit(self: *ExpectedSegments, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    record_digests: []const [32]u8,
) !ExpectedSegments {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    _ = lines.next() orelse return error.InvalidRetainedJournalDescription;
    const items = try allocator.alloc(ExpectedSegment, record_digests.len);
    errdefer allocator.free(items);
    for (items, record_digests) |*destination, record_digest| {
        const line = lines.next() orelse
            return error.InvalidRetainedJournalDescription;
        if (line.len == 0) return error.InvalidRetainedJournalDescription;
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            line,
            .{},
        );
        defer parsed.deinit();
        const payload = try objectField(parsed.value, "payload");
        const external = try arrayField(payload, "external_family_rows");
        const families = try arrayField(payload, "opcode_family_rows");
        if (external.items.len != 2 or families.items.len != family_count)
            return error.InvalidRetainedJournalDescription;
        var external_calls: [2]u64 = undefined;
        var external_rows: [2]u64 = undefined;
        for (external.items, 0..) |item, index| {
            external_calls[index] = try unsignedField(item, "calls");
            external_rows[index] = try unsignedField(item, "execution_rows");
        }
        var family_rows: [family_count]u64 = .{0} ** family_count;
        var occupied_families: [family_count]bool = .{false} ** family_count;
        for (families.items, 0..) |item, transcript_index| {
            try storeFamilyRow(
                &family_rows,
                &occupied_families,
                transcript_index,
                try stringField(item, "family"),
                try unsignedField(item, "rows"),
            );
        }
        for (occupied_families) |present|
            if (!present) return error.InvalidRetainedJournalDescription;
        destination.* = .{
            .record_sha256 = record_digest,
            .segment_index = try u32Field(payload, "segment_index"),
            .global_first_cycle = try unsignedField(payload, "global_first_cycle"),
            .cycle_count = try unsignedField(payload, "cycle_count"),
            .is_first = try boolField(payload, "is_first"),
            .is_last = try boolField(payload, "is_last"),
            .entry = try parseBoundary(try objectField(payload, "entry")),
            .exit = try parseBoundary(try objectField(payload, "exit")),
            .core_trace_rows = try unsignedField(payload, "core_trace_rows"),
            .external_trace_rows = try unsignedField(payload, "external_trace_rows"),
            .external_calls = external_calls,
            .external_execution_rows = external_rows,
            .unclassified_core_rows = try unsignedField(
                payload,
                "unclassified_core_rows",
            ),
            .opcode_family_rows = family_rows,
            .completion_reason = try optionalCompletionReason(
                try objectField(payload, "completion_reason"),
            ),
            .completion_address = try u32Field(payload, "completion_address"),
            .completion_value = try u32Field(payload, "completion_value"),
            .completion_clock = try u32Field(payload, "completion_clock"),
            .exit_code = try optionalU32(try objectField(payload, "exit_code")),
            .output_bytes = try optionalU64(try objectField(payload, "output_bytes")),
            .output_sha256 = try optionalDigest(
                try objectField(payload, "output_sha256"),
            ),
            .continuation_sha256 = try optionalDigest(
                try objectField(payload, "continuation_sha256"),
            ),
        };
    }
    return .{ .items = items };
}

fn parseBoundary(value: std.json.Value) !ExpectedBoundary {
    return .{
        .pc = try u32Field(value, "pc"),
        .cpu_sha256 = try digestField(value, "cpu_sha256"),
        .memory_sha256 = try digestField(value, "rw_memory_sha256"),
        .retained_words = try unsignedField(value, "rw_memory_retained_words"),
        .nonzero_words = try unsignedField(value, "rw_memory_nonzero_words"),
        .access_clocks_sha256 = try digestField(value, "access_clocks_sha256"),
        .memory_clock_entries = try unsignedField(
            value,
            "memory_access_clock_entries",
        ),
    };
}

fn storeFamilyRow(
    rows: *[family_count]u64,
    occupied: *[family_count]bool,
    transcript_index: usize,
    family_name: []const u8,
    row_count: u64,
) !void {
    if (transcript_index >= family_count)
        return error.InvalidRetainedJournalDescription;
    const family = std.meta.stringToEnum(Family, family_name) orelse
        return error.InvalidRetainedJournalDescription;
    if (family != frontend.witness_layout.canonical_families[transcript_index])
        return error.InvalidRetainedJournalDescription;
    const enum_index: usize = @intFromEnum(family);
    if (occupied[enum_index]) return error.InvalidRetainedJournalDescription;
    occupied[enum_index] = true;
    rows[enum_index] = row_count;
}

pub fn validateFullSegment(
    segment: *const frontend.runner.EthereumSegmentResult,
    expected: ExpectedSegment,
) !void {
    try validateSegmentEntry(segment, expected);
    const base = &segment.base;
    if (base.cycle_count != expected.cycle_count or
        base.segment_role.is_first != expected.is_first or
        base.segment_role.is_last != expected.is_last or
        base.execution_trace.rows.items.len != expected.core_trace_rows or
        base.completion_reason != expected.completion_reason or
        base.completion_address != expected.completion_address or
        base.completion_value != expected.completion_value or
        base.completion_clock != expected.completion_clock or
        base.exit_code != expected.exit_code)
    {
        return error.RetainedJournalExecutionMismatch;
    }
    try validateBoundary(
        expected.segment_index,
        .exit,
        base.exit_cpu,
        base.rw_memory,
        .final,
        base.exit_access_clocks,
        expected.exit,
    );

    var family_rows: [family_count]u64 = .{0} ** family_count;
    var unclassified: u64 = 0;
    for (base.execution_trace.rows.items) |row| {
        const family = frontend.runner.trace.proofOpcodeFamily(row.opcode) catch {
            unclassified += 1;
            continue;
        };
        family_rows[@intFromEnum(family)] += 1;
    }
    const external_calls = [2]u64{
        @intCast(segment.keccakf_calls.len()),
        @intCast(segment.signer_recovery_calls.len()),
    };
    const external_rows = [2]u64{
        @intCast(segment.keccakf_execution_rows.rows().len),
        @intCast(segment.signer_recovery_execution_rows.rows().len),
    };
    const external_total = try std.math.add(
        u64,
        external_rows[0],
        external_rows[1],
    );
    if (!std.meta.eql(family_rows, expected.opcode_family_rows) or
        unclassified != expected.unclassified_core_rows or
        !std.meta.eql(external_calls, expected.external_calls) or
        !std.meta.eql(external_rows, expected.external_execution_rows) or
        external_total != expected.external_trace_rows or
        try std.math.add(u64, expected.core_trace_rows, external_total) !=
            expected.cycle_count)
    {
        return error.RetainedJournalInventoryMismatch;
    }

    const output_bytes: ?u64 = if (base.output) |output| @intCast(output.len) else null;
    const output_sha256: ?[32]u8 = if (base.output) |output| sha256(output) else null;
    const continuation_sha256: ?[32]u8 = if (base.continuation) |continuation|
        continuationIdentity(continuation)
    else
        null;
    if (output_bytes != expected.output_bytes or
        !std.meta.eql(output_sha256, expected.output_sha256) or
        !std.meta.eql(continuation_sha256, expected.continuation_sha256))
    {
        return error.RetainedJournalCompletionMismatch;
    }
}

pub fn validateSegmentEntry(
    segment: *const frontend.runner.EthereumSegmentResult,
    expected: ExpectedSegment,
) !void {
    const base = &segment.base;
    if (base.segment_index != expected.segment_index or
        base.global_first_cycle != expected.global_first_cycle)
    {
        return error.RetainedJournalExecutionMismatch;
    }
    try validateBoundary(
        expected.segment_index,
        .entry,
        base.entry_cpu,
        base.rw_memory,
        .initial,
        base.entry_access_clocks,
        expected.entry,
    );
}

pub const MemorySide = enum { initial, final };
pub const MemoryIdentity = struct { digest: [32]u8, nonzero_words: u64 };

fn validateBoundary(
    segment_index: u32,
    boundary_side: BoundarySide,
    cpu: frontend.runner.Cpu,
    memory: frontend.runner.memory_state.Snapshot,
    comptime side: MemorySide,
    clocks: frontend.runner.result_mod.AccessClockBoundary,
    expected: ExpectedBoundary,
) !void {
    const memory_identity = memoryIdentity(memory, side);
    const observed = ObservedBoundary{
        .pc = cpu.pc,
        .cpu_sha256 = cpuIdentity(cpu),
        .memory_sha256 = memory_identity.digest,
        .retained_words = @intCast(memory.words.len),
        .nonzero_words = memory_identity.nonzero_words,
        .access_clocks_sha256 = accessClockIdentity(clocks),
        .memory_clock_entries = @intCast(clocks.memory_clocks.len),
    };
    if (classifyBoundaryMismatch(
        segment_index,
        boundary_side,
        observed,
        expected,
    )) |diagnostic| {
        logBoundaryDiagnostic(diagnostic, observed, expected);
        return error.RetainedJournalBoundaryMismatch;
    }
}

const maximum_boundary_diagnostic_bytes = 320;

fn logBoundaryDiagnostic(
    diagnostic: BoundaryDiagnostic,
    observed: ObservedBoundary,
    expected: ExpectedBoundary,
) void {
    var storage: [maximum_boundary_diagnostic_bytes]u8 = undefined;
    const message = formatBoundaryDiagnostic(
        &storage,
        diagnostic,
        observed,
        expected,
    ) catch {
        std.log.err(
            "retained journal boundary mismatch: segment={d} side={s} field={s}",
            .{
                diagnostic.segment_index,
                @tagName(diagnostic.side),
                @tagName(diagnostic.field),
            },
        );
        return;
    };
    std.log.err("{s}", .{message});
}

fn formatBoundaryDiagnostic(
    storage: []u8,
    diagnostic: BoundaryDiagnostic,
    observed: ObservedBoundary,
    expected: ExpectedBoundary,
) ![]const u8 {
    const prefix =
        "retained journal boundary mismatch: segment={d} side={s} field={s}";
    return switch (diagnostic.field) {
        .pc => std.fmt.bufPrint(
            storage,
            prefix ++ " observed={d} expected={d}",
            .{
                diagnostic.segment_index,
                @tagName(diagnostic.side),
                @tagName(diagnostic.field),
                observed.pc,
                expected.pc,
            },
        ),
        .retained_word_count => blk: {
            const observed_zero_words = try std.math.sub(
                u64,
                observed.retained_words,
                observed.nonzero_words,
            );
            const expected_zero_words = try std.math.sub(
                u64,
                expected.retained_words,
                expected.nonzero_words,
            );
            break :blk std.fmt.bufPrint(
                storage,
                prefix ++
                    " observed={d} expected={d}" ++
                    " observed_zero_words={d} expected_zero_words={d}",
                .{
                    diagnostic.segment_index,
                    @tagName(diagnostic.side),
                    @tagName(diagnostic.field),
                    observed.retained_words,
                    expected.retained_words,
                    observed_zero_words,
                    expected_zero_words,
                },
            );
        },
        .nonzero_word_count => std.fmt.bufPrint(
            storage,
            prefix ++ " observed={d} expected={d}",
            .{
                diagnostic.segment_index,
                @tagName(diagnostic.side),
                @tagName(diagnostic.field),
                observed.nonzero_words,
                expected.nonzero_words,
            },
        ),
        .access_clock_count => std.fmt.bufPrint(
            storage,
            prefix ++ " observed={d} expected={d}",
            .{
                diagnostic.segment_index,
                @tagName(diagnostic.side),
                @tagName(diagnostic.field),
                observed.memory_clock_entries,
                expected.memory_clock_entries,
            },
        ),
        .cpu_digest, .memory_digest, .access_clock_digest => std.fmt.bufPrint(
            storage,
            prefix,
            .{
                diagnostic.segment_index,
                @tagName(diagnostic.side),
                @tagName(diagnostic.field),
            },
        ),
    };
}

fn classifyBoundaryMismatch(
    segment_index: u32,
    side: BoundarySide,
    observed: ObservedBoundary,
    expected: ExpectedBoundary,
) ?BoundaryDiagnostic {
    const field: BoundaryField = if (observed.pc != expected.pc)
        .pc
    else if (!std.meta.eql(observed.cpu_sha256, expected.cpu_sha256))
        .cpu_digest
    else if (!std.meta.eql(observed.memory_sha256, expected.memory_sha256))
        .memory_digest
    else if (observed.retained_words != expected.retained_words)
        .retained_word_count
    else if (observed.nonzero_words != expected.nonzero_words)
        .nonzero_word_count
    else if (!std.meta.eql(
        observed.access_clocks_sha256,
        expected.access_clocks_sha256,
    ))
        .access_clock_digest
    else if (observed.memory_clock_entries != expected.memory_clock_entries)
        .access_clock_count
    else
        return null;
    return .{ .segment_index = segment_index, .side = side, .field = field };
}

pub fn cpuIdentity(cpu: frontend.runner.Cpu) [32]u8 {
    return compact_manifest.cpuIdentity(cpu);
}

pub fn memoryIdentity(
    snapshot: frontend.runner.memory_state.Snapshot,
    comptime side: MemorySide,
) MemoryIdentity {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-memory/v1\x00");
    inline for (@typeInfo(frontend.runner.memory_state.MemoryLayout).@"struct".fields) |field|
        hashInt(&hash, u32, @field(snapshot.layout, field.name));
    var nonzero_words: u64 = 0;
    for (snapshot.words) |word| {
        const value = switch (side) {
            .initial => word.initial_word,
            .final => word.final_word,
        };
        nonzero_words += @intFromBool(value != 0);
    }
    hashInt(&hash, u64, nonzero_words);
    for (snapshot.words) |word| {
        const value = switch (side) {
            .initial => word.initial_word,
            .final => word.final_word,
        };
        if (value == 0) continue;
        hashInt(&hash, u32, word.addr);
        hashInt(&hash, u32, value);
    }
    return .{ .digest = hash.finalResult(), .nonzero_words = nonzero_words };
}

pub fn accessClockIdentity(
    boundary: frontend.runner.result_mod.AccessClockBoundary,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-access-clocks/v1\x00");
    for (boundary.register_clocks) |clock| hashInt(&hash, u32, clock);
    hashInt(&hash, u64, @as(u64, @intCast(boundary.memory_clocks.len)));
    for (boundary.memory_clocks) |entry| {
        hashInt(&hash, u32, entry.addr);
        hashInt(&hash, u32, entry.clock);
    }
    return hash.finalResult();
}

pub fn continuationIdentity(
    token: frontend.runner.result_mod.ContinuationToken,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-continuation/v2\x00");
    hashInt(&hash, u32, token.schema_version);
    hashInt(&hash, u8, @intFromEnum(token.clock_frame));
    hashInt(&hash, u64, token.session_tag);
    hashInt(&hash, u32, token.next_segment_index);
    hashInt(&hash, u64, token.next_cycle);
    hash.update(&cpuIdentity(token.cpu));
    hashInt(&hash, u32, token.rw_memory.word_count);
    hashInt(&hash, u64, token.rw_memory.fingerprint);
    hashInt(&hash, u64, token.access_clocks);
    return hash.finalResult();
}

fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidRetainedJournalDescription;
    return value.object.get(name) orelse error.InvalidRetainedJournalDescription;
}

fn arrayField(value: std.json.Value, name: []const u8) !std.json.Array {
    const field = try objectField(value, name);
    if (field != .array) return error.InvalidRetainedJournalDescription;
    return field.array;
}

fn unsignedField(value: std.json.Value, name: []const u8) !u64 {
    const field = try objectField(value, name);
    if (field != .integer) return error.InvalidRetainedJournalDescription;
    return std.math.cast(u64, field.integer) orelse
        error.InvalidRetainedJournalDescription;
}

fn u32Field(value: std.json.Value, name: []const u8) !u32 {
    return std.math.cast(u32, try unsignedField(value, name)) orelse
        error.InvalidRetainedJournalDescription;
}

fn boolField(value: std.json.Value, name: []const u8) !bool {
    const field = try objectField(value, name);
    if (field != .bool) return error.InvalidRetainedJournalDescription;
    return field.bool;
}

fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const field = try objectField(value, name);
    if (field != .string) return error.InvalidRetainedJournalDescription;
    return field.string;
}

fn digestField(value: std.json.Value, name: []const u8) ![32]u8 {
    return contract.parseSha256(try stringField(value, name));
}

fn optionalU64(value: std.json.Value) !?u64 {
    return switch (value) {
        .null => null,
        .integer => |number| std.math.cast(u64, number) orelse
            error.InvalidRetainedJournalDescription,
        else => error.InvalidRetainedJournalDescription,
    };
}

fn optionalU32(value: std.json.Value) !?u32 {
    const result = try optionalU64(value);
    return if (result) |number|
        std.math.cast(u32, number) orelse
            error.InvalidRetainedJournalDescription
    else
        null;
}

fn optionalDigest(value: std.json.Value) !?[32]u8 {
    return switch (value) {
        .null => null,
        .string => |text| try contract.parseSha256(text),
        else => error.InvalidRetainedJournalDescription,
    };
}

fn optionalCompletionReason(value: std.json.Value) !?CompletionReason {
    return switch (value) {
        .null => null,
        .string => |text| std.meta.stringToEnum(CompletionReason, text) orelse
            error.InvalidRetainedJournalDescription,
        else => error.InvalidRetainedJournalDescription,
    };
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "journal family rows map transcript tags into enum slots without losing totals" {
    const canonical = frontend.witness_layout.canonical_families;
    try std.testing.expect(@intFromEnum(canonical[0]) != 0);

    var rows: [family_count]u64 = .{0} ** family_count;
    var occupied: [family_count]bool = .{false} ** family_count;
    var expected_total: u64 = 0;
    for (canonical, 0..) |family, transcript_index| {
        const row_count: u64 = @intCast(transcript_index + 1);
        expected_total += row_count;
        try storeFamilyRow(
            &rows,
            &occupied,
            transcript_index,
            @tagName(family),
            row_count,
        );
    }
    var actual_total: u64 = 0;
    for (rows) |row_count| actual_total += row_count;
    try std.testing.expectEqual(expected_total, actual_total);
    try std.testing.expectEqual(@as(u64, 1), rows[@intFromEnum(canonical[0])]);
    try std.testing.expectEqual(
        @as(u64, 3),
        rows[@intFromEnum(Family.base_alu_reg)],
    );

    var duplicate_rows: [family_count]u64 = .{0} ** family_count;
    var duplicate_occupied: [family_count]bool = .{false} ** family_count;
    try storeFamilyRow(
        &duplicate_rows,
        &duplicate_occupied,
        0,
        @tagName(canonical[0]),
        1,
    );
    try std.testing.expectError(
        error.InvalidRetainedJournalDescription,
        storeFamilyRow(
            &duplicate_rows,
            &duplicate_occupied,
            0,
            @tagName(canonical[0]),
            1,
        ),
    );
    try std.testing.expectError(
        error.InvalidRetainedJournalDescription,
        storeFamilyRow(
            &duplicate_rows,
            &duplicate_occupied,
            1,
            @tagName(canonical[0]),
            1,
        ),
    );
}

test "boundary diagnostics identify side segment and every exact field" {
    const observed = ObservedBoundary{
        .pc = 0x1234,
        .cpu_sha256 = .{0x11} ** 32,
        .memory_sha256 = .{0x22} ** 32,
        .retained_words = 41,
        .nonzero_words = 29,
        .access_clocks_sha256 = .{0x33} ** 32,
        .memory_clock_entries = 17,
    };
    const matching = ExpectedBoundary{
        .pc = observed.pc,
        .cpu_sha256 = observed.cpu_sha256,
        .memory_sha256 = observed.memory_sha256,
        .retained_words = observed.retained_words,
        .nonzero_words = observed.nonzero_words,
        .access_clocks_sha256 = observed.access_clocks_sha256,
        .memory_clock_entries = observed.memory_clock_entries,
    };
    try std.testing.expectEqual(
        @as(?BoundaryDiagnostic, null),
        classifyBoundaryMismatch(37, .entry, observed, matching),
    );
    try std.testing.expectEqual(
        @as(?BoundaryDiagnostic, null),
        classifyBoundaryMismatch(37, .exit, observed, matching),
    );

    var mutated = matching;
    mutated.pc +%= 4;
    try expectBoundaryDiagnostic(
        .entry,
        37,
        .pc,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=37 side=entry field=pc" ++
            " observed=4660 expected=4664",
    );

    mutated = matching;
    mutated.cpu_sha256[0] ^= 1;
    try expectBoundaryDiagnostic(
        .entry,
        37,
        .cpu_digest,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=37 side=entry" ++
            " field=cpu_digest",
    );

    mutated = matching;
    mutated.memory_sha256[0] ^= 1;
    try expectBoundaryDiagnostic(
        .entry,
        37,
        .memory_digest,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=37 side=entry" ++
            " field=memory_digest",
    );

    mutated = matching;
    mutated.retained_words += 1;
    try expectBoundaryDiagnostic(
        .entry,
        37,
        .retained_word_count,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=37 side=entry" ++
            " field=retained_word_count observed=41 expected=42" ++
            " observed_zero_words=12 expected_zero_words=13",
    );

    mutated = matching;
    mutated.nonzero_words += 1;
    try expectBoundaryDiagnostic(
        .entry,
        37,
        .nonzero_word_count,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=37 side=entry" ++
            " field=nonzero_word_count observed=29 expected=30",
    );

    mutated = matching;
    mutated.access_clocks_sha256[0] ^= 1;
    try expectBoundaryDiagnostic(
        .entry,
        37,
        .access_clock_digest,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=37 side=entry" ++
            " field=access_clock_digest",
    );

    mutated = matching;
    mutated.memory_clock_entries += 1;
    try expectBoundaryDiagnostic(
        .exit,
        62,
        .access_clock_count,
        observed,
        mutated,
        "retained journal boundary mismatch: segment=62 side=exit" ++
            " field=access_clock_count observed=17 expected=18",
    );

    mutated = matching;
    mutated.retained_words = mutated.nonzero_words - 1;
    const underflow = classifyBoundaryMismatch(
        37,
        .entry,
        observed,
        mutated,
    ) orelse return error.MissingBoundaryDiagnostic;
    var underflow_storage: [maximum_boundary_diagnostic_bytes]u8 = undefined;
    try std.testing.expectError(
        error.Overflow,
        formatBoundaryDiagnostic(
            &underflow_storage,
            underflow,
            observed,
            mutated,
        ),
    );
}

fn expectBoundaryDiagnostic(
    side: BoundarySide,
    segment_index: u32,
    field: BoundaryField,
    observed: ObservedBoundary,
    expected: ExpectedBoundary,
    expected_message: []const u8,
) !void {
    const diagnostic = classifyBoundaryMismatch(
        segment_index,
        side,
        observed,
        expected,
    ) orelse return error.MissingBoundaryDiagnostic;
    try std.testing.expectEqualDeep(BoundaryDiagnostic{
        .segment_index = segment_index,
        .side = side,
        .field = field,
    }, diagnostic);
    var storage: [maximum_boundary_diagnostic_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        expected_message,
        try formatBoundaryDiagnostic(&storage, diagnostic, observed, expected),
    );
}
