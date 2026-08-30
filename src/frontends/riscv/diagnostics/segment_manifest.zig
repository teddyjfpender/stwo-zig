//! Canonical, streaming execution inventory for bounded RISC-V segments.
//!
//! This is deliberately an execution diagnostic, not a proof artifact.  Each
//! NDJSON record is content-addressed and chained to its predecessor, while
//! entry/exit CPU, sparse memory, and access-clock states are independently
//! hashed.  A durable controller can therefore replay from the ELF after a
//! crash, compare an already-fsynced prefix, and append only a byte-identical
//! continuation without retaining the whole execution trace in memory.

const std = @import("std");
const runner = @import("../runner/mod.zig");
const memory_state = @import("../runner/memory_state.zig");
const result_mod = @import("../runner/result.zig");
const trace_mod = @import("../runner/trace.zig");
const witness_layout = @import("../witness_layout.zig");
const segment_statement_v2 = @import("../recursion/segment_statement_v2.zig");

pub const HEADER_SCHEMA = "stwo.riscv.segmented-execution-header.v1";
pub const SEGMENT_SCHEMA = "stwo.riscv.segmented-execution-segment.v1";
pub const SUMMARY_SCHEMA = "stwo.riscv.segmented-execution-summary.v1";
pub const CLAIM_BOUNDARY = "execution-only-not-a-proof";

const Digest = [32]u8;

const HeaderPayload = struct {
    schema: []const u8,
    profile: []const u8,
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

const BoundaryPayload = struct {
    pc: u32,
    cpu_sha256: []const u8,
    rw_memory_sha256: []const u8,
    rw_memory_retained_words: u64,
    rw_memory_nonzero_words: u64,
    access_clocks_sha256: []const u8,
    memory_access_clock_entries: u64,
};

const SegmentPayload = struct {
    schema: []const u8,
    previous_record_sha256: []const u8,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u64,
    is_first: bool,
    is_last: bool,
    entry: BoundaryPayload,
    exit: BoundaryPayload,
    core_trace_rows: u64,
    external_trace_rows: u64,
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

const SummaryPayload = struct {
    schema: []const u8,
    previous_record_sha256: []const u8,
    claim_boundary: []const u8,
    completed: bool,
    segment_count: u32,
    total_cycles: u64,
    total_core_trace_rows: u64,
    total_external_trace_rows: u64,
    total_unclassified_core_rows: u64,
    opcode_family_rows: []const FamilyRows,
    completion_reason: []const u8,
    exit_code: ?u32,
    output_bytes: ?u64,
    output_sha256: ?[]const u8,
    final_cpu_sha256: []const u8,
    final_rw_memory_sha256: []const u8,
    final_access_clocks_sha256: []const u8,
    segment_statement_v2_global_cycle_limit: u32,
    segment_statement_v2_admissible: bool,
};

const MemoryDigest = struct {
    digest: Digest,
    nonzero_words: u64,
};

const Side = enum { initial, final };

/// Execute a base RV32IM guest as bounded, segment-owned ranges and stream one
/// canonical NDJSON chain.  The writer is flushed after every record so a
/// supervising process can fsync a verified prefix before the next segment.
pub fn stream(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    segment_step_budget: usize,
    strict_completion: bool,
    writer: *std.Io.Writer,
) !void {
    if (segment_step_budget == 0) return error.ZeroSegmentStepBudget;

    const elf_digest = sha256(elf_bytes);
    const input_digest = sha256(input);
    const elf_hex = hex(elf_digest);
    const input_hex = hex(input_digest);
    var previous_record = try writeEnvelope(allocator, writer, HeaderPayload{
        .schema = HEADER_SCHEMA,
        .profile = "rv32im-zkvm-v1",
        .claim_boundary = CLAIM_BOUNDARY,
        .elf_bytes = try u64FromUsize(elf_bytes.len),
        .elf_sha256 = &elf_hex,
        .input_bytes = try u64FromUsize(input.len),
        .input_sha256 = &input_hex,
        .segment_step_budget = try u64FromUsize(segment_step_budget),
        .strict_completion = strict_completion,
        .trace_retention = "segment-owned",
    });

    var session = try runner.BaseExecutionSession.init(allocator, elf_bytes, .{
        .input = input,
        .stop_on_halt_flag = strict_completion,
        .strict_completion = strict_completion,
        .trace_retention = .segment_owned,
    });
    defer session.deinit();

    var continuation: ?runner.ContinuationToken = null;
    var expected_cpu: ?Digest = null;
    var expected_memory: ?Digest = null;
    var expected_clocks: ?Digest = null;
    var total_cycles: u64 = 0;
    var total_core_rows: u64 = 0;
    var total_external_rows: u64 = 0;
    var total_unclassified_rows: u64 = 0;
    var total_families = trace_mod.OpcodeFamilyCounts{};
    var final_cpu: Digest = undefined;
    var final_memory: Digest = undefined;
    var final_clocks: Digest = undefined;
    var final_completion: ?result_mod.CompletionReason = null;
    var final_exit_code: ?u32 = null;
    var final_output_digest: ?Digest = null;
    var final_output_bytes: ?u64 = null;

    while (true) {
        var segment = if (continuation) |token|
            try session.resumeSegment(token, segment_step_budget)
        else
            try session.startSegment(segment_step_budget);
        defer segment.deinit();

        const entry_cpu = digestCpu(segment.entry_cpu);
        const exit_cpu = digestCpu(segment.exit_cpu);
        const entry_memory = digestMemory(segment.rw_memory, .initial);
        const exit_memory = digestMemory(segment.rw_memory, .final);
        const entry_clocks = digestAccessClocks(segment.entry_access_clocks);
        const exit_clocks = digestAccessClocks(segment.exit_access_clocks);
        if (expected_cpu) |digest| try requireDigest(digest, entry_cpu);
        if (expected_memory) |digest| try requireDigest(digest, entry_memory.digest);
        if (expected_clocks) |digest| try requireDigest(digest, entry_clocks);

        var family_counts = trace_mod.OpcodeFamilyCounts{};
        var unclassified_rows: u64 = 0;
        for (segment.execution_trace.rows.items) |row| {
            const family = trace_mod.proofOpcodeFamily(row.opcode) catch {
                unclassified_rows += 1;
                continue;
            };
            family_counts.increment(family);
            total_families.increment(family);
        }
        total_unclassified_rows = std.math.add(
            u64,
            total_unclassified_rows,
            unclassified_rows,
        ) catch return error.ExecutionCycleCountOverflow;
        var family_rows: [witness_layout.canonical_families.len]FamilyRows = undefined;
        fillFamilyRows(&family_rows, &family_counts);

        const cycles = try u64FromUsize(segment.cycle_count);
        const core_rows = try u64FromUsize(segment.execution_trace.rows.items.len);
        if (try u64FromUsize(family_counts.total()) + unclassified_rows != core_rows)
            return error.OpcodeInventoryMismatch;
        const external_rows = std.math.sub(u64, cycles, core_rows) catch
            return error.TraceCycleCountMismatch;
        total_cycles = std.math.add(u64, total_cycles, cycles) catch
            return error.ExecutionCycleCountOverflow;
        total_core_rows = std.math.add(u64, total_core_rows, core_rows) catch
            return error.ExecutionCycleCountOverflow;
        total_external_rows = std.math.add(u64, total_external_rows, external_rows) catch
            return error.ExecutionCycleCountOverflow;

        const previous_hex = hex(previous_record);
        const entry_cpu_hex = hex(entry_cpu);
        const exit_cpu_hex = hex(exit_cpu);
        const entry_memory_hex = hex(entry_memory.digest);
        const exit_memory_hex = hex(exit_memory.digest);
        const entry_clocks_hex = hex(entry_clocks);
        const exit_clocks_hex = hex(exit_clocks);
        const completion_name: ?[]const u8 = if (segment.completion_reason) |reason|
            @tagName(reason)
        else
            null;
        const output_digest: ?Digest = if (segment.output) |output| sha256(output) else null;
        const output_hex = if (output_digest) |digest| hex(digest) else undefined;
        const continuation_digest: ?Digest = if (segment.continuation) |token|
            digestContinuation(token)
        else
            null;
        const continuation_hex = if (continuation_digest) |digest| hex(digest) else undefined;
        previous_record = try writeEnvelope(allocator, writer, SegmentPayload{
            .schema = SEGMENT_SCHEMA,
            .previous_record_sha256 = &previous_hex,
            .segment_index = segment.segment_index,
            .global_first_cycle = segment.global_first_cycle,
            .cycle_count = cycles,
            .is_first = segment.segment_role.is_first,
            .is_last = segment.segment_role.is_last,
            .entry = boundaryPayload(
                segment.entry_cpu.pc,
                &entry_cpu_hex,
                &entry_memory_hex,
                segment.rw_memory.words.len,
                entry_memory.nonzero_words,
                &entry_clocks_hex,
                segment.entry_access_clocks.memory_clocks.len,
            ),
            .exit = boundaryPayload(
                segment.exit_cpu.pc,
                &exit_cpu_hex,
                &exit_memory_hex,
                segment.rw_memory.words.len,
                exit_memory.nonzero_words,
                &exit_clocks_hex,
                segment.exit_access_clocks.memory_clocks.len,
            ),
            .core_trace_rows = core_rows,
            .external_trace_rows = external_rows,
            .unclassified_core_rows = unclassified_rows,
            .opcode_family_rows = &family_rows,
            .completion_reason = completion_name,
            .completion_address = segment.completion_address,
            .completion_value = segment.completion_value,
            .completion_clock = segment.completion_clock,
            .exit_code = segment.exit_code,
            .output_bytes = if (segment.output) |output| try u64FromUsize(output.len) else null,
            .output_sha256 = if (output_digest != null) &output_hex else null,
            .continuation_sha256 = if (continuation_digest != null) &continuation_hex else null,
        });

        expected_cpu = exit_cpu;
        expected_memory = exit_memory.digest;
        expected_clocks = exit_clocks;
        continuation = segment.continuation;
        if (!segment.isComplete()) continue;

        final_cpu = exit_cpu;
        final_memory = exit_memory.digest;
        final_clocks = exit_clocks;
        final_completion = segment.completion_reason;
        final_exit_code = segment.exit_code;
        final_output_digest = output_digest;
        final_output_bytes = if (segment.output) |output| try u64FromUsize(output.len) else null;
        break;
    }

    var total_family_rows: [witness_layout.canonical_families.len]FamilyRows = undefined;
    fillFamilyRows(&total_family_rows, &total_families);
    const previous_hex = hex(previous_record);
    const final_cpu_hex = hex(final_cpu);
    const final_memory_hex = hex(final_memory);
    const final_clocks_hex = hex(final_clocks);
    const output_hex = if (final_output_digest) |digest| hex(digest) else undefined;
    _ = try writeEnvelope(allocator, writer, SummaryPayload{
        .schema = SUMMARY_SCHEMA,
        .previous_record_sha256 = &previous_hex,
        .claim_boundary = CLAIM_BOUNDARY,
        .completed = true,
        .segment_count = session.next_segment_index,
        .total_cycles = total_cycles,
        .total_core_trace_rows = total_core_rows,
        .total_external_trace_rows = total_external_rows,
        .total_unclassified_core_rows = total_unclassified_rows,
        .opcode_family_rows = &total_family_rows,
        .completion_reason = @tagName(final_completion.?),
        .exit_code = final_exit_code,
        .output_bytes = final_output_bytes,
        .output_sha256 = if (final_output_digest != null) &output_hex else null,
        .final_cpu_sha256 = &final_cpu_hex,
        .final_rw_memory_sha256 = &final_memory_hex,
        .final_access_clocks_sha256 = &final_clocks_hex,
        .segment_statement_v2_global_cycle_limit = segment_statement_v2.MAX_GLOBAL_CYCLES,
        .segment_statement_v2_admissible = total_cycles <= segment_statement_v2.MAX_GLOBAL_CYCLES,
    });
}

fn writeEnvelope(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    payload: anytype,
) !Digest {
    const encoded = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(encoded);
    const digest = sha256(encoded);
    const digest_hex = hex(digest);
    try std.json.Stringify.value(.{
        .payload = payload,
        .content_sha256 = digest_hex[0..],
    }, .{}, writer);
    try writer.writeByte('\n');
    try writer.flush();
    return digest;
}

fn boundaryPayload(
    pc: u32,
    cpu_sha256: []const u8,
    rw_memory_sha256: []const u8,
    retained_words: usize,
    nonzero_words: u64,
    access_clocks_sha256: []const u8,
    memory_clock_entries: usize,
) BoundaryPayload {
    return .{
        .pc = pc,
        .cpu_sha256 = cpu_sha256,
        .rw_memory_sha256 = rw_memory_sha256,
        .rw_memory_retained_words = u64FromUsize(retained_words) catch unreachable,
        .rw_memory_nonzero_words = nonzero_words,
        .access_clocks_sha256 = access_clocks_sha256,
        .memory_access_clock_entries = u64FromUsize(memory_clock_entries) catch unreachable,
    };
}

fn fillFamilyRows(
    destination: *[witness_layout.canonical_families.len]FamilyRows,
    counts: *const trace_mod.OpcodeFamilyCounts,
) void {
    for (witness_layout.canonical_families, 0..) |family, index| {
        destination[index] = .{
            .family = @tagName(family),
            .rows = u64FromUsize(counts.get(family)) catch unreachable,
        };
    }
}

fn digestCpu(cpu: runner.Cpu) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-cpu/v1\x00");
    updateInt(&hash, u32, cpu.pc);
    for (cpu.regs) |value| updateInt(&hash, u32, value);
    return hash.finalResult();
}

fn digestMemory(snapshot: memory_state.Snapshot, comptime side: Side) MemoryDigest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-memory/v1\x00");
    inline for (@typeInfo(memory_state.MemoryLayout).@"struct".fields) |field| {
        updateInt(&hash, u32, @field(snapshot.layout, field.name));
    }
    var nonzero_words: u64 = 0;
    for (snapshot.words) |word| {
        const value = switch (side) {
            .initial => word.initial_word,
            .final => word.final_word,
        };
        nonzero_words += @intFromBool(value != 0);
    }
    updateInt(&hash, u64, nonzero_words);
    for (snapshot.words) |word| {
        const value = switch (side) {
            .initial => word.initial_word,
            .final => word.final_word,
        };
        if (value == 0) continue;
        updateInt(&hash, u32, word.addr);
        updateInt(&hash, u32, value);
    }
    return .{ .digest = hash.finalResult(), .nonzero_words = nonzero_words };
}

fn digestAccessClocks(boundary: result_mod.AccessClockBoundary) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-access-clocks/v1\x00");
    for (boundary.register_clocks) |clock| updateInt(&hash, u32, clock);
    updateInt(&hash, u64, u64FromUsize(boundary.memory_clocks.len) catch unreachable);
    for (boundary.memory_clocks) |entry| {
        updateInt(&hash, u32, entry.addr);
        updateInt(&hash, u32, entry.clock);
    }
    return hash.finalResult();
}

fn digestContinuation(token: runner.ContinuationToken) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-continuation/v1\x00");
    updateInt(&hash, u32, token.schema_version);
    updateInt(&hash, u64, token.session_tag);
    updateInt(&hash, u32, token.next_segment_index);
    updateInt(&hash, u64, token.next_cycle);
    hash.update(&digestCpu(token.cpu));
    updateInt(&hash, u32, token.rw_memory.word_count);
    updateInt(&hash, u64, token.rw_memory.fingerprint);
    updateInt(&hash, u64, token.access_clocks);
    return hash.finalResult();
}

fn updateInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn sha256(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn hex(digest: Digest) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

fn u64FromUsize(value: usize) !u64 {
    return std.math.cast(u64, value) orelse error.IntegerOutOfRange;
}

fn requireDigest(expected: Digest, actual: Digest) !void {
    if (!std.mem.eql(u8, &expected, &actual)) return error.SegmentBoundaryMismatch;
}

test "segmented manifest is deterministic, chained, and exposes V2 claim boundary" {
    const elf = runner.trace_dump.buildTestElf(5, .{
        0x0010_0093, // ADDI x1, x0, 1.
        0x0010_8093, // ADDI x1, x1, 1.
        0x0010_8093, // ADDI x1, x1, 1.
        0x0010_8093, // ADDI x1, x1, 1.
        0x0000_0073, // ECALL.
    });
    var first = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer first.deinit();
    try stream(std.testing.allocator, &elf, &.{}, 2, false, &first.writer);
    var second = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer second.deinit();
    try stream(std.testing.allocator, &elf, &.{}, 2, false, &second.writer);
    try std.testing.expectEqualStrings(first.written(), second.written());
    try std.testing.expectEqual(@as(usize, 5), std.mem.count(u8, first.written(), "\n"));
    try std.testing.expect(std.mem.indexOf(u8, first.written(), HEADER_SCHEMA) != null);
    try std.testing.expect(std.mem.indexOf(u8, first.written(), SEGMENT_SCHEMA) != null);
    try std.testing.expect(std.mem.indexOf(u8, first.written(), SUMMARY_SCHEMA) != null);
    try std.testing.expect(std.mem.indexOf(u8, first.written(), "\"segment_count\":3,\"total_cycles\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, first.written(), "\"segment_statement_v2_admissible\":true") != null);
}
