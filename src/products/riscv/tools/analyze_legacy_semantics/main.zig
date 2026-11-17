//! Exact diagnostic observer for Revm42 legacy analysis; command orchestration only.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const witness_codes = @import("witness_codes.zig");

const runner = frontend.runner;

const authority_owner = @import("authority.zig");
const InputFile = authority_owner.InputFile;
const JournalAuthority = authority_owner.JournalAuthority;
const Options = authority_owner.Options;
const cargo_lock_sha256 = authority_owner.cargo_lock_sha256;
const clock_frame = authority_owner.clock_frame;
const expected_call_count = authority_owner.expected_call_count;
const expected_length_sum = authority_owner.expected_length_sum;
const maximum_elf_bytes = authority_owner.maximum_elf_bytes;
const maximum_evidence_bytes = authority_owner.maximum_evidence_bytes;
const maximum_executable_bytes = authority_owner.maximum_executable_bytes;
const maximum_input_bytes = authority_owner.maximum_input_bytes;
const maximum_journal_bytes = authority_owner.maximum_journal_bytes;
const maximum_source_bytes = authority_owner.maximum_source_bytes;
const revm_source_sha256 = authority_owner.revm_source_sha256;
const validateNmAuthority = authority_owner.validateNmAuthority;
const capture_owner = @import("capture.zig");
const Capture = capture_owner.Capture;
const observation_owner = @import("observation.zig");
const encodeObservation = observation_owner.encodeObservation;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = try Options.parse(args[1..]);

    var executable = try InputFile.open(
        allocator,
        args[0],
        maximum_executable_bytes,
    );
    defer executable.deinit(allocator);
    var elf = try InputFile.open(allocator, options.elf, maximum_elf_bytes);
    defer elf.deinit(allocator);
    var input = try InputFile.open(allocator, options.input, maximum_input_bytes);
    defer input.deinit(allocator);
    var journal = try InputFile.open(
        allocator,
        options.execution_journal,
        maximum_journal_bytes,
    );
    defer journal.deinit(allocator);
    var observer_source = try InputFile.open(
        allocator,
        options.observer_source,
        maximum_source_bytes,
    );
    defer observer_source.deinit(allocator);
    var observer_semantics_source = try InputFile.open(
        allocator,
        options.observer_semantics_source,
        maximum_source_bytes,
    );
    defer observer_semantics_source.deinit(allocator);
    var observer_witness_source = try InputFile.open(
        allocator,
        options.observer_witness_source,
        maximum_source_bytes,
    );
    defer observer_witness_source.deinit(allocator);
    var revm_source = try InputFile.open(
        allocator,
        options.revm_source,
        maximum_source_bytes,
    );
    defer revm_source.deinit(allocator);
    var cargo_lock = try InputFile.open(
        allocator,
        options.cargo_lock,
        maximum_source_bytes,
    );
    defer cargo_lock.deinit(allocator);
    var function_value_evidence = try InputFile.open(
        allocator,
        options.function_value_evidence,
        maximum_evidence_bytes,
    );
    defer function_value_evidence.deinit(allocator);
    var nm_map = try InputFile.open(
        allocator,
        options.nm_map,
        maximum_evidence_bytes,
    );
    defer nm_map.deinit(allocator);
    var pc_observation = try InputFile.open(
        allocator,
        options.pc_observation,
        maximum_evidence_bytes,
    );
    defer pc_observation.deinit(allocator);
    if (!std.mem.eql(u8, &revm_source.sha256_hex, revm_source_sha256) or
        !std.mem.eql(u8, &cargo_lock.sha256_hex, cargo_lock_sha256))
    {
        return error.RevmAuthorityMismatch;
    }
    try validateNmAuthority(nm_map.bytes);

    var inventory = try witness_codes.parse(allocator, input.bytes);
    defer inventory.deinit(allocator);
    if (inventory.codes.len != 120 or inventory.total_bytes != 1_328_577 or
        inventory.legacy_count != expected_call_count or
        inventory.legacy_bytes != expected_length_sum or
        inventory.eip7702_delegation_count != 4 or inventory.empty_count != 1)
    {
        return error.WitnessCodeInventoryMismatch;
    }
    inline for ([_]usize{ 4, 30, 70, 110 }) |index| {
        if (inventory.codes[index].classification != .eip7702_delegation or
            inventory.codes[index].bytes.len != 23)
        {
            return error.WitnessCodeInventoryMismatch;
        }
    }
    if (inventory.codes[119].classification != .empty)
        return error.WitnessCodeInventoryMismatch;

    var expected = try JournalAuthority.parse(
        allocator,
        journal.bytes,
        elf.sha256,
        input.sha256,
        options.segment_count,
    );
    defer expected.deinit(allocator);

    var capture = try Capture.init(allocator, inventory);
    defer capture.deinit();
    var session = try runner.EthereumExecutionSession.init(allocator, elf.bytes, .{
        .input = input.bytes,
        .stop_on_halt_flag = true,
        .strict_completion = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .retirement_observer = capture.observer(),
    });
    defer session.deinit();

    var continuation: ?runner.result_mod.ContinuationToken = null;
    for (expected.segments, 0..) |wanted, index| {
        var segment = if (index == 0)
            try session.startSegment(expected.segment_step_budget)
        else
            try session.resumeSegment(
                continuation orelse return error.MissingContinuation,
                expected.segment_step_budget,
            );
        defer segment.deinit();
        if (segment.base.segment_index != wanted.segment_index or
            segment.base.global_first_cycle != wanted.global_first_cycle or
            segment.base.cycle_count != wanted.cycle_count or
            segment.base.execution_trace.rows.items.len != wanted.core_trace_rows or
            capture.current_segment_rows != wanted.core_trace_rows)
        {
            return error.JournalExecutionMismatch;
        }
        try capture.finishSegment(segment.base.rw_memory, wanted.segment_index);
        continuation = segment.base.continuation;
        if (index + 1 < expected.segments.len and continuation == null)
            return error.ExecutionCompletedBeforeSample;
    }

    try capture.validate(expected.retired_instructions, expected.segments.len);
    const encoded = try encodeObservation(
        allocator,
        &capture,
        expected,
        executable,
        elf,
        input,
        journal,
        observer_source,
        observer_semantics_source,
        observer_witness_source,
        revm_source,
        cargo_lock,
        function_value_evidence,
        nm_map,
        pc_observation,
        inventory,
    );
    defer allocator.free(encoded);
    try std.fs.File.stdout().writeAll(encoded);
}

test {
    _ = @import("tests.zig");
}
