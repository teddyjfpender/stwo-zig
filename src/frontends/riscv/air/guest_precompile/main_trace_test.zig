//! Exact and adversarial C-007 guest main-trace evidence.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const m31 = @import("stwo_core").fields.m31;
const access_clock = @import("../../access_clock.zig");
const custom0 = @import("../../isa/custom0.zig");
const isa_profile = @import("../../isa/profile.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const components = @import("component_registry.zig");
const subject = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const statement_mod = @import("statement.zig");

fn expectValue(expected: u32, actual: M31) !void {
    try std.testing.expectEqual(expected, actual.toU32());
}

fn byte(word: u32, index: usize) u32 {
    return (word >> @intCast(index * 8)) & 0xff;
}

fn expectAllZero(values: []const M31) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

test "guest main trace has exact caller provider selectors and padding" {
    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var logs = try support.logsFixture(std.testing.allocator, 2);
    defer logs.deinit();
    var result = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 4), result.log_size);
    try std.testing.expectEqual(@as(u32, 2), result.n_rows);
    try std.testing.expectEqual(@as(usize, 16), result.domainSize());
    try std.testing.expectEqual(
        subject.total_column_count * result.domainSize(),
        result.committedCells().len,
    );

    const base = @intFromPtr(result.committedCells().ptr);
    const column_bytes = result.domainSize() * @sizeOf(M31);
    try std.testing.expectEqual(base, @intFromPtr(result.callerPreprocessed(0).ptr));
    try std.testing.expectEqual(base + column_bytes, @intFromPtr(result.callerPreprocessed(1).ptr));
    try std.testing.expectEqual(base + 2 * column_bytes, @intFromPtr(result.providerPreprocessed(0).ptr));
    try std.testing.expectEqual(base + 4 * column_bytes, @intFromPtr(result.callerMain(0).ptr));
    try std.testing.expectEqual(base + 290 * column_bytes, @intFromPtr(result.providerMain(0).ptr));

    for (0..result.domainSize()) |logical_row| {
        const dst = subject.committedRow(logical_row, result.log_size);
        const is_first: u32 = @intFromBool(logical_row == 0);
        const is_active: u32 = @intFromBool(logical_row < 2);
        try expectValue(is_first, result.callerPreprocessed(0)[dst]);
        try expectValue(is_active, result.callerPreprocessed(1)[dst]);
        try expectValue(is_first, result.providerPreprocessed(0)[dst]);
        try expectValue(is_active, result.providerPreprocessed(1)[dst]);
    }

    const layout = components.caller_layout;
    for (logs.calls.records(), 0..) |record, logical_row| {
        const dst = subject.committedRow(logical_row, result.log_size);
        try expectValue(1, result.callerMain(layout.enabler)[dst]);
        try expectValue(record.execution_clock, result.callerMain(layout.execution_clock)[dst]);
        try expectValue(record.pc, result.callerMain(layout.pc)[dst]);
        try expectValue(record.pointer_register, result.callerMain(layout.pointer_register)[dst]);
        try expectValue(record.pointer_previous_clock, result.callerMain(layout.pointer_previous_clock)[dst]);
        for (0..4) |part| {
            try expectValue(
                byte(record.state_ptr, part),
                result.callerMain(layout.pointer_bytes + part)[dst],
            );
        }
        const word_index = record.state_ptr / 4;
        const span_end = word_index + 15;
        try expectValue(word_index, result.callerMain(layout.pointer_word_index)[dst]);
        try expectValue(byte(span_end, 0), result.callerMain(layout.span_end_limbs)[dst]);
        try expectValue(byte(span_end, 1), result.callerMain(layout.span_end_limbs + 1)[dst]);
        try expectValue(byte(span_end, 2), result.callerMain(layout.span_end_limbs + 2)[dst]);
        try expectValue((span_end >> 24) & 0x0f, result.callerMain(layout.span_end_limbs + 3)[dst]);

        for (record.input, 0..) |word, lane| {
            for (0..4) |part| try expectValue(
                byte(word, part),
                result.callerMain(layout.inputByte(@intCast(lane), @intCast(part)))[dst],
            );
            const expected = support.independentCanonicalMaterializations(word);
            for (expected, 0..) |value, materialization| {
                try std.testing.expect(value.eql(result.callerMain(
                    layout.canonicalMaterialization(false, @intCast(lane), @intCast(materialization)),
                )[dst]));
            }
        }
        for (record.output, 0..) |word, lane| {
            for (0..4) |part| try expectValue(
                byte(word, part),
                result.callerMain(layout.outputByte(@intCast(lane), @intCast(part)))[dst],
            );
            const expected = support.independentCanonicalMaterializations(word);
            for (expected, 0..) |value, materialization| {
                try std.testing.expect(value.eql(result.callerMain(
                    layout.canonicalMaterialization(true, @intCast(lane), @intCast(materialization)),
                )[dst]));
            }
        }
        for (record.memory_previous_clocks, 0..) |clock, lane| {
            try expectValue(clock, result.callerMain(layout.previousClock(@intCast(lane)))[dst]);
        }

        const provider = poseidon2_air.fill(.{
            .input = record.input,
            .wide = false,
            .io = true,
        });
        for (provider, 0..) |value, column| {
            try std.testing.expect(value.eql(result.providerMain(column)[dst]));
        }
        const output = poseidon2_air.output(provider);
        for (output, record.output) |actual, expected| {
            try std.testing.expectEqual(expected, actual.toU32());
        }
    }

    // Equal function tuples remain two ordered unit rows.
    const first = subject.committedRow(0, result.log_size);
    const second = subject.committedRow(1, result.log_size);
    for (0..64) |column| {
        try std.testing.expect(result.callerMain(layout.input_bytes + column)[first].eql(
            result.callerMain(layout.input_bytes + column)[second],
        ));
        try std.testing.expect(result.callerMain(layout.output_bytes + column)[first].eql(
            result.callerMain(layout.output_bytes + column)[second],
        ));
    }
    try expectValue(1, result.callerMain(layout.execution_clock)[first]);
    try expectValue(2, result.callerMain(layout.execution_clock)[second]);

    for (2..result.domainSize()) |logical_row| {
        const dst = subject.committedRow(logical_row, result.log_size);
        for (0..subject.caller_main_column_count) |column| {
            try std.testing.expect(result.callerMain(column)[dst].isZero());
        }
        for (0..subject.provider_main_column_count) |column| {
            try std.testing.expect(result.providerMain(column)[dst].isZero());
        }
    }
}

test "guest main trace zero-call geometry and deterministic replay are exact" {
    var zero_core = support.coreFixture(0);
    const zero_extension = try statement_mod.ExtensionStatement.canonical(&zero_core, 0);
    var zero_logs = try support.logsFixture(std.testing.allocator, 0);
    defer zero_logs.deinit();
    var zero = try subject.generate(
        std.testing.allocator,
        &zero_core,
        &zero_extension,
        &zero_logs.calls,
        &zero_logs.rows,
    );
    defer zero.deinit();
    try std.testing.expectEqual(@as(u32, 4), zero.log_size);
    try std.testing.expectEqual(@as(usize, 16), zero.domainSize());
    try expectValue(1, zero.callerPreprocessed(0)[subject.committedRow(0, 4)]);
    try expectValue(1, zero.providerPreprocessed(0)[subject.committedRow(0, 4)]);
    try expectAllZero(zero.callerPreprocessed(1));
    try expectAllZero(zero.providerPreprocessed(1));
    for (0..subject.caller_main_column_count) |column| try expectAllZero(zero.callerMain(column));
    for (0..subject.provider_main_column_count) |column| try expectAllZero(zero.providerMain(column));

    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var logs = try support.logsFixture(std.testing.allocator, 2);
    defer logs.deinit();
    var first = try subject.generate(std.testing.allocator, &core, &extension, &logs.calls, &logs.rows);
    defer first.deinit();
    var second = try subject.generate(std.testing.allocator, &core, &extension, &logs.calls, &logs.rows);
    defer second.deinit();
    try std.testing.expectEqualSlices(M31, first.committedCells(), second.committedCells());
}

test "guest main trace uses one canonical bit-reversal placement above minimum log" {
    var core = support.coreFixture(17);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    var result = try subject.generate(std.testing.allocator, &core, &extension, &logs.calls, &logs.rows);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 5), result.log_size);
    try std.testing.expectEqual(@as(usize, 32), result.domainSize());
    try std.testing.expect(subject.committedRow(1, 5) != 1);
    for (0..result.domainSize()) |logical_row| {
        const dst = subject.committedRow(logical_row, 5);
        const active = logical_row < 17;
        try expectValue(@intFromBool(active), result.callerPreprocessed(1)[dst]);
        try expectValue(@intFromBool(active), result.providerPreprocessed(1)[dst]);
        try expectValue(
            if (active) @intCast(logical_row + 1) else 0,
            result.callerMain(components.caller_layout.execution_clock)[dst],
        );
    }
}

test "guest main trace rejects every noncanonical input and output representative" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    const invalid = [_]u32{
        m31.Modulus,
        m31.Modulus + 1,
        2 * m31.Modulus,
        std.math.maxInt(u32),
    };
    const original_input = logs.calls.storage.items[0].input[0];
    for (invalid) |word| {
        logs.calls.storage.items[0].input[0] = word;
        try std.testing.expectError(
            error.NonCanonicalPrecompileWord,
            subject.generate(std.testing.allocator, &core, &extension, &logs.calls, &logs.rows),
        );
    }
    logs.calls.storage.items[0].input[0] = original_input;
    logs.calls.storage.items[0].output[0] = m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalPrecompileWord,
        subject.generate(std.testing.allocator, &core, &extension, &logs.calls, &logs.rows),
    );
}

test "guest main trace rejects malformed counts order instruction pointer and clocks" {
    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var logs = try support.logsFixture(std.testing.allocator, 2);
    defer logs.deinit();
    const original_record = logs.calls.storage.items[1];
    const original_row = logs.rows.storage.items[1];

    logs.rows.storage.items[1].call_index = 0;
    try std.testing.expectError(error.CallIndexMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.rows.storage.items[1] = original_row;

    logs.rows.storage.items[1].execution_clock += 1;
    try std.testing.expectError(error.ExecutionClockMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.rows.storage.items[1] = original_row;

    logs.calls.storage.items[1].execution_clock = 0;
    logs.rows.storage.items[1].execution_clock = 0;
    try std.testing.expectError(error.ExecutionClockOutOfRange, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;
    logs.rows.storage.items[1] = original_row;

    logs.calls.storage.items[1].execution_clock = 1;
    logs.rows.storage.items[1].execution_clock = 1;
    try std.testing.expectError(error.ExecutionOrderMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;
    logs.rows.storage.items[1] = original_row;

    logs.rows.storage.items[1].pc += 4;
    try std.testing.expectError(error.PcMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.rows.storage.items[1] = original_row;

    logs.calls.storage.items[1].pc = 0x1002;
    logs.rows.storage.items[1].pc = 0x1002;
    try std.testing.expectError(error.MisalignedProgramWord, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;
    logs.rows.storage.items[1] = original_row;

    logs.rows.storage.items[1].inst_word ^= 1;
    try std.testing.expectError(error.IllegalInstruction, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.rows.storage.items[1].inst_word = original_row.inst_word | (1 << 7);
    try std.testing.expectError(error.InvalidPrecompileEncoding, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.rows.storage.items[1].inst_word = custom0.encodePoseidon2(6);
    try std.testing.expectError(error.PointerRegisterMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.rows.storage.items[1] = original_row;

    logs.calls.storage.items[1].state_ptr += 2;
    try std.testing.expectError(error.PrecompileAddressMisaligned, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1].state_ptr = isa_profile.program_commitment_size - 60;
    try std.testing.expectError(error.PrecompileSpanOutOfRange, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;

    logs.calls.storage.items[1].pointer_previous_clock =
        access_clock.encode(original_record.execution_clock, .first);
    try std.testing.expectError(error.PointerPreviousClockInvalid, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;
    logs.calls.storage.items[1].memory_previous_clocks[7] =
        access_clock.encode(original_record.execution_clock, .second);
    try std.testing.expectError(error.MemoryPreviousClockInvalid, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;

    logs.calls.storage.items[1].output[3] +%= 1;
    try std.testing.expectError(error.ProviderOutputMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    logs.calls.storage.items[1] = original_record;

    var short_logs = try support.logsFixture(std.testing.allocator, 1);
    defer short_logs.deinit();
    try std.testing.expectError(error.CallCountMismatch, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &short_logs.calls,
        &short_logs.rows,
    ));
}

fn exerciseAllocationFailures(
    allocator: std.mem.Allocator,
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    calls: *const support.FrozenCalls,
    rows: *const support.FrozenExecutionRows,
) !void {
    var result = try subject.generate(allocator, core, extension, calls, rows);
    defer result.deinit();
}

test "guest main trace preflights before allocation and releases every failure" {
    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var logs = try support.logsFixture(std.testing.allocator, 2);
    defer logs.deinit();

    logs.calls.storage.items[1].output[15] +%= 1;
    var preflight_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(error.ProviderOutputMismatch, subject.generate(
        preflight_failing.allocator(),
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    try std.testing.expect(!preflight_failing.has_induced_failure);
    logs.calls.storage.items[1].output[15] -%= 1;

    var allocation_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(error.OutOfMemory, subject.generate(
        allocation_failing.allocator(),
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    ));
    try std.testing.expect(allocation_failing.has_induced_failure);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAllocationFailures,
        .{ &core, &extension, &logs.calls, &logs.rows },
    );
}

comptime {
    if (call_buffer.lane_count != 16 or subject.total_column_count != 735)
        @compileError("C-007 evidence geometry drifted");
}
