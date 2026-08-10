//! Exact, adversarial, and allocation-bound C-008 interaction evidence.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const components = @import("component_registry.zig");
const subject = @import("interaction.zig");
const main_trace = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const registry = @import("relation_registry.zig");
const relation_challenges = @import("relation_challenges.zig");
const statement_mod = @import("statement.zig");

const caller_main_start: usize = main_trace.preprocessed_column_count;
const provider_main_start: usize = caller_main_start + main_trace.caller_main_column_count;

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn byte(word: u32, index: usize) u32 {
    return (word >> @intCast(index * 8)) & 0xff;
}

fn wordBytes(word: u32) [4]QM31 {
    return .{ q(byte(word, 0)), q(byte(word, 1)), q(byte(word, 2)), q(byte(word, 3)) };
}

fn assign(entry: *subject.Entry, values: anytype) void {
    std.debug.assert(values.len == entry.arity);
    inline for (values, 0..) |value, index| entry.values[index] = value;
}

fn assignMemory(
    entry: *subject.Entry,
    address_space: u32,
    address: u32,
    clock: u32,
    limbs: [4]QM31,
) void {
    assign(entry, .{
        q(address_space), q(address), q(clock),
        limbs[0],         limbs[1],   limbs[2],
        limbs[3],
    });
}

/// Independent log-facing oracle: this never reads the committed main trace.
fn oracleCallerEntry(
    record: call_buffer.Record,
    event_index: usize,
) subject.Entry {
    const plan = components.caller_events[event_index];
    var entry = subject.Entry{
        .schema = plan.schema,
        .role = plan.role,
        .access_ordinal = plan.access_ordinal,
        .numerator = switch (plan.numerator) {
            .negative_active => q(1).neg(),
            .positive_active => q(1),
            .zero_in_guest_mode => QM31.zero(),
        },
        .values = undefined,
        .arity = plan.arity,
    };
    const span_end_word = record.state_ptr / @sizeOf(u32) + 15;
    switch (plan.projection) {
        .program => assign(&entry, .{
            q(record.pc),               q(components.guest_opcode_id), QM31.zero(),
            q(record.pointer_register), QM31.zero(),
        }),
        .state_before => assign(&entry, .{ q(record.pc), q(record.execution_clock) }),
        .state_after => assign(&entry, .{
            q(record.pc + 4), q(record.execution_clock + 1),
        }),
        .pointer_consume => assignMemory(
            &entry,
            0,
            record.pointer_register,
            record.pointer_previous_clock,
            wordBytes(record.state_ptr),
        ),
        .pointer_emit => assignMemory(
            &entry,
            0,
            record.pointer_register,
            access_clock.encode(record.execution_clock, .first),
            wordBytes(record.state_ptr),
        ),
        .pointer_clock_gap => assign(&entry, .{q(
            access_clock.encode(record.execution_clock, .first) -
                record.pointer_previous_clock - 1,
        )}),
        .lane_consume => {
            const lane = plan.index;
            assignMemory(
                &entry,
                1,
                record.state_ptr + 4 * @as(u32, lane),
                record.memory_previous_clocks[lane],
                wordBytes(record.input[lane]),
            );
        },
        .lane_emit => {
            const lane = plan.index;
            assignMemory(
                &entry,
                1,
                record.state_ptr + 4 * @as(u32, lane),
                access_clock.encode(record.execution_clock, .second),
                wordBytes(record.output[lane]),
            );
        },
        .lane_clock_gap => assign(&entry, .{q(
            access_clock.encode(record.execution_clock, .second) -
                record.memory_previous_clocks[plan.index] - 1,
        )}),
        .input_byte_pair => {
            const word = record.input[plan.index];
            assign(&entry, .{
                q(byte(word, 2 * plan.part)),
                q(byte(word, 2 * plan.part + 1)),
            });
        },
        .input_high_limb => assign(&entry, .{
            QM31.zero(), q(byte(record.input[plan.index], 3)),
        }),
        .output_byte_pair => {
            const word = record.output[plan.index];
            assign(&entry, .{
                q(byte(word, 2 * plan.part)),
                q(byte(word, 2 * plan.part + 1)),
            });
        },
        .output_high_limb => assign(&entry, .{
            QM31.zero(), q(byte(record.output[plan.index], 3)),
        }),
        .pointer_span_low => assign(&entry, .{
            q(byte(span_end_word, 0)), q(byte(span_end_word, 1)),
        }),
        .pointer_span_high => assign(&entry, .{
            q(byte(span_end_word, 2)),
            q(4 * byte(record.state_ptr, 3)),
            q(byte(span_end_word, 3) & 0x0f),
        }),
        .guest_input_output => {
            for (record.input, record.output, 0..) |input, output, lane| {
                entry.values[lane] = q(input);
                entry.values[16 + lane] = q(output);
            }
        },
        else => unreachable,
    }
    return entry;
}

fn expectEntry(expected: subject.Entry, actual: subject.Entry) !void {
    try std.testing.expectEqual(expected.schema, actual.schema);
    try std.testing.expectEqual(expected.role, actual.role);
    try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
    try std.testing.expect(expected.numerator.eql(actual.numerator));
    try std.testing.expectEqual(expected.arity, actual.arity);
    for (expected.values[0..expected.arity], actual.values[0..actual.arity]) |expected_value, actual_value| {
        try std.testing.expect(expected_value.eql(actual_value));
    }
}

fn expectPair(expected: @import("../logup.zig").RowPair, actual: @TypeOf(expected)) !void {
    try std.testing.expect(expected.n1.eql(actual.n1));
    try std.testing.expect(expected.d1.eql(actual.d1));
    try std.testing.expect(expected.n2.eql(actual.n2));
    try std.testing.expect(expected.d2.eql(actual.d2));
}

fn callerSecureRow(main: *const main_trace.Result, row: usize) [main_trace.caller_main_column_count]QM31 {
    var result: [main_trace.caller_main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(main.callerMain(column)[row]);
    }
    return result;
}

fn providerSecureRow(main: *const main_trace.Result, row: usize) [main_trace.provider_main_column_count]QM31 {
    var result: [main_trace.provider_main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(main.providerMain(column)[row]);
    }
    return result;
}

fn callerSums(interaction: *const subject.Result, row: usize) [subject.caller_batch_count]QM31 {
    var result: [subject.caller_batch_count]QM31 = undefined;
    for (&result, 0..) |*value, batch| {
        value.* = QM31.fromM31Array(.{
            interaction.callerColumn(4 * batch)[row],
            interaction.callerColumn(4 * batch + 1)[row],
            interaction.callerColumn(4 * batch + 2)[row],
            interaction.callerColumn(4 * batch + 3)[row],
        });
    }
    return result;
}

fn providerSums(interaction: *const subject.Result, row: usize) [subject.provider_batch_count]QM31 {
    var result: [subject.provider_batch_count]QM31 = undefined;
    for (&result, 0..) |*value, batch| {
        value.* = QM31.fromM31Array(.{
            interaction.providerColumn(4 * batch)[row],
            interaction.providerColumn(4 * batch + 1)[row],
            interaction.providerColumn(4 * batch + 2)[row],
            interaction.providerColumn(4 * batch + 3)[row],
        });
    }
    return result;
}

fn expectAllZero(values: anytype) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

fn expectSomeNonZero(values: anytype) !void {
    for (values) |value| if (!value.isZero()) return;
    return error.TestExpectedSomeNonZero;
}

fn callerCell(main: *main_trace.Result, column: usize, row: usize) *M31 {
    return &main.storage[(caller_main_start + column) * main.domainSize() + row];
}

fn providerCell(main: *main_trace.Result, column: usize, row: usize) *M31 {
    return &main.storage[(provider_main_start + column) * main.domainSize() + row];
}

test "guest interaction reconstructs every caller event and authenticated batch in order" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const row = main_trace.committedRow(0, main.log_size);
    const secure = callerSecureRow(&main, row);
    const relations = relation_challenges.Poseidon2V1Relations.dummy();

    for (components.caller_events, 0..) |plan, event_index| {
        try std.testing.expectEqual(event_index, plan.ordinal);
        try expectEntry(
            oracleCallerEntry(logs.calls.records()[0], event_index),
            try subject.callerEntry(&secure, event_index),
        );
    }
    try std.testing.expectError(
        error.InvalidEventIndex,
        subject.callerEntry(&secure, subject.caller_event_count),
    );

    const pairs = try subject.callerRowPairs(&secure, &relations);
    for (components.caller_batches, pairs, 0..) |batch, actual, ordinal| {
        try std.testing.expectEqual(ordinal, batch.ordinal);
        try std.testing.expectEqual(@as(u16, @intCast(4 * ordinal)), batch.interaction_column_start);
        const first = try subject.callerEntry(&secure, batch.first_event);
        const expected = if (batch.second_event) |second_index| blk: {
            const second = try subject.callerEntry(&secure, second_index);
            break :blk @import("../logup.zig").RowPair{
                .n1 = first.numerator,
                .d1 = try first.denominator(&relations),
                .n2 = second.numerator,
                .d2 = try second.denominator(&relations),
            };
        } else @import("../logup.zig").RowPair.single(
            first.numerator,
            try first.denominator(&relations),
        );
        try expectPair(expected, actual);
    }
    try std.testing.expectEqual(@as(u8, 152), components.caller_batches[76].first_event);
    try std.testing.expectEqual(@as(?u8, null), components.caller_batches[76].second_event);
}

test "guest provider compatibility exactly replaces only the IO interaction" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const row = main_trace.committedRow(0, main.log_size);
    const secure = providerSecureRow(&main, row);
    const production = poseidon2_air.entries(secure);
    const relations = relation_challenges.Poseidon2V1Relations.dummy();

    try std.testing.expectEqual(@as(usize, 4), production.len);
    for (0..3) |event_index| {
        const expected = production.entries[event_index];
        const actual = try subject.providerEntry(&secure, event_index);
        try std.testing.expectEqual(@intFromEnum(expected.domain), @intFromEnum(actual.schema));
        try std.testing.expectEqual(expected.arity, actual.arity);
        try std.testing.expect(actual.numerator.eql(expected.numerator));
        try std.testing.expect(actual.numerator.isZero());
        for (expected.values[0..expected.arity], actual.values[0..actual.arity]) |a, b| {
            try std.testing.expect(a.eql(b));
        }
    }
    const guest = try subject.providerEntry(&secure, 3);
    try std.testing.expectEqual(registry.guest_schema_id, guest.schema);
    try std.testing.expectEqual(.emit, guest.role);
    try std.testing.expect(guest.numerator.eql(QM31.one()));
    for (logs.calls.records()[0].input, logs.calls.records()[0].output, 0..) |input, output, lane| {
        try std.testing.expect(guest.values[lane].eql(q(input)));
        try std.testing.expect(guest.values[16 + lane].eql(q(output)));
    }

    // Coefficients are profile-fixed, not inferred from mutable mode cells.
    // The provider AIR separately pins `(wide, io) = (0, 1)`.
    var forged_modes = secure;
    forged_modes[poseidon2_air.N_MAIN_COLUMNS - 2] = QM31.one();
    forged_modes[poseidon2_air.N_MAIN_COLUMNS - 1] = QM31.zero();
    for (0..3) |event_index| {
        try std.testing.expect((try subject.providerEntry(
            &forged_modes,
            event_index,
        )).numerator.isZero());
    }
    try std.testing.expect((try subject.providerEntry(
        &forged_modes,
        3,
    )).numerator.eql(QM31.one()));

    const pairs = try subject.providerRowPairs(&secure, &relations);
    for (components.provider_batches, pairs, 0..) |batch, actual, ordinal| {
        try std.testing.expectEqual(ordinal, batch.ordinal);
        const first = try subject.providerEntry(&secure, batch.first_event);
        const second = try subject.providerEntry(&secure, batch.second_event.?);
        try expectPair(.{
            .n1 = first.numerator,
            .d1 = try first.denominator(&relations),
            .n2 = second.numerator,
            .d2 = try second.denominator(&relations),
        }, actual);
    }
    try std.testing.expectError(
        error.InvalidEventIndex,
        subject.providerEntry(&secure, subject.provider_event_count),
    );
}

test "honest interaction columns satisfy every active padding and cyclic boundary row" {
    var core = support.coreFixture(3);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 3);
    var logs = try support.logsFixture(std.testing.allocator, 3);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relation_challenges.Poseidon2V1Relations.dummy();
    var interaction = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();

    try std.testing.expectEqual(@as(u32, 4), interaction.log_size);
    try std.testing.expectEqual(@as(u32, 3), interaction.n_rows);
    try std.testing.expectEqual(@as(usize, 16), interaction.domainSize());
    try std.testing.expectEqual(
        subject.total_column_count * interaction.domainSize(),
        interaction.committedCells().len,
    );
    try std.testing.expect(interaction.provider_claims[0].isZero());
    try interaction.verifyGuestCancellation();
    try std.testing.expect(interaction.guestRelationTotal().isZero());

    for (0..interaction.domainSize()) |logical_row| {
        const row = main_trace.committedRow(logical_row, interaction.log_size);
        const previous_logical = if (logical_row == 0)
            interaction.domainSize() - 1
        else
            logical_row - 1;
        const previous_row = main_trace.committedRow(previous_logical, interaction.log_size);
        const caller_constraints = try subject.callerInteractionConstraints(
            &callerSecureRow(&main, row),
            q(@intFromBool(logical_row == 0)),
            callerSums(&interaction, row),
            callerSums(&interaction, previous_row),
            interaction.caller_claims,
            &relations,
        );
        const provider_constraints = try subject.providerInteractionConstraints(
            &providerSecureRow(&main, row),
            q(@intFromBool(logical_row == 0)),
            providerSums(&interaction, row),
            providerSums(&interaction, previous_row),
            interaction.provider_claims,
            &relations,
        );
        try expectAllZero(caller_constraints);
        try expectAllZero(provider_constraints);

        if (logical_row >= interaction.n_rows) {
            for (callerSums(&interaction, row), interaction.caller_claims) |actual, claim| {
                try std.testing.expect(actual.eql(claim));
            }
            for (providerSums(&interaction, row), interaction.provider_claims) |actual, claim| {
                try std.testing.expect(actual.eql(claim));
            }
        }
    }

    var expected_caller_guest = QM31.zero();
    var expected_provider_guest = QM31.zero();
    for (0..interaction.n_rows) |logical_row| {
        const row = main_trace.committedRow(logical_row, interaction.log_size);
        const caller_guest = try subject.callerEntry(&callerSecureRow(&main, row), 152);
        const provider_guest = try subject.providerEntry(&providerSecureRow(&main, row), 3);
        expected_caller_guest = expected_caller_guest.add(try caller_guest.term(&relations));
        expected_provider_guest = expected_provider_guest.add(try provider_guest.term(&relations));
    }
    try std.testing.expect(expected_caller_guest.eql(interaction.caller_claims[76]));
    try std.testing.expect(expected_provider_guest.eql(interaction.provider_claims[1]));
    try std.testing.expect(expected_caller_guest.add(expected_provider_guest).isZero());

    const padding_row = main_trace.committedRow(interaction.n_rows, interaction.log_size);
    interaction.storage[padding_row] = interaction.storage[padding_row].add(M31.one());
    try expectSomeNonZero(try subject.callerInteractionConstraints(
        &callerSecureRow(&main, padding_row),
        QM31.zero(),
        callerSums(&interaction, padding_row),
        callerSums(&interaction, main_trace.committedRow(
            interaction.n_rows - 1,
            interaction.log_size,
        )),
        interaction.caller_claims,
        &relations,
    ));
}

test "zero-call interaction is one owned zero block with zero claims" {
    var core = support.coreFixture(0);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 0);
    var logs = try support.logsFixture(std.testing.allocator, 0);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relation_challenges.Poseidon2V1Relations.dummy();
    var interaction = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();

    try std.testing.expectEqual(@as(usize, 16), interaction.domainSize());
    try expectAllZero(interaction.committedCells());
    try expectAllZero(interaction.caller_claims);
    try expectAllZero(interaction.provider_claims);
    try interaction.verifyGuestCancellation();
}

test "committed caller mutation fails constraints and regenerated guest cancellation" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relation_challenges.Poseidon2V1Relations.dummy();
    var honest = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer honest.deinit();

    const row = main_trace.committedRow(0, main.log_size);
    callerCell(&main, components.caller_layout.inputByte(0, 0), row).* = M31.one();
    const forged_constraints = try subject.callerInteractionConstraints(
        &callerSecureRow(&main, row),
        QM31.one(),
        callerSums(&honest, row),
        callerSums(&honest, main_trace.committedRow(15, main.log_size)),
        honest.caller_claims,
        &relations,
    );
    try expectSomeNonZero(forged_constraints);

    var regenerated = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer regenerated.deinit();
    try std.testing.expectError(
        error.UnbalancedGuestRelation,
        regenerated.verifyGuestCancellation(),
    );
}

test "omitted caller or provider and duplicated provider cannot balance the guest multiset" {
    const relations = relation_challenges.Poseidon2V1Relations.dummy();

    {
        var core = support.coreFixture(1);
        const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
        var logs = try support.logsFixture(std.testing.allocator, 1);
        defer logs.deinit();
        var main = try main_trace.generate(
            std.testing.allocator,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        defer main.deinit();
        const row = main_trace.committedRow(0, main.log_size);

        callerCell(&main, components.caller_layout.enabler, row).* = M31.zero();
        var caller_omitted = try subject.generate(
            std.testing.allocator,
            &core,
            &extension,
            &main,
            &relations,
        );
        defer caller_omitted.deinit();
        try std.testing.expectError(
            error.UnbalancedGuestRelation,
            caller_omitted.verifyGuestCancellation(),
        );
        callerCell(&main, components.caller_layout.enabler, row).* = M31.one();

        providerCell(&main, 0, row).* = M31.zero();
        var interaction = try subject.generate(
            std.testing.allocator,
            &core,
            &extension,
            &main,
            &relations,
        );
        defer interaction.deinit();
        try std.testing.expectError(
            error.UnbalancedGuestRelation,
            interaction.verifyGuestCancellation(),
        );
    }

    {
        var core = support.coreFixture(3);
        const extension = try statement_mod.ExtensionStatement.canonical(&core, 3);
        var logs = try support.logsFixture(std.testing.allocator, 3);
        defer logs.deinit();
        var main = try main_trace.generate(
            std.testing.allocator,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        defer main.deinit();
        const source = main_trace.committedRow(0, main.log_size);
        const destination = main_trace.committedRow(2, main.log_size);
        for (0..main_trace.provider_main_column_count) |column| {
            providerCell(&main, column, destination).* = providerCell(&main, column, source).*;
        }
        var interaction = try subject.generate(
            std.testing.allocator,
            &core,
            &extension,
            &main,
            &relations,
        );
        defer interaction.deinit();
        try std.testing.expectError(
            error.UnbalancedGuestRelation,
            interaction.verifyGuestCancellation(),
        );
    }
}

fn exerciseAllocationFailures(
    allocator: std.mem.Allocator,
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    main: *const main_trace.Result,
    relations: *const relation_challenges.Poseidon2V1Relations,
) !void {
    var interaction = try subject.generate(allocator, core, extension, main, relations);
    defer interaction.deinit();
}

test "interaction preflights before allocation and rolls back both allocations" {
    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var logs = try support.logsFixture(std.testing.allocator, 2);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relation_challenges.Poseidon2V1Relations.dummy();

    var malformed = main;
    malformed.n_rows += 1;
    var preflight_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(error.InvalidMainTraceShape, subject.generate(
        preflight_failing.allocator(),
        &core,
        &extension,
        &malformed,
        &relations,
    ));
    try std.testing.expect(!preflight_failing.has_induced_failure);

    const first_row = main_trace.committedRow(0, main.log_size);
    const caller_active_cell = &main.storage[main.domainSize() + first_row];
    caller_active_cell.* = M31.zero();
    var selector_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(error.MainTraceSelectorMismatch, subject.generate(
        selector_failing.allocator(),
        &core,
        &extension,
        &main,
        &relations,
    ));
    try std.testing.expect(!selector_failing.has_induced_failure);
    caller_active_cell.* = M31.one();

    var scratch_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    try std.testing.expectError(error.OutOfMemory, subject.generate(
        scratch_failing.allocator(),
        &core,
        &extension,
        &main,
        &relations,
    ));
    try std.testing.expect(scratch_failing.has_induced_failure);

    // Success at fail index two proves generation performs exactly two
    // allocations: retained columns followed by bounded scratch.
    var third_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 2 },
    );
    var exact_two = try subject.generate(
        third_failing.allocator(),
        &core,
        &extension,
        &main,
        &relations,
    );
    defer exact_two.deinit();
    try std.testing.expect(!third_failing.has_induced_failure);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAllocationFailures,
        .{ &core, &extension, &main, &relations },
    );
}

test "nonzero guest coefficient rejects a zero denominator without leaks" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const row = main_trace.committedRow(0, main.log_size);
    const caller = callerSecureRow(&main, row);
    const guest = try subject.callerEntry(&caller, 152);

    var zero_coefficient_relations = relation_challenges.Poseidon2V1Relations.dummy();
    const provider = providerSecureRow(&main, row);
    const unused_input = try subject.providerEntry(&provider, 0);
    zero_coefficient_relations.base.poseidon2.z =
        zero_coefficient_relations.base.poseidon2.z.add(
            try unused_input.denominator(&zero_coefficient_relations),
        );
    try std.testing.expect((try unused_input.denominator(
        &zero_coefficient_relations,
    )).isZero());
    var accepted = try subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &zero_coefficient_relations,
    );
    defer accepted.deinit();
    try accepted.verifyGuestCancellation();

    var relations = relation_challenges.Poseidon2V1Relations.dummy();
    const old_denominator = try guest.denominator(&relations);
    relations.guest_poseidon2_io.z =
        relations.guest_poseidon2_io.z.add(old_denominator);
    try std.testing.expect((try guest.denominator(&relations)).isZero());
    try std.testing.expectError(error.ZeroDenominator, subject.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    ));
}
