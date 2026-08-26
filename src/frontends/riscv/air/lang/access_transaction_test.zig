const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const access_witness = @import("../../runner/access_witness.zig");
const decode = @import("../../isa/decode.zig");
const state_chain = @import("../../runner/state_chain.zig");
const transaction = @import("access_transaction.zig");
const typed_fence = @import("typed_fence.zig");
const typed_fence_authority = @import("typed_fence_authority.zig");
const typed_lui = @import("typed_lui.zig");
const typed_lui_authority = @import("typed_lui_authority.zig");

const DecodedInst = decode.DecodedInst;
const Opcode = decode.Opcode;
const StateChainTracker = state_chain.StateChainTracker;

test "E-017 transaction matches legacy register clocks for every opcode" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    tracker.reg_last_clk[1] = 7;
    tracker.reg_last_clk[2] = 11;
    tracker.reg_last_clk[3] = 13;
    try tracker.mem_last_clk.put(0x2000, 17);

    for (std.enums.values(Opcode)) |opcode| {
        const inst = instruction(opcode, 3, 1, 2, 0);
        const input = honestInput(inst, 20, 0x2000, 0x1122_3344, 0xa5a5_5a5a);
        const compiled = try transaction.compile(&tracker, input);
        const legacy = access_witness.capture(&tracker, inst, input.instruction_clock);

        try std.testing.expectEqual(legacy.rs1_prev_clock, compiled.row_projection.rs1_previous_clock);
        try std.testing.expectEqual(legacy.rs2_prev_clock, compiled.row_projection.rs2_previous_clock);
        try std.testing.expectEqual(legacy.rd_prev_clock, compiled.row_projection.rd_previous_clock);
        try expectRegisterEventClock(&compiled, .rs1, inst.rs1, legacy.rs1_clock);
        try expectRegisterEventClock(&compiled, .rs2, inst.rs2, legacy.rs2_clock);
        try expectRegisterEventClock(&compiled, .rd, inst.rd, legacy.rd_clock);

        if (decode.isLoad(opcode) or decode.isStore(opcode)) {
            const memory = compiled.row_projection.memory.?;
            try std.testing.expectEqual(
                access_clock.encode(input.instruction_clock, .third),
                memory.current_clock,
            );
        } else {
            try std.testing.expect(compiled.row_projection.memory == null);
        }
    }
}

test "E-017 exhaustively resolves all x0 and three-register alias patterns" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    for (&tracker.reg_last_clk, 0..) |*clock, index| {
        clock.* = if (index == 0) 0 else @intCast(index);
    }

    for (0..32) |rs1_raw| {
        for (0..32) |rs2_raw| {
            for (0..32) |rd_raw| {
                const rs1: u5 = @intCast(rs1_raw);
                const rs2: u5 = @intCast(rs2_raw);
                const rd: u5 = @intCast(rd_raw);
                const rs1_value = registerValue(rs1);
                const rs2_value = registerValue(rs2);
                const rd_previous = registerValue(rd);
                const rd_next: u32 = if (rd == 0)
                    0
                else
                    rs1_value +% rs2_value;
                const inst = instruction(.ADD, rd, rs1, rs2, 0);
                const compiled = try transaction.compile(&tracker, .{
                    .instruction = inst,
                    .instruction_clock = 40,
                    .rs1_value = rs1_value,
                    .rs2_value = rs2_value,
                    .rd_previous_value = rd_previous,
                    .rd_next_value = rd_next,
                });
                const legacy = access_witness.capture(&tracker, inst, 40);
                try std.testing.expectEqual(legacy.rs1_prev_clock, compiled.row_projection.rs1_previous_clock);
                try std.testing.expectEqual(legacy.rs2_prev_clock, compiled.row_projection.rs2_previous_clock);
                try std.testing.expectEqual(legacy.rd_prev_clock, compiled.row_projection.rd_previous_clock);
            }
        }
    }
}

test "E-017 rejects forged x0 and aliased values before publication" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try std.testing.expectError(error.ZeroRegisterValue, transaction.compile(&tracker, .{
        .instruction = instruction(.ADDI, 1, 0, 0, 1),
        .instruction_clock = 2,
        .rs1_value = 9,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 10,
    }));
    try std.testing.expectError(error.ZeroRegisterValue, transaction.compile(&tracker, .{
        .instruction = instruction(.LUI, 0, 0, 0, @bitCast(@as(u32, 0x1234_5000))),
        .instruction_clock = 2,
        .rs1_value = 0,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0x1234_5000,
    }));
    try std.testing.expectError(error.AliasedRegisterValueMismatch, transaction.compile(&tracker, .{
        .instruction = instruction(.ADD, 3, 1, 1, 0),
        .instruction_clock = 2,
        .rs1_value = 7,
        .rs2_value = 8,
        .rd_previous_value = 0,
        .rd_next_value = 15,
    }));
    try std.testing.expectError(error.AliasedRegisterValueMismatch, transaction.compile(&tracker, .{
        .instruction = instruction(.ADDI, 1, 1, 0, 1),
        .instruction_clock = 2,
        .rs1_value = 7,
        .rs2_value = 0,
        .rd_previous_value = 8,
        .rd_next_value = 8,
    }));
}

test "E-017 preserves logical load ordering while committing physical clocks" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const previous_word: u32 = 0x80aa_55fe;
    const compiled = try transaction.compile(&tracker, .{
        .instruction = instruction(.LB, 5, 5, 0, 3),
        .instruction_clock = 8,
        .rs1_value = 0x2000,
        .rs2_value = 0,
        .rd_previous_value = 0x2000,
        .rd_next_value = 0xffff_ff80,
        .memory_words = .{ .previous = previous_word, .next = previous_word },
    });

    try std.testing.expectEqual(@as(usize, 3), compiled.accessEvents().len);
    try std.testing.expectEqual(transaction.EventKind.register_read, compiled.events[0].kind);
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(compiled.events[0].logical_ordinal));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(compiled.events[0].physical_phase));
    try std.testing.expectEqual(transaction.EventKind.register_write, compiled.events[1].kind);
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(compiled.events[1].logical_ordinal));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(compiled.events[1].physical_phase));
    try std.testing.expectEqual(compiled.events[0].current_clock, compiled.events[1].raw_previous_clock);
    try std.testing.expectEqual(transaction.EventKind.memory_read, compiled.events[2].kind);
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(compiled.events[2].logical_ordinal));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(compiled.events[2].physical_phase));
}

test "E-017 derives exact load store masks transitions and signed results" {
    const cases = [_]struct {
        opcode: Opcode,
        offset: u2,
        addressed_mask: u4,
        word_mask: u4,
    }{
        .{ .opcode = .LB, .offset = 0, .addressed_mask = 0b0001, .word_mask = 0b0001 },
        .{ .opcode = .LBU, .offset = 3, .addressed_mask = 0b0001, .word_mask = 0b1000 },
        .{ .opcode = .LH, .offset = 0, .addressed_mask = 0b0011, .word_mask = 0b0011 },
        .{ .opcode = .LHU, .offset = 2, .addressed_mask = 0b0011, .word_mask = 0b1100 },
        .{ .opcode = .LW, .offset = 0, .addressed_mask = 0b1111, .word_mask = 0b1111 },
        .{ .opcode = .SB, .offset = 3, .addressed_mask = 0b0001, .word_mask = 0b1000 },
        .{ .opcode = .SH, .offset = 2, .addressed_mask = 0b0011, .word_mask = 0b1100 },
        .{ .opcode = .SW, .offset = 0, .addressed_mask = 0b1111, .word_mask = 0b1111 },
    };
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();

    for (cases) |case| {
        const rs2_value: u32 = 0xdead_beef;
        const previous: u32 = 0x807f_2211;
        const inst = instruction(case.opcode, 3, 1, 2, case.offset);
        const next = expectedMemoryNext(case.opcode, previous, rs2_value, case.offset);
        const result = expectedLoadResult(case.opcode, previous, case.offset);
        const compiled = try transaction.compile(&tracker, .{
            .instruction = inst,
            .instruction_clock = 4,
            .rs1_value = 0x2000,
            .rs2_value = rs2_value,
            .rd_previous_value = 0x1234,
            .rd_next_value = if (decode.isLoad(case.opcode)) result else 0,
            .memory_words = .{ .previous = previous, .next = next },
        });
        const memory = compiled.row_projection.memory.?;
        try std.testing.expectEqual(case.addressed_mask, memory.addressed_mask);
        try std.testing.expectEqual(case.word_mask, if (decode.isLoad(case.opcode))
            memory.word_read_mask
        else
            memory.word_write_mask);
        try std.testing.expectEqual(@as(u32, 0x2000) + case.offset, memory.effective_address);
        try std.testing.expectEqual(@as(u32, 0x2000), memory.aligned_address);
        try std.testing.expectEqual(next, memory.next_word);
    }
}

test "E-017 rejects address transition and load-result forgeries" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const previous: u32 = 0x8877_6655;

    try std.testing.expectError(error.MemoryAddressMisaligned, transaction.compile(&tracker, .{
        .instruction = instruction(.LH, 3, 1, 0, 1),
        .instruction_clock = 2,
        .rs1_value = 0x2000,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0,
        .memory_words = .{ .previous = previous, .next = previous },
    }));
    try std.testing.expectError(error.MemoryAddressOutOfRange, transaction.compile(&tracker, .{
        .instruction = instruction(.LW, 3, 1, 0, 0),
        .instruction_clock = 2,
        .rs1_value = transaction.MAX_ALIGNED_DATA_ADDRESS + 4,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = previous,
        .memory_words = .{ .previous = previous, .next = previous },
    }));
    try std.testing.expectError(error.MemoryBaseOutOfRange, transaction.compile(&tracker, .{
        .instruction = instruction(.LW, 3, 1, 0, 0),
        .instruction_clock = 2,
        .rs1_value = transaction.M31_MODULUS,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = previous,
        .memory_words = .{ .previous = previous, .next = previous },
    }));
    try std.testing.expectError(error.MemoryTransitionMismatch, transaction.compile(&tracker, .{
        .instruction = instruction(.SB, 0, 1, 2, 1),
        .instruction_clock = 2,
        .rs1_value = 0x2000,
        .rs2_value = 0xaa,
        .rd_previous_value = 0,
        .rd_next_value = 0,
        .memory_words = .{ .previous = previous, .next = previous },
    }));
    try std.testing.expectError(error.LoadResultMismatch, transaction.compile(&tracker, .{
        .instruction = instruction(.LB, 3, 1, 0, 0),
        .instruction_clock = 2,
        .rs1_value = 0x2000,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0x55,
        .memory_words = .{ .previous = 0x80, .next = 0x80 },
    }));
    try std.testing.expectError(error.MissingMemoryWords, transaction.compile(&tracker, .{
        .instruction = instruction(.LW, 3, 1, 0, 0),
        .instruction_clock = 2,
        .rs1_value = 0x2000,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0,
    }));
    try std.testing.expectError(error.UnexpectedMemoryWords, transaction.compile(&tracker, .{
        .instruction = instruction(.LUI, 3, 0, 0, 0),
        .instruction_clock = 2,
        .rs1_value = 0,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0,
        .memory_words = .{ .previous = 0, .next = 0 },
    }));
}

test "E-017 strict clocks include exact synthetic-gap reservation" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const instruction_clock = state_chain.MAX_CLOCK_DIFF / access_clock.STRIDE + 5;
    const compiled = try transaction.compile(&tracker, .{
        .instruction = instruction(.LUI, 7, 0, 0, @bitCast(@as(u32, 0x1234_5000))),
        .instruction_clock = instruction_clock,
        .rs1_value = 0,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0x1234_5000,
    });
    try std.testing.expectEqual(
        StateChainTracker.clockGapCount(0, compiled.events[0].current_clock),
        compiled.reservation.register_clock_update_count,
    );
    try std.testing.expect(compiled.events[0].previous_clock < compiled.events[0].current_clock);

    try std.testing.expectError(error.ClockOutOfRange, transaction.compile(&tracker, .{
        .instruction = instruction(.FENCE, 0, 0, 0, 0),
        .instruction_clock = 0,
        .rs1_value = 0,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0,
    }));
    try std.testing.expectError(error.ClockOutOfRange, transaction.compile(&tracker, .{
        .instruction = instruction(.FENCE, 0, 0, 0, 0),
        .instruction_clock = (@as(u32, 1) << 24) + 1,
        .rs1_value = 0,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 0,
    }));

    var stale_clock_tracker = StateChainTracker.init(std.testing.allocator);
    defer stale_clock_tracker.deinit();
    stale_clock_tracker.reg_last_clk[1] = access_clock.encode(2, .first);
    try std.testing.expectError(error.NonIncreasingClock, transaction.compile(&stale_clock_tracker, .{
        .instruction = instruction(.ADDI, 2, 1, 0, 1),
        .instruction_clock = 2,
        .rs1_value = 4,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 5,
    }));
}

test "E-017 row projection is failure atomic and LUI-ready" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const authority = try authenticatedLuiAuthority();
    tracker.reg_last_clk[9] = 5;
    const inst = instruction(.LUI, 9, 10, 11, @bitCast(@as(u32, 0xabcde000)));
    const compiled = try transaction.compileLui(&authority, &tracker, .{
        .instruction = inst,
        .instruction_clock = 4,
        .rs1_value = 0x5566_7788,
        .rs2_value = 0x99aa_bbcc,
        .rd_previous_value = 0x1122_3344,
    });
    const generic = try transaction.compile(&tracker, .{
        .instruction = inst,
        .instruction_clock = 4,
        .rs1_value = 0x5566_7788,
        .rs2_value = 0x99aa_bbcc,
        .rd_previous_value = 0x1122_3344,
        .rd_next_value = 0xabcde000,
    });
    try expectTransactionsEqual(&generic, &compiled);
    const legacy = access_witness.capture(&tracker, inst, 4);
    try std.testing.expectEqual(legacy.rd_prev_clock, compiled.row_projection.rd_previous_clock);
    try std.testing.expectEqual(@as(u32, 0xabcde000), compiled.rd_next_value);

    var row = candidateRow(compiled);
    const before = row;
    row.opcode = .AUIPC;
    const forged = row;
    try std.testing.expectError(error.RowProjectionMismatch, compiled.applyToRow(&row));
    try std.testing.expectEqualDeep(forged, row);
    row = before;
    try compiled.applyToRow(&row);
    try std.testing.expectEqual(legacy.rd_prev_clock, row.rd_prev_clk);
    try std.testing.expectEqual(@as(u32, 0), row.mem_addr);
    try std.testing.expect(!row.is_load and !row.is_store);

    try std.testing.expectError(error.WrongLuiOpcode, transaction.compileLui(
        &authority,
        &tracker,
        .{
            .instruction = instruction(.AUIPC, 9, 0, 0, 0),
            .instruction_clock = 4,
            .rs1_value = 0,
            .rs2_value = 0,
            .rd_previous_value = 0,
        },
    ));
}

test "E-019 FENCE compiler authenticates retirement and preserves exact empty geometry" {
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const authority = try authenticatedFenceAuthority();
    for (&tracker.reg_last_clk, 0..) |*clock, index|
        clock.* = @intCast(index * 17);

    const inst = instruction(.FENCE, 31, 17, 19, -173);
    const input = transaction.FenceInput{
        .instruction = inst,
        .instruction_clock = 29,
        .pc_before = 0xffff_fffc,
        .rs1_value = 0x1122_3344,
        .rs2_value = 0x5566_7788,
        .rd_previous_value = 0x99aa_bbcc,
    };
    const compiled = try transaction.compileFence(&authority, &tracker, input);
    const generic = try transaction.compile(&tracker, .{
        .instruction = inst,
        .instruction_clock = input.instruction_clock,
        .rs1_value = input.rs1_value,
        .rs2_value = input.rs2_value,
        .rd_previous_value = input.rd_previous_value,
        .rd_next_value = input.rd_previous_value,
    });
    try expectTransactionsEqual(&generic, &compiled);
    try std.testing.expectEqual(@as(usize, 0), compiled.accessEvents().len);
    try std.testing.expectEqualDeep(
        StateChainTracker.Reservation{
            .memory_address_count = 0,
            .access_count = 0,
            .memory_clock_update_count = 0,
            .register_clock_update_count = 0,
        },
        compiled.reservation,
    );
    try std.testing.expectEqualDeep(transaction.RowProjection{
        .rs1_previous_clock = 0,
        .rs2_previous_clock = 0,
        .rd_previous_clock = 0,
        .memory = null,
    }, compiled.row_projection);

    try std.testing.expectError(error.WrongFenceOpcode, transaction.compileFence(
        &authority,
        &tracker,
        .{
            .instruction = instruction(.ADDI, 0, 0, 0, 0),
            .instruction_clock = 1,
            .pc_before = 0,
            .rs1_value = 0,
            .rs2_value = 0,
            .rd_previous_value = 0,
        },
    ));
    try std.testing.expectError(error.InvalidFenceImmediate, transaction.compileFence(
        &authority,
        &tracker,
        .{
            .instruction = instruction(.FENCE, 0, 0, 0, 2048),
            .instruction_clock = 1,
            .pc_before = 0,
            .rs1_value = 0,
            .rs2_value = 0,
            .rd_previous_value = 0,
        },
    ));
    var invalid_clock = input;
    invalid_clock.instruction_clock = 0;
    try std.testing.expectError(
        error.ClockOutOfRange,
        transaction.compileFence(&authority, &tracker, invalid_clock),
    );
}

test "E-017 prepared commit is allocation-free and matches legacy state chain" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var actual = StateChainTracker.init(failing.allocator());
    defer actual.deinit();
    var expected = StateChainTracker.init(std.testing.allocator);
    defer expected.deinit();
    actual.reg_last_clk[5] = 3;
    expected.reg_last_clk[5] = 3;
    try actual.mem_last_clk.put(0x2000, 2);
    try expected.mem_last_clk.put(0x2000, 2);
    try actual.mem_initial.put(0x2000, 0x4433_2211);
    try expected.mem_initial.put(0x2000, 0x4433_2211);

    const inst = instruction(.LB, 5, 5, 0, 1);
    const input = transaction.Input{
        .instruction = inst,
        .instruction_clock = 6,
        .rs1_value = 0x2000,
        .rs2_value = 0,
        .rd_previous_value = 0x2000,
        .rd_next_value = 0x22,
        .memory_words = .{ .previous = 0x4433_2211, .next = 0x4433_2211 },
    };
    const compiled = try transaction.compile(&actual, input);
    var prepared = try compiled.prepareCommit(&actual);
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try prepared.commit(&actual);
    try std.testing.expect(!failing.has_induced_failure);

    const legacy = access_witness.capture(&expected, inst, input.instruction_clock);
    try legacy.recordRegisters(
        &expected,
        inst,
        input.rs1_value,
        input.rs2_value,
        input.rd_previous_value,
        input.rd_next_value,
    );
    try expected.recordMemTransition(
        0x2000,
        access_clock.encode(input.instruction_clock, .third),
        input.memory_words.?.previous,
        input.memory_words.?.next,
    );
    try expectTrackersEqual(&expected, &actual);
    try std.testing.expectError(error.AlreadyCommitted, prepared.commit(&actual));
}

test "E-017 allocation and stale failures expose no transaction prefix" {
    var observed_failure = false;
    for (0..16) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        const compiled = try transaction.compile(&tracker, .{
            .instruction = instruction(.SW, 0, 1, 2, 0),
            .instruction_clock = 3,
            .rs1_value = 0x2000,
            .rs2_value = 0xdead_beef,
            .rd_previous_value = 0,
            .rd_next_value = 0,
            .memory_words = .{ .previous = 0, .next = 0xdead_beef },
        });
        _ = compiled.prepareCommit(&tracker) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try expectTrackerLogicallyEmpty(&tracker);
            observed_failure = true;
            continue;
        };
        try expectTrackerLogicallyEmpty(&tracker);
        break;
    }
    try std.testing.expect(observed_failure);

    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const compiled = try transaction.compile(&tracker, .{
        .instruction = instruction(.ADDI, 2, 1, 0, 1),
        .instruction_clock = 3,
        .rs1_value = 9,
        .rs2_value = 0,
        .rd_previous_value = 0,
        .rd_next_value = 10,
    });
    tracker.reg_last_clk[1] = 1;
    try std.testing.expectError(error.StaleTransaction, compiled.prepareCommit(&tracker));
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);

    tracker.reg_last_clk[1] = 0;
    var forged_reservation = compiled;
    forged_reservation.reservation.access_count = 0;
    try std.testing.expectError(
        error.StaleTransaction,
        forged_reservation.prepareCommit(&tracker),
    );
    var forged_address = compiled;
    forged_address.events[0].address = 32;
    try std.testing.expectError(
        error.StaleTransaction,
        forged_address.prepareCommit(&tracker),
    );
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
}

const EventRole = enum { rs1, rs2, rd };

fn expectTransactionsEqual(
    expected: *const transaction.Transaction,
    actual: *const transaction.Transaction,
) !void {
    try std.testing.expectEqual(expected.format_version, actual.format_version);
    try std.testing.expectEqualDeep(expected.instruction, actual.instruction);
    try std.testing.expectEqual(expected.instruction_clock, actual.instruction_clock);
    try std.testing.expectEqualDeep(expected.usage, actual.usage);
    try std.testing.expectEqual(expected.rs1_value, actual.rs1_value);
    try std.testing.expectEqual(expected.rs2_value, actual.rs2_value);
    try std.testing.expectEqual(expected.rd_previous_value, actual.rd_previous_value);
    try std.testing.expectEqual(expected.rd_next_value, actual.rd_next_value);
    try std.testing.expectEqualSlices(
        transaction.Event,
        expected.accessEvents(),
        actual.accessEvents(),
    );
    try std.testing.expectEqualDeep(expected.row_projection, actual.row_projection);
    try std.testing.expectEqualDeep(expected.reservation, actual.reservation);
}

fn authenticatedFenceAuthority() !typed_fence_authority.Authority {
    var definition = try typed_fence.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try typed_fence_authority.Binding.canonical(&definition);
    return typed_fence_authority.Authority.init(&definition, &binding);
}

fn authenticatedLuiAuthority() !typed_lui_authority.Authority {
    var definition = try typed_lui.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = typed_lui_authority.Binding.canonical(&definition);
    return typed_lui_authority.Authority.init(&definition, &binding);
}

fn expectRegisterEventClock(
    compiled: *const transaction.Transaction,
    role: EventRole,
    register: u5,
    expected_clock: u32,
) !void {
    const used = switch (role) {
        .rs1 => compiled.usage.reads_rs1,
        .rs2 => compiled.usage.reads_rs2,
        .rd => compiled.usage.writes_rd,
    };
    if (!used) {
        try std.testing.expectEqual(@as(u32, 0), expected_clock);
        return;
    }
    const kind: transaction.EventKind = if (role == .rd)
        .register_write
    else
        .register_read;
    for (compiled.accessEvents()) |event| {
        if (event.kind == kind and event.address == register and
            event.current_clock == expected_clock)
        {
            return;
        }
    }
    return error.ExpectedRegisterEventNotFound;
}

fn instruction(opcode: Opcode, rd: u5, rs1: u5, rs2: u5, imm: i32) DecodedInst {
    return .{
        .opcode = opcode,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = imm,
    };
}

fn honestInput(
    inst: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous: u32,
) transaction.Input {
    const is_load = decode.isLoad(inst.opcode);
    const is_store = decode.isStore(inst.opcode);
    const previous: u32 = 0x807f_2211;
    const next = expectedMemoryNext(inst.opcode, previous, rs2_value, 0);
    return .{
        .instruction = inst,
        .instruction_clock = instruction_clock,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_previous,
        .rd_next_value = if (is_load)
            expectedLoadResult(inst.opcode, previous, 0)
        else if (decode.operandUsage(inst.opcode).writes_rd)
            0x7654_3210
        else
            rd_previous,
        .memory_words = if (is_load or is_store)
            .{ .previous = previous, .next = next }
        else
            null,
    };
}

fn registerValue(register: u5) u32 {
    return if (register == 0) 0 else 0x1000_0000 + @as(u32, register) * 0x0101;
}

fn expectedMemoryNext(opcode: Opcode, previous: u32, value: u32, offset: u2) u32 {
    if (!decode.isStore(opcode)) return previous;
    const width = decode.memoryWidthBytes(opcode).?;
    const mask: u32 = switch (width) {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        else => unreachable,
    };
    const shift: u5 = @intCast(@as(u6, offset) * 8);
    return (previous & ~(mask << shift)) | ((value & mask) << shift);
}

fn expectedLoadResult(opcode: Opcode, previous: u32, offset: u2) u32 {
    if (!decode.isLoad(opcode)) return 0;
    const width = decode.memoryWidthBytes(opcode).?;
    const mask: u32 = switch (width) {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        else => unreachable,
    };
    const shift: u5 = @intCast(@as(u6, offset) * 8);
    const value = (previous >> shift) & mask;
    return switch (opcode) {
        .LB => @bitCast(@as(i32, @as(i8, @bitCast(@as(u8, @truncate(value)))))),
        .LH => @bitCast(@as(i32, @as(i16, @bitCast(@as(u16, @truncate(value)))))),
        .LBU, .LHU, .LW => value,
        else => unreachable,
    };
}

fn candidateRow(compiled: transaction.Transaction) transaction.TraceRow {
    return .{
        .clk = compiled.instruction_clock,
        .pc = 0x1000,
        .opcode = compiled.instruction.opcode,
        .rd = compiled.instruction.rd,
        .rs1 = compiled.instruction.rs1,
        .rs2 = compiled.instruction.rs2,
        .imm = compiled.instruction.imm,
        .rs1_val = compiled.rs1_value,
        .rs2_val = compiled.rs2_value,
        .rd_prev_val = compiled.rd_previous_value,
        .rd_val = compiled.rd_next_value,
        .mem_addr = 0xaaaa_aaaa,
        .mem_val = 0xbbbb_bbbb,
        .mem_prev_word = 0xcccc_cccc,
        .mem_next_word = 0xdddd_dddd,
        .is_load = true,
        .is_store = true,
        .branch_taken = false,
        .next_pc = 0x1004,
    };
}

fn expectTrackersEqual(expected: *const StateChainTracker, actual: *const StateChainTracker) !void {
    try std.testing.expectEqual(expected.reg_last_clk, actual.reg_last_clk);
    try std.testing.expectEqualSlices(state_chain.Access, expected.accesses.items, actual.accesses.items);
    try std.testing.expectEqualSlices(
        state_chain.ClockUpdate,
        expected.clock_updates_reg.items,
        actual.clock_updates_reg.items,
    );
    try std.testing.expectEqualSlices(
        state_chain.ClockUpdate,
        expected.clock_updates_mem.items,
        actual.clock_updates_mem.items,
    );
    try std.testing.expectEqual(expected.mem_initial.count(), actual.mem_initial.count());
    try std.testing.expectEqual(expected.mem_last_clk.count(), actual.mem_last_clk.count());
    var keys = expected.mem_last_clk.keyIterator();
    while (keys.next()) |address| {
        try std.testing.expectEqual(expected.mem_last_clk.get(address.*), actual.mem_last_clk.get(address.*));
        try std.testing.expectEqual(expected.mem_initial.get(address.*), actual.mem_initial.get(address.*));
    }
}

fn expectTrackerLogicallyEmpty(tracker: *const StateChainTracker) !void {
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_mem.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.mem_initial.count());
    try std.testing.expectEqual(@as(usize, 0), tracker.mem_last_clk.count());
    try std.testing.expectEqual([_]u32{0} ** 32, tracker.reg_last_clk);
}
