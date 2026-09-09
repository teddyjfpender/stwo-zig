//! Candidate-only SWAP1..SWAP16 semantics, AIR, custody, and mutation tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const caller = @import("../../air/guest_precompile/stack_swap_caller_candidate_v1.zig");
const relations = @import("../../air/guest_precompile/stack_swap_relations_v1.zig");
const words = @import("../../air/guest_precompile/stack_swap_word_candidate_v1.zig");
const base_alu_imm_authority = @import("../../air/lang/typed_base_alu_imm_authority.zig");
const base_alu_reg_authority = @import("../../air/lang/typed_base_alu_reg_authority.zig");
const branch_lt_authority = @import("../../air/lang/typed_branch_lt_authority.zig");
const jalr_authority = @import("../../air/lang/typed_jalr_authority.zig");
const load_store_authority = @import("../../air/lang/typed_load_store_authority.zig");
const shifts_imm_authority = @import("../../air/lang/typed_shifts_imm_authority.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const subject = @import("stack_swap_v1.zig");
const tape_mod = @import("stack_swap_session_tape_v1.zig");

const stack_base: u32 = 0x4000;
const stack_value_count: usize = 17;
const top_index: usize = stack_value_count - 1;

const Sink = struct {
    count: usize = 0,
    nonzero: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: M31, degree: u8) void {
        self.count += 1;
        self.nonzero += @intFromBool(!value.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

fn fixtureAuthority() !abi.Authority {
    var registry_identity: [32]u8 = undefined;
    for (&registry_identity, 0..) |*byte, index|
        byte.* = @intCast(0x41 + index);
    return abi.Authority.create(.{
        // Fixture-only allocation. Production and the ABI request remain
        // unallocated until the shared registry owner assigns both values.
        .funct7 = 5,
        .proof_opcode_id = 49,
        .registry_identity = registry_identity,
    });
}

fn testLayout() MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x2000,
        .data_base = 0x2000,
        .data_end = 0x3000,
        .stack_bottom = stack_base,
        .stack_top = 0x5000,
        .io_base = 0x6000,
        .io_end = 0x7000,
        .input_base = 0x6000,
        .input_end = 0x6100,
        .output_len_addr = 0x6200,
        .output_data_addr = 0x6204,
        .output_base = 0x6200,
        .output_end = 0x7000,
    };
}

fn valuePointer(index: usize) u32 {
    return stack_base + @as(u32, @intCast(index * abi.u256_bytes));
}

fn initialWord(value_index: usize, lane: usize) u32 {
    return 0x5100_0000 |
        (@as(u32, @intCast(value_index)) << 8) |
        @as(u32, @intCast(lane));
}

fn initializeStack(memory: *Memory, expected: *[stack_value_count][words.lane_count]u32) void {
    for (expected, 0..) |*value, value_index| {
        for (value, 0..) |*word, lane| {
            word.* = initialWord(value_index, lane);
            memory.writeU32(
                valuePointer(value_index) + @as(u32, @intCast(lane * abi.word_bytes)),
                word.*,
            );
        }
    }
}

fn stackWindow(memory: *const Memory) [stack_value_count * abi.u256_bytes]u8 {
    var result: [stack_value_count * abi.u256_bytes]u8 = undefined;
    memory.readSlice(stack_base, &result);
    return result;
}

fn canonicalInteractionColumnCount(comptime Authority: type) u64 {
    const count: u64 = Authority.LOOKUP_COUNT;
    const batch: u64 = Authority.LOOKUP_BATCH_SIZE;
    return 2 * ((count + batch - 1) / batch) * batch;
}

test "registry authority is explicit and cold-decodes only its allocated CUSTOM-0 word" {
    try std.testing.expect(!abi.production_active);
    try std.testing.expectEqual(@as(?u7, null), abi.registry_request.requested_funct7);
    try std.testing.expectEqual(
        @as(?u32, null),
        abi.registry_request.requested_proof_opcode_id,
    );
    const authority = try fixtureAuthority();
    try authority.validate();
    const decoded = try authority.decode(authority.fixed_word);
    try std.testing.expectEqual(abi.destination_register, decoded.destination_register);
    try std.testing.expectEqual(abi.lhs_pointer_register, decoded.lhs_pointer_register);
    try std.testing.expectEqual(abi.rhs_pointer_register, decoded.rhs_pointer_register);
    try std.testing.expectError(
        error.InvalidStackSwapEncoding,
        authority.decode(authority.fixed_word ^ 1),
    );

    var changed = authority;
    changed.allocation.proof_opcode_id += 1;
    try std.testing.expectError(error.InvalidStackSwapProgramAuthority, changed.validate());
    changed = authority;
    changed.semantic_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidStackSwapProgramAuthority, changed.validate());
}

test "SWAP1 through SWAP16 exchange exact U256 spans transactionally" {
    const authority = try fixtureAuthority();
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var expected: [stack_value_count][words.lane_count]u32 = undefined;
    initializeStack(&memory, &expected);
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tape = try tape_mod.Builder.init(
        std.testing.allocator,
        authority,
        16,
        0,
    );
    defer tape.deinit();
    var cpu = Cpu.init(0x1000, 0x4ff0);

    for (1..17) |depth| {
        const rhs_index = top_index - depth;
        const lhs_pointer = valuePointer(top_index);
        const rhs_pointer = valuePointer(rhs_index);
        try std.testing.expectEqual(
            @as(u32, @intCast(depth * abi.u256_bytes)),
            lhs_pointer - rhs_pointer,
        );
        cpu.writeReg(abi.lhs_pointer_register, lhs_pointer);
        cpu.writeReg(abi.rhs_pointer_register, rhs_pointer);
        try subject.executeWithRecordedClock(
            authority.fixed_word,
            @intCast(depth),
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &trace,
            &tape,
        );
        const temporary = expected[top_index];
        expected[top_index] = expected[rhs_index];
        expected[rhs_index] = temporary;
        for (expected, 0..) |value, value_index| for (value, 0..) |word, lane|
            try std.testing.expectEqual(
                word,
                memory.readU32(
                    valuePointer(value_index) +
                        @as(u32, @intCast(lane * abi.word_bytes)),
                ),
            );
    }

    try std.testing.expectEqual(@as(u32, 0x1040), cpu.pc);
    try std.testing.expectEqual(@as(usize, 16), tape.len());
    try std.testing.expectEqual(@as(usize, 16 * words.lane_count), tape.wordLen());
    try std.testing.expectEqual(@as(usize, 16), tape.rowLen());
    const counts = tape.externalCounts();
    try std.testing.expectEqual(@as(usize, 16), counts.calls);
    try std.testing.expectEqual(@as(usize, 16), counts.rows);
    try tape.validate();
    try trace.validateClockRange(0, 16, 16);
    const register_clock = access_clock.encode(16, .first);
    try std.testing.expectEqual(
        register_clock,
        tracker.reg_last_clk[abi.lhs_pointer_register],
    );
    try std.testing.expectEqual(
        register_clock,
        tracker.reg_last_clk[abi.rhs_pointer_register],
    );

    var frozen = tape.freeze();
    defer frozen.deinit();
    try frozen.validateAgainst(authority, 0);
    const capture_identity = try frozen.captureIdentity();

    frozen.word_rows.items[0].rhs_before[0] +%= 1;
    const changed_value_identity = try frozen.captureIdentity();
    try std.testing.expect(!std.mem.eql(
        u8,
        &capture_identity,
        &changed_value_identity,
    ));
    frozen.word_rows.items[0].rhs_before[0] -%= 1;
    try frozen.validateAgainst(authority, 0);

    frozen.execution_rows.items[0].inst_word ^= 1;
    try std.testing.expectError(error.InvalidStackSwapEncoding, frozen.validate());
    frozen.execution_rows.items[0].inst_word ^= 1;
    try frozen.validateAgainst(authority, 0);

    frozen.calls.items[0].caller.rhs_pointer += abi.word_bytes;
    try std.testing.expectError(error.InvalidStackSwapCall, frozen.validate());
    frozen.calls.items[0].caller.rhs_pointer -= abi.word_bytes;
    try frozen.validateAgainst(authority, 0);

    var replacement_allocation = authority.allocation;
    replacement_allocation.registry_identity[0] ^= 1;
    frozen.authority = try abi.Authority.create(replacement_allocation);
    try frozen.validate();
    try std.testing.expectError(
        error.InvalidStackSwapSessionAuthority,
        frozen.validateAgainst(authority, 0),
    );
    frozen.authority = authority;
    try frozen.validateAgainst(authority, 0);

    frozen.external_step_origin = 1;
    try std.testing.expectError(
        error.InvalidStackSwapSessionAuthority,
        frozen.validateAgainst(authority, 0),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &capture_identity,
        &(try frozen.captureIdentity()),
    ));
}

test "runner rejects encoding span clock and capacity failures without mutation" {
    const authority = try fixtureAuthority();
    const Case = struct {
        word: u32 = 0,
        clock: u32 = 1,
        lhs: u32 = valuePointer(top_index),
        rhs: u32 = valuePointer(top_index - 1),
        call_limit: usize = 1,
        expected: anyerror,
    };
    const cases = [_]Case{
        .{ .word = authority.fixed_word ^ 1, .expected = error.InvalidStackSwapCallerRecord },
        .{
            .word = authority.fixed_word,
            .clock = 0,
            .expected = error.StackSwapProfileClockAuthorityMismatch,
        },
        .{
            .word = authority.fixed_word,
            .rhs = valuePointer(top_index),
            .expected = error.InvalidStackSwapCall,
        },
        .{
            .word = authority.fixed_word,
            .rhs = valuePointer(top_index) - 16,
            .expected = error.InvalidStackSwapCall,
        },
        .{
            .word = authority.fixed_word,
            .lhs = valuePointer(top_index) + 1,
            .expected = error.InvalidStackSwapCallerRecord,
        },
        .{
            .word = authority.fixed_word,
            .lhs = 0x4ff0,
            .expected = error.StackSwapSpanOutsideRwMemory,
        },
        .{
            .word = authority.fixed_word,
            .call_limit = 0,
            .expected = error.StackSwapTapeLimitExceeded,
        },
    };

    for (cases) |case| {
        var memory = try Memory.initFallible(std.testing.allocator);
        defer memory.deinit();
        var expected: [stack_value_count][words.lane_count]u32 = undefined;
        initializeStack(&memory, &expected);
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tape = try tape_mod.Builder.init(
            std.testing.allocator,
            authority,
            case.call_limit,
            0,
        );
        defer tape.deinit();
        var cpu = Cpu.init(0x1000, 0x4ff0);
        cpu.writeReg(abi.lhs_pointer_register, case.lhs);
        cpu.writeReg(abi.rhs_pointer_register, case.rhs);
        const before_cpu = cpu;
        const before_memory = stackWindow(&memory);

        try std.testing.expectError(case.expected, subject.executeWithRecordedClock(
            case.word,
            case.clock,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &trace,
            &tape,
        ));
        try std.testing.expectEqualDeep(before_cpu, cpu);
        try std.testing.expectEqual(before_memory, stackWindow(&memory));
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(usize, 0), tape.len());
        try std.testing.expectEqual(@as(usize, 0), tape.wordLen());
        try std.testing.expectEqual(@as(usize, 0), tape.rowLen());
        try trace.validateClockRange(0, 0, 0);
    }
}

test "caller and eight word lanes satisfy direct constraints and one call relation" {
    const authority = try fixtureAuthority();
    const record = caller.Record{
        .execution_clock = 91,
        .pc = 0x1200,
        .lhs_previous_clock = 3,
        .rhs_previous_clock = 5,
        .lhs_pointer = 0x4200,
        .rhs_pointer = 0x4100,
        .call_index = 7,
    };
    const caller_row = try caller.materialize(record);
    var caller_encoded = caller_row.encode();
    var sink = Sink{};
    try caller.evaluateDirect(M31, &caller_encoded, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
    try std.testing.expectEqual(caller.maximum_constraint_degree, sink.maximum_degree);
    const events = try caller_row.relationEvents(authority);
    try std.testing.expectEqualDeep(try authority.programTuple(record.pc), events.program);

    var word_rows: [words.lane_count]words.Row = undefined;
    for (&word_rows, 0..) |*row, index| row.* = try words.materializeRow(
        record.call(),
        .at(@intCast(index)),
        .{
            .lhs_previous_clock = @intCast(10 + index),
            .rhs_previous_clock = @intCast(20 + index),
            .lhs_before = .{ @intCast(index), 2, 3, 4 },
            .rhs_before = .{ @intCast(100 + index), 6, 7, 8 },
        },
    );
    const padding = words.Row.padding().encode();
    for (word_rows, 0..) |row, index| {
        const current = row.encode();
        const next = if (index + 1 < word_rows.len)
            word_rows[index + 1].encode()
        else
            padding;
        sink = .{};
        try words.evaluateDirect(
            M31,
            &current,
            &next,
            .at(@intCast(index)),
            .at(@intCast((index + 1) % words.lane_count)),
            M31.zero(),
            &sink,
        );
        try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
        try std.testing.expectEqual(words.maximum_constraint_degree, sink.maximum_degree);
        const memory_events = try row.memoryEvents();
        switch (memory_events[1]) {
            .emit => |event| try std.testing.expectEqualDeep(row.rhs_before, event.bytes),
            else => return error.InvalidStackSwapWordRow,
        }
        switch (memory_events[3]) {
            .emit => |event| try std.testing.expectEqualDeep(row.lhs_before, event.bytes),
            else => return error.InvalidStackSwapWordRow,
        }
    }
    const word_first_encoded = word_rows[0].encode();
    try std.testing.expectEqualDeep(
        relations.callerCallTuple(M31, &caller_encoded),
        relations.wordCallTuple(M31, &word_first_encoded),
    );

    caller_encoded[caller.Layout.wordIndex(1)] =
        caller_encoded[caller.Layout.wordIndex(1)].add(M31.one());
    sink = .{};
    try caller.evaluateDirect(M31, &caller_encoded, &sink);
    try std.testing.expect(sink.nonzero != 0);

    const first = word_rows[0].encode();
    var second = word_rows[1].encode();
    second[words.Layout.lhs_word_address] =
        second[words.Layout.lhs_word_address].add(M31.one());
    sink = .{};
    try words.evaluateDirect(
        M31,
        &first,
        &second,
        .at(0),
        .at(1),
        M31.zero(),
        &sink,
    );
    try std.testing.expect(sink.nonzero != 0);
}

test "word constraints admit only the deterministic padded and full-domain wraps" {
    const call = words.Call{
        .execution_clock = 33,
        .call_index = 0,
        .pc = 0x1400,
        .lhs_first_word = 0x400,
        .rhs_first_word = 0x420,
    };
    var active_rows: [words.lane_count][words.main_column_count]M31 = undefined;
    for (&active_rows, 0..) |*encoded, index| {
        const row = try words.materializeRow(call, .at(@intCast(index)), .{
            .lhs_previous_clock = @intCast(1 + index),
            .rhs_previous_clock = @intCast(9 + index),
            .lhs_before = .{ @intCast(index), 2, 3, 4 },
            .rhs_before = .{ @intCast(100 + index), 6, 7, 8 },
        });
        encoded.* = row.encode();
    }
    const padding = words.Row.padding().encode();

    // One active call in a 16-row domain: row 15 is padding and wraps to the
    // active row zero. Every earlier padding row must still reject activity.
    for (0..16) |row_index| {
        const next_index = (row_index + 1) % 16;
        const current = if (row_index < words.lane_count)
            active_rows[row_index]
        else
            padding;
        const next = if (next_index < words.lane_count)
            active_rows[next_index]
        else
            padding;
        var sink = Sink{};
        try words.evaluateDirect(
            M31,
            &current,
            &next,
            .at(@intCast(row_index % words.lane_count)),
            .at(@intCast(next_index % words.lane_count)),
            M31.fromCanonical(@intFromBool(row_index == 15)),
            &sink,
        );
        try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
    }
    var bad_padding_wrap = Sink{};
    try words.evaluateDirect(
        M31,
        &padding,
        &active_rows[0],
        .at(7),
        .at(0),
        M31.zero(),
        &bad_padding_wrap,
    );
    try std.testing.expect(bad_padding_wrap.nonzero != 0);

    // One active call fills an eight-row domain. Its lane-seven successor is
    // row zero of the same call, so only deterministic domain_last may waive
    // the ordinary cross-call call_index increment.
    for (active_rows, 0..) |current, row_index| {
        const next_index = (row_index + 1) % words.lane_count;
        var sink = Sink{};
        try words.evaluateDirect(
            M31,
            &current,
            &active_rows[next_index],
            .at(@intCast(row_index)),
            .at(@intCast(next_index)),
            M31.fromCanonical(@intFromBool(row_index + 1 == words.lane_count)),
            &sink,
        );
        try std.testing.expectEqual(@as(usize, 0), sink.nonzero);
    }
    var bad_active_wrap = Sink{};
    try words.evaluateDirect(
        M31,
        &active_rows[words.lane_count - 1],
        &active_rows[0],
        .at(7),
        .at(0),
        M31.zero(),
        &bad_active_wrap,
    );
    try std.testing.expect(bad_active_wrap.nonzero != 0);
}

test "word memory tuples use native aligned byte addresses" {
    const execution_clock: u32 = 7;
    const memory_clock = access_clock.encode(execution_clock, .second);
    const row = try words.materializeRow(.{
        .execution_clock = execution_clock,
        .call_index = 0,
        .pc = 0x200,
        .lhs_first_word = 0x1000 / abi.word_bytes,
        .rhs_first_word = 0x1080 / abi.word_bytes,
    }, .at(0), .{
        .lhs_previous_clock = 0,
        .rhs_previous_clock = 0,
        .lhs_before = .{ 1, 2, 3, 4 },
        .rhs_before = .{ 5, 6, 7, 8 },
    });
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.reserveTransitions(.{
        .memory_address_count = 2,
        .access_count = 2,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    });
    tracker.recordMemTransitionAssumeCapacity(0x1000, memory_clock, 0x0403_0201, 0x0807_0605);
    tracker.recordMemTransitionAssumeCapacity(0x1080, memory_clock, 0x0807_0605, 0x0403_0201);
    const events = try row.memoryEvents();
    switch (events[1]) {
        .emit => |event| {
            try std.testing.expectEqual(tracker.accesses.items[0].addr, event.address);
            try std.testing.expectEqual(@as(u32, 0x1000), event.address);
        },
        else => return error.InvalidStackSwapWordRow,
    }
    switch (events[3]) {
        .emit => |event| {
            try std.testing.expectEqual(tracker.accesses.items[1].addr, event.address);
            try std.testing.expectEqual(@as(u32, 0x1080), event.address);
        },
        else => return error.InvalidStackSwapWordRow,
    }

    var changed = row;
    changed.lhs_word_address += 1;
    const changed_events = try changed.memoryEvents();
    switch (changed_events[1]) {
        .emit => |event| try std.testing.expect(event.address != tracker.accesses.items[0].addr),
        else => return error.InvalidStackSwapWordRow,
    }
}

test "typed nonproduction geometry binds retained scope without extrapolation" {
    const caller_rows: u64 = 1 << 16;
    const word_rows: u64 = 1 << 19;
    const main_cells = caller_rows * @as(u64, caller.main_column_count) +
        word_rows * @as(u64, words.main_column_count);
    const interaction_cells = caller_rows * @as(u64, caller.interaction_column_count) +
        word_rows * @as(u64, words.interaction_column_count);
    const preprocessed_cells = (caller_rows + word_rows) * 3;
    try std.testing.expectEqual(@as(u64, 10_813_440), main_cells);
    try std.testing.expectEqual(@as(u64, 10_485_760), interaction_cells);
    try std.testing.expectEqual(@as(u64, 1_769_472), preprocessed_cells);
    try std.testing.expectEqual(
        @as(u64, 92_274_688),
        (main_cells + interaction_cells + preprocessed_cells) * @as(u64, @sizeOf(M31)),
    );
    try std.testing.expectEqual(@as(u64, 43_456), abi.retained_scope.calls);
    try std.testing.expectEqual(@as(u64, 5_953_472), abi.retained_scope.retired_rv32_rows);
    try std.testing.expectEqual(@as(u32, 137), abi.retained_scope.rows_per_call);
    try std.testing.expectEqual(
        abi.retained_scope.retired_rv32_rows,
        abi.retained_scope.calls * abi.retained_scope.rows_per_call,
    );
    const family_rows = abi.retained_software_family_rows;
    try std.testing.expectEqual(abi.retained_scope.rows_per_call, family_rows.total());
    const software_main_cells_per_call =
        @as(u64, family_rows.load_store) * load_store_authority.MAIN_COLUMN_COUNT +
        @as(u64, family_rows.base_alu_imm) * base_alu_imm_authority.MAIN_COLUMN_COUNT +
        @as(u64, family_rows.base_alu_reg) * base_alu_reg_authority.MAIN_COLUMN_COUNT +
        @as(u64, family_rows.branch_lt) * branch_lt_authority.MAIN_COLUMN_COUNT +
        @as(u64, family_rows.jalr) * jalr_authority.MAIN_COLUMN_COUNT +
        @as(u64, family_rows.shifts_imm) * shifts_imm_authority.MAIN_COLUMN_COUNT;
    try std.testing.expectEqual(@as(u64, 6_769), software_main_cells_per_call);
    const retained_software_main_cells =
        abi.retained_scope.calls * software_main_cells_per_call;
    try std.testing.expectEqual(@as(u64, 294_153_664), retained_software_main_cells);
    try std.testing.expectEqual(
        @as(u64, 283_340_224),
        retained_software_main_cells - main_cells,
    );
    try std.testing.expectEqual(@as(u64, 36), canonicalInteractionColumnCount(load_store_authority));
    try std.testing.expectEqual(@as(u64, 32), canonicalInteractionColumnCount(base_alu_imm_authority));
    try std.testing.expectEqual(@as(u64, 36), canonicalInteractionColumnCount(base_alu_reg_authority));
    try std.testing.expectEqual(@as(u64, 24), canonicalInteractionColumnCount(branch_lt_authority));
    try std.testing.expectEqual(@as(u64, 36), canonicalInteractionColumnCount(jalr_authority));
    try std.testing.expectEqual(@as(u64, 32), canonicalInteractionColumnCount(shifts_imm_authority));
    const software_interaction_cells_per_call =
        @as(u64, family_rows.load_store) * canonicalInteractionColumnCount(load_store_authority) +
        @as(u64, family_rows.base_alu_imm) * canonicalInteractionColumnCount(base_alu_imm_authority) +
        @as(u64, family_rows.base_alu_reg) * canonicalInteractionColumnCount(base_alu_reg_authority) +
        @as(u64, family_rows.branch_lt) * canonicalInteractionColumnCount(branch_lt_authority) +
        @as(u64, family_rows.jalr) * canonicalInteractionColumnCount(jalr_authority) +
        @as(u64, family_rows.shifts_imm) * canonicalInteractionColumnCount(shifts_imm_authority);
    const retained_software_interaction_cells =
        abi.retained_scope.calls * software_interaction_cells_per_call;
    try std.testing.expectEqual(
        @as(u64, 213_108_224),
        retained_software_interaction_cells,
    );
    const candidate_all_cells = main_cells + interaction_cells + preprocessed_cells;
    try std.testing.expectEqual(@as(u64, 23_068_672), candidate_all_cells);
    try std.testing.expectEqual(
        @as(u64, 484_193_216),
        retained_software_main_cells + retained_software_interaction_cells -
            candidate_all_cells,
    );
}
