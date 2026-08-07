//! Transactional execution of `stwo.p2perm.m31.v1`.
//!
//! Prepare performs every validation, snapshot, permutation, and capacity/page
//! reservation. Commit contains only assume-capacity operations and direct
//! writes, so no rejected call or allocation failure can partially retire.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const isa_profile = @import("../../isa/profile.zig");
const m31 = @import("stwo_core").fields.m31;
const permutation = @import("../../air/memory_commitment/poseidon2.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const state_chain = @import("../state_chain.zig");
const StateChainTracker = state_chain.StateChainTracker;
const call_buffer = @import("call_buffer.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;
pub const lane_count = call_buffer.lane_count;

pub const Error = custom0.DecodeError || error{
    OutOfMemory,
    PrecompileCallLimitExceeded,
    PrecompileClockOutOfRange,
    PrecompileAddressMisaligned,
    PrecompileSpanOutsideRwMemory,
    NonCanonicalPrecompileInput,
};

/// Compact custom-retirement row. Wide permutation values remain exclusively
/// in the call buffer rather than bloating every ordinary core trace row.
pub const ExecutionRow = struct {
    execution_clock: u32,
    pc: u32,
    inst_word: u32,
    call_index: u32,
};

pub const FrozenExecutionRows = struct {
    storage: std.ArrayList(ExecutionRow),
    allocator: std.mem.Allocator,

    pub fn rows(self: *const FrozenExecutionRows) []const ExecutionRow {
        return self.storage.items;
    }

    pub fn capacity(self: *const FrozenExecutionRows) usize {
        return self.storage.capacity;
    }

    pub fn deinit(self: *FrozenExecutionRows) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const ExecutionRowsBuilder = struct {
    storage: std.ArrayList(ExecutionRow) = .empty,
    allocator: std.mem.Allocator,
    limit: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        limit: usize,
    ) error{PrecompileCallLimitExceeded}!ExecutionRowsBuilder {
        if (limit > call_buffer.max_calls)
            return error.PrecompileCallLimitExceeded;
        return .{ .allocator = allocator, .limit = limit };
    }

    pub fn deinit(self: *ExecutionRowsBuilder) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const ExecutionRowsBuilder) usize {
        return self.storage.items.len;
    }

    pub fn rows(self: *const ExecutionRowsBuilder) []const ExecutionRow {
        return self.storage.items;
    }

    pub fn reserveOne(self: *ExecutionRowsBuilder) Error!void {
        if (self.storage.items.len >= self.limit)
            return error.PrecompileCallLimitExceeded;
        try self.storage.ensureUnusedCapacity(self.allocator, 1);
    }

    fn appendAssumeCapacity(self: *ExecutionRowsBuilder, row: ExecutionRow) void {
        std.debug.assert(self.storage.items.len < self.limit);
        self.storage.appendAssumeCapacity(row);
    }

    pub fn freeze(self: *ExecutionRowsBuilder) FrozenExecutionRows {
        const result = FrozenExecutionRows{
            .storage = self.storage,
            .allocator = self.allocator,
        };
        self.storage = .empty;
        self.limit = 0;
        return result;
    }
};

const Prepared = struct {
    record: call_buffer.Record,
    row: ExecutionRow,
    addresses: [lane_count]u32,
    pointer_clock: u32,
    memory_clock: u32,
};

/// Execute one custom instruction as a two-phase transaction.
pub fn execute(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) Error!void {
    const prepared = try prepare(
        profile,
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        calls,
    );

    // Capacity growth is allowed during prepare but no logical append occurs.
    try calls.reserveOne();
    try execution_rows.reserveOne();

    var memory_gap_count: usize = 0;
    for (prepared.addresses) |addr| {
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(addr) orelse 0,
            prepared.memory_clock,
        );
    }
    const register_gap_count = StateChainTracker.clockGapCount(
        tracker.reg_last_clk[prepared.record.pointer_register],
        prepared.pointer_clock,
    );
    try tracker.reserveTransitions(.{
        .memory_address_count = lane_count,
        .access_count = lane_count + 1,
        .memory_clock_update_count = memory_gap_count,
        .register_clock_update_count = register_gap_count,
    });
    try memory.prepareAlignedWordWrites(&prepared.addresses);

    commit(prepared, cpu, memory, tracker, calls, execution_rows);
}

fn prepare(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *const Memory,
    layout: MemoryLayout,
    tracker: *const StateChainTracker,
    calls: *const call_buffer.Builder,
) Error!Prepared {
    const decoded = try custom0.decode(profile, inst_word);
    if (execution_clock == 0 or
        access_clock.maximum(execution_clock) > std.math.maxInt(u32))
    {
        return error.PrecompileClockOutOfRange;
    }

    const state_ptr = cpu.readReg(decoded.rs1);
    if (state_ptr & 3 != 0)
        return error.PrecompileAddressMisaligned;
    const span_end = @as(u64, state_ptr) + lane_count * @sizeOf(u32);
    if (span_end > isa_profile.program_commitment_size or
        !spanWithinOneRwInterval(layout, state_ptr, span_end))
    {
        return error.PrecompileSpanOutsideRwMemory;
    }

    const pointer_clock = access_clock.encode(execution_clock, .first);
    const memory_clock = access_clock.encode(execution_clock, .second);
    const pointer_previous_clock = StateChainTracker.effectivePreviousClock(
        tracker.reg_last_clk[decoded.rs1],
        pointer_clock,
    );

    var addresses: [lane_count]u32 = undefined;
    var input: [lane_count]u32 = undefined;
    var previous_clocks: [lane_count]u32 = undefined;
    var state: permutation.State = undefined;
    for (0..lane_count) |lane| {
        const addr = state_ptr + @as(u32, @intCast(lane * @sizeOf(u32)));
        const word = memory.readU32(addr);
        if (word >= m31.Modulus)
            return error.NonCanonicalPrecompileInput;
        addresses[lane] = addr;
        input[lane] = word;
        previous_clocks[lane] = StateChainTracker.effectivePreviousClock(
            tracker.mem_last_clk.get(addr) orelse 0,
            memory_clock,
        );
        state[lane] = m31.M31.fromCanonical(word);
    }
    permutation.permute(&state);
    var output: [lane_count]u32 = undefined;
    for (&output, state) |*word, value| word.* = value.v;

    return .{
        .record = .{
            .execution_clock = execution_clock,
            .pc = cpu.pc,
            .state_ptr = state_ptr,
            .pointer_register = decoded.rs1,
            .pointer_previous_clock = pointer_previous_clock,
            .input = input,
            .output = output,
            .memory_previous_clocks = previous_clocks,
        },
        .row = .{
            .execution_clock = execution_clock,
            .pc = cpu.pc,
            .inst_word = inst_word,
            .call_index = @intCast(calls.len()),
        },
        .addresses = addresses,
        .pointer_clock = pointer_clock,
        .memory_clock = memory_clock,
    };
}

fn commit(
    prepared: Prepared,
    cpu: *Cpu,
    memory: *Memory,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) void {
    tracker.recordRegTransitionAssumeCapacity(
        prepared.record.pointer_register,
        prepared.pointer_clock,
        prepared.record.state_ptr,
        prepared.record.state_ptr,
    );
    for (0..lane_count) |lane| {
        memory.writeU32AssumePrepared(
            prepared.addresses[lane],
            prepared.record.output[lane],
        );
        tracker.recordMemTransitionAssumeCapacity(
            prepared.addresses[lane],
            prepared.memory_clock,
            prepared.record.input[lane],
            prepared.record.output[lane],
        );
    }
    execution_rows.appendAssumeCapacity(prepared.row);
    calls.appendAssumeCapacity(prepared.record);
    cpu.pc +%= 4;
}

fn spanWithinOneRwInterval(layout: MemoryLayout, start: u32, end: u64) bool {
    const intervals = [_][2]u32{
        .{ layout.data_base, layout.data_end },
        .{ layout.stack_bottom, layout.stack_top },
        .{ layout.io_base, layout.io_end },
    };
    for (intervals) |interval| {
        if (interval[0] < interval[1] and
            start >= interval[0] and end <= @as(u64, interval[1]))
        {
            return true;
        }
    }
    return false;
}

fn testLayout() MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x3000,
        .stack_bottom = 0x4000,
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

test "Poseidon2 v1 transaction commits exact output, clocks, and owned records" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 2);
    defer calls.deinit();
    var rows = try ExecutionRowsBuilder.init(std.testing.allocator, 2);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(5, 0x2000);
    for (0..lane_count) |lane| memory.writeU32(0x2000 + @as(u32, @intCast(4 * lane)), @intCast(lane));

    try execute(
        .rv32im_zkvm_poseidon2_v1,
        custom0.encodePoseidon2(5),
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    );
    const expected = [_]u32{
        1_348_310_665, 996_460_804,   2_044_919_169, 1_269_301_599,
        615_961_333,   595_876_573,   1_377_780_500, 1_776_267_289,
        715_842_585,   1_823_756_332, 1_870_636_634, 1_979_645_732,
        311_256_455,   1_364_752_356, 58_674_647,    323_699_327,
    };
    for (expected, 0..) |word, lane| {
        try std.testing.expectEqual(word, memory.readU32(0x2000 + @as(u32, @intCast(4 * lane))));
    }
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
    try std.testing.expectEqual(@as(usize, 17), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(u32, 1), tracker.accesses.items[0].clk);
    for (tracker.accesses.items[1..]) |access| try std.testing.expectEqual(@as(u32, 2), access.clk);
    try std.testing.expectEqual(@as(usize, 1), calls.len());
    try std.testing.expectEqual(@as(usize, 1), rows.len());

    var frozen_calls = calls.freeze();
    defer frozen_calls.deinit();
    var frozen_rows = rows.freeze();
    defer frozen_rows.deinit();
    try std.testing.expectEqualSlices(u32, &expected, &frozen_calls.records()[0].output);
    try std.testing.expectEqual(@as(u5, 5), frozen_calls.records()[0].pointer_register);
    try std.testing.expectEqual(@as(u32, 0), frozen_calls.records()[0].pointer_previous_clock);
    try std.testing.expectEqual(@as(u32, 0), frozen_rows.rows()[0].call_index);
}

test "Poseidon2 v1 rejects profile, encoding, address, span, and noncanonical words atomically" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 2);
    defer calls.deinit();
    var rows = try ExecutionRowsBuilder.init(std.testing.allocator, 2);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(5, 0x2000);
    const canonical_word = custom0.encodePoseidon2(5);

    try std.testing.expectError(error.PrecompileClockOutOfRange, execute(
        .rv32im_zkvm_poseidon2_v1,
        canonical_word,
        0,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    const maximum_execution_clock: u32 = 1 << 30;
    try std.testing.expectEqual(
        @as(u64, std.math.maxInt(u32)),
        access_clock.maximum(maximum_execution_clock),
    );
    _ = try prepare(
        .rv32im_zkvm_poseidon2_v1,
        canonical_word,
        maximum_execution_clock,
        cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
    );
    try std.testing.expectError(error.PrecompileClockOutOfRange, execute(
        .rv32im_zkvm_poseidon2_v1,
        canonical_word,
        maximum_execution_clock + 1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    try std.testing.expectError(error.RequiredCapabilityUnavailable, execute(
        .rv32im_zkvm_v1,
        canonical_word,
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    try std.testing.expectError(error.InvalidPrecompileEncoding, execute(
        .rv32im_zkvm_poseidon2_v1,
        canonical_word | 0x80,
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    cpu.writeReg(5, 0x2002);
    try std.testing.expectError(error.PrecompileAddressMisaligned, execute(
        .rv32im_zkvm_poseidon2_v1,
        canonical_word,
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    cpu.writeReg(5, 0x2fe0);
    try std.testing.expectError(error.PrecompileSpanOutsideRwMemory, execute(
        .rv32im_zkvm_poseidon2_v1,
        canonical_word,
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    cpu.writeReg(5, 0x2000);
    for ([_]u32{ m31.Modulus, m31.Modulus + 1, 2 * m31.Modulus, std.math.maxInt(u32) }) |word| {
        memory.writeU32(0x2000, word);
        try std.testing.expectError(error.NonCanonicalPrecompileInput, execute(
            .rv32im_zkvm_poseidon2_v1,
            canonical_word,
            1,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &calls,
            &rows,
        ));
    }
    try std.testing.expectEqual(@as(u32, 0x1000), cpu.pc);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), calls.len());
    try std.testing.expectEqual(@as(usize, 0), rows.len());
}

test "Poseidon2 v1 allocation-failure sweep preserves complete logical state" {
    for (0..32) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const allocator = failing.allocator();
        var memory = Memory.initFallible(allocator) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        defer memory.deinit();
        var tracker = StateChainTracker.init(allocator);
        defer tracker.deinit();
        var calls = try call_buffer.Builder.init(allocator, 1);
        defer calls.deinit();
        var rows = try ExecutionRowsBuilder.init(allocator, 1);
        defer rows.deinit();
        var cpu = Cpu.init(0x1000, 0x4000);
        cpu.writeReg(5, 0x2000);

        execute(
            .rv32im_zkvm_poseidon2_v1,
            custom0.encodePoseidon2(5),
            1,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &calls,
            &rows,
        ) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(@as(u32, 0x1000), cpu.pc);
            for (0..lane_count) |lane| try std.testing.expectEqual(
                @as(u32, 0),
                memory.readU32(0x2000 + @as(u32, @intCast(4 * lane))),
            );
            try std.testing.expectEqual(@as(usize, 0), memory.initialized_words.count());
            try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
            try std.testing.expectEqual(@as(usize, 0), tracker.mem_initial.count());
            try std.testing.expectEqual(@as(usize, 0), tracker.mem_last_clk.count());
            try std.testing.expectEqual(@as(u32, 0), tracker.reg_last_clk[5]);
            try std.testing.expectEqual(@as(usize, 0), calls.len());
            try std.testing.expectEqual(@as(usize, 0), rows.len());
            continue;
        };

        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
        return;
    }
    return error.AllocationFailureSweepDidNotTerminate;
}

test "Poseidon2 v1 allocation failures preserve a nonempty committed prefix" {
    var observed_rollback = false;
    for (0..64) |failure_offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const allocator = failing.allocator();
        var memory = try Memory.initFallible(allocator);
        defer memory.deinit();
        var tracker = StateChainTracker.init(allocator);
        defer tracker.deinit();
        var calls = try call_buffer.Builder.init(allocator, 4);
        defer calls.deinit();
        var rows = try ExecutionRowsBuilder.init(allocator, 4);
        defer rows.deinit();
        var cpu = Cpu.init(0x1000, 0x4000);
        cpu.writeReg(5, 0x2000);
        for (0..lane_count) |lane| memory.writeU32(
            0x2000 + @as(u32, @intCast(4 * lane)),
            @intCast(lane),
        );

        var layout = testLayout();
        layout.data_end = 0x0003_0000;
        const prefix_clock = state_chain.MAX_CLOCK_DIFF / access_clock.STRIDE + 2;
        try execute(
            .rv32im_zkvm_poseidon2_v1,
            custom0.encodePoseidon2(5),
            prefix_clock,
            &cpu,
            &memory,
            layout,
            &tracker,
            &calls,
            &rows,
        );

        // The second span crosses two untouched sparse pages. A failure may
        // therefore leave physical zero pages behind, but no logical memory,
        // state-chain, call, row, register, or PC mutation is permitted.
        const second_ptr: u32 = 0x0001_fff0;
        cpu.writeReg(5, second_ptr);
        const cpu_before = cpu;
        const initialized_word_count = memory.initialized_words.count();
        const mem_initial_count = tracker.mem_initial.count();
        const mem_last_count = tracker.mem_last_clk.count();
        const reg_clocks_before = tracker.reg_last_clk;
        const accesses_before = try std.testing.allocator.dupe(
            state_chain.Access,
            tracker.accesses.items,
        );
        defer std.testing.allocator.free(accesses_before);
        const mem_updates_before = try std.testing.allocator.dupe(
            state_chain.ClockUpdate,
            tracker.clock_updates_mem.items,
        );
        defer std.testing.allocator.free(mem_updates_before);
        const reg_updates_before = try std.testing.allocator.dupe(
            state_chain.ClockUpdate,
            tracker.clock_updates_reg.items,
        );
        defer std.testing.allocator.free(reg_updates_before);
        const call_before = calls.records()[0];
        const row_before = rows.rows()[0];
        try std.testing.expect(mem_updates_before.len != 0);
        try std.testing.expect(reg_updates_before.len != 0);

        failing.fail_index = failing.alloc_index + failure_offset;
        execute(
            .rv32im_zkvm_poseidon2_v1,
            custom0.encodePoseidon2(5),
            prefix_clock + 1,
            &cpu,
            &memory,
            layout,
            &tracker,
            &calls,
            &rows,
        ) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            observed_rollback = true;
            try std.testing.expectEqual(cpu_before, cpu);
            try std.testing.expectEqual(initialized_word_count, memory.initialized_words.count());
            try std.testing.expectEqual(mem_initial_count, tracker.mem_initial.count());
            try std.testing.expectEqual(mem_last_count, tracker.mem_last_clk.count());
            try std.testing.expectEqual(reg_clocks_before, tracker.reg_last_clk);
            try std.testing.expectEqualSlices(
                state_chain.Access,
                accesses_before,
                tracker.accesses.items,
            );
            try std.testing.expectEqualSlices(
                state_chain.ClockUpdate,
                mem_updates_before,
                tracker.clock_updates_mem.items,
            );
            try std.testing.expectEqualSlices(
                state_chain.ClockUpdate,
                reg_updates_before,
                tracker.clock_updates_reg.items,
            );
            try std.testing.expectEqual(@as(usize, 1), calls.len());
            try std.testing.expectEqual(call_before, calls.records()[0]);
            try std.testing.expectEqual(@as(usize, 1), rows.len());
            try std.testing.expectEqual(row_before, rows.rows()[0]);
            for (0..lane_count) |lane| {
                const prefix_addr = 0x2000 + @as(u32, @intCast(4 * lane));
                try std.testing.expectEqual(
                    call_before.output[lane],
                    memory.readU32(prefix_addr),
                );
                try std.testing.expectEqual(
                    @as(u32, 0),
                    memory.readU32(second_ptr + @as(u32, @intCast(4 * lane))),
                );
                try std.testing.expect(tracker.mem_initial.contains(prefix_addr));
                try std.testing.expect(!tracker.mem_initial.contains(
                    second_ptr + @as(u32, @intCast(4 * lane)),
                ));
                try std.testing.expect(!tracker.mem_last_clk.contains(
                    second_ptr + @as(u32, @intCast(4 * lane)),
                ));
            }
            continue;
        };

        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expect(observed_rollback);
        return;
    }
    return error.AllocationFailureSweepDidNotTerminate;
}
