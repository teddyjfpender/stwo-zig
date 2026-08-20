const std = @import("std");
const builtin = @import("builtin");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const subject = @import("jalr_retirement.zig");
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");
const typed_jalr = @import("../air/lang/typed_jalr.zig");
const typed_authority = @import("../air/lang/typed_jalr_authority.zig");

const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = state_chain.StateChainTracker;
const Trace = trace_mod.Trace;

test "typed JALR retirement is exact for every I-immediate x0 and diagnostic aliases" {
    const authority = try authenticatedAuthority();
    var actual_cpu = initializedCpu();
    var oracle_cpu = actual_cpu;
    var actual_trace = Trace.init(std.testing.allocator);
    defer actual_trace.deinit();
    var oracle_trace = Trace.init(std.testing.allocator);
    defer oracle_trace.deinit();
    var actual_tracker = StateChainTracker.init(std.testing.allocator);
    defer actual_tracker.deinit();
    var oracle_tracker = StateChainTracker.init(std.testing.allocator);
    defer oracle_tracker.deinit();
    try actual_trace.reserveAdditional(4096);
    try oracle_trace.reserveAdditional(4096);
    try actual_tracker.reserveTransitions(noGapReservation(8192));
    try oracle_tracker.reserveTransitions(noGapReservation(8192));

    var immediate: i32 = -2048;
    while (immediate <= 2047) : (immediate += 1) {
        const immediate_bits: u32 = @bitCast(immediate);
        const rs1: u5 = if (immediate_bits & 2 == 0) 5 else 7;
        const rd_options = [_]u5{ 0, 6, 8, 9 };
        const rd = rd_options[@as(usize, @intCast(immediate + 2048)) & 3];
        const word = encodeJalr(rd, rs1, immediate);
        const clock: u32 = @intCast(actual_trace.rows.items.len + 1);
        try retireBoth(
            &authority,
            &actual_cpu,
            &actual_trace,
            &actual_tracker,
            &oracle_cpu,
            &oracle_trace,
            &oracle_tracker,
            word,
            clock,
        );
    }

    try std.testing.expectEqualDeep(oracle_cpu, actual_cpu);
    try std.testing.expectEqualSlices(
        trace_mod.TraceRow,
        oracle_trace.rows.items,
        actual_trace.rows.items,
    );
    try expectTrackersEqual(&oracle_tracker, &actual_tracker);
}

test "typed JALR source destination aliases preserve pre-write target and chain order" {
    const authority = try authenticatedAuthority();
    const cases = [_]struct {
        rd: u5,
        rs1: u5,
        immediate: i32,
        source: u32,
    }{
        .{ .rd = 5, .rs1 = 5, .immediate = -1, .source = 0x2001 },
        .{ .rd = 0, .rs1 = 0, .immediate = 0, .source = 0 },
        .{ .rd = 7, .rs1 = 5, .immediate = 4, .source = 0x2000 },
        .{ .rd = 5, .rs1 = 7, .immediate = -4, .source = 0x2004 },
    };
    for (cases) |case| {
        var actual_cpu = initializedCpu();
        actual_cpu.writeReg(case.rs1, case.source);
        var oracle_cpu = actual_cpu;
        var actual_trace = Trace.init(std.testing.allocator);
        defer actual_trace.deinit();
        var oracle_trace = Trace.init(std.testing.allocator);
        defer oracle_trace.deinit();
        var actual_tracker = StateChainTracker.init(std.testing.allocator);
        defer actual_tracker.deinit();
        var oracle_tracker = StateChainTracker.init(std.testing.allocator);
        defer oracle_tracker.deinit();
        try retireBoth(
            &authority,
            &actual_cpu,
            &actual_trace,
            &actual_tracker,
            &oracle_cpu,
            &oracle_trace,
            &oracle_tracker,
            encodeJalr(case.rd, case.rs1, case.immediate),
            1,
        );
        try std.testing.expectEqualDeep(oracle_cpu, actual_cpu);
        try std.testing.expectEqualSlices(
            state_chain.Access,
            oracle_tracker.accesses.items,
            actual_tracker.accesses.items,
        );
        if (case.rd == case.rs1) {
            try std.testing.expectEqual(@as(u32, 1), actual_tracker.accesses.items[1].clk_prev);
            try std.testing.expectEqual(case.source, actual_trace.rows.items[0].rd_prev_val);
        }
    }
}

test "typed JALR encoding admission exhausts all immediate and register fields" {
    var immediate: i32 = -2048;
    while (immediate <= 2047) : (immediate += 1) {
        const rd: u5 = @truncate(@as(u32, @bitCast(immediate)));
        const rs1: u5 = @truncate(@as(u32, @bitCast(immediate)) >> 5);
        const word = encodeJalr(rd, rs1, immediate);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expect(subject.instructionMatchesWord(instruction, word));
        try std.testing.expect(!subject.instructionMatchesWord(instruction, word ^ 1));
        try std.testing.expect(!subject.instructionMatchesWord(instruction, word ^ (@as(u32, 1) << 12)));
    }
}

test "typed JALR retirement rejects malformed and stale plans atomically" {
    const authority = try authenticatedAuthority();
    {
        var cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeJalr(6, 5, 4);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            error.InstructionWordMismatch,
            subject.stage(
                &authority,
                &cpu,
                &trace,
                &tracker,
                instruction,
                word ^ 1,
                1,
            ),
        );
        try std.testing.expectError(
            error.InstructionClockMismatch,
            subject.stage(
                &authority,
                &cpu,
                &trace,
                &tracker,
                instruction,
                word,
                2,
            ),
        );
        cpu.writeReg(5, 2);
        try std.testing.expectError(
            error.MisalignedJumpTarget,
            subject.stage(
                &authority,
                &cpu,
                &trace,
                &tracker,
                instruction,
                word,
                1,
            ),
        );
    }

    inline for ([_]Mutation{
        .plan, .pc, .source, .destination, .diagnostic, .trace, .tracker,
    }) |mutation| {
        var cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        try trace.reserveOne();
        try tracker.reserveTransitions(noGapReservation(2));
        // Keep the diagnostic rs2 snapshot independent of rs1/rd/x0 so every
        // stale-plan dimension is observable.  For I-type instructions the
        // decoder's diagnostic rs2 field is immediate[4:0].
        const word = encodeJalr(6, 5, 4);
        var plan = try subject.stage(
            &authority,
            &cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &trace, &tracker);
        switch (mutation) {
            .plan => plan.next_pc +%= 4,
            .pc => cpu.pc +%= 4,
            .source => cpu.writeReg(5, cpu.readReg(5) +% 4),
            .destination => cpu.writeReg(6, cpu.readReg(6) ^ 1),
            .diagnostic => cpu.writeReg(plan.instruction.rs2, cpu.readReg(plan.instruction.rs2) ^ 1),
            .trace => trace.appendAssumeCapacity(plan.traceRow()),
            .tracker => tracker.reg_last_clk[5] +%= 1,
        }
        const cpu_before = cpu;
        const trace_len = trace.rows.items.len;
        const access_len = tracker.accesses.items.len;
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &trace, &tracker),
        );
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(trace_len, trace.rows.items.len);
        try std.testing.expectEqual(access_len, tracker.accesses.items.len);
    }
}

test "typed JALR capacity failures expose no logical prefix and warm path allocates nothing" {
    const authority = try authenticatedAuthority();
    var observed_failures: usize = 0;
    var reached_success = false;
    for (0..8) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var cpu = initializedCpu();
        const before = cpu;
        var trace = Trace.init(failing.allocator());
        defer trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        const word = encodeJalr(6, 5, 0);
        subject.retireAtomic(
            &authority,
            &cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        ) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqualDeep(before, cpu);
            try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
            try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
            observed_failures += 1;
            continue;
        };
        reached_success = true;
        break;
    }
    try std.testing.expect(observed_failures >= 2);
    try std.testing.expect(reached_success);

    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var trace = Trace.init(failing.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    for (0..iterations) |index| {
        const immediate: i32 = @intCast(@as(i64, @intCast(index & 0x7ff)) - 1024);
        const bits: u32 = @bitCast(immediate);
        const rs1: u5 = if (bits & 2 == 0) 5 else 7;
        const word = encodeJalr(6, rs1, immediate);
        try subject.retireAtomic(
            &authority,
            &cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    try std.testing.expect(!failing.has_induced_failure);
}

test "typed JALR retirement retains at least 97 percent legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try authenticatedAuthority();
    const samples = 13;
    const iterations = 1 << 14;
    _ = try measureTyped(&authority, 1 << 10);
    _ = try measureOracle(1 << 10);
    var typed: [samples]u64 = undefined;
    var oracle: [samples]u64 = undefined;
    for (0..samples) |sample| {
        if ((sample & 1) == 0) {
            typed[sample] = try measureTyped(&authority, iterations);
            oracle[sample] = try measureOracle(iterations);
        } else {
            oracle[sample] = try measureOracle(iterations);
            typed[sample] = try measureTyped(&authority, iterations);
        }
    }
    const typed_median = median(&typed);
    const oracle_median = median(&oracle);
    std.debug.print(
        "\n  typed JALR retirement={d} ns legacy={d} ns speed={d:.4}x plan={d}B\n",
        .{
            typed_median,
            oracle_median,
            @as(f64, @floatFromInt(oracle_median)) /
                @as(f64, @floatFromInt(typed_median)),
            @sizeOf(subject.Plan),
        },
    );
    try std.testing.expect(
        @as(u128, typed_median) * 97 <= @as(u128, oracle_median) * 100,
    );
}

const Mutation = enum {
    plan,
    pc,
    source,
    destination,
    diagnostic,
    trace,
    tracker,
};

fn retireBoth(
    authority: *const typed_authority.Authority,
    actual_cpu: *Cpu,
    actual_trace: *Trace,
    actual_tracker: *StateChainTracker,
    oracle_cpu: *Cpu,
    oracle_trace: *Trace,
    oracle_tracker: *StateChainTracker,
    word: u32,
    clock: u32,
) !void {
    const instruction = try decode.DecodedInst.decode(word);
    try subject.retireAtomic(
        authority,
        actual_cpu,
        actual_trace,
        actual_tracker,
        instruction,
        word,
        clock,
    );
    try oracleRetire(
        oracle_cpu,
        oracle_trace,
        oracle_tracker,
        instruction,
        word,
        clock,
    );
}

fn oracleRetire(
    cpu: *Cpu,
    trace: *Trace,
    tracker: *StateChainTracker,
    instruction: decode.DecodedInst,
    inst_word: u32,
    clock: u32,
) !void {
    const pc_before = cpu.pc;
    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_previous = cpu.readReg(instruction.rd);
    const access = access_witness.capture(tracker, instruction, clock);
    const target = (rs1_value +% @as(u32, @bitCast(instruction.imm))) &
        ~@as(u32, 1);
    if ((target & 3) != 0 or target >= (@as(u32, 1) << 30))
        return error.InvalidOracleInput;
    cpu.writeReg(instruction.rd, pc_before +% 4);
    cpu.pc = target;
    const rd_value = cpu.readReg(instruction.rd);
    try trace.append(.{
        .clk = clock,
        .pc = pc_before,
        .opcode = instruction.opcode,
        .rd = instruction.rd,
        .rs1 = instruction.rs1,
        .rs2 = instruction.rs2,
        .imm = instruction.imm,
        .rs1_val = rs1_value,
        .rs2_val = rs2_value,
        .rs1_prev_clk = access.rs1_prev_clock,
        .rs2_prev_clk = 0,
        .rd_prev_val = rd_previous,
        .rd_prev_clk = access.rd_prev_clock,
        .rd_val = rd_value,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = target != pc_before +% 4,
        .next_pc = target,
        .inst_word = inst_word,
    });
    try access.recordRegisters(
        tracker,
        instruction,
        rs1_value,
        rs2_value,
        rd_previous,
        rd_value,
    );
}

fn measureTyped(
    authority: *const typed_authority.Authority,
    iterations: usize,
) !u64 {
    var cpu = initializedCpu();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const immediate: i32 = @intCast(@as(i64, @intCast(index & 0x7ff)) - 1024);
        const bits: u32 = @bitCast(immediate);
        const rs1: u5 = if (bits & 2 == 0) 5 else 7;
        const word = encodeJalr(6, rs1, immediate);
        try subject.retireAtomic(
            authority,
            &cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(trace.rows.items.ptr);
    return elapsed;
}

fn measureOracle(iterations: usize) !u64 {
    var cpu = initializedCpu();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const immediate: i32 = @intCast(@as(i64, @intCast(index & 0x7ff)) - 1024);
        const bits: u32 = @bitCast(immediate);
        const rs1: u5 = if (bits & 2 == 0) 5 else 7;
        const word = encodeJalr(6, rs1, immediate);
        try oracleRetire(
            &cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(trace.rows.items.ptr);
    return elapsed;
}

fn initializedCpu() Cpu {
    var cpu = Cpu.init(0x1000, 0x7000_0000);
    for (1..32) |index| cpu.writeReg(
        @intCast(index),
        @as(u32, @intCast(index)) *% 0x0102_0305,
    );
    // Chosen so every I-immediate selects one of these two sources and lands
    // on a four-byte-aligned target after JALR clears bit zero.
    cpu.writeReg(5, 0x2000);
    cpu.writeReg(7, 0x2002);
    return cpu;
}

fn authenticatedAuthority() !typed_authority.Authority {
    var definition = try typed_jalr.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

fn encodeJalr(rd: u5, rs1: u5, immediate: i32) u32 {
    std.debug.assert(immediate >= -2048 and immediate <= 2047);
    const immediate_12 = @as(u32, @bitCast(immediate)) & 0xfff;
    return (immediate_12 << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, rd) << 7) |
        0b1100111;
}

fn noGapReservation(accesses: usize) StateChainTracker.Reservation {
    return .{
        .memory_address_count = 0,
        .access_count = accesses,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    };
}

fn expectTrackersEqual(
    expected: *const StateChainTracker,
    actual: *const StateChainTracker,
) !void {
    try std.testing.expectEqualSlices(u32, &expected.reg_last_clk, &actual.reg_last_clk);
    try std.testing.expectEqualSlices(
        state_chain.Access,
        expected.accesses.items,
        actual.accesses.items,
    );
    try std.testing.expectEqualSlices(
        state_chain.ClockUpdate,
        expected.clock_updates_reg.items,
        actual.clock_updates_reg.items,
    );
}

fn median(samples: []u64) u64 {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return samples[samples.len / 2];
}
