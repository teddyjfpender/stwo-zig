const std = @import("std");
const builtin = @import("builtin");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const subject = @import("auipc_retirement.zig");
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");
const typed_auipc = @import("../air/lang/typed_auipc.zig");
const typed_auipc_authority = @import("../air/lang/typed_auipc_authority.zig");

const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = state_chain.StateChainTracker;
const Trace = trace_mod.Trace;

test "typed AUIPC retirement is exact across PC result x0 and encoding aliases" {
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
    for (&actual_tracker.reg_last_clk, &oracle_tracker.reg_last_clk, 0..) |*actual, *oracle, index| {
        const initial: u32 = if (index == 0) 0 else @intCast(index);
        actual.* = initial;
        oracle.* = initial;
    }

    const boundaries = [_]u32{
        0, 1, 0x7ffff, 0x80000, 0xfffff, 0x12345, 0xabcde,
    };
    var clock: u32 = 16;
    try actual_trace.bindExtractedClockRange(clock - 1, clock - 1, 0);
    try oracle_trace.bindExtractedClockRange(clock - 1, clock - 1, 0);
    for (0..32) |rd_raw| {
        const rd: u5 = @intCast(rd_raw);
        for (boundaries) |upper| {
            try retireBoth(
                &authority,
                &actual_cpu,
                &actual_trace,
                &actual_tracker,
                &oracle_cpu,
                &oracle_trace,
                &oracle_tracker,
                encodeAuipc(rd, upper),
                clock,
            );
            clock += 1;
        }
        // U-type bits 15..24 decode into trace-visible diagnostic source
        // fields. Force both to alias rd even though neither is an operand.
        const alias_upper = (@as(u32, rd) << 3) |
            (@as(u32, rd) << 8) | 0x40000;
        try retireBoth(
            &authority,
            &actual_cpu,
            &actual_trace,
            &actual_tracker,
            &oracle_cpu,
            &oracle_trace,
            &oracle_tracker,
            encodeAuipc(rd, alias_upper),
            clock,
        );
        clock += 1;
    }

    try std.testing.expectEqualDeep(oracle_cpu, actual_cpu);
    try std.testing.expectEqualSlices(
        trace_mod.TraceRow,
        oracle_trace.rows.items,
        actual_trace.rows.items,
    );
    try expectTrackersEqual(&oracle_tracker, &actual_tracker);
    for (actual_trace.rows.items) |row| {
        if (row.rd == 0) try std.testing.expectEqual(@as(u32, 0), row.rd_val);
    }
}

test "typed AUIPC retirement is failure-atomic and allocation-free after preflight" {
    const authority = try authenticatedAuthority();
    var observed_failures: usize = 0;
    var reached_success = false;
    for (0..12) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var cpu = initializedCpu();
        const cpu_before = cpu;
        var exec_trace = Trace.init(failing.allocator());
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        const clock = state_chain.MAX_CLOCK_DIFF / 4 + 9;
        try exec_trace.bindExtractedClockRange(clock - 1, clock - 1, 0);
        const word = encodeAuipc(7, 0xabcde);
        subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            clock,
        ) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try expectLogicallyUnchanged(cpu_before, &cpu, &exec_trace, &tracker);
            observed_failures += 1;
            continue;
        };
        try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 1), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(u32, 0xabce_e000), cpu.readReg(7));
        reached_success = true;
        break;
    }
    try std.testing.expect(observed_failures >= 3);
    try std.testing.expect(reached_success);

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    const clock = state_chain.MAX_CLOCK_DIFF / 4 + 9;
    try exec_trace.bindExtractedClockRange(clock - 1, clock - 1, 0);
    const word = encodeAuipc(9, 0x80000);
    const plan = try subject.stage(
        &authority,
        cpu,
        &exec_trace,
        &tracker,
        try decode.DecodedInst.decode(word),
        word,
        clock,
    );
    const reservation = plan.reservation();
    var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
    try std.testing.expect(exec_trace.rows.capacity >= 1);
    try std.testing.expect(tracker.accesses.capacity >= reservation.access_count);
    try std.testing.expect(
        tracker.clock_updates_reg.capacity >=
            reservation.register_clock_update_count,
    );
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try prepared.commit(&cpu, &exec_trace, &tracker);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(u32, 0x8001_0000), cpu.readReg(9));
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
}

test "typed AUIPC rejects malformed words forged plans and stale snapshots" {
    const authority = try authenticatedAuthority();
    {
        const cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeAuipc(5, 0x12345);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            error.InstructionWordMismatch,
            subject.stage(
                &authority,
                cpu,
                &trace,
                &tracker,
                instruction,
                word ^ 1,
                1,
            ),
        );
        var forged = try subject.stage(
            &authority,
            cpu,
            &trace,
            &tracker,
            instruction,
            word,
            1,
        );
        forged.instruction_clock = 0;
        try std.testing.expectError(
            error.StaleRetirement,
            forged.prepare(&cpu, &trace, &tracker),
        );
    }

    inline for ([_]Mutation{
        .plan, .pc, .destination, .trace, .tracker,
    }) |mutation| {
        var cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeAuipc(5, 0x12345);
        var plan = try subject.stage(
            &authority,
            cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &trace, &tracker);
        switch (mutation) {
            .plan => plan.rd_next_value +%= 1,
            .pc => cpu.pc +%= 4,
            .destination => cpu.writeReg(5, cpu.readReg(5) ^ 1),
            .trace => trace.appendAssumeCapacity(plan.traceRow()),
            .tracker => tracker.reg_last_clk[5] +%= 1,
        }
        const cpu_before = cpu;
        const trace_len = trace.rows.items.len;
        const access_len = tracker.accesses.items.len;
        const gap_len = tracker.clock_updates_reg.items.len;
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &trace, &tracker),
        );
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(trace_len, trace.rows.items.len);
        try std.testing.expectEqual(access_len, tracker.accesses.items.len);
        try std.testing.expectEqual(gap_len, tracker.clock_updates_reg.items.len);
    }
}

test "typed AUIPC warm fused path performs no allocation" {
    const authority = try authenticatedAuthority();
    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var trace = Trace.init(failing.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try reserveBenchmark(&trace, &tracker, iterations);
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index & 31);
        const word = encodeAuipc(
            rd,
            @intCast((index *% 0x9e377) & 0xfffff),
        );
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
    try std.testing.expectEqual(@as(usize, iterations), trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, iterations), tracker.accesses.items.len);
}

test "typed AUIPC retirement retains at least 97 percent legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try authenticatedAuthority();
    const samples = 9;
    const iterations = 1 << 13;
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
        "\n  typed AUIPC runner: atomic={d} ns legacy={d} ns speed={d:.4}x plan={d}B token={d}B\n",
        .{
            typed_median,
            oracle_median,
            @as(f64, @floatFromInt(oracle_median)) /
                @as(f64, @floatFromInt(typed_median)),
            @sizeOf(subject.Plan),
            @sizeOf(subject.Prepared),
        },
    );
    try std.testing.expect(typed_median * 97 <= oracle_median * 100);
}

const Mutation = enum { plan, pc, destination, trace, tracker };

fn retireBoth(
    authority: *const typed_auipc_authority.Authority,
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
    const plan = try subject.stage(
        authority,
        actual_cpu.*,
        actual_trace,
        actual_tracker,
        instruction,
        word,
        clock,
    );
    var prepared = try plan.prepare(actual_cpu, actual_trace, actual_tracker);
    try prepared.commit(actual_cpu, actual_trace, actual_tracker);
    try oracleRetire(
        oracle_cpu,
        oracle_trace,
        oracle_tracker,
        instruction,
        word,
        clock,
    );
    try std.testing.expectEqualDeep(oracle_cpu.*, actual_cpu.*);
    try std.testing.expectEqualDeep(
        oracle_trace.rows.items[oracle_trace.rows.items.len - 1],
        actual_trace.rows.items[actual_trace.rows.items.len - 1],
    );
    try expectTrackersEqual(oracle_tracker, actual_tracker);
}

/// Independent retained oracle for the production arm removed at cutover.
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
    cpu.writeReg(
        instruction.rd,
        pc_before +% @as(u32, @bitCast(instruction.imm)),
    );
    cpu.pc +%= 4;
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
        .rs2_prev_clk = access.rs2_prev_clock,
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
        .branch_taken = false,
        .next_pc = cpu.pc,
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
    authority: *const typed_auipc_authority.Authority,
    iterations: usize,
) !u64 {
    var cpu = initializedCpu();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try reserveBenchmark(&trace, &tracker, iterations);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index & 31);
        const word = encodeAuipc(rd, @intCast((index *% 0x9e377) & 0xfffff));
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
    std.mem.doNotOptimizeAway(tracker.accesses.items.ptr);
    return elapsed;
}

fn measureOracle(iterations: usize) !u64 {
    var cpu = initializedCpu();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try reserveBenchmark(&trace, &tracker, iterations);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index & 31);
        const word = encodeAuipc(rd, @intCast((index *% 0x9e377) & 0xfffff));
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
    std.mem.doNotOptimizeAway(tracker.accesses.items.ptr);
    return elapsed;
}

fn reserveBenchmark(
    trace: *Trace,
    tracker: *StateChainTracker,
    iterations: usize,
) !void {
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    });
}

fn initializedCpu() Cpu {
    var cpu = Cpu.init(0x10000, 0x7000_0000);
    for (1..32) |index| cpu.writeReg(
        @intCast(index),
        @as(u32, @intCast(index)) *% 0x0102_0305,
    );
    return cpu;
}

fn authenticatedAuthority() !typed_auipc_authority.Authority {
    var definition = try typed_auipc.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try typed_auipc_authority.Binding.canonical(&definition);
    return typed_auipc_authority.Authority.init(&definition, &binding);
}

fn encodeAuipc(rd: u5, upper: u32) u32 {
    std.debug.assert(upper < 1 << 20);
    return (upper << 12) | (@as(u32, rd) << 7) | 0b0010111;
}

fn expectLogicallyUnchanged(
    expected_cpu: Cpu,
    actual_cpu: *const Cpu,
    trace: *const Trace,
    tracker: *const StateChainTracker,
) !void {
    const zero_clocks = [_]u32{0} ** 32;
    try std.testing.expectEqualDeep(expected_cpu, actual_cpu.*);
    try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 0), trace.step_count);
    try std.testing.expectEqualSlices(u32, &zero_clocks, &tracker.reg_last_clk);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
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
    try std.testing.expectEqual(expected.mem_last_clk.count(), actual.mem_last_clk.count());
    try std.testing.expectEqual(expected.mem_initial.count(), actual.mem_initial.count());
}

fn median(samples: []u64) u64 {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return samples[samples.len / 2];
}
