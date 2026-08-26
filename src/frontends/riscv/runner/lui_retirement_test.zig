const std = @import("std");
const builtin = @import("builtin");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const Memory = @import("memory.zig").Memory;
const subject = @import("lui_retirement.zig");
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");
const typed_lui = @import("../air/lang/typed_lui.zig");
const typed_lui_authority = @import("../air/lang/typed_lui_authority.zig");

const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = state_chain.StateChainTracker;
const Trace = trace_mod.Trace;

test "E-018 staged LUI retirement is exact across x0 encoding aliases and boundaries" {
    const authority = try authenticatedAuthority();
    var actual_cpu = initializedCpu();
    var legacy_cpu = actual_cpu;
    var actual_trace = Trace.init(std.testing.allocator);
    defer actual_trace.deinit();
    var legacy_trace = Trace.init(std.testing.allocator);
    defer legacy_trace.deinit();
    actual_trace.initial_pc = actual_cpu.pc;
    legacy_trace.initial_pc = legacy_cpu.pc;
    var actual_tracker = StateChainTracker.init(std.testing.allocator);
    defer actual_tracker.deinit();
    var legacy_tracker = StateChainTracker.init(std.testing.allocator);
    defer legacy_tracker.deinit();
    for (&actual_tracker.reg_last_clk, &legacy_tracker.reg_last_clk, 0..) |*actual, *legacy, index| {
        const initial: u32 = if (index == 0) 0 else @intCast(index);
        actual.* = initial;
        legacy.* = initial;
    }
    var legacy_memory = Memory.init(std.testing.allocator);
    defer legacy_memory.deinit();

    const boundaries = [_]u32{ 0, 1, 0x7ffff, 0x80000, 0xfffff, 0x12345, 0xabcde };
    var clock: u32 = 1;
    for (0..32) |rd_raw| {
        const rd: u5 = @intCast(rd_raw);
        for (boundaries) |upper| {
            try retireBoth(
                &authority,
                &actual_cpu,
                &actual_trace,
                &actual_tracker,
                &legacy_cpu,
                &legacy_memory,
                &legacy_trace,
                &legacy_tracker,
                encodeLui(rd, upper),
                clock,
            );
            clock += 1;
        }

        // U-type bits 15..24 become the decoder's diagnostic rs1/rs2 fields.
        // Force both to alias rd and prove the staged row captures pre-write
        // values exactly even though LUI has no architectural source access.
        const alias_upper = (@as(u32, rd) << 3) | (@as(u32, rd) << 8) | 0x40000;
        try retireBoth(
            &authority,
            &actual_cpu,
            &actual_trace,
            &actual_tracker,
            &legacy_cpu,
            &legacy_memory,
            &legacy_trace,
            &legacy_tracker,
            encodeLui(rd, alias_upper),
            clock,
        );
        clock += 1;
    }

    try std.testing.expectEqualDeep(legacy_cpu, actual_cpu);
    try std.testing.expectEqualSlices(
        trace_mod.TraceRow,
        legacy_trace.rows.items,
        actual_trace.rows.items,
    );
    try expectTrackersEqual(&legacy_tracker, &actual_tracker);
    for (actual_trace.rows.items) |row| {
        if (row.rd == 0) try std.testing.expectEqual(@as(u32, 0), row.rd_val);
    }
}

test "E-018 staged LUI capacity failures expose no retirement prefix" {
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
        const instruction_clock = state_chain.MAX_CLOCK_DIFF / 4 + 9;
        try exec_trace.bindExtractedClockRange(
            instruction_clock - 1,
            instruction_clock - 1,
            0,
        );
        const word = encodeLui(7, 0xabcde);
        const instruction = try decode.DecodedInst.decode(word);
        subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word,
            instruction_clock,
        ) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try expectLogicallyUnchanged(cpu_before, &cpu, &exec_trace, &tracker);
            observed_failures += 1;
            continue;
        };
        try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 1), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(u32, 0xabcde000), cpu.readReg(7));
        reached_success = true;
        break;
    }
    // Trace storage, access storage, and the synthetic register-gap log are
    // three independent fallible destinations for this deliberately distant
    // instruction clock.
    try std.testing.expect(observed_failures >= 3);
    try std.testing.expect(reached_success);
}

test "E-018 staged LUI commit is allocation-free after exact preflight" {
    const authority = try authenticatedAuthority();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    const instruction_clock = state_chain.MAX_CLOCK_DIFF / 4 + 9;
    try exec_trace.bindExtractedClockRange(
        instruction_clock - 1,
        instruction_clock - 1,
        0,
    );
    const word = encodeLui(9, 0x80000);
    const instruction = try decode.DecodedInst.decode(word);
    const plan = try subject.stage(
        &authority,
        cpu,
        &exec_trace,
        &tracker,
        instruction,
        word,
        instruction_clock,
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
    try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 1), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(u32, 0x8000_0000), cpu.readReg(9));
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
}

test "E-018 staged LUI rejects forged and stale plans before publication" {
    const authority = try authenticatedAuthority();

    {
        const cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeLui(5, 0x12345);
        var plan = try subject.stage(
            &authority,
            cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        plan.instruction.opcode = .AUIPC;
        try std.testing.expectError(
            error.StaleRetirement,
            plan.prepare(&cpu, &exec_trace, &tracker),
        );
        try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    }

    {
        const cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeLui(5, 0x12345);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            error.InstructionWordMismatch,
            subject.stage(
                &authority,
                cpu,
                &exec_trace,
                &tracker,
                instruction,
                word ^ 1,
                1,
            ),
        );
    }

    inline for ([_]Mutation{ .pc, .destination, .trace, .tracker }) |mutation| {
        var cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeLui(5, 0x12345);
        const plan = try subject.stage(
            &authority,
            cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
        switch (mutation) {
            .pc => cpu.pc +%= 4,
            .destination => cpu.writeReg(5, cpu.readReg(5) ^ 1),
            .trace => exec_trace.appendAssumeCapacity(plan.traceRow()),
            .tracker => tracker.reg_last_clk[5] +%= 1,
        }
        const cpu_before = cpu;
        const trace_len_before = exec_trace.rows.items.len;
        const access_len_before = tracker.accesses.items.len;
        const clock_updates_before = tracker.clock_updates_reg.items.len;
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &exec_trace, &tracker),
        );
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(trace_len_before, exec_trace.rows.items.len);
        try std.testing.expectEqual(access_len_before, tracker.accesses.items.len);
        try std.testing.expectEqual(clock_updates_before, tracker.clock_updates_reg.items.len);
    }
}

test "E-018 staged LUI warm hot path performs no allocation" {
    const authority = try authenticatedAuthority();
    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;

    for (0..iterations) |index| {
        const rd: u5 = @intCast(index & 31);
        const upper: u32 = @intCast((index *% 0x9e377) & 0xfffff);
        const word = encodeLui(rd, upper);
        try subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, iterations), exec_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, iterations), tracker.accesses.items.len);
}

test "E-018 staged LUI retirement retains paired legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;

    const authority = try authenticatedAuthority();
    const samples = 9;
    const iterations = 1 << 13;
    var staged_samples: [samples]u64 = undefined;
    var legacy_samples: [samples]u64 = undefined;
    for (0..samples) |sample| {
        if ((sample & 1) == 0) {
            staged_samples[sample] = try measureStaged(&authority, iterations);
            legacy_samples[sample] = try measureLegacy(iterations);
        } else {
            legacy_samples[sample] = try measureLegacy(iterations);
            staged_samples[sample] = try measureStaged(&authority, iterations);
        }
    }
    const staged_median = median(&staged_samples);
    const legacy_median = median(&legacy_samples);
    std.debug.print(
        "\n  E-018 staged LUI runner: atomic={d} ns legacy={d} ns speed={d:.4}x plan={d}B token={d}B\n",
        .{
            staged_median,
            legacy_median,
            @as(f64, @floatFromInt(legacy_median)) /
                @as(f64, @floatFromInt(staged_median)),
            @sizeOf(subject.Plan),
            @sizeOf(subject.Prepared),
        },
    );
    // A safety boundary may consume at most 15% versus the current fallible
    // publication sequence. This is deliberately stricter than an unbounded
    // "correct but slow" admission while tranche 2 remains shadow-only.
    try std.testing.expect(staged_median * 85 <= legacy_median * 100);
}

const Mutation = enum { pc, destination, trace, tracker };

fn retireBoth(
    authority: *const typed_lui_authority.Authority,
    actual_cpu: *Cpu,
    actual_trace: *Trace,
    actual_tracker: *StateChainTracker,
    legacy_cpu: *Cpu,
    legacy_memory: *Memory,
    legacy_trace: *Trace,
    legacy_tracker: *StateChainTracker,
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
    try legacyRetire(
        legacy_cpu,
        legacy_memory,
        legacy_trace,
        legacy_tracker,
        instruction,
        word,
        clock,
    );
    try std.testing.expectEqualDeep(legacy_cpu.*, actual_cpu.*);
    try std.testing.expectEqualDeep(
        legacy_trace.rows.items[legacy_trace.rows.items.len - 1],
        actual_trace.rows.items[actual_trace.rows.items.len - 1],
    );
    try expectTrackersEqual(legacy_tracker, actual_tracker);
}

fn legacyRetire(
    cpu: *Cpu,
    _: *Memory,
    exec_trace: *Trace,
    tracker: *StateChainTracker,
    instruction: decode.DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) !void {
    const pc_before = cpu.pc;
    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_previous_value = cpu.readReg(instruction.rd);
    const access = access_witness.capture(tracker, instruction, instruction_clock);
    // Explicit retained oracle for the removed legacy executor arm. Keeping
    // this formula in the differential test (and nowhere in production
    // dispatch) lets the generated retirement continue to compare against an
    // independent implementation until the external Sail receipt is frozen.
    cpu.writeReg(instruction.rd, @bitCast(instruction.imm));
    cpu.pc +%= 4;
    const rd_value = cpu.readReg(instruction.rd);
    try exec_trace.append(.{
        .clk = instruction_clock,
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
        .rd_prev_val = rd_previous_value,
        .rd_prev_clk = access.rd_prev_clock,
        .rd_val = rd_value,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = cpu.pc != pc_before +% 4,
        .next_pc = cpu.pc,
        .inst_word = inst_word,
    });
    try access.recordRegisters(
        tracker,
        instruction,
        rs1_value,
        rs2_value,
        rd_previous_value,
        rd_value,
    );
}

fn measureStaged(
    authority: *const typed_lui_authority.Authority,
    iterations: usize,
) !u64 {
    var cpu = initializedCpu();
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index & 31);
        const word = encodeLui(rd, @intCast((index *% 0x9e377) & 0xfffff));
        try subject.retireAtomic(
            authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(exec_trace.rows.items.ptr);
    std.mem.doNotOptimizeAway(tracker.accesses.items.ptr);
    return elapsed;
}

fn measureLegacy(iterations: usize) !u64 {
    var cpu = initializedCpu();
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = 0,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index & 31);
        const word = encodeLui(rd, @intCast((index *% 0x9e377) & 0xfffff));
        try legacyRetire(
            &cpu,
            &memory,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            @intCast(index + 1),
        );
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(exec_trace.rows.items.ptr);
    std.mem.doNotOptimizeAway(tracker.accesses.items.ptr);
    return elapsed;
}

fn initializedCpu() Cpu {
    var cpu = Cpu.init(0x10000, 0x7000_0000);
    for (1..32) |index| cpu.writeReg(
        @intCast(index),
        @as(u32, @intCast(index)) *% 0x0102_0305,
    );
    return cpu;
}

fn authenticatedAuthority() !typed_lui_authority.Authority {
    var definition = try typed_lui.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = typed_lui_authority.Binding.canonical(&definition);
    return typed_lui_authority.Authority.init(&definition, &binding);
}

fn encodeLui(rd: u5, upper: u32) u32 {
    std.debug.assert(upper < 1 << 20);
    return (upper << 12) | (@as(u32, rd) << 7) | 0b0110111;
}

fn expectLogicallyUnchanged(
    expected_cpu: Cpu,
    actual_cpu: *const Cpu,
    exec_trace: *const Trace,
    tracker: *const StateChainTracker,
) !void {
    const zero_clocks = [_]u32{0} ** 32;
    try std.testing.expectEqualDeep(expected_cpu, actual_cpu.*);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.step_count);
    try std.testing.expectEqualSlices(u32, &zero_clocks, &tracker.reg_last_clk);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_mem.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
    try std.testing.expectEqual(@as(u32, 0), tracker.mem_last_clk.count());
    try std.testing.expectEqual(@as(u32, 0), tracker.mem_initial.count());
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
        expected.clock_updates_mem.items,
        actual.clock_updates_mem.items,
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
