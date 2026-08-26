const std = @import("std");
const builtin = @import("builtin");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const subject = @import("fence_retirement.zig");
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");
const typed_fence = @import("../air/lang/typed_fence.zig");
const typed_fence_authority = @import("../air/lang/typed_fence_authority.zig");

const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = state_chain.StateChainTracker;
const Trace = trace_mod.Trace;

test "E-019 staged FENCE is exact for every immediate and reserved register field" {
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
    try seedTracker(&actual_tracker);
    try seedTracker(&legacy_tracker);

    var clock: u32 = 1;
    for (0..4096) |immediate_raw| {
        const immediate: u12 = @intCast(immediate_raw);
        const rd: u5 = @truncate(immediate_raw *% 13);
        const rs1: u5 = @truncate((immediate_raw *% 29) >> 2);
        try retireBoth(
            &authority,
            &actual_cpu,
            &actual_trace,
            &actual_tracker,
            &legacy_cpu,
            &legacy_trace,
            &legacy_tracker,
            encodeFence(rd, rs1, immediate),
            clock,
        );
        clock += 1;
    }

    // Cover every rd/rs1 pair independently of the exhaustive immediate arm;
    // rs2 is the low five immediate bits and cycles over every value here.
    for (0..32) |rd_raw| {
        for (0..32) |rs1_raw| {
            const immediate: u12 = @intCast(
                0x800 | ((rd_raw * 7 + rs1_raw * 11) & 0x7ff),
            );
            try retireBoth(
                &authority,
                &actual_cpu,
                &actual_trace,
                &actual_tracker,
                &legacy_cpu,
                &legacy_trace,
                &legacy_tracker,
                encodeFence(@intCast(rd_raw), @intCast(rs1_raw), immediate),
                clock,
            );
            clock += 1;
        }
    }

    // Sequential state transition is wrapping RV32 arithmetic.
    actual_cpu.pc = 0xffff_fffc;
    legacy_cpu.pc = actual_cpu.pc;
    try retireBoth(
        &authority,
        &actual_cpu,
        &actual_trace,
        &actual_tracker,
        &legacy_cpu,
        &legacy_trace,
        &legacy_tracker,
        encodeFence(0, 0, 0xfff),
        clock,
    );

    try std.testing.expectEqualDeep(legacy_cpu, actual_cpu);
    try std.testing.expectEqualSlices(
        trace_mod.TraceRow,
        legacy_trace.rows.items,
        actual_trace.rows.items,
    );
    try expectTrackersEqual(&legacy_tracker, &actual_tracker);
    for (actual_trace.rows.items) |row| {
        try std.testing.expectEqual(row.rd_prev_val, row.rd_val);
        try std.testing.expectEqual(@as(u32, 0), row.rs1_prev_clk);
        try std.testing.expectEqual(@as(u32, 0), row.rs2_prev_clk);
        try std.testing.expectEqual(@as(u32, 0), row.rd_prev_clk);
        if (row.rd == 0) try std.testing.expectEqual(@as(u32, 0), row.rd_val);
        if (row.rs1 == 0) try std.testing.expectEqual(@as(u32, 0), row.rs1_val);
        if (row.rs2 == 0) try std.testing.expectEqual(@as(u32, 0), row.rs2_val);
    }
}

test "E-019 staged FENCE has one fallible destination and no logical prefix" {
    const authority = try authenticatedAuthority();
    var observed_failures: usize = 0;
    var reached_success = false;
    for (0..4) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var cpu = initializedCpu();
        const cpu_before = cpu;
        var exec_trace = Trace.init(failing.allocator());
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        try seedTracker(&tracker);
        const tracker_before = tracker;
        const word = encodeFence(7, 6, 0x8a5);
        subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        ) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqualDeep(cpu_before, cpu);
            try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
            try std.testing.expectEqual(@as(usize, 0), exec_trace.step_count);
            try expectTrackerHeaderUnchanged(&tracker_before, &tracker);
            observed_failures += 1;
            continue;
        };
        try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
        try std.testing.expectEqual(cpu_before.pc +% 4, cpu.pc);
        try expectTrackerHeaderUnchanged(&tracker_before, &tracker);
        reached_success = true;
        break;
    }
    try std.testing.expectEqual(@as(usize, 1), observed_failures);
    try std.testing.expect(reached_success);
}

test "E-019 staged FENCE commit is allocation-free after exact trace preflight" {
    const authority = try authenticatedAuthority();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try seedTracker(&tracker);
    const tracker_before = tracker;
    const word = encodeFence(9, 10, 0x81f);
    const plan = try subject.stage(
        &authority,
        &cpu,
        &exec_trace,
        &tracker,
        try decode.DecodedInst.decode(word),
        word,
        1,
    );
    var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
    try std.testing.expect(exec_trace.rows.capacity >= 1);

    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try prepared.commit(&cpu, &exec_trace, &tracker);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
    try expectTrackerHeaderUnchanged(&tracker_before, &tracker);
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
}

test "E-019 staged FENCE rejects forged and stale trace-visible state" {
    const authority = try authenticatedAuthority();

    {
        var cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeFence(7, 6, 0x805);
        var plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        plan.instruction.opcode = .ADDI;
        try std.testing.expectError(
            error.StaleRetirement,
            plan.prepare(&cpu, &exec_trace, &tracker),
        );
        plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        plan.instruction.imm = 2048;
        try std.testing.expectError(
            error.StaleRetirement,
            plan.prepare(&cpu, &exec_trace, &tracker),
        );
        plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        plan.inst_word ^= 1;
        try std.testing.expectError(
            error.StaleRetirement,
            plan.prepare(&cpu, &exec_trace, &tracker),
        );
        plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        plan.instruction_clock = 2;
        try std.testing.expectError(
            error.StaleRetirement,
            plan.prepare(&cpu, &exec_trace, &tracker),
        );
        try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
    }

    {
        var cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeFence(7, 6, 0x805);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            error.InstructionClockMismatch,
            subject.stage(
                &authority,
                &cpu,
                &exec_trace,
                &tracker,
                instruction,
                word,
                2,
            ),
        );
        try std.testing.expectError(
            error.InstructionWordMismatch,
            subject.stage(
                &authority,
                &cpu,
                &exec_trace,
                &tracker,
                instruction,
                word ^ (@as(u32, 1) << 12),
                1,
            ),
        );
        exec_trace.step_count = 1;
        try std.testing.expectError(
            error.TraceInvariantViolation,
            subject.stage(
                &authority,
                &cpu,
                &exec_trace,
                &tracker,
                instruction,
                word,
                1,
            ),
        );
    }

    inline for ([_]Mutation{ .pc, .rs1, .rs2, .rd, .trace }) |mutation| {
        var cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeFence(7, 6, 0x805); // rs2 = x5
        const plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
        switch (mutation) {
            .pc => cpu.pc +%= 4,
            .rs1 => cpu.writeReg(6, cpu.readReg(6) ^ 1),
            .rs2 => cpu.writeReg(5, cpu.readReg(5) ^ 1),
            .rd => cpu.writeReg(7, cpu.readReg(7) ^ 1),
            .trace => exec_trace.appendAssumeCapacity(plan.traceRow()),
        }
        const cpu_before = cpu;
        const trace_len_before = exec_trace.rows.items.len;
        const step_before = exec_trace.step_count;
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &exec_trace, &tracker),
        );
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(trace_len_before, exec_trace.rows.items.len);
        try std.testing.expectEqual(step_before, exec_trace.step_count);
    }

    // Tracker clock drift is intentionally irrelevant: authenticated FENCE
    // carries no address and must not manufacture a false dependency.
    {
        var cpu = initializedCpu();
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeFence(7, 6, 0x805);
        const plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
        tracker.reg_last_clk[7] = 0x1234;
        try prepared.commit(&cpu, &exec_trace, &tracker);
        try std.testing.expectEqual(@as(u32, 0x1234), tracker.reg_last_clk[7]);
    }
}

test "E-019 staged FENCE warm hot path performs no allocation or tracker write" {
    const authority = try authenticatedAuthority();
    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = initializedCpu();
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try seedTracker(&tracker);
    try exec_trace.reserveAdditional(iterations);
    const tracker_before = tracker;
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;

    for (0..iterations) |index| {
        const word = encodeFence(
            @truncate(index *% 13),
            @truncate(index *% 29),
            @truncate(index *% 0x9e3),
        );
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
    try expectTrackerHeaderUnchanged(&tracker_before, &tracker);
    try std.testing.expect(@sizeOf(subject.Plan) <= subject.MAX_PLAN_BYTES);
    try std.testing.expect(@sizeOf(subject.Prepared) <= subject.MAX_PREPARED_BYTES);
}

test "E-019 staged FENCE retirement retains paired legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;

    const authority = try authenticatedAuthority();
    const samples = 9;
    // FENCE is so small that 8K rows complete below the host scheduler's
    // useful timing granularity in the aggregate AIR suite. Keep nine paired
    // samples but lengthen each to make preemption noise a small fraction.
    const iterations = 1 << 16;
    var staged_samples: [samples]u64 = undefined;
    var legacy_samples: [samples]u64 = undefined;
    var paired_samples: [samples]TimingPair = undefined;
    for (0..samples) |sample| {
        if ((sample & 1) == 0) {
            staged_samples[sample] = try measureStaged(&authority, iterations);
            legacy_samples[sample] = try measureLegacy(iterations);
        } else {
            legacy_samples[sample] = try measureLegacy(iterations);
            staged_samples[sample] = try measureStaged(&authority, iterations);
        }
        paired_samples[sample] = .{
            .staged = staged_samples[sample],
            .legacy = legacy_samples[sample],
        };
    }
    const staged_median = median(&staged_samples);
    const legacy_median = median(&legacy_samples);
    std.sort.heap(TimingPair, &paired_samples, {}, timingRatioLessThan);
    const paired_median = paired_samples[samples / 2];
    std.debug.print(
        "\n  E-019 staged FENCE runner: atomic={d} ns legacy={d} ns " ++
            "paired_speed={d:.4}x plan={d}B token={d}B\n",
        .{
            staged_median,
            legacy_median,
            @as(f64, @floatFromInt(paired_median.legacy)) /
                @as(f64, @floatFromInt(paired_median.staged)),
            @sizeOf(subject.Plan),
            @sizeOf(subject.Prepared),
        },
    );
    // Keep E-018's strict cap unchanged: the safety boundary may consume at
    // most 15% versus the current fallible publication sequence. The paired
    // median preserves temporal locality under frequency and thermal drift.
    try std.testing.expect(
        paired_median.staged * 85 <= paired_median.legacy * 100,
    );
}

const Mutation = enum { pc, rs1, rs2, rd, trace };
const TimingPair = struct { staged: u64, legacy: u64 };

fn retireBoth(
    authority: *const typed_fence_authority.Authority,
    actual_cpu: *Cpu,
    actual_trace: *Trace,
    actual_tracker: *StateChainTracker,
    legacy_cpu: *Cpu,
    legacy_trace: *Trace,
    legacy_tracker: *StateChainTracker,
    word: u32,
    clock: u32,
) !void {
    const instruction = try decode.DecodedInst.decode(word);
    const plan = try subject.stage(
        authority,
        actual_cpu,
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
    // Independent test-only architectural oracle: FENCE is a state-only
    // sequential retirement in the single-hart profile. Reserved rd/rs1/rs2
    // encoding fields are trace-visible but create no register accesses.
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
    authority: *const typed_fence_authority.Authority,
    iterations: usize,
) !u64 {
    var cpu = initializedCpu();
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const word = benchmarkWord(index);
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
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const word = benchmarkWord(index);
        try legacyRetire(
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

inline fn benchmarkWord(index: usize) u32 {
    return encodeFence(
        @truncate(index *% 13),
        @truncate(index *% 29),
        @truncate(index *% 0x9e3),
    );
}

fn initializedCpu() Cpu {
    var cpu = Cpu.init(0x10000, 0x7000_0000);
    for (1..32) |index| cpu.writeReg(
        @intCast(index),
        @as(u32, @intCast(index)) *% 0x0102_0305,
    );
    return cpu;
}

fn authenticatedAuthority() !typed_fence_authority.Authority {
    var definition = try typed_fence.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try typed_fence_authority.Binding.canonical(&definition);
    return typed_fence_authority.Authority.init(&definition, &binding);
}

fn encodeFence(rd: u5, rs1: u5, immediate: u12) u32 {
    return (@as(u32, immediate) << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, rd) << 7) |
        0b0001111;
}

fn seedTracker(tracker: *StateChainTracker) !void {
    for (&tracker.reg_last_clk, 0..) |*clock, index|
        clock.* = @intCast(index * 19);
    try tracker.mem_initial.put(0x2000, 0x1122_3344);
    try tracker.mem_last_clk.put(0x2000, 77);
}

fn expectTrackerHeaderUnchanged(
    expected: *const StateChainTracker,
    actual: *const StateChainTracker,
) !void {
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(expected),
        std.mem.asBytes(actual),
    );
}

fn expectTrackersEqual(
    expected: *const StateChainTracker,
    actual: *const StateChainTracker,
) !void {
    try std.testing.expectEqual(expected.reg_last_clk, actual.reg_last_clk);
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
    try std.testing.expectEqualSlices(
        state_chain.ClockUpdate,
        expected.clock_updates_mem.items,
        actual.clock_updates_mem.items,
    );
    try std.testing.expectEqual(expected.mem_initial.count(), actual.mem_initial.count());
    try std.testing.expectEqual(expected.mem_last_clk.count(), actual.mem_last_clk.count());
    var keys = expected.mem_last_clk.keyIterator();
    while (keys.next()) |address| {
        try std.testing.expectEqual(
            expected.mem_last_clk.get(address.*),
            actual.mem_last_clk.get(address.*),
        );
        try std.testing.expectEqual(
            expected.mem_initial.get(address.*),
            actual.mem_initial.get(address.*),
        );
    }
}

fn median(values: []u64) u64 {
    std.sort.heap(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

fn timingRatioLessThan(_: void, lhs: TimingPair, rhs: TimingPair) bool {
    return @as(u128, lhs.staged) * rhs.legacy <
        @as(u128, rhs.staged) * lhs.legacy;
}
