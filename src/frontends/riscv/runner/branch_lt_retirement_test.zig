const std = @import("std");
const builtin = @import("builtin");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const subject = @import("branch_lt_retirement.zig");
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");
const typed = @import("../air/lang/typed_branch_lt.zig");
const typed_authority = @import("../air/lang/typed_branch_lt_authority.zig");

const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = state_chain.StateChainTracker;
const Trace = trace_mod.Trace;

test "typed BRANCH_LT retirement is exact for every B-immediate and opcode" {
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

    const opcodes = [_]decode.Opcode{ .BLT, .BLTU, .BGE, .BGEU };
    var immediate: i32 = -4096;
    while (immediate <= 4094) : (immediate += 2) {
        const opcode = opcodes[
            @as(usize, @intCast(@divExact(immediate + 4096, 2))) & 3
        ];
        // Select a strict non-taken ordering for every opcode. This admits the
        // complete B-type encoding domain, including 2-mod-4 immediates whose
        // unselected target is intentionally outside the zkVM profile.
        const rs1: u5 = switch (opcode) {
            .BLT, .BLTU => 6,
            .BGE, .BGEU => 5,
            else => unreachable,
        };
        const rs2: u5 = switch (opcode) {
            .BLT, .BLTU => 5,
            .BGE, .BGEU => 6,
            else => unreachable,
        };
        const word = encodeBranch(opcode, rs1, rs2, immediate);
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

test "typed BRANCH_LT decisions cover signed unsigned equality aliases and target bounds" {
    const authority = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: decode.Opcode,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
        immediate: i32,
        taken: bool,
    }{
        .{ .opcode = .BLT, .rs1 = 5, .rs2 = 6, .lhs = 0xffff_ffff, .rhs = 0, .immediate = -4096, .taken = true },
        .{ .opcode = .BLT, .rs1 = 5, .rs2 = 6, .lhs = 0, .rhs = 0xffff_ffff, .immediate = 4, .taken = false },
        .{ .opcode = .BLTU, .rs1 = 5, .rs2 = 6, .lhs = 0, .rhs = 0xffff_ffff, .immediate = 4092, .taken = true },
        .{ .opcode = .BLTU, .rs1 = 5, .rs2 = 6, .lhs = 0xffff_ffff, .rhs = 0, .immediate = -4, .taken = false },
        .{ .opcode = .BGE, .rs1 = 5, .rs2 = 5, .lhs = 0x8000_0000, .rhs = 0x8000_0000, .immediate = 8, .taken = true },
        .{ .opcode = .BGE, .rs1 = 5, .rs2 = 6, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff, .immediate = 12, .taken = false },
        .{ .opcode = .BGEU, .rs1 = 5, .rs2 = 5, .lhs = 7, .rhs = 7, .immediate = 16, .taken = true },
        .{ .opcode = .BGEU, .rs1 = 5, .rs2 = 6, .lhs = 1, .rhs = 2, .immediate = 20, .taken = false },
    };
    for (cases) |case| {
        var actual_cpu = initializedCpu();
        actual_cpu.writeReg(case.rs1, case.lhs);
        actual_cpu.writeReg(case.rs2, case.rhs);
        if (case.rs1 == case.rs2) actual_cpu.writeReg(case.rs1, case.lhs);
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
            encodeBranch(case.opcode, case.rs1, case.rs2, case.immediate),
            1,
        );
        try std.testing.expectEqual(case.taken, actual_cpu.pc != 0x20_0000 + 4);
        try std.testing.expectEqualDeep(oracle_cpu, actual_cpu);
        try std.testing.expectEqualSlices(
            state_chain.Access,
            oracle_tracker.accesses.items,
            actual_tracker.accesses.items,
        );
        if (case.rs1 == case.rs2) {
            try std.testing.expectEqual(@as(u32, 1), actual_tracker.accesses.items[1].clk_prev);
            try std.testing.expectEqual(case.lhs, actual_trace.rows.items[0].rs2_val);
        }
    }
}

test "typed BRANCH_LT exact word admission exhausts registers and immediate fields" {
    const opcodes = [_]decode.Opcode{ .BLT, .BLTU, .BGE, .BGEU };
    var immediate: i32 = -4096;
    while (immediate <= 4094) : (immediate += 2) {
        const index: usize = @intCast(@divExact(immediate + 4096, 2));
        const opcode = opcodes[index & 3];
        const rs1: u5 = @truncate(index);
        const rs2: u5 = @truncate(index >> 5);
        const word = encodeBranch(opcode, rs1, rs2, immediate);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expect(subject.instructionMatchesWord(instruction, word));
        try std.testing.expect(!subject.instructionMatchesWord(instruction, word ^ 1));
        try std.testing.expect(!subject.instructionMatchesWord(instruction, word ^ (@as(u32, 1) << 12)));
    }
    for (0..32) |rs1_raw| for (0..32) |rs2_raw| for (opcodes) |opcode| {
        const word = encodeBranch(
            opcode,
            @intCast(rs1_raw),
            @intCast(rs2_raw),
            8,
        );
        try std.testing.expect(subject.instructionMatchesWord(
            try decode.DecodedInst.decode(word),
            word,
        ));
    };
}

test "typed BRANCH_LT retirement rejects malformed and stale plans atomically" {
    const authority = try authenticatedAuthority();
    {
        var cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeBranch(.BLTU, 5, 6, 2);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            error.InstructionWordMismatch,
            subject.stage(&authority, &cpu, &trace, &tracker, instruction, word ^ 1, 1),
        );
        try std.testing.expectError(
            error.InstructionClockMismatch,
            subject.stage(&authority, &cpu, &trace, &tracker, instruction, word, 2),
        );
        // BLTU is taken for x5 < x6; selecting a 2-mod-4 offset must fail.
        try std.testing.expectError(
            error.InstructionAddressMisaligned,
            subject.stage(&authority, &cpu, &trace, &tracker, instruction, word, 1),
        );
    }

    inline for ([_]Mutation{
        .plan,      .word,      .pc, .source_1, .source_2, .diagnostic, .trace,
        .tracker_1, .tracker_2,
    }) |mutation| {
        var cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        try trace.reserveOne();
        try tracker.reserveTransitions(noGapReservation(2));
        const word = encodeBranch(.BLTU, 5, 6, 8);
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
            .word => plan.inst_word ^= 1,
            .pc => cpu.pc +%= 4,
            .source_1 => cpu.writeReg(5, cpu.readReg(5) +% 4),
            .source_2 => cpu.writeReg(6, cpu.readReg(6) +% 4),
            .diagnostic => cpu.writeReg(plan.instruction.rd, cpu.readReg(plan.instruction.rd) ^ 1),
            .trace => trace.appendAssumeCapacity(plan.traceRow()),
            .tracker_1 => tracker.reg_last_clk[5] +%= 1,
            .tracker_2 => tracker.reg_last_clk[6] +%= 1,
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

    // A prepared token is a linear capability: exactly one successful
    // publication, followed by a side-effect-free AlreadyCommitted result.
    {
        var cpu = initializedCpu();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeBranch(.BLTU, 5, 6, 8);
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
        try prepared.commit(&cpu, &trace, &tracker);
        const cpu_after = cpu;
        const trace_len = trace.rows.items.len;
        const access_len = tracker.accesses.items.len;
        try std.testing.expectError(
            error.AlreadyCommitted,
            prepared.commit(&cpu, &trace, &tracker),
        );
        try std.testing.expectEqualDeep(cpu_after, cpu);
        try std.testing.expectEqual(trace_len, trace.rows.items.len);
        try std.testing.expectEqual(access_len, tracker.accesses.items.len);
    }
}

test "typed BRANCH_LT capacity failures expose no prefix and warm path allocates nothing" {
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
        const word = encodeBranch(.BLTU, 6, 5, 8);
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
        const word = encodeBranch(.BLTU, 6, 5, @intCast((index & 0x7ff) << 1));
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

test "typed BRANCH_LT retirement retains at least 97 percent legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try authenticatedAuthority();
    const samples = 13;
    const iterations = 1 << 14;
    _ = try measureTyped(&authority, 1 << 10);
    _ = try measureOracle(1 << 10);
    var fixed: [samples]u64 = undefined;
    var old: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        fixed[sample] = try measureTyped(&authority, iterations);
        old[sample] = try measureOracle(iterations);
    } else {
        old[sample] = try measureOracle(iterations);
        fixed[sample] = try measureTyped(&authority, iterations);
    };
    const fixed_median = median(&fixed);
    const old_median = median(&old);
    std.debug.print(
        "\n  typed BRANCH_LT retirement={d} ns legacy={d} ns speed={d:.4}x plan={d}B\n",
        .{
            fixed_median,
            old_median,
            @as(f64, @floatFromInt(old_median)) /
                @as(f64, @floatFromInt(fixed_median)),
            @sizeOf(subject.Plan),
        },
    );
    try std.testing.expect(
        @as(u128, fixed_median) * 97 <= @as(u128, old_median) * 100,
    );
}

const Mutation = enum {
    plan,
    word,
    pc,
    source_1,
    source_2,
    diagnostic,
    trace,
    tracker_1,
    tracker_2,
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
    const rd_value = cpu.readReg(instruction.rd);
    const access = access_witness.capture(tracker, instruction, clock);
    const taken = typed_authority.branchCondition(
        instruction.opcode,
        rs1_value,
        rs2_value,
    );
    const target = if (taken)
        pc_before +% @as(u32, @bitCast(instruction.imm))
    else
        pc_before +% 4;
    if ((target & 3) != 0 or target >= typed_authority.PC_BOUND)
        return error.InvalidOracleInput;
    cpu.pc = target;
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
        .rd_prev_val = rd_value,
        .rd_prev_clk = 0,
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
        rd_value,
        rd_value,
    );
}

fn measureTyped(authority: *const typed_authority.Authority, iterations: usize) !u64 {
    var cpu = initializedCpu();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const word = encodeBranch(.BLTU, 6, 5, @intCast((index & 0x7ff) << 1));
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
        const word = encodeBranch(.BLTU, 6, 5, @intCast((index & 0x7ff) << 1));
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
    var cpu = Cpu.init(0x20_0000, 0x7000_0000);
    for (1..32) |index| cpu.writeReg(
        @intCast(index),
        @as(u32, @intCast(index)) *% 0x0102_0305,
    );
    cpu.writeReg(5, 0x100);
    cpu.writeReg(6, 0x200);
    return cpu;
}

fn authenticatedAuthority() !typed_authority.Authority {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

fn encodeBranch(
    opcode: decode.Opcode,
    rs1: u5,
    rs2: u5,
    immediate: i32,
) u32 {
    std.debug.assert(immediate >= -4096 and immediate <= 4094 and
        (@as(u32, @bitCast(immediate)) & 1) == 0);
    const immediate_13 = @as(u32, @bitCast(immediate)) & 0x1fff;
    const funct3: u32 = switch (opcode) {
        .BLT => 0b100,
        .BGE => 0b101,
        .BLTU => 0b110,
        .BGEU => 0b111,
        else => unreachable,
    };
    return ((immediate_13 >> 12) & 1) << 31 |
        ((immediate_13 >> 5) & 0x3f) << 25 |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        ((immediate_13 >> 1) & 0xf) << 8 |
        ((immediate_13 >> 11) & 1) << 7 |
        0b1100011;
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
