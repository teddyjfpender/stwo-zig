const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../access_clock.zig");
const access_transaction = @import("../air/lang/access_transaction.zig");
const isa_profile = @import("../isa/profile.zig");
const decode = @import("decode.zig");
const subject = @import("jal_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

test "JAL retirement is exact across target link x0 encoding aliases and boundaries" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct {
        pc: u32,
        immediate: i32,
        rd: u5,
    }{
        .{ .pc = 0, .immediate = 4, .rd = 0 },
        .{ .pc = 4, .immediate = -4, .rd = 1 },
        .{ .pc = 0x10_0000, .immediate = -1_048_576, .rd = 31 },
        .{ .pc = 0x20_0000, .immediate = 1_048_572, .rd = 7 },
        .{ .pc = 0x3fff_fffc, .immediate = -4, .rd = 9 },
    };

    for (cases, 0..) |case, index| {
        var cpu = Cpu.init(case.pc, 0);
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeJal(case.rd, case.immediate);
        const instruction = try decode.DecodedInst.decode(word);
        cpu.writeReg(instruction.rs1, 0x1111_0000 +% @as(u32, @intCast(index)));
        cpu.writeReg(instruction.rs2, 0x2222_0000 +% @as(u32, @intCast(index)));
        cpu.writeReg(case.rd, 0x3333_0000 +% @as(u32, @intCast(index)));
        const pc_before = cpu.pc;
        const rs1_before = cpu.readReg(instruction.rs1);
        const rs2_before = cpu.readReg(instruction.rs2);
        const rd_before = cpu.readReg(case.rd);

        try subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word,
            1,
        );

        try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 1), tracker.accesses.items.len);
        const row = exec_trace.rows.items[0];
        const target = pc_before +% @as(u32, @bitCast(case.immediate));
        const link = pc_before +% 4;
        try std.testing.expectEqual(target, cpu.pc);
        try std.testing.expectEqual(if (case.rd == 0) 0 else link, cpu.readReg(case.rd));
        try std.testing.expectEqual(rs1_before, row.rs1_val);
        try std.testing.expectEqual(rs2_before, row.rs2_val);
        try std.testing.expectEqual(rd_before, row.rd_prev_val);
        try std.testing.expectEqual(if (case.rd == 0) 0 else link, row.rd_val);
        try std.testing.expectEqual(target, row.next_pc);
        try std.testing.expectEqual(target != link, row.branch_taken);
        try std.testing.expectEqual(word, row.inst_word);
        try std.testing.expectEqual(
            access_clock.encode(1, .first),
            tracker.accesses.items[0].clk,
        );
        try std.testing.expectEqual(if (case.rd == 0) 0 else link, tracker.accesses.items[0].value);

        var main_storage: [20][1]M31 = undefined;
        var main: [20][]M31 = undefined;
        for (&main_storage, &main) |*owned, *view| view.* = owned;
        authority.writeActiveRow(&main, 0, row);
        var scalars: [20]QM31 = undefined;
        for (&scalars, main_storage) |*scalar, cell|
            scalar.* = QM31.fromBase(cell[0]);
        const program = try authority.buildProgram(
            QM31,
            &scalars,
            scalars[2],
            QM31.one(),
        );
        try std.testing.expect(program.direct_constraints.allZero());
    }
}

test "JAL exact word gate covers every representable displacement" {
    const registers = [_]u5{ 0, 1, 17, 31 };
    var immediate: i32 = -1_048_576;
    var count: usize = 0;
    while (immediate <= 1_048_574) : (immediate += 2) {
        const rd = registers[count & (registers.len - 1)];
        const word = encodeJal(rd, immediate);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expect(subject.instructionMatchesWord(instruction, word));
        var forged = instruction;
        forged.rs1 +%= 1;
        try std.testing.expect(!subject.instructionMatchesWord(forged, word));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1 << 20), count);
}

test "JAL compact transaction equals the generic one-register compiler" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct { rd: u5, immediate: i32, pc: u32 }{
        .{ .rd = 0, .immediate = 4, .pc = 0 },
        .{ .rd = 1, .immediate = -4, .pc = 8 },
        .{ .rd = 31, .immediate = 0x1ffc, .pc = 0x1000 },
    };
    for (cases) |case| {
        var cpu = Cpu.init(case.pc, 0);
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        tracker.reg_last_clk[case.rd] = 0;
        cpu.writeReg(case.rd, 0x7654_3210);
        const word = encodeJal(case.rd, case.immediate);
        const instruction = try decode.DecodedInst.decode(word);
        const plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word,
            1,
        );
        const generic = try access_transaction.compile(&tracker, .{
            .instruction = instruction,
            .instruction_clock = 1,
            .rs1_value = cpu.readReg(instruction.rs1),
            .rs2_value = cpu.readReg(instruction.rs2),
            .rd_previous_value = cpu.readReg(case.rd),
            .rd_next_value = plan.rd_next_value,
        });
        try std.testing.expectEqual(@as(usize, 1), generic.accessEvents().len);
        try std.testing.expectEqual(plan.raw_previous_clock, generic.events[0].raw_previous_clock);
        try std.testing.expectEqual(plan.previous_clock, generic.events[0].previous_clock);
        try std.testing.expectEqual(
            plan.register_clock_update_count,
            generic.reservation.register_clock_update_count,
        );
        try std.testing.expectEqual(plan.rd_next_value, generic.rd_next_value);
    }
}

test "JAL target alignment bounds clock and word failures publish nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct {
        pc: u32,
        immediate: i32,
        expected: anyerror,
    }{
        .{ .pc = 2, .immediate = 0, .expected = error.MisalignedProgramCounter },
        .{ .pc = 0x4000_0000, .immediate = 0, .expected = error.ProgramCounterOutOfRange },
        .{ .pc = 0, .immediate = 2, .expected = error.MisalignedJumpTarget },
        .{ .pc = 0, .immediate = -4, .expected = error.JumpTargetOutOfRange },
        .{ .pc = 0x3fff_fffc, .immediate = 4, .expected = error.JumpTargetOutOfRange },
    };
    for (cases) |case| {
        var cpu = Cpu.init(case.pc, 0);
        const before = cpu;
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeJal(1, case.immediate);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            case.expected,
            subject.retireAtomic(
                &authority,
                &cpu,
                &exec_trace,
                &tracker,
                instruction,
                word,
                1,
            ),
        );
        try expectLogicallyUnchanged(before, &cpu, &exec_trace, &tracker);
    }

    var cpu = Cpu.init(0x1000, 0);
    const before = cpu;
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encodeJal(1, 4);
    const instruction = try decode.DecodedInst.decode(word);
    try std.testing.expectError(
        error.InstructionWordMismatch,
        subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word ^ (@as(u32, 1) << 12),
            1,
        ),
    );
    try expectLogicallyUnchanged(before, &cpu, &exec_trace, &tracker);
    try std.testing.expectError(
        error.InstructionClockMismatch,
        subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word,
            2,
        ),
    );
}

test "JAL forged and stale plans reject before logical mutation" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(1, 0xaaaa_aaaa);
    cpu.writeReg(2, 0x2222_2222);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    // Immediate bit 15 is also the decoder's trace-visible diagnostic `rs1`
    // field, so this word gives us a nonzero encoding alias distinct from rd.
    const word = encodeJal(2, 1 << 15);
    const instruction = try decode.DecodedInst.decode(word);

    inline for ([_]PlanMutation{
        .target,
        .link,
        .branch_taken,
        .previous_clock,
        .raw_clock,
        .gap_count,
        .word,
    }) |mutation| {
        var plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word,
            1,
        );
        switch (mutation) {
            .target => plan.next_pc +%= 4,
            .link => plan.rd_next_value +%= 1,
            .branch_taken => plan.branch_taken = !plan.branch_taken,
            .previous_clock => plan.previous_clock +%= 1,
            .raw_clock => plan.raw_previous_clock +%= 1,
            .gap_count => plan.register_clock_update_count += 1,
            .word => plan.inst_word ^= 1 << 12,
        }
        try expectPrepareAtomicFailure(&plan, &cpu, &exec_trace, &tracker);
    }

    inline for ([_]StaleMutation{
        .pc,
        .destination,
        .encoding_alias,
        .trace,
        .tracker,
    }) |mutation| {
        cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(1, 0xaaaa_aaaa);
        cpu.writeReg(2, 0x2222_2222);
        exec_trace.rows.clearRetainingCapacity();
        exec_trace.step_count = 0;
        tracker.reg_last_clk = .{0} ** 32;
        tracker.accesses.clearRetainingCapacity();
        tracker.clock_updates_reg.clearRetainingCapacity();
        const plan = try subject.stage(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            instruction,
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
        switch (mutation) {
            .pc => cpu.pc +%= 4,
            .destination => cpu.writeReg(2, cpu.readReg(2) ^ 1),
            .encoding_alias => cpu.writeReg(instruction.rs1, cpu.readReg(instruction.rs1) ^ 1),
            .trace => exec_trace.appendAssumeCapacity(plan.traceRow()),
            .tracker => tracker.reg_last_clk[2] +%= 1,
        }
        const before = cpu;
        const rows_before = exec_trace.rows.items.len;
        const accesses_before = tracker.accesses.items.len;
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &exec_trace, &tracker),
        );
        try std.testing.expectEqualDeep(before, cpu);
        try std.testing.expectEqual(rows_before, exec_trace.rows.items.len);
        try std.testing.expectEqual(accesses_before, tracker.accesses.items.len);
    }
}

test "JAL cold allocation failure is atomic and warm retirement allocates nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var cpu = Cpu.init(0x1000, 0);
        var exec_trace = Trace.init(failing.allocator());
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        const before = cpu;
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const word = encodeJal(1, 4);
        try std.testing.expectError(
            error.OutOfMemory,
            subject.retireAtomic(
                &authority,
                &cpu,
                &exec_trace,
                &tracker,
                try decode.DecodedInst.decode(word),
                word,
                1,
            ),
        );
        try expectLogicallyUnchanged(before, &cpu, &exec_trace, &tracker);
    }

    const iterations = 1 << 12;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = Cpu.init(0, 0);
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = iterations * 4,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index % 31 + 1);
        const word = encodeJal(rd, 4);
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
    try std.testing.expect(@sizeOf(subject.Plan) <= subject.MAX_PLAN_BYTES);
}

test "JAL retirement retains paired legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const samples = 9;
    const iterations = 1 << 14;
    var staged: [samples]u64 = undefined;
    var legacy: [samples]u64 = undefined;
    var direct_floor: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        staged[sample] = try measureStaged(&authority, iterations);
        legacy[sample] = try measureLegacy(iterations);
        direct_floor[sample] = try measureDirectFloor(iterations);
    } else {
        direct_floor[sample] = try measureDirectFloor(iterations);
        legacy[sample] = try measureLegacy(iterations);
        staged[sample] = try measureStaged(&authority, iterations);
    };
    const staged_median = median(&staged);
    const legacy_median = median(&legacy);
    const direct_floor_median = median(&direct_floor);
    std.debug.print(
        "\n  typed JAL retirement={d} ns legacy={d} ns " ++
            "legacy_ratio={d:.4} direct_floor={d} ns floor_ratio={d:.4}\n",
        .{
            staged_median,
            legacy_median,
            @as(f64, @floatFromInt(staged_median)) /
                @as(f64, @floatFromInt(legacy_median)),
            direct_floor_median,
            @as(f64, @floatFromInt(staged_median)) /
                @as(f64, @floatFromInt(direct_floor_median)),
        },
    );
    // Regression admission compares the same execution/trace/access work as
    // the pre-cutover runner. The unchecked assume-capacity implementation is
    // retained only as a lower-bound diagnostic: it deliberately omits word,
    // clock, target, and failure-atomicity checks and is not a valid baseline.
    // The typed safety boundary may consume at most 20% over that exact legacy
    // work; current medians are faster, leaving deliberate scheduler margin.
    try std.testing.expect(@as(u128, staged_median) * 100 <=
        @as(u128, legacy_median) * 120);
}

const PlanMutation = enum {
    target,
    link,
    branch_taken,
    previous_clock,
    raw_clock,
    gap_count,
    word,
};

const StaleMutation = enum {
    pc,
    destination,
    encoding_alias,
    trace,
    tracker,
};

fn expectPrepareAtomicFailure(
    plan: *const subject.Plan,
    cpu: *const Cpu,
    exec_trace: *Trace,
    tracker: *StateChainTracker,
) !void {
    const before = cpu.*;
    const accesses_before = tracker.accesses.items.len;
    try std.testing.expectError(
        error.StaleRetirement,
        plan.prepare(cpu, exec_trace, tracker),
    );
    try std.testing.expectEqualDeep(before, cpu.*);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
    try std.testing.expectEqual(accesses_before, tracker.accesses.items.len);
}

fn expectLogicallyUnchanged(
    expected_cpu: Cpu,
    cpu: *const Cpu,
    exec_trace: *const Trace,
    tracker: *const StateChainTracker,
) !void {
    try std.testing.expectEqualDeep(expected_cpu, cpu.*);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.step_count);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
}

fn encodeJal(rd: u5, immediate: i32) u32 {
    std.debug.assert(immediate >= -1_048_576 and immediate <= 1_048_574);
    const bits: u32 = @bitCast(immediate);
    std.debug.assert(bits & 1 == 0);
    return ((bits >> 20) & 1) << 31 |
        ((bits >> 1) & 0x3ff) << 21 |
        ((bits >> 11) & 1) << 20 |
        ((bits >> 12) & 0xff) << 12 |
        (@as(u32, rd) << 7) |
        0x6f;
}

fn measureStaged(
    authority: *const subject.Authority,
    iterations: usize,
) !u64 {
    var cpu = Cpu.init(0x20_0000, 0);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = iterations * 4,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index % 31 + 1);
        const word = encodeJal(rd, benchmarkImmediate(index));
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
    std.mem.doNotOptimizeAway(exec_trace.rows.items[iterations - 1]);
    std.mem.doNotOptimizeAway(tracker.accesses.items[iterations - 1]);
    return elapsed;
}

fn measureLegacy(iterations: usize) !u64 {
    var cpu = Cpu.init(0x20_0000, 0);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = iterations * 4,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index % 31 + 1);
        const word = encodeJal(rd, benchmarkImmediate(index));
        const instruction = try decode.DecodedInst.decode(word);
        const pc_before = cpu.pc;
        const rs1_value = cpu.readReg(instruction.rs1);
        const rs2_value = cpu.readReg(instruction.rs2);
        const previous = cpu.readReg(rd);
        const current = access_clock.encode(@intCast(index + 1), .first);
        const previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[rd],
            current,
        );
        const target = pc_before +% @as(u32, @bitCast(instruction.imm));
        try isa_profile.requireInstructionAligned(target);
        const link = pc_before +% 4;
        cpu.writeReg(rd, link);
        cpu.pc = target;
        try exec_trace.append(.{
            .clk = @intCast(index + 1),
            .pc = pc_before,
            .opcode = instruction.opcode,
            .rd = rd,
            .rs1 = instruction.rs1,
            .rs2 = instruction.rs2,
            .imm = instruction.imm,
            .rs1_val = rs1_value,
            .rs2_val = rs2_value,
            .rs1_prev_clk = 0,
            .rs2_prev_clk = 0,
            .rd_prev_val = previous,
            .rd_prev_clk = previous_clock,
            .rd_val = link,
            .mem_addr = 0,
            .mem_val = 0,
            .mem_prev_word = 0,
            .mem_next_word = 0,
            .mem_prev_clk = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = target != pc_before +% 4,
            .next_pc = target,
            .inst_word = word,
        });
        try tracker.recordRegTransition(rd, current, previous, link);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(exec_trace.rows.items[iterations - 1]);
    std.mem.doNotOptimizeAway(tracker.accesses.items[iterations - 1]);
    return elapsed;
}

fn measureDirectFloor(iterations: usize) !u64 {
    var cpu = Cpu.init(0x20_0000, 0);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = iterations,
        .memory_clock_update_count = 0,
        .register_clock_update_count = iterations * 4,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @intCast(index % 31 + 1);
        const immediate = benchmarkImmediate(index);
        const word = encodeJal(rd, immediate);
        const instruction = try decode.DecodedInst.decode(word);
        const previous = cpu.readReg(rd);
        const link = cpu.pc +% 4;
        const target = cpu.pc +% @as(u32, @bitCast(immediate));
        const current = access_clock.encode(@intCast(index + 1), .first);
        tracker.recordRegTransitionAssumeCapacity(rd, current, previous, link);
        cpu.writeReg(rd, link);
        const row = subject.TraceRow{
            .clk = @intCast(index + 1),
            .pc = cpu.pc,
            .opcode = .JAL,
            .rd = rd,
            .rs1 = instruction.rs1,
            .rs2 = instruction.rs2,
            .imm = immediate,
            .rs1_val = cpu.readReg(instruction.rs1),
            .rs2_val = cpu.readReg(instruction.rs2),
            .rd_prev_val = previous,
            .rd_prev_clk = tracker.accesses.items[tracker.accesses.items.len - 1].clk_prev,
            .rd_val = link,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = target != link,
            .next_pc = target,
            .inst_word = word,
        };
        cpu.pc = target;
        exec_trace.appendAssumeCapacity(row);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(exec_trace.rows.items[iterations - 1]);
    std.mem.doNotOptimizeAway(tracker.accesses.items[iterations - 1]);
    return elapsed;
}

inline fn benchmarkImmediate(index: usize) i32 {
    return ([_]i32{ 4, 8, -4, 12 })[index & 3];
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}
