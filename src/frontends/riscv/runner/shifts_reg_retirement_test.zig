const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const access_transaction = @import("../air/lang/access_transaction.zig");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const subject = @import("shifts_reg_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

const operations = [_]decode.Opcode{ .SLL, .SRL, .SRA };

test "SHIFTS_REG retirement is exact across opcodes aliases x0 and extrema" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const Case = struct { rd: u5, rs1: u5, rs2: u5, lhs: u32, rhs: u32, previous: u32 };
    const cases = [_]Case{
        .{ .rd = 0, .rs1 = 0, .rs2 = 0, .lhs = 0, .rhs = 0, .previous = 0 },
        .{ .rd = 7, .rs1 = 7, .rs2 = 7, .lhs = 0xffff_ffff, .rhs = 0, .previous = 0 },
        .{ .rd = 7, .rs1 = 7, .rs2 = 9, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff, .previous = 0 },
        .{ .rd = 9, .rs1 = 7, .rs2 = 9, .lhs = 0xffff_ffff, .rhs = 0, .previous = 0 },
        .{ .rd = 31, .rs1 = 3, .rs2 = 3, .lhs = 1, .rhs = 0, .previous = 0x1020_3040 },
        .{ .rd = 1, .rs1 = 2, .rs2 = 3, .lhs = 0, .rhs = 0xffff_ffff, .previous = 0x55aa_1234 },
    };
    var instruction_clock: u32 = 1;
    for (operations) |opcode| for (cases) |case| {
        var cpu = Cpu.init(0x1000, 0);
        var exec_trace = Trace.init(std.testing.allocator);
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const lhs = if (case.rs1 == 0) 0 else case.lhs;
        const rhs = if (case.rs2 == 0) 0 else if (case.rs2 == case.rs1) lhs else case.rhs;
        cpu.writeReg(case.rs1, lhs);
        cpu.writeReg(case.rs2, rhs);
        if (case.rd != case.rs1 and case.rd != case.rs2)
            cpu.writeReg(case.rd, case.previous);
        const word = encode(opcode, case.rd, case.rs1, case.rs2);
        const inst = try decode.DecodedInst.decode(word);
        const pc_before = cpu.pc;
        const previous = cpu.readReg(case.rd);
        const expected = result(opcode, lhs, rhs);
        try subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            inst,
            word,
            instruction_clock,
        );
        const row = exec_trace.rows.items[0];
        try std.testing.expectEqual(if (case.rd == 0) 0 else expected, cpu.readReg(case.rd));
        try std.testing.expectEqual(pc_before +% 4, cpu.pc);
        try std.testing.expectEqual(lhs, row.rs1_val);
        try std.testing.expectEqual(rhs, row.rs2_val);
        try std.testing.expectEqual(previous, row.rd_prev_val);
        try std.testing.expectEqual(if (case.rd == 0) 0 else expected, row.rd_val);
        try std.testing.expectEqual(@as(usize, 3), tracker.accesses.items.len);
        if (case.rs1 == case.rs2) {
            try std.testing.expectEqual(
                access_clock.encode(instruction_clock, .first),
                row.rs2_prev_clk,
            );
            try std.testing.expectEqual(row.rs1_val, row.rs2_val);
        }
        if (case.rd == case.rs2) {
            try std.testing.expectEqual(
                access_clock.encode(instruction_clock, .second),
                row.rd_prev_clk,
            );
            try std.testing.expectEqual(row.rs2_val, row.rd_prev_val);
        } else if (case.rd == case.rs1) {
            try std.testing.expectEqual(
                access_clock.encode(instruction_clock, .first),
                row.rd_prev_clk,
            );
            try std.testing.expectEqual(row.rs1_val, row.rd_prev_val);
        }
        instruction_clock += 1;
    };
}

test "SHIFTS_REG compact compiler exactly equals generic three-register transactions" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct { rd: u5, rs1: u5, rs2: u5 }{
        .{ .rd = 0, .rs1 = 0, .rs2 = 0 },
        .{ .rd = 3, .rs1 = 3, .rs2 = 3 },
        .{ .rd = 3, .rs1 = 3, .rs2 = 4 },
        .{ .rd = 4, .rs1 = 3, .rs2 = 4 },
        .{ .rd = 5, .rs1 = 3, .rs2 = 3 },
        .{ .rd = 5, .rs1 = 3, .rs2 = 4 },
    };
    for (operations) |opcode| for (cases) |case| {
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        tracker.reg_last_clk[3] = 7;
        tracker.reg_last_clk[4] = 11;
        tracker.reg_last_clk[5] = 13;
        const lhs: u32 = if (case.rs1 == 0) 0 else 0x8123_4567;
        const rhs: u32 = if (case.rs2 == 0) 0 else if (case.rs2 == case.rs1)
            lhs
        else
            0x1234_5678;
        const previous: u32 = if (case.rd == 0) 0 else if (case.rd == case.rs2)
            rhs
        else if (case.rd == case.rs1)
            lhs
        else
            0x7654_3210;
        const inst = try decode.DecodedInst.decode(encode(opcode, case.rd, case.rs1, case.rs2));
        const retired = try authority.retire(inst, lhs, rhs);
        const generic = try access_transaction.compile(&tracker, .{
            .instruction = inst,
            .instruction_clock = 8,
            .rs1_value = lhs,
            .rs2_value = rhs,
            .rd_previous_value = previous,
            .rd_next_value = retired.visible_value,
        });
        const compact = try subject.compileCompact(&authority, &tracker, .{
            .instruction = inst,
            .instruction_clock = 8,
            .rs1_value = lhs,
            .rs2_value = rhs,
            .rd_previous_value = previous,
        });
        try std.testing.expectEqual(@as(u2, 3), generic.event_count);
        try std.testing.expectEqual(generic.rs1_value, compact.rs1_value);
        try std.testing.expectEqual(generic.rs2_value, compact.rs2_value);
        try std.testing.expectEqual(generic.rd_next_value, compact.rd_next_value);
        const raw = [_]u32{
            compact.source_1_raw_previous_clock,
            compact.source_2_raw_previous_clock,
            compact.destination_raw_previous_clock,
        };
        const effective = [_]u32{
            compact.source_1_previous_clock,
            compact.source_2_previous_clock,
            compact.destination_previous_clock,
        };
        for (generic.events[0..3], raw, effective) |event, expected_raw, expected_effective| {
            try std.testing.expectEqual(expected_raw, event.raw_previous_clock);
            try std.testing.expectEqual(expected_effective, event.previous_clock);
        }
        try std.testing.expectEqual(
            generic.reservation.register_clock_update_count,
            compact.source_1_gap_count + compact.source_2_gap_count +
                compact.destination_gap_count,
        );
    };
}

test "SHIFTS_REG accepts exactly every architectural R-type family encoding" {
    for (operations) |opcode| for (0..32) |rd| for (0..32) |rs1| for (0..32) |rs2| {
        const word = encode(opcode, @intCast(rd), @intCast(rs1), @intCast(rs2));
        const decoded = try decode.DecodedInst.decode(word);
        try std.testing.expectEqual(opcode, decoded.opcode);
        try std.testing.expectEqual(@as(u5, @intCast(rd)), decoded.rd);
        try std.testing.expectEqual(@as(u5, @intCast(rs1)), decoded.rs1);
        try std.testing.expectEqual(@as(u5, @intCast(rs2)), decoded.rs2);
    };
}

test "SHIFTS_REG forged stale and reused plans reject before mutation" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(3, 0x1234_5678);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encode(.SRL, 3, 3, 3);
    const inst = try decode.DecodedInst.decode(word);

    var plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    plan.rd_next_value ^= 1;
    try expectPrepareAtomicFailure(&plan, &cpu, &exec_trace, &tracker);
    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    plan.source_2_previous_clock +%= 1;
    try expectPrepareAtomicFailure(&plan, &cpu, &exec_trace, &tracker);
    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    plan.destination_raw_previous_clock -%= 1;
    try expectPrepareAtomicFailure(&plan, &cpu, &exec_trace, &tracker);

    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
    cpu.writeReg(3, cpu.readReg(3) ^ 1);
    const cpu_before = cpu;
    try std.testing.expectError(
        error.StaleRetirement,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);

    cpu.writeReg(3, 0x1234_5678);
    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
    try prepared.commit(&cpu, &exec_trace, &tracker);
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
    try std.testing.expectEqual(@as(usize, 1), exec_trace.rows.items.len);
}

test "SHIFTS_REG cold allocation failure is atomic and warm path allocates nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 41);
        cpu.writeReg(3, 42);
        var exec_trace = Trace.init(failing.allocator());
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const word = encode(.SRL, 1, 2, 3);
        const cpu_before = cpu;
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
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    }

    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = Cpu.init(0x1000, 0);
    var exec_trace = Trace.init(failing.allocator());
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .access_count = iterations * 3,
        .register_clock_update_count = iterations * 12,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    for (0..iterations) |index| {
        cpu.writeReg(2, @truncate(index *% 0x9e37_79b1));
        cpu.writeReg(3, @truncate(index *% 0x85eb_ca77));
        const opcode = operations[index % operations.len];
        const word = encode(opcode, 1, 2, 3);
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
    try std.testing.expect(@sizeOf(subject.CompactTransaction) <= subject.MAX_TRANSACTION_BYTES);
    try std.testing.expect(@sizeOf(subject.Prepared) <= subject.MAX_PREPARED_BYTES);
}

test "SHIFTS_REG retirement retains at least 0.97x legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const samples = 11;
    const iterations = 1 << 13;
    var staged: [samples]u64 = undefined;
    var legacy: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        staged[sample] = try measureStaged(&authority, iterations);
        legacy[sample] = try measureLegacy(iterations);
    } else {
        legacy[sample] = try measureLegacy(iterations);
        staged[sample] = try measureStaged(&authority, iterations);
    };
    const staged_median = median(&staged);
    const legacy_median = median(&legacy);
    std.debug.print(
        "\n  SHIFTS_REG retirement={d} ns legacy={d} ns speed={d:.4}x " ++
            "transaction={d}B plan={d}B prepared={d}B\n",
        .{
            staged_median,
            legacy_median,
            @as(f64, @floatFromInt(legacy_median)) /
                @as(f64, @floatFromInt(staged_median)),
            @sizeOf(subject.CompactTransaction),
            @sizeOf(subject.Plan),
            @sizeOf(subject.Prepared),
        },
    );
    try std.testing.expect(
        @as(u128, staged_median) * 97 <= @as(u128, legacy_median) * 100,
    );
}

fn expectPrepareAtomicFailure(
    plan: *const subject.Plan,
    cpu: *const Cpu,
    exec_trace: *Trace,
    tracker: *StateChainTracker,
) !void {
    const cpu_before = cpu.*;
    const access_before = tracker.accesses.items.len;
    try std.testing.expectError(
        error.StaleRetirement,
        plan.prepare(cpu, exec_trace, tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu.*);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
    try std.testing.expectEqual(access_before, tracker.accesses.items.len);
}

fn encode(opcode: decode.Opcode, rd: u5, rs1: u5, rs2: u5) u32 {
    const funct3: u3 = switch (opcode) {
        .SLL => 0b001,
        .SRL, .SRA => 0b101,
        else => unreachable,
    };
    const funct7: u7 = switch (opcode) {
        .SLL, .SRL => 0b0000000,
        .SRA => 0b0100000,
        else => unreachable,
    };
    return (@as(u32, funct7) << 25) | (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, funct3) << 12) | (@as(u32, rd) << 7) | 0x33;
}

fn result(opcode: decode.Opcode, lhs: u32, rhs: u32) u32 {
    const amount: u5 = @truncate(rhs);
    return switch (opcode) {
        .SLL => lhs << amount,
        .SRL => lhs >> amount,
        .SRA => @bitCast(@as(i32, @bitCast(lhs)) >> amount),
        else => unreachable,
    };
}

fn measureStaged(authority: *const subject.Authority, iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .access_count = iterations * 3,
        .register_clock_update_count = iterations * 12,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        cpu.writeReg(2, @truncate(index *% 0x9e37_79b1));
        cpu.writeReg(3, @truncate(index *% 0x85eb_ca77));
        const opcode = operations[index % operations.len];
        const word = encode(opcode, 1, 2, 3);
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
    return timer.read();
}

fn measureLegacy(iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .access_count = iterations * 3,
        .register_clock_update_count = iterations * 12,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        cpu.writeReg(2, @truncate(index *% 0x9e37_79b1));
        cpu.writeReg(3, @truncate(index *% 0x85eb_ca77));
        const opcode = operations[index % operations.len];
        const word = encode(opcode, 1, 2, 3);
        const inst = try decode.DecodedInst.decode(word);
        const clock: u32 = @intCast(index + 1);
        const lhs = cpu.readReg(inst.rs1);
        const rhs = cpu.readReg(inst.rs2);
        const previous = cpu.readReg(inst.rd);
        const access = access_witness.capture(&tracker, inst, clock);
        const next = result(opcode, lhs, rhs);
        cpu.writeReg(inst.rd, next);
        const pc = cpu.pc;
        cpu.pc +%= 4;
        try exec_trace.append(.{
            .clk = clock,
            .pc = pc,
            .opcode = opcode,
            .rd = inst.rd,
            .rs1 = inst.rs1,
            .rs2 = inst.rs2,
            .imm = 0,
            .rs1_val = lhs,
            .rs2_val = rhs,
            .rs1_prev_clk = access.rs1_prev_clock,
            .rs2_prev_clk = access.rs2_prev_clock,
            .rd_prev_val = previous,
            .rd_prev_clk = access.rd_prev_clock,
            .rd_val = next,
            .mem_addr = 0,
            .mem_val = 0,
            .mem_prev_word = 0,
            .mem_next_word = 0,
            .mem_prev_clk = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = cpu.pc,
            .inst_word = word,
        });
        try access.recordRegisters(&tracker, inst, lhs, rhs, previous, next);
    }
    return timer.read();
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}
