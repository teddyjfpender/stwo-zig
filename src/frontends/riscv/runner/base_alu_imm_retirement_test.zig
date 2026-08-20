const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const access_transaction = @import("../air/lang/access_transaction.zig");
const decode = @import("decode.zig");
const subject = @import("base_alu_imm_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

test "E-020 BASE_ALU_IMM retirement is exact across opcodes aliases x0 and boundaries" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const opcodes = [_]decode.Opcode{ .ADDI, .XORI, .ORI, .ANDI };
    const values = [_]u32{ 0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff };
    const immediates = [_]i32{ -2048, -1, 0, 1, 2047 };
    var cpu = Cpu.init(0x1000, 0);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try exec_trace.reserveAdditional(opcodes.len * values.len * immediates.len);
    try tracker.reserveTransitions(.{
        .access_count = opcodes.len * values.len * immediates.len * 2,
        .register_clock_update_count = opcodes.len * values.len * immediates.len * 8,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });

    var clock: u32 = 1;
    for (opcodes) |opcode| for (values) |source| for (immediates) |imm| {
        const rd: u5 = @truncate(clock *% 11);
        const rs1: u5 = if ((clock & 3) == 0) rd else @truncate(clock *% 7);
        cpu.writeReg(rs1, source);
        const word = encode(opcode, rd, rs1, imm);
        const inst = try decode.DecodedInst.decode(word);
        const pc_before = cpu.pc;
        const effective_source = cpu.readReg(rs1);
        const expected = result(opcode, effective_source, imm);
        try subject.retireAtomic(
            &authority,
            &cpu,
            &exec_trace,
            &tracker,
            inst,
            word,
            clock,
        );
        const row = exec_trace.rows.items[exec_trace.rows.items.len - 1];
        try std.testing.expectEqual(if (rd == 0) 0 else expected, cpu.readReg(rd));
        try std.testing.expectEqual(pc_before +% 4, cpu.pc);
        try std.testing.expectEqual(effective_source, row.rs1_val);
        try std.testing.expectEqual(if (rd == 0) 0 else expected, row.rd_val);
        try std.testing.expectEqual(
            access_clock.encode(clock, .first),
            tracker.accesses.items[tracker.accesses.items.len - 2].clk,
        );
        try std.testing.expectEqual(
            access_clock.encode(clock, .second),
            tracker.accesses.items[tracker.accesses.items.len - 1].clk,
        );
        if (rd == rs1) {
            try std.testing.expectEqual(
                access_clock.encode(clock, .first),
                row.rd_prev_clk,
            );
            try std.testing.expectEqual(row.rs1_val, row.rd_prev_val);
        }
        clock += 1;
    };
}

test "E-020 compact BASE_ALU_IMM compiler is exactly the generic two-register transaction" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const opcodes = [_]decode.Opcode{ .ADDI, .XORI, .ORI, .ANDI };
    for (opcodes) |opcode| for ([_]bool{ false, true }) |aliased| {
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        tracker.reg_last_clk[3] = 7;
        tracker.reg_last_clk[4] = 11;
        const rs1: u5 = 3;
        const rd: u5 = if (aliased) rs1 else 4;
        const source: u32 = 0x8123_4567;
        const previous: u32 = if (aliased) source else 0x7654_3210;
        const word = encode(opcode, rd, rs1, -17);
        const inst = try decode.DecodedInst.decode(word);
        const retired = try authority.retire(inst, source);
        const generic = try access_transaction.compile(&tracker, .{
            .instruction = inst,
            .instruction_clock = 8,
            .rs1_value = source,
            .rs2_value = 0,
            .rd_previous_value = previous,
            .rd_next_value = retired.visible_value,
        });
        const compact = try access_transaction.compileBaseAluImmCompact(
            &authority,
            &tracker,
            .{
                .instruction = inst,
                .instruction_clock = 8,
                .rs1_value = source,
                .rs2_value = 0,
                .rd_previous_value = previous,
            },
        );
        try std.testing.expectEqual(generic.rs1_value, compact.rs1_value);
        try std.testing.expectEqual(generic.rd_next_value, compact.rd_next_value);
        try std.testing.expectEqual(generic.events[0].raw_previous_clock, compact.source_raw_previous_clock);
        try std.testing.expectEqual(generic.events[0].previous_clock, compact.source_previous_clock);
        try std.testing.expectEqual(generic.events[1].raw_previous_clock, compact.destination_raw_previous_clock);
        try std.testing.expectEqual(generic.events[1].previous_clock, compact.destination_previous_clock);
        try std.testing.expectEqual(
            generic.reservation.register_clock_update_count,
            compact.source_gap_count + compact.destination_gap_count,
        );
    };
}

test "E-020 BASE_ALU_IMM forged and stale plans reject before logical mutation" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(3, 0x1234_5678);
    var exec_trace = Trace.init(std.testing.allocator);
    defer exec_trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encode(.ADDI, 3, 3, -1);
    const inst = try decode.DecodedInst.decode(word);
    var plan = try subject.stage(
        &authority,
        &cpu,
        &exec_trace,
        &tracker,
        inst,
        word,
        1,
    );
    plan.rd_next_value ^= 1;
    try expectPrepareAtomicFailure(&plan, &cpu, &exec_trace, &tracker);

    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    plan.source_previous_clock +%= 1;
    try expectPrepareAtomicFailure(&plan, &cpu, &exec_trace, &tracker);

    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    var prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
    cpu.writeReg(3, cpu.readReg(3) ^ 1);
    const cpu_before = cpu;
    const accesses_before = tracker.accesses.items.len;
    try std.testing.expectError(
        error.StaleRetirement,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu);
    try std.testing.expectEqual(accesses_before, tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);

    cpu.writeReg(3, 0x1234_5678);
    plan = try subject.stage(&authority, &cpu, &exec_trace, &tracker, inst, word, 1);
    prepared = try plan.prepare(&cpu, &exec_trace, &tracker);
    tracker.reg_last_clk[3] = 7;
    try std.testing.expectError(
        error.StaleRetirement,
        prepared.commit(&cpu, &exec_trace, &tracker),
    );
    try std.testing.expectEqual(@as(usize, 0), exec_trace.rows.items.len);
}

test "E-020 BASE_ALU_IMM cold allocation failure is atomic and warm path allocates nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 41);
        var exec_trace = Trace.init(failing.allocator());
        defer exec_trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const word = encode(.ADDI, 1, 2, 1);
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
        .access_count = iterations * 2,
        .register_clock_update_count = iterations * 8,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    for (0..iterations) |index| {
        const rs1: u5 = @truncate(index *% 7 + 1);
        const rd: u5 = @truncate(index *% 11);
        cpu.writeReg(rs1, @truncate(index *% 0x9e37_79b1));
        const opcode = ([_]decode.Opcode{ .ADDI, .XORI, .ORI, .ANDI })[index & 3];
        const word = encode(opcode, rd, rs1, @intCast(index & 0x7ff));
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

test "E-020 BASE_ALU_IMM retirement retains paired legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    // Prime code pages and allocator capacity classes outside the paired
    // samples. Each measured side still owns a fresh CPU, trace, and tracker.
    _ = try measureStaged(&authority, 1 << 10);
    _ = try measureLegacy(1 << 10);
    const samples = 13;
    const iterations = 1 << 14;
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
        "\n  E-020 BASE_ALU_IMM retirement={d} ns legacy={d} ns speed={d:.4}x\n",
        .{ staged_median, legacy_median, @as(f64, @floatFromInt(legacy_median)) /
            @as(f64, @floatFromInt(staged_median)) },
    );
    try std.testing.expect(@as(u128, staged_median) * 97 <=
        @as(u128, legacy_median) * 100);
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

fn encode(opcode: decode.Opcode, rd: u5, rs1: u5, imm: i32) u32 {
    const funct3: u3 = switch (opcode) {
        .ADDI => 0,
        .XORI => 4,
        .ORI => 6,
        .ANDI => 7,
        else => unreachable,
    };
    return ((@as(u32, @bitCast(imm)) & 0xfff) << 20) |
        (@as(u32, rs1) << 15) | (@as(u32, funct3) << 12) |
        (@as(u32, rd) << 7) | 0x13;
}

fn result(opcode: decode.Opcode, source: u32, imm: i32) u32 {
    const bits: u32 = @bitCast(imm);
    return switch (opcode) {
        .ADDI => source +% bits,
        .XORI => source ^ bits,
        .ORI => source | bits,
        .ANDI => source & bits,
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
        .access_count = iterations * 2,
        .register_clock_update_count = iterations * 8,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @truncate(index *% 13 + 1);
        const rs1: u5 = @truncate(index *% 7 + 1);
        cpu.writeReg(rs1, @truncate(index *% 0x9e37_79b1));
        const opcode = ([_]decode.Opcode{ .ADDI, .XORI, .ORI, .ANDI })[index & 3];
        const word = encode(opcode, rd, rs1, @intCast(index & 0x7ff));
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
        .access_count = iterations * 2,
        .register_clock_update_count = iterations * 8,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const rd: u5 = @truncate(index *% 13 + 1);
        const rs1: u5 = @truncate(index *% 7 + 1);
        cpu.writeReg(rs1, @truncate(index *% 0x9e37_79b1));
        const opcode = ([_]decode.Opcode{ .ADDI, .XORI, .ORI, .ANDI })[index & 3];
        const imm: i32 = @intCast(index & 0x7ff);
        const word = encode(opcode, rd, rs1, imm);
        const source = cpu.readReg(rs1);
        const previous = cpu.readReg(rd);
        const source_clock = access_clock.encode(@intCast(index + 1), .first);
        const destination_clock = access_clock.encode(@intCast(index + 1), .second);
        try tracker.recordRegAccess(rs1, source_clock, source);
        const next = result(opcode, source, imm);
        try tracker.recordRegTransition(rd, destination_clock, previous, next);
        cpu.writeReg(rd, next);
        const pc = cpu.pc;
        cpu.pc +%= 4;
        try exec_trace.append(.{
            .clk = @intCast(index + 1),
            .pc = pc,
            .opcode = opcode,
            .rd = rd,
            .rs1 = rs1,
            .rs2 = @truncate(@as(u32, @bitCast(imm))),
            .imm = imm,
            .rs1_val = source,
            .rs2_val = 0,
            .rs1_prev_clk = 0,
            .rs2_prev_clk = 0,
            .rd_prev_val = previous,
            .rd_prev_clk = source_clock,
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
    }
    return timer.read();
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}
