const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const access_transaction = @import("../air/lang/access_transaction.zig");
const decode = @import("decode.zig");
const subject = @import("shifts_imm_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

const operations = [_]decode.Opcode{ .SLLI, .SRLI, .SRAI };

test "SHIFTS_IMM retirement is exact across directions extrema aliases and x0" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct {
        opcode: decode.Opcode,
        rd: u5,
        rs1: u5,
        source: u32,
        amount: u5,
    }{
        .{ .opcode = .SLLI, .rd = 1, .rs1 = 2, .source = 1, .amount = 31 },
        .{ .opcode = .SRLI, .rd = 3, .rs1 = 4, .source = 0x8000_0000, .amount = 31 },
        .{ .opcode = .SRAI, .rd = 5, .rs1 = 6, .source = 0x8000_0000, .amount = 31 },
        .{ .opcode = .SLLI, .rd = 7, .rs1 = 8, .source = 0xffff_ffff, .amount = 0 },
        .{ .opcode = .SRLI, .rd = 9, .rs1 = 10, .source = 0x0102_0304, .amount = 8 },
        .{ .opcode = .SRAI, .rd = 11, .rs1 = 12, .source = 0x7fff_ffff, .amount = 24 },
        .{ .opcode = .SRAI, .rd = 13, .rs1 = 13, .source = 0xffff_ffff, .amount = 1 },
        .{ .opcode = .SLLI, .rd = 0, .rs1 = 0, .source = 0, .amount = 0 },
    };
    var cpu = Cpu.init(0x1000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(cases.len);
    try tracker.reserveTransitions(.{
        .access_count = cases.len * 2,
        .register_clock_update_count = cases.len * 8,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });

    for (cases, 0..) |case, index| {
        const clock: u32 = @intCast(index + 1);
        cpu.writeReg(case.rs1, case.source);
        const word = encode(case.opcode, case.rd, case.rs1, case.amount);
        const inst = try decode.DecodedInst.decode(word);
        const pc_before = cpu.pc;
        const source = cpu.readReg(inst.rs1);
        const previous = cpu.readReg(inst.rd);
        const diagnostic = cpu.readReg(inst.rs2);
        const expected = independentResult(case.opcode, source, case.amount);
        try subject.retireAtomic(
            &authority,
            &cpu,
            &trace,
            &tracker,
            inst,
            word,
            clock,
        );
        const row = trace.rows.items[index];
        try std.testing.expectEqual(if (inst.rd == 0) 0 else expected, cpu.readReg(inst.rd));
        try std.testing.expectEqual(pc_before +% 4, cpu.pc);
        try std.testing.expectEqual(source, row.rs1_val);
        try std.testing.expectEqual(diagnostic, row.rs2_val);
        try std.testing.expectEqual(previous, row.rd_prev_val);
        try std.testing.expectEqual(if (inst.rd == 0) 0 else expected, row.rd_val);
        try std.testing.expectEqual(word, row.inst_word);
        try std.testing.expectEqual(
            access_clock.encode(clock, .first),
            tracker.accesses.items[index * 2].clk,
        );
        try std.testing.expectEqual(
            access_clock.encode(clock, .second),
            tracker.accesses.items[index * 2 + 1].clk,
        );
        if (inst.rd == inst.rs1) {
            try std.testing.expectEqual(
                access_clock.encode(clock, .first),
                row.rd_prev_clk,
            );
            try std.testing.expectEqual(row.rs1_val, row.rd_prev_val);
        }
    }
}

test "SHIFTS_IMM compact compiler exactly matches generic access geometry" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    for (operations) |opcode| for ([_]bool{ false, true }) |aliased| {
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        tracker.reg_last_clk[3] = 7;
        tracker.reg_last_clk[4] = 11;
        const rs1: u5 = 3;
        const rd: u5 = if (aliased) rs1 else 4;
        const source: u32 = 0x8123_4567;
        const previous: u32 = if (aliased) source else 0x7654_3210;
        const amount: u5 = 17;
        const word = encode(opcode, rd, rs1, amount);
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
        const compact = try subject.compileCompact(&authority, &tracker, .{
            .instruction = inst,
            .instruction_clock = 8,
            .rs1_value = source,
            .rs2_diagnostic_value = if (inst.rs2 == rs1)
                source
            else if (inst.rs2 == rd)
                previous
            else
                0,
            .rd_previous_value = previous,
        });
        try std.testing.expectEqual(generic.rs1_value, compact.rs1_value);
        try std.testing.expectEqual(generic.rd_next_value, compact.rd_next_value);
        try std.testing.expectEqual(
            generic.events[0].raw_previous_clock,
            compact.source_raw_previous_clock,
        );
        try std.testing.expectEqual(
            generic.events[0].previous_clock,
            compact.source_previous_clock,
        );
        try std.testing.expectEqual(
            generic.events[1].raw_previous_clock,
            compact.destination_raw_previous_clock,
        );
        try std.testing.expectEqual(
            generic.events[1].previous_clock,
            compact.destination_previous_clock,
        );
        try std.testing.expectEqual(
            generic.reservation.register_clock_update_count,
            compact.source_gap_count + compact.destination_gap_count,
        );
    };
}

test "SHIFTS_IMM admission exhausts legal fields and every illegal funct7" {
    var legal_count: usize = 0;
    for (operations) |opcode| for (0..32) |amount_raw| {
        const amount: u5 = @intCast(amount_raw);
        for (0..32) |rd_raw| for (0..32) |rs1_raw| {
            const rd: u5 = @intCast(rd_raw);
            const rs1: u5 = @intCast(rs1_raw);
            const word = encode(opcode, rd, rs1, amount);
            const inst = try decode.DecodedInst.decode(word);
            try std.testing.expectEqual(opcode, inst.opcode);
            try std.testing.expectEqual(rd, inst.rd);
            try std.testing.expectEqual(rs1, inst.rs1);
            try std.testing.expectEqual(amount, inst.rs2);
            try std.testing.expectEqual(@as(i32, amount), inst.imm);
            try std.testing.expect(subject.instructionMatchesWord(inst, word));
            legal_count += 1;
        };
    };
    try std.testing.expectEqual(@as(usize, 98_304), legal_count);

    var upper_count: usize = 0;
    for ([_]u32{ 0b001, 0b101 }) |funct3| for (0..128) |funct7| {
        for (0..32) |amount| {
            const word = (@as(u32, @intCast(funct7)) << 25) |
                (@as(u32, @intCast(amount)) << 20) |
                (3 << 15) |
                (funct3 << 12) |
                (2 << 7) |
                0b0010011;
            const decoded = decode.DecodedInst.decode(word);
            const legal = (funct3 == 0b001 and funct7 == 0) or
                (funct3 == 0b101 and (funct7 == 0 or funct7 == 0b0100000));
            if (legal) {
                const inst = try decoded;
                try std.testing.expect(subject.instructionMatchesWord(inst, word));
            } else {
                try std.testing.expectError(error.IllegalInstruction, decoded);
            }
            upper_count += 1;
        }
    };
    try std.testing.expectEqual(@as(usize, 8_192), upper_count);

    const word = encode(.SRAI, 3, 4, 17);
    var inst = try decode.DecodedInst.decode(word);
    inst.rs2 +%= 1;
    try std.testing.expect(!subject.instructionMatchesWord(inst, word));
    inst = try decode.DecodedInst.decode(word);
    inst.imm = 16;
    try std.testing.expect(!subject.instructionMatchesWord(inst, word));
    inst = try decode.DecodedInst.decode(word);
    try std.testing.expect(!subject.instructionMatchesWord(inst, word ^ (1 << 30)));
}

test "SHIFTS_IMM forged plan dimensions reject before logical mutation" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x1234_5678);
    cpu.writeReg(3, 0xabcd_ef01);
    cpu.writeReg(7, 0x7777_7777);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encode(.SLLI, 3, 2, 7);
    const inst = try decode.DecodedInst.decode(word);
    const canonical = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        inst,
        word,
        1,
    );

    inline for (.{
        "word",
        "opcode",
        "amount",
        "clock",
        "pc",
        "source",
        "diagnostic",
        "previous",
        "result",
        "source_raw",
        "source_effective",
        "destination_raw",
        "destination_effective",
        "source_gaps",
        "destination_gaps",
        "trace_len",
    }) |mutation| {
        var forged = canonical;
        if (std.mem.eql(u8, mutation, "word")) forged.inst_word ^= 1 << 20;
        if (std.mem.eql(u8, mutation, "opcode")) forged.instruction.opcode = .ADDI;
        if (std.mem.eql(u8, mutation, "amount")) forged.instruction.imm = 8;
        if (std.mem.eql(u8, mutation, "clock")) forged.instruction_clock = 2;
        if (std.mem.eql(u8, mutation, "pc")) forged.pc_before +%= 4;
        if (std.mem.eql(u8, mutation, "source")) forged.rs1_value ^= 1;
        if (std.mem.eql(u8, mutation, "diagnostic")) forged.rs2_diagnostic_value ^= 1;
        if (std.mem.eql(u8, mutation, "previous")) forged.rd_previous_value ^= 1;
        if (std.mem.eql(u8, mutation, "result")) forged.rd_next_value ^= 1;
        if (std.mem.eql(u8, mutation, "source_raw")) forged.source_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "source_effective")) forged.source_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "destination_raw")) forged.destination_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "destination_effective")) forged.destination_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "source_gaps")) forged.source_gap_count +%= 1;
        if (std.mem.eql(u8, mutation, "destination_gaps")) forged.destination_gap_count +%= 1;
        if (std.mem.eql(u8, mutation, "trace_len")) forged.expected_trace_len +%= 1;
        try expectPrepareAtomicFailure(&forged, &cpu, &trace, &tracker);
    }
}

test "SHIFTS_IMM prepared token is single-use and rejects stale state" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 1);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encode(.SLLI, 3, 2, 1);
    const inst = try decode.DecodedInst.decode(word);
    const plan = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        inst,
        word,
        1,
    );
    var prepared = try plan.prepare(&cpu, &trace, &tracker);
    try prepared.commit(&cpu, &trace, &tracker);
    try std.testing.expectEqual(@as(u32, 2), cpu.readReg(3));
    try std.testing.expectEqual(@as(usize, 1), trace.rows.items.len);
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &trace, &tracker),
    );

    const word_2 = encode(.SRAI, 4, 2, 1);
    const inst_2 = try decode.DecodedInst.decode(word_2);
    const plan_2 = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        inst_2,
        word_2,
        2,
    );
    var prepared_2 = try plan_2.prepare(&cpu, &trace, &tracker);
    cpu.writeReg(2, 7);
    const cpu_before = cpu;
    const accesses_before = tracker.accesses.items.len;
    try std.testing.expectError(
        error.StaleRetirement,
        prepared_2.commit(&cpu, &trace, &tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu);
    try std.testing.expectEqual(accesses_before, tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 1), trace.rows.items.len);
}

test "SHIFTS_IMM cold allocation failure is atomic and warm path allocates nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 1);
        var trace = Trace.init(failing.allocator());
        defer trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const word = encode(.SLLI, 1, 2, 2);
        const cpu_before = cpu;
        try std.testing.expectError(
            error.OutOfMemory,
            subject.retireAtomic(
                &authority,
                &cpu,
                &trace,
                &tracker,
                try decode.DecodedInst.decode(word),
                word,
                1,
            ),
        );
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    }

    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = Cpu.init(0x1000, 0);
    var trace = Trace.init(failing.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .access_count = iterations * 2,
        .register_clock_update_count = iterations * 8,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    for (0..iterations) |index| {
        const rd: u5 = @truncate(index *% 13 + 1);
        const rs1: u5 = @truncate(index *% 7 + 1);
        cpu.writeReg(rs1, @truncate(index *% 0x9e37_79b1));
        const opcode = operations[index % operations.len];
        const amount: u5 = @truncate(index);
        const word = encode(opcode, rd, rs1, amount);
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
    try std.testing.expect(!containsPointer(subject.CompactTransaction));
    try std.testing.expect(!containsPointer(subject.Plan));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(subject.CompactTransaction));
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(subject.Plan));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(subject.Prepared));
}

test "SHIFTS_IMM retirement strictly preserves paired legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    _ = try measureFixed(&authority, 1 << 10);
    _ = try measureLegacy(1 << 10);
    const samples = 13;
    const iterations = 1 << 14;
    var fixed: [samples]u64 = undefined;
    var legacy: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        fixed[sample] = try measureFixed(&authority, iterations);
        legacy[sample] = try measureLegacy(iterations);
    } else {
        legacy[sample] = try measureLegacy(iterations);
        fixed[sample] = try measureFixed(&authority, iterations);
    };
    const fixed_median = median(&fixed);
    const legacy_median = median(&legacy);
    std.debug.print(
        "\n  SHIFTS_IMM retirement={d} ns legacy={d} ns speed={d:.4}x\n",
        .{ fixed_median, legacy_median, @as(f64, @floatFromInt(legacy_median)) /
            @as(f64, @floatFromInt(fixed_median)) },
    );
    try std.testing.expect(
        @as(u128, fixed_median) * 97 <= @as(u128, legacy_median) * 100,
    );
}

fn expectPrepareAtomicFailure(
    plan: *const subject.Plan,
    cpu: *const Cpu,
    trace: *Trace,
    tracker: *StateChainTracker,
) !void {
    const cpu_before = cpu.*;
    const trace_before = trace.rows.items.len;
    const access_before = tracker.accesses.items.len;
    const gaps_before = tracker.clock_updates_reg.items.len;
    try std.testing.expectError(
        error.StaleRetirement,
        plan.prepare(cpu, trace, tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu.*);
    try std.testing.expectEqual(trace_before, trace.rows.items.len);
    try std.testing.expectEqual(access_before, tracker.accesses.items.len);
    try std.testing.expectEqual(gaps_before, tracker.clock_updates_reg.items.len);
}

fn encode(opcode: decode.Opcode, rd: u5, rs1: u5, amount: u5) u32 {
    const shape = switch (opcode) {
        .SLLI => .{ @as(u32, 0b001), @as(u32, 0b0000000) },
        .SRLI => .{ @as(u32, 0b101), @as(u32, 0b0000000) },
        .SRAI => .{ @as(u32, 0b101), @as(u32, 0b0100000) },
        else => unreachable,
    };
    return (shape[1] << 25) |
        (@as(u32, amount) << 20) |
        (@as(u32, rs1) << 15) |
        (shape[0] << 12) |
        (@as(u32, rd) << 7) |
        0b0010011;
}

fn independentResult(opcode: decode.Opcode, source: u32, amount: u5) u32 {
    return switch (opcode) {
        .SLLI => source << amount,
        .SRLI => source >> amount,
        .SRAI => @bitCast(@as(i32, @bitCast(source)) >> amount),
        else => unreachable,
    };
}

fn measureFixed(authority: *const subject.Authority, iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
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
        const opcode = operations[index % operations.len];
        const amount: u5 = @truncate(index);
        const word = encode(opcode, rd, rs1, amount);
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
    return timer.read();
}

fn measureLegacy(iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
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
        const opcode = operations[index % operations.len];
        const amount: u5 = @truncate(index);
        const word = encode(opcode, rd, rs1, amount);
        const inst = try decode.DecodedInst.decode(word);
        const source = cpu.readReg(rs1);
        const diagnostic = cpu.readReg(inst.rs2);
        const previous = cpu.readReg(rd);
        const source_clock = access_clock.encode(@intCast(index + 1), .first);
        const destination_clock = access_clock.encode(@intCast(index + 1), .second);
        try tracker.recordRegAccess(rs1, source_clock, source);
        const next = if (rd == 0) 0 else independentResult(opcode, source, amount);
        try tracker.recordRegTransition(rd, destination_clock, previous, next);
        cpu.writeReg(rd, next);
        const pc = cpu.pc;
        cpu.pc +%= 4;
        try trace.append(.{
            .clk = @intCast(index + 1),
            .pc = pc,
            .opcode = opcode,
            .rd = rd,
            .rs1 = rs1,
            .rs2 = inst.rs2,
            .imm = amount,
            .rs1_val = source,
            .rs2_val = diagnostic,
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

fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .array => |array| containsPointer(array.child),
        .optional => |optional| containsPointer(optional.child),
        .@"struct" => |structure| blk: {
            inline for (structure.fields) |field|
                if (containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        .@"union" => |union_info| blk: {
            inline for (union_info.fields) |field|
                if (containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        else => false,
    };
}
