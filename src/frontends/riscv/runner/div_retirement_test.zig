const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const access_transaction = @import("../air/lang/access_transaction.zig");
const access_witness = @import("access_witness.zig");
const decode = @import("decode.zig");
const subject = @import("div_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

const OPERATIONS = [_]decode.Opcode{ .DIV, .DIVU, .REM, .REMU };
const BOUNDARY_OPERANDS = [_]u32{
    0,
    1,
    2,
    3,
    7,
    0x7fff_ffff,
    0x8000_0000,
    0x8000_0001,
    0xffff_fff9,
    0xffff_fffd,
    0xffff_fffe,
    0xffff_ffff,
};

test "DIV retirement is exact across boundary corpus aliases x0 and special cases" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();

    var index: usize = 0;
    for (OPERATIONS) |opcode| for (BOUNDARY_OPERANDS) |lhs_input| for (BOUNDARY_OPERANDS) |rhs_input| {
        const registers = switch (index % 6) {
            0 => .{ @as(u5, 0), @as(u5, 0), @as(u5, 0) },
            1 => .{ @as(u5, 7), @as(u5, 7), @as(u5, 7) },
            2 => .{ @as(u5, 7), @as(u5, 7), @as(u5, 9) },
            3 => .{ @as(u5, 9), @as(u5, 7), @as(u5, 9) },
            4 => .{ @as(u5, 10), @as(u5, 7), @as(u5, 7) },
            else => .{ @as(u5, 10), @as(u5, 7), @as(u5, 9) },
        };
        const rd = registers[0];
        const rs1 = registers[1];
        const rs2 = registers[2];
        cpu.writeReg(rs1, lhs_input);
        if (rs2 != rs1) cpu.writeReg(rs2, rhs_input);
        if (rd != rs1 and rd != rs2)
            cpu.writeReg(rd, @truncate(0x1122_3344 +% index));
        const lhs = cpu.readReg(rs1);
        const rhs = cpu.readReg(rs2);
        const previous = cpu.readReg(rd);
        const expected = independentResult(opcode, lhs, rhs);
        const word = encode(opcode, rd, rs1, rs2);
        const instruction = try decode.DecodedInst.decode(word);
        const clock: u32 = @intCast(index + 1);
        const pc_before = cpu.pc;
        try subject.retireAtomic(
            &authority,
            &cpu,
            &trace,
            &tracker,
            instruction,
            word,
            clock,
        );
        const row = trace.rows.items[index];
        try std.testing.expectEqual(if (rd == 0) 0 else expected, cpu.readReg(rd));
        try std.testing.expectEqual(pc_before +% 4, cpu.pc);
        try std.testing.expectEqual(lhs, row.rs1_val);
        try std.testing.expectEqual(rhs, row.rs2_val);
        try std.testing.expectEqual(previous, row.rd_prev_val);
        try std.testing.expectEqual(if (rd == 0) 0 else expected, row.rd_val);
        try std.testing.expectEqual(@as(usize, (index + 1) * 3), tracker.accesses.items.len);
        if (rs1 == rs2) {
            try std.testing.expectEqual(
                access_clock.encode(clock, .first),
                row.rs2_prev_clk,
            );
            try std.testing.expectEqual(row.rs1_val, row.rs2_val);
        }
        if (rd == rs2) {
            try std.testing.expectEqual(
                access_clock.encode(clock, .second),
                row.rd_prev_clk,
            );
            try std.testing.expectEqual(row.rs2_val, row.rd_prev_val);
        } else if (rd == rs1) {
            try std.testing.expectEqual(
                access_clock.encode(clock, .first),
                row.rd_prev_clk,
            );
            try std.testing.expectEqual(row.rs1_val, row.rd_prev_val);
        }
        index += 1;
    };
}

test "DIV compact compiler exactly matches generic three-register transactions" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct { rd: u5, rs1: u5, rs2: u5 }{
        .{ .rd = 0, .rs1 = 0, .rs2 = 0 },
        .{ .rd = 3, .rs1 = 3, .rs2 = 3 },
        .{ .rd = 3, .rs1 = 3, .rs2 = 4 },
        .{ .rd = 4, .rs1 = 3, .rs2 = 4 },
        .{ .rd = 5, .rs1 = 3, .rs2 = 3 },
        .{ .rd = 5, .rs1 = 3, .rs2 = 4 },
    };
    for (OPERATIONS) |opcode| for (cases) |case| {
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        tracker.reg_last_clk[3] = 7;
        tracker.reg_last_clk[4] = 11;
        tracker.reg_last_clk[5] = 13;
        const lhs: u32 = if (case.rs1 == 0) 0 else 0x8123_4567;
        const rhs: u32 = if (case.rs2 == 0) 0 else if (case.rs2 == case.rs1)
            lhs
        else
            0xfedc_ba98;
        const previous: u32 = if (case.rd == 0) 0 else if (case.rd == case.rs2)
            rhs
        else if (case.rd == case.rs1)
            lhs
        else
            0x7654_3210;
        const instruction = try decode.DecodedInst.decode(
            encode(opcode, case.rd, case.rs1, case.rs2),
        );
        const retired = try authority.retire(instruction, lhs, rhs);
        const generic = try access_transaction.compile(&tracker, .{
            .instruction = instruction,
            .instruction_clock = 8,
            .rs1_value = lhs,
            .rs2_value = rhs,
            .rd_previous_value = previous,
            .rd_next_value = retired.visible_value,
        });
        const compact = try subject.compileCompact(&authority, &tracker, .{
            .instruction = instruction,
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
        for (generic.events[0..3], raw, effective) |
            event,
            expected_raw,
            expected_effective,
        | {
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

test "DIV admission exhausts legal registers and every opcode selector" {
    var legal_count: usize = 0;
    for (OPERATIONS) |opcode| for (0..32) |rd_raw| for (0..32) |rs1_raw| for (0..32) |rs2_raw| {
        const rd: u5 = @intCast(rd_raw);
        const rs1: u5 = @intCast(rs1_raw);
        const rs2: u5 = @intCast(rs2_raw);
        const word = encode(opcode, rd, rs1, rs2);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectEqual(opcode, instruction.opcode);
        try std.testing.expectEqual(rd, instruction.rd);
        try std.testing.expectEqual(rs1, instruction.rs1);
        try std.testing.expectEqual(rs2, instruction.rs2);
        try std.testing.expectEqual(@as(i32, 0), instruction.imm);
        try std.testing.expect(subject.instructionMatchesWord(instruction, word));
        legal_count += 1;
    };
    try std.testing.expectEqual(@as(usize, 131_072), legal_count);

    var selector_count: usize = 0;
    for (0..128) |opcode_field| for (0..128) |funct7| for (0..8) |funct3| {
        const word = (@as(u32, @intCast(funct7)) << 25) |
            (3 << 20) | (2 << 15) |
            (@as(u32, @intCast(funct3)) << 12) | (1 << 7) |
            @as(u32, @intCast(opcode_field));
        const maybe_instruction = decode.DecodedInst.decode(word) catch null;
        const expected_div = opcode_field == 0x33 and funct7 == 1 and
            funct3 >= 4 and funct3 <= 7;
        if (maybe_instruction) |instruction| {
            try std.testing.expectEqual(
                expected_div,
                subject.instructionMatchesWord(instruction, word),
            );
        } else {
            try std.testing.expect(!expected_div);
        }
        selector_count += 1;
    };
    try std.testing.expectEqual(@as(usize, 131_072), selector_count);

    const word = encode(.DIV, 3, 4, 5);
    var instruction = try decode.DecodedInst.decode(word);
    instruction.opcode = .MUL;
    try std.testing.expect(!subject.instructionMatchesWord(instruction, word));
    instruction = try decode.DecodedInst.decode(word);
    instruction.rd +%= 1;
    try std.testing.expect(!subject.instructionMatchesWord(instruction, word));
    instruction = try decode.DecodedInst.decode(word);
    instruction.rs1 +%= 1;
    try std.testing.expect(!subject.instructionMatchesWord(instruction, word));
    instruction = try decode.DecodedInst.decode(word);
    instruction.rs2 +%= 1;
    try std.testing.expect(!subject.instructionMatchesWord(instruction, word));
    instruction = try decode.DecodedInst.decode(word);
    instruction.imm = 1;
    try std.testing.expect(!subject.instructionMatchesWord(instruction, word));
    instruction = try decode.DecodedInst.decode(word);
    try std.testing.expect(!subject.instructionMatchesWord(instruction, word ^ (1 << 13)));
}

test "DIV forged plan dimensions reject before logical mutation" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x1234_5678);
    cpu.writeReg(3, 0xabcd_ef01);
    cpu.writeReg(4, 0x7777_7777);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encode(.DIVU, 4, 2, 3);
    const instruction = try decode.DecodedInst.decode(word);
    const canonical = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        instruction,
        word,
        1,
    );

    inline for (.{
        "word",               "opcode",           "immediate",             "clock",         "pc",                 "source_1",
        "source_2",           "previous",         "result",                "source_1_raw",  "source_1_effective", "source_2_raw",
        "source_2_effective", "destination_raw",  "destination_effective", "source_1_gaps", "source_2_gaps",      "destination_gaps",
        "access_len",         "register_gap_len", "trace_len",
    }) |mutation| {
        var forged = canonical;
        if (std.mem.eql(u8, mutation, "word")) forged.inst_word ^= 1 << 20;
        if (std.mem.eql(u8, mutation, "opcode")) forged.instruction.opcode = .MUL;
        if (std.mem.eql(u8, mutation, "immediate")) forged.instruction.imm = 1;
        if (std.mem.eql(u8, mutation, "clock")) forged.instruction_clock = 2;
        if (std.mem.eql(u8, mutation, "pc")) forged.pc_before +%= 4;
        if (std.mem.eql(u8, mutation, "source_1")) forged.rs1_value ^= 1;
        if (std.mem.eql(u8, mutation, "source_2")) forged.rs2_value ^= 1;
        if (std.mem.eql(u8, mutation, "previous")) forged.rd_previous_value ^= 1;
        if (std.mem.eql(u8, mutation, "result")) forged.rd_next_value ^= 1;
        if (std.mem.eql(u8, mutation, "source_1_raw"))
            forged.source_1_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "source_1_effective"))
            forged.source_1_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "source_2_raw"))
            forged.source_2_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "source_2_effective"))
            forged.source_2_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "destination_raw"))
            forged.destination_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "destination_effective"))
            forged.destination_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "source_1_gaps"))
            forged.source_1_gap_count += 1;
        if (std.mem.eql(u8, mutation, "source_2_gaps"))
            forged.source_2_gap_count += 1;
        if (std.mem.eql(u8, mutation, "destination_gaps"))
            forged.destination_gap_count += 1;
        if (std.mem.eql(u8, mutation, "access_len"))
            forged.expected_access_len += 1;
        if (std.mem.eql(u8, mutation, "register_gap_len"))
            forged.expected_register_gap_len += 1;
        if (std.mem.eql(u8, mutation, "trace_len")) forged.expected_trace_len += 1;
        try expectPrepareAtomicFailure(&forged, &cpu, &trace, &tracker);
    }
}

test "DIV prepared token is single-use and rejects stale state" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0xffff_ffff);
    cpu.writeReg(3, 2);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encode(.DIV, 4, 2, 3);
    const instruction = try decode.DecodedInst.decode(word);

    var plan = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        instruction,
        word,
        1,
    );
    var prepared = try plan.prepare(&cpu, &trace, &tracker);
    cpu.writeReg(2, 7);
    const cpu_before = cpu;
    try std.testing.expectError(
        error.StaleRetirement,
        prepared.commit(&cpu, &trace, &tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu);
    try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);

    cpu.writeReg(2, 0xffff_ffff);
    plan = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        instruction,
        word,
        1,
    );
    prepared = try plan.prepare(&cpu, &trace, &tracker);
    try prepared.commit(&cpu, &trace, &tracker);
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &trace, &tracker),
    );
    try std.testing.expectEqual(@as(usize, 1), trace.rows.items.len);
}

test "DIV prepared token rejects append-log staleness" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    inline for (.{ "access_log", "register_gap_log" }) |mutation| {
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 7);
        cpu.writeReg(3, 9);
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encode(.DIVU, 4, 2, 3);
        const plan = try subject.stage(
            &authority,
            &cpu,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &trace, &tracker);
        if (std.mem.eql(u8, mutation, "access_log")) try tracker.accesses.append(
            std.testing.allocator,
            .{ .addr_space = 0, .addr = 31, .clk = 1, .value = 0, .clk_prev = 0 },
        );
        if (std.mem.eql(u8, mutation, "register_gap_log")) try tracker.clock_updates_reg.append(
            std.testing.allocator,
            .{ .addr_space = 0, .addr = 31, .clk = 1, .clk_prev = 0, .value = 0 },
        );
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &trace, &tracker),
        );
        try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
    }
}

test "DIV cold allocation failure is atomic and warm path allocates nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 0xffff_ffff);
        cpu.writeReg(3, 0xffff_ffff);
        var trace = Trace.init(failing.allocator());
        defer trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const word = encode(.REMU, 1, 2, 3);
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
        try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
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
        .access_count = iterations * 3,
        .register_clock_update_count = iterations * 12,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    const word = encode(.DIV, 1, 2, 3);
    const instruction = try decode.DecodedInst.decode(word);
    for (0..iterations) |index| {
        cpu.writeReg(2, @truncate(index *% 0x9e37_79b1));
        cpu.writeReg(3, @truncate(index *% 0x85eb_ca77));
        try subject.retireAtomic(
            &authority,
            &cpu,
            &trace,
            &tracker,
            instruction,
            word,
            @intCast(index + 1),
        );
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, iterations), trace.rows.items.len);
    try std.testing.expect(!containsPointer(subject.CompactTransaction));
    try std.testing.expect(!containsPointer(subject.Plan));
    std.debug.print(
        "\n  DIV footprint transaction={d}B plan={d}B prepared={d}B\n",
        .{
            @sizeOf(subject.CompactTransaction),
            @sizeOf(subject.Plan),
            @sizeOf(subject.Prepared),
        },
    );
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(subject.CompactTransaction));
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(subject.Plan));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(subject.Prepared));
}

test "DIV reserve reentrancy is detected before retirement publication" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x8000_0000);
    cpu.writeReg(3, 0xffff_ffff);
    var reentrant = ReentrantMutationAllocator{
        .child = std.testing.allocator,
        .cpu = &cpu,
    };
    var trace = Trace.init(reentrant.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(reentrant.allocator());
    defer tracker.deinit();
    const word = encode(.DIVU, 4, 2, 3);
    const plan = try subject.stage(
        &authority,
        &cpu,
        &trace,
        &tracker,
        try decode.DecodedInst.decode(word),
        word,
        1,
    );

    reentrant.armed = true;
    try std.testing.expectError(
        error.StaleRetirement,
        plan.commitAtomic(&cpu, &trace, &tracker),
    );
    reentrant.armed = false;
    try std.testing.expect(reentrant.fired);
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
    try std.testing.expectEqual(@as(u32, 0), cpu.readReg(4));
    try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
}

test "DIV retirement strictly preserves paired legacy throughput" {
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
        "\n  DIV retirement={d} ns legacy={d} ns speed={d:.4}x\n",
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

fn encode(opcode: decode.Opcode, rd: u5, rs1: u5, rs2: u5) u32 {
    const funct3: u32 = switch (opcode) {
        .DIV => 4,
        .DIVU => 5,
        .REM => 6,
        .REMU => 7,
        else => unreachable,
    };
    return (1 << 25) | (@as(u32, rs2) << 20) | (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) | 0x33;
}

fn measureFixed(authority: *const subject.Authority, iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .access_count = iterations * 3,
        .register_clock_update_count = iterations * 12,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    const word = encode(.DIV, 1, 2, 3);
    const instruction = try decode.DecodedInst.decode(word);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        cpu.writeReg(2, @truncate(index *% 0x9e37_79b1));
        cpu.writeReg(3, @truncate(index *% 0x85eb_ca77));
        try subject.retireAtomic(
            authority,
            &cpu,
            &trace,
            &tracker,
            instruction,
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
        .access_count = iterations * 3,
        .register_clock_update_count = iterations * 12,
        .memory_address_count = 0,
        .memory_clock_update_count = 0,
    });
    const word = encode(.DIV, 1, 2, 3);
    const instruction = try decode.DecodedInst.decode(word);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        cpu.writeReg(2, @truncate(index *% 0x9e37_79b1));
        cpu.writeReg(3, @truncate(index *% 0x85eb_ca77));
        const clock: u32 = @intCast(index + 1);
        const lhs = cpu.readReg(instruction.rs1);
        const rhs = cpu.readReg(instruction.rs2);
        const previous = cpu.readReg(instruction.rd);
        const accesses = access_witness.capture(&tracker, instruction, clock);
        const next = independentResult(instruction.opcode, lhs, rhs);
        cpu.writeReg(instruction.rd, next);
        const pc = cpu.pc;
        cpu.pc +%= 4;
        try trace.append(.{
            .clk = clock,
            .pc = pc,
            .opcode = instruction.opcode,
            .rd = instruction.rd,
            .rs1 = instruction.rs1,
            .rs2 = instruction.rs2,
            .imm = 0,
            .rs1_val = lhs,
            .rs2_val = rhs,
            .rs1_prev_clk = accesses.rs1_prev_clock,
            .rs2_prev_clk = accesses.rs2_prev_clock,
            .rd_prev_val = previous,
            .rd_prev_clk = accesses.rd_prev_clock,
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
        try accesses.recordRegisters(
            &tracker,
            instruction,
            lhs,
            rhs,
            previous,
            next,
        );
    }
    return timer.read();
}

fn independentResult(opcode: decode.Opcode, lhs_bits: u32, rhs_bits: u32) u32 {
    return switch (opcode) {
        .DIV => blk: {
            if (rhs_bits == 0) break :blk std.math.maxInt(u32);
            if (lhs_bits == 0x8000_0000 and rhs_bits == 0xffff_ffff)
                break :blk 0x8000_0000;
            const lhs: i32 = @bitCast(lhs_bits);
            const rhs: i32 = @bitCast(rhs_bits);
            break :blk @bitCast(@divTrunc(lhs, rhs));
        },
        .DIVU => if (rhs_bits == 0) std.math.maxInt(u32) else lhs_bits / rhs_bits,
        .REM => blk: {
            if (rhs_bits == 0) break :blk lhs_bits;
            if (lhs_bits == 0x8000_0000 and rhs_bits == 0xffff_ffff)
                break :blk 0;
            const lhs: i32 = @bitCast(lhs_bits);
            const rhs: i32 = @bitCast(rhs_bits);
            break :blk @bitCast(@rem(lhs, rhs));
        },
        .REMU => if (rhs_bits == 0) lhs_bits else lhs_bits % rhs_bits,
        else => unreachable,
    };
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

const ReentrantMutationAllocator = struct {
    child: std.mem.Allocator,
    cpu: *Cpu,
    armed: bool = false,
    fired: bool = false,

    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn trigger(self: *@This()) void {
        if (!self.armed or self.fired) return;
        self.fired = true;
        self.cpu.pc +%= 4;
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.trigger();
        return self.child.rawAlloc(len, alignment, return_address);
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.trigger();
        return self.child.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.trigger();
        return self.child.rawRemap(memory, alignment, new_len, return_address);
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.child.rawFree(memory, alignment, return_address);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};
