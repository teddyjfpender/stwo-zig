const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const access_witness = @import("access_witness.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const authority_mod = @import("../air/lang/typed_load_store_authority.zig");
const decode = @import("decode.zig");
const subject = @import("load_store_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

test "LOAD_STORE retirement owns all operations alignment sign extension partial writes aliases and x0" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    const cases = [_]struct {
        opcode: decode.Opcode,
        rd: u5,
        rs1: u5,
        rs2: u5,
        base: u32,
        source: u32,
        previous_word: u32,
        immediate: i32,
    }{
        .{ .opcode = .LB, .rd = 5, .rs1 = 2, .rs2 = 0, .base = 0x2000, .source = 0, .previous_word = 0x1122_8033, .immediate = 1 },
        .{ .opcode = .LH, .rd = 3, .rs1 = 3, .rs2 = 0, .base = 0x2100, .source = 0, .previous_word = 0x8001_1234, .immediate = 2 },
        .{ .opcode = .LBU, .rd = 0, .rs1 = 0, .rs2 = 0, .base = 0, .source = 0, .previous_word = 0xfe12_3456, .immediate = 3 },
        .{ .opcode = .LHU, .rd = 6, .rs1 = 4, .rs2 = 0, .base = 0x2200, .source = 0, .previous_word = 0xfedc_5678, .immediate = 2 },
        .{ .opcode = .LW, .rd = 7, .rs1 = 8, .rs2 = 0, .base = 0x2304, .source = 0, .previous_word = 0xdead_beef, .immediate = -4 },
        .{ .opcode = .SB, .rd = 0, .rs1 = 9, .rs2 = 10, .base = 0x2400, .source = 0xa1b2_c3d4, .previous_word = 0x1122_3344, .immediate = 2 },
        .{ .opcode = .SH, .rd = 0, .rs1 = 11, .rs2 = 11, .base = 0x2500, .source = 0x2500, .previous_word = 0x5566_7788, .immediate = 2 },
        .{ .opcode = .SW, .rd = 0, .rs1 = 12, .rs2 = 13, .base = 0x2604, .source = 0xcafe_babe, .previous_word = 0x0102_0304, .immediate = -4 },
    };

    for (cases) |case| {
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(case.rs1, case.base);
        if (case.rs2 != case.rs1) cpu.writeReg(case.rs2, case.source);
        if (decode.isLoad(case.opcode) and
            case.rd != case.rs1)
        {
            cpu.writeReg(case.rd, 0x7654_3210);
        }
        const word = if (decode.isLoad(case.opcode))
            encodeLoad(case.opcode, case.rd, case.rs1, case.immediate)
        else
            encodeStore(case.opcode, case.rs1, case.rs2, case.immediate);
        const instruction = try decode.DecodedInst.decode(word);
        const address = cpu.readReg(instruction.rs1) +%
            @as(u32, @bitCast(instruction.imm));
        const aligned = address & ~@as(u32, 3);

        var memory = try Memory.initFallible(std.testing.allocator);
        defer memory.deinit();
        memory.writeU32(aligned, case.previous_word);
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();

        const rs1_before = cpu.readReg(instruction.rs1);
        const rs2_before = cpu.readReg(instruction.rs2);
        const rd_before = cpu.readReg(instruction.rd);
        const expected = try authority.retire(
            instruction,
            rs1_before,
            rs2_before,
            case.previous_word,
        );
        try subject.retireAtomic(
            &authority,
            &cpu,
            &memory,
            &trace,
            &tracker,
            instruction,
            word,
            1,
        );

        try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
        try std.testing.expectEqual(expected.memory_next_word, memory.readU32(aligned));
        try std.testing.expectEqual(
            if (expected.is_load) expected.register_value else rd_before,
            cpu.readReg(instruction.rd),
        );
        try std.testing.expectEqual(@as(usize, 1), trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 3), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(u1, 0), tracker.accesses.items[0].addr_space);
        try std.testing.expectEqual(@as(u32, instruction.rs1), tracker.accesses.items[0].addr);
        try std.testing.expectEqual(
            @as(u32, if (expected.is_load) instruction.rd else instruction.rs2),
            tracker.accesses.items[1].addr,
        );
        try std.testing.expectEqual(@as(u1, 1), tracker.accesses.items[2].addr_space);
        try std.testing.expectEqual(aligned, tracker.accesses.items[2].addr);
        try std.testing.expectEqual(access_clock.encode(1, .first), tracker.accesses.items[0].clk);
        try std.testing.expectEqual(access_clock.encode(1, .second), tracker.accesses.items[1].clk);
        try std.testing.expectEqual(access_clock.encode(1, .third), tracker.accesses.items[2].clk);
        try std.testing.expectEqual(case.previous_word, tracker.mem_initial.get(aligned).?);
        try std.testing.expectEqual(access_clock.encode(1, .third), tracker.mem_last_clk.get(aligned).?);

        var storage: [authority_mod.MAIN_COLUMN_COUNT][1]M31 = undefined;
        var columns: [authority_mod.MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&storage, &columns) |*owned, *view| view.* = owned;
        try authority.generateMainInto(&columns, trace.rows.items, 0);
    }
}

test "LOAD_STORE exact word admission exhausts immediates register fields and selector matrix" {
    const load_ops = [_]decode.Opcode{ .LB, .LH, .LW, .LBU, .LHU };
    const store_ops = [_]decode.Opcode{ .SB, .SH, .SW };
    var legal_count: usize = 0;
    var immediate: i32 = -2048;
    while (immediate <= 2047) : (immediate += 1) {
        for (load_ops) |opcode| for (0..32) |rd| for (0..32) |rs1| {
            const word = encodeLoad(opcode, @intCast(rd), @intCast(rs1), immediate);
            const instruction = try decode.DecodedInst.decode(word);
            try std.testing.expect(subject.instructionMatchesWord(instruction, word));
            legal_count += 1;
        };
        for (store_ops) |opcode| for (0..32) |rs1| for (0..32) |rs2| {
            const word = encodeStore(opcode, @intCast(rs1), @intCast(rs2), immediate);
            const instruction = try decode.DecodedInst.decode(word);
            try std.testing.expect(subject.instructionMatchesWord(instruction, word));
            legal_count += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 33_554_432), legal_count);

    var selector_count: usize = 0;
    for (0..128) |opcode_field| for (0..128) |funct7| for (0..8) |funct3| {
        const word = (@as(u32, @intCast(funct7)) << 25) |
            (3 << 20) | (2 << 15) |
            (@as(u32, @intCast(funct3)) << 12) | (1 << 7) |
            @as(u32, @intCast(opcode_field));
        const maybe_instruction = decode.DecodedInst.decode(word) catch null;
        const expected = (opcode_field == 0x03 and
            (funct3 <= 2 or funct3 == 4 or funct3 == 5)) or
            (opcode_field == 0x23 and funct3 <= 2);
        if (maybe_instruction) |instruction| {
            try std.testing.expectEqual(
                expected,
                subject.instructionMatchesWord(instruction, word),
            );
        } else try std.testing.expect(!expected);
        selector_count += 1;
    };
    try std.testing.expectEqual(@as(usize, 131_072), selector_count);
}

test "LOAD_STORE staging and forged plans reject before logical publication" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x2000);
    cpu.writeReg(3, 0xaabb_ccdd);
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x2000, 0x1122_3344);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encodeStore(.SW, 2, 3, 0);
    const instruction = try decode.DecodedInst.decode(word);

    try std.testing.expectError(
        error.InstructionWordMismatch,
        subject.stage(&authority, &cpu, &memory, &trace, &tracker, instruction, word ^ 1, 1),
    );
    try std.testing.expectError(
        error.InstructionClockMismatch,
        subject.stage(&authority, &cpu, &memory, &trace, &tracker, instruction, word, 2),
    );
    const misaligned_word = encodeStore(.SW, 2, 3, 2);
    try std.testing.expectError(
        error.MisalignedMemoryAccess,
        subject.stage(
            &authority,
            &cpu,
            &memory,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(misaligned_word),
            misaligned_word,
            1,
        ),
    );

    const canonical = try subject.stage(
        &authority,
        &cpu,
        &memory,
        &trace,
        &tracker,
        instruction,
        word,
        1,
    );
    inline for (.{
        "word",       "clock",           "pc",               "rs1",       "rs2",          "rd_previous",     "rd_next",
        "address",    "memory_previous", "memory_next",      "first_raw", "second_raw",   "memory_raw",      "initial",
        "access_len", "memory_gap_len",  "register_gap_len", "trace_len", "last_present", "initial_present", "initialized",
    }) |mutation| {
        var forged = canonical;
        if (std.mem.eql(u8, mutation, "word")) forged.inst_word ^= 1;
        if (std.mem.eql(u8, mutation, "clock")) forged.instruction_clock +%= 1;
        if (std.mem.eql(u8, mutation, "pc")) forged.pc_before +%= 4;
        if (std.mem.eql(u8, mutation, "rs1")) forged.rs1_value ^= 1;
        if (std.mem.eql(u8, mutation, "rs2")) forged.rs2_value ^= 1;
        if (std.mem.eql(u8, mutation, "rd_previous")) forged.rd_previous_value ^= 1;
        if (std.mem.eql(u8, mutation, "rd_next")) forged.rd_next_value ^= 1;
        if (std.mem.eql(u8, mutation, "address")) forged.memory_address +%= 4;
        if (std.mem.eql(u8, mutation, "memory_previous")) forged.memory_previous_word ^= 1;
        if (std.mem.eql(u8, mutation, "memory_next")) forged.memory_next_word ^= 1;
        if (std.mem.eql(u8, mutation, "first_raw")) forged.first_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "second_raw")) forged.second_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "memory_raw")) forged.memory_raw_previous_clock +%= 1;
        if (std.mem.eql(u8, mutation, "initial")) forged.memory_initial_value ^= 1;
        if (std.mem.eql(u8, mutation, "access_len")) forged.expected_access_len +%= 1;
        if (std.mem.eql(u8, mutation, "memory_gap_len")) forged.expected_memory_gap_len +%= 1;
        if (std.mem.eql(u8, mutation, "register_gap_len")) forged.expected_register_gap_len +%= 1;
        if (std.mem.eql(u8, mutation, "trace_len")) forged.expected_trace_len += 1;
        if (std.mem.eql(u8, mutation, "last_present"))
            forged.memory_last_was_present = !forged.memory_last_was_present;
        if (std.mem.eql(u8, mutation, "initial_present"))
            forged.memory_initial_was_present = !forged.memory_initial_was_present;
        if (std.mem.eql(u8, mutation, "initialized"))
            forged.memory_word_was_initialized = !forged.memory_word_was_initialized;
        try expectPrepareAtomicFailure(
            &forged,
            &cpu,
            &memory,
            &trace,
            &tracker,
        );
    }
}

test "LOAD_STORE prepared token detects runner maps and append-log staleness" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    inline for (.{ "cpu", "memory", "tracker", "access_log", "memory_gap_log", "register_gap_log" }) |mutation| {
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 0x2000);
        var memory = try Memory.initFallible(std.testing.allocator);
        defer memory.deinit();
        memory.writeU32(0x2000, 0x1234_5678);
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeLoad(.LW, 4, 2, 0);
        const plan = try subject.stage(
            &authority,
            &cpu,
            &memory,
            &trace,
            &tracker,
            try decode.DecodedInst.decode(word),
            word,
            1,
        );
        var prepared = try plan.prepare(&cpu, &memory, &trace, &tracker);
        if (std.mem.eql(u8, mutation, "cpu")) cpu.pc +%= 4;
        if (std.mem.eql(u8, mutation, "memory")) memory.writeU32(0x2000, 7);
        if (std.mem.eql(u8, mutation, "tracker")) tracker.reg_last_clk[2] = 1;
        if (std.mem.eql(u8, mutation, "access_log")) try tracker.accesses.append(
            std.testing.allocator,
            .{ .addr_space = 0, .addr = 31, .clk = 1, .value = 0, .clk_prev = 0 },
        );
        if (std.mem.eql(u8, mutation, "memory_gap_log")) try tracker.clock_updates_mem.append(
            std.testing.allocator,
            .{ .addr_space = 1, .addr = 0x3000, .clk = 1, .clk_prev = 0, .value = 0 },
        );
        if (std.mem.eql(u8, mutation, "register_gap_log")) try tracker.clock_updates_reg.append(
            std.testing.allocator,
            .{ .addr_space = 0, .addr = 31, .clk = 1, .clk_prev = 0, .value = 0 },
        );
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &memory, &trace, &tracker),
        );
        try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
    }

    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x2000);
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x2000, 0x1234_5678);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encodeLoad(.LW, 4, 2, 0);
    const plan = try subject.stage(
        &authority,
        &cpu,
        &memory,
        &trace,
        &tracker,
        try decode.DecodedInst.decode(word),
        word,
        1,
    );
    var prepared = try plan.prepare(&cpu, &memory, &trace, &tracker);
    try prepared.commit(&cpu, &memory, &trace, &tracker);
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &memory, &trace, &tracker),
    );
}

test "LOAD_STORE cold allocation failure is atomic and warm stores allocate nothing" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var cpu = Cpu.init(0x1000, 0);
        cpu.writeReg(2, 0x2000);
        cpu.writeReg(3, 0xdead_beef);
        var memory = try Memory.initFallible(failing.allocator());
        defer memory.deinit();
        var trace = Trace.init(failing.allocator());
        defer trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
        const word = encodeStore(.SW, 2, 3, 0);
        const before = cpu;
        try std.testing.expectError(
            error.OutOfMemory,
            subject.retireAtomic(
                &authority,
                &cpu,
                &memory,
                &trace,
                &tracker,
                try decode.DecodedInst.decode(word),
                word,
                1,
            ),
        );
        try std.testing.expectEqualDeep(before, cpu);
        try std.testing.expectEqual(@as(u32, 0), memory.readU32(0x2000));
        try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    }

    const iterations = 1 << 10;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x2000);
    cpu.writeReg(3, 0xa5a5_5a5a);
    var memory = try Memory.initFallible(failing.allocator());
    defer memory.deinit();
    memory.writeU32(0x2000, 0);
    var trace = Trace.init(failing.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 1,
        .access_count = iterations * 3,
        .memory_clock_update_count = iterations,
        .register_clock_update_count = iterations * 2,
    });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    const word = encodeStore(.SW, 2, 3, 0);
    const instruction = try decode.DecodedInst.decode(word);
    for (0..iterations) |index| {
        try subject.retireAtomic(
            &authority,
            &cpu,
            &memory,
            &trace,
            &tracker,
            instruction,
            word,
            @intCast(index + 1),
        );
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, iterations), trace.rows.items.len);
    try std.testing.expectEqual(@as(u32, 0xa5a5_5a5a), memory.readU32(0x2000));
    try std.testing.expect(!containsPointer(subject.Plan));
    try std.testing.expect(!containsPointer(subject.Authority));
    std.debug.print(
        "\n  LOAD_STORE footprint plan={d}B prepared={d}B\n",
        .{ @sizeOf(subject.Plan), @sizeOf(subject.Prepared) },
    );
    try std.testing.expectEqual(@as(usize, 88), @sizeOf(subject.Plan));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(subject.Prepared));
}

test "LOAD_STORE reserve reentrancy is detected before publication" {
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x2000);
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x2000, 0x1122_3344);
    var reentrant = ReentrantMutationAllocator{
        .child = std.testing.allocator,
        .cpu = &cpu,
    };
    var trace = Trace.init(reentrant.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(reentrant.allocator());
    defer tracker.deinit();
    const word = encodeLoad(.LW, 4, 2, 0);
    const plan = try subject.stage(
        &authority,
        &cpu,
        &memory,
        &trace,
        &tracker,
        try decode.DecodedInst.decode(word),
        word,
        1,
    );
    reentrant.armed = true;
    try std.testing.expectError(
        error.StaleRetirement,
        plan.prepare(&cpu, &memory, &trace, &tracker),
    );
    reentrant.armed = false;
    try std.testing.expect(reentrant.fired);
    try std.testing.expectEqual(@as(usize, 0), trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
}

test "LOAD_STORE retirement strictly preserves paired legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try subject.authenticateCanonical(std.testing.allocator);
    _ = try measureFixed(&authority, 1 << 9);
    _ = try measureLegacy(1 << 9);
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
        "\n  LOAD_STORE retirement={d} ns legacy={d} ns speed={d:.4}x\n",
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
    memory: *Memory,
    trace: *Trace,
    tracker: *StateChainTracker,
) !void {
    const cpu_before = cpu.*;
    const memory_before = memory.readU32(plan.alignedAddress());
    const trace_before = trace.rows.items.len;
    const access_before = tracker.accesses.items.len;
    const mem_gap_before = tracker.clock_updates_mem.items.len;
    const reg_gap_before = tracker.clock_updates_reg.items.len;
    try std.testing.expectError(
        error.StaleRetirement,
        plan.prepare(cpu, memory, trace, tracker),
    );
    try std.testing.expectEqualDeep(cpu_before, cpu.*);
    try std.testing.expectEqual(memory_before, memory.readU32(plan.alignedAddress()));
    try std.testing.expectEqual(trace_before, trace.rows.items.len);
    try std.testing.expectEqual(access_before, tracker.accesses.items.len);
    try std.testing.expectEqual(mem_gap_before, tracker.clock_updates_mem.items.len);
    try std.testing.expectEqual(reg_gap_before, tracker.clock_updates_reg.items.len);
}

fn encodeLoad(opcode: decode.Opcode, rd: u5, rs1: u5, immediate: i32) u32 {
    const funct3: u32 = switch (opcode) {
        .LB => 0,
        .LH => 1,
        .LW => 2,
        .LBU => 4,
        .LHU => 5,
        else => unreachable,
    };
    const immediate_12 = @as(u32, @bitCast(immediate)) & 0xfff;
    return (immediate_12 << 20) | (@as(u32, rs1) << 15) |
        (funct3 << 12) | (@as(u32, rd) << 7) | 0x03;
}

fn encodeStore(opcode: decode.Opcode, rs1: u5, rs2: u5, immediate: i32) u32 {
    const funct3: u32 = switch (opcode) {
        .SB => 0,
        .SH => 1,
        .SW => 2,
        else => unreachable,
    };
    const immediate_12 = @as(u32, @bitCast(immediate)) & 0xfff;
    return ((immediate_12 & 0xfe0) << 20) | (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) | (funct3 << 12) |
        ((immediate_12 & 0x1f) << 7) | 0x23;
}

fn measureFixed(authority: *const subject.Authority, iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x2000);
    cpu.writeReg(3, 0xa5a5_5a5a);
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x2000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 1,
        .access_count = iterations * 3,
        .memory_clock_update_count = iterations,
        .register_clock_update_count = iterations * 2,
    });
    const word = encodeStore(.SW, 2, 3, 0);
    const instruction = try decode.DecodedInst.decode(word);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        cpu.writeReg(3, @truncate(index *% 0x9e37_79b1));
        try subject.retireAtomic(
            authority,
            &cpu,
            &memory,
            &trace,
            &tracker,
            instruction,
            word,
            @intCast(index + 1),
        );
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(memory.readU32(0x2000));
    std.mem.doNotOptimizeAway(trace.rows.items.len);
    return elapsed;
}

fn measureLegacy(iterations: usize) !u64 {
    var cpu = Cpu.init(0x1000, 0);
    cpu.writeReg(2, 0x2000);
    cpu.writeReg(3, 0xa5a5_5a5a);
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x2000, 0);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(.{
        .memory_address_count = 1,
        .access_count = iterations * 3,
        .memory_clock_update_count = iterations,
        .register_clock_update_count = iterations * 2,
    });
    const word = encodeStore(.SW, 2, 3, 0);
    const instruction = try decode.DecodedInst.decode(word);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| {
        const clock: u32 = @intCast(index + 1);
        cpu.writeReg(3, @truncate(index *% 0x9e37_79b1));
        const rs1_value = cpu.readReg(instruction.rs1);
        const rs2_value = cpu.readReg(instruction.rs2);
        const rd_previous = cpu.readReg(instruction.rd);
        const address = rs1_value +% @as(u32, @bitCast(instruction.imm));
        const aligned = address & ~@as(u32, 3);
        const previous_word = memory.readU32(aligned);
        const accesses = access_witness.capture(&tracker, instruction, clock);
        const memory_clock = access_clock.encode(clock, .third);
        const memory_previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.mem_last_clk.get(aligned) orelse 0,
            memory_clock,
        );
        memory.writeU32(aligned, rs2_value);
        const pc = cpu.pc;
        cpu.pc +%= 4;
        try trace.append(.{
            .clk = clock,
            .pc = pc,
            .opcode = .SW,
            .rd = instruction.rd,
            .rs1 = instruction.rs1,
            .rs2 = instruction.rs2,
            .imm = instruction.imm,
            .rs1_val = rs1_value,
            .rs2_val = rs2_value,
            .rs1_prev_clk = accesses.rs1_prev_clock,
            .rs2_prev_clk = accesses.rs2_prev_clock,
            .rd_prev_val = rd_previous,
            .rd_prev_clk = 0,
            .rd_val = rd_previous,
            .mem_addr = address,
            .mem_val = rs2_value,
            .mem_prev_word = previous_word,
            .mem_next_word = rs2_value,
            .mem_prev_clk = memory_previous_clock,
            .is_load = false,
            .is_store = true,
            .branch_taken = false,
            .next_pc = cpu.pc,
            .inst_word = word,
        });
        try accesses.recordRegisters(
            &tracker,
            instruction,
            rs1_value,
            rs2_value,
            rd_previous,
            rd_previous,
        );
        try tracker.recordMemTransition(
            aligned,
            memory_clock,
            previous_word,
            rs2_value,
        );
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(memory.readU32(0x2000));
    std.mem.doNotOptimizeAway(trace.rows.items.len);
    return elapsed;
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
