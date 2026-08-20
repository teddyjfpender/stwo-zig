const std = @import("std");
const builtin = @import("builtin");
const typed = @import("../air/lang/typed_branch_eq.zig");
const typed_authority = @import("../air/lang/typed_branch_eq_authority.zig");
const access_clock = @import("../access_clock.zig");
const access_witness = @import("access_witness.zig");
const Cpu = @import("cpu.zig").Cpu;
const decode = @import("decode.zig");
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");
const subject = @import("branch_eq_retirement.zig");

const Opcode = decode.Opcode;
const StateChainTracker = state_chain.StateChainTracker;
const Trace = trace_mod.Trace;

test "typed BRANCH_EQ retirement equals independent legacy behavior and events" {
    const authority = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: Opcode,
        pc: u32,
        immediate: i32,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
    }{
        // x0, same-source, positive/negative extremes, taken/fallthrough, and
        // the subtle selected-imm=4 case whose architectural next PC is still
        // indistinguishable from sequential fallthrough.
        .{ .opcode = .BEQ, .pc = 0x1000, .immediate = 0, .rs1 = 0, .rs2 = 0, .lhs = 0, .rhs = 0 },
        .{ .opcode = .BNE, .pc = 0x1000, .immediate = 8, .rs1 = 0, .rs2 = 5, .lhs = 0, .rhs = 7 },
        .{ .opcode = .BEQ, .pc = 0x4000, .immediate = -4096, .rs1 = 5, .rs2 = 7, .lhs = 0x8000_0000, .rhs = 0x8000_0000 },
        .{ .opcode = .BNE, .pc = 0x2000, .immediate = 4092, .rs1 = 5, .rs2 = 7, .lhs = 9, .rhs = 9 },
        .{ .opcode = .BEQ, .pc = 0x2000, .immediate = 4, .rs1 = 5, .rs2 = 5, .lhs = 0xdead_beef, .rhs = 0xdead_beef },
        // imm=2052 exposes diagnostic rd=x5, aliasing rs1 without creating a
        // branch destination effect.
        .{ .opcode = .BNE, .pc = 0x2000, .immediate = 2052, .rs1 = 5, .rs2 = 7, .lhs = 0x1234, .rhs = 0x5678 },
        .{ .opcode = .BEQ, .pc = 0x2000, .immediate = -4, .rs1 = 31, .rs2 = 30, .lhs = 0xffff_ffff, .rhs = 0xffff_ffff },
    };

    for (cases) |case| {
        const word = encodeBranch(
            case.opcode,
            case.rs1,
            case.rs2,
            case.immediate,
        );
        const instruction = try decode.DecodedInst.decode(word);
        var actual_cpu = initializedCpu(case.pc);
        try installSources(&actual_cpu, instruction, case.lhs, case.rhs);
        var expected_cpu = actual_cpu;
        var actual_trace = Trace.init(std.testing.allocator);
        defer actual_trace.deinit();
        var expected_trace = Trace.init(std.testing.allocator);
        defer expected_trace.deinit();
        var actual_tracker = StateChainTracker.init(std.testing.allocator);
        defer actual_tracker.deinit();
        var expected_tracker = StateChainTracker.init(std.testing.allocator);
        defer expected_tracker.deinit();

        try subject.retireAtomic(
            &authority,
            &actual_cpu,
            &actual_trace,
            &actual_tracker,
            instruction,
            word,
            1,
        );
        try oracleRetire(
            &expected_cpu,
            &expected_trace,
            &expected_tracker,
            instruction,
            word,
            1,
        );
        try std.testing.expectEqualDeep(expected_cpu, actual_cpu);
        try std.testing.expectEqualSlices(
            trace_mod.TraceRow,
            expected_trace.rows.items,
            actual_trace.rows.items,
        );
        try expectTrackersEqual(&expected_tracker, &actual_tracker);
        const row = actual_trace.rows.items[0];
        try std.testing.expectEqual(row.rd_prev_val, row.rd_val);
        try std.testing.expectEqual(@as(u32, 0), row.rd_prev_clk);
        try std.testing.expectEqual(
            actual_cpu.pc != case.pc +% 4,
            row.branch_taken,
        );
    }
}

test "typed BRANCH_EQ encoding admission exhausts every B immediate and register field" {
    var immediate: i32 = -4096;
    while (immediate <= 4094) : (immediate += 2) {
        inline for ([_]Opcode{ .BEQ, .BNE }) |opcode| {
            var rs1_index: u8 = 0;
            while (rs1_index < 32) : (rs1_index += 1) {
                var rs2_index: u8 = 0;
                while (rs2_index < 32) : (rs2_index += 1) {
                    const rs1: u5 = @intCast(rs1_index);
                    const rs2: u5 = @intCast(rs2_index);
                    const word = encodeBranch(opcode, rs1, rs2, immediate);
                    const instruction = try decode.DecodedInst.decode(word);
                    if (instruction.opcode != opcode or
                        instruction.rs1 != rs1 or
                        instruction.rs2 != rs2 or
                        instruction.imm != immediate or
                        instruction.rd != @as(u5, @truncate(word >> 7)) or
                        !subject.instructionMatchesWord(instruction, word))
                    {
                        return error.TestUnexpectedResult;
                    }
                }
            }
            const boundary_word = encodeBranch(opcode, 0, 31, immediate);
            const decoded = try decode.DecodedInst.decode(boundary_word);
            try std.testing.expect(!subject.instructionMatchesWord(
                decoded,
                boundary_word ^ 1,
            ));
            var forged = decoded;
            forged.rd +%= 1;
            try std.testing.expect(!subject.instructionMatchesWord(
                forged,
                boundary_word,
            ));
        }
    }
}

test "typed BRANCH_EQ x0 source aliases and diagnostic rd aliases remain coherent" {
    const authority = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: Opcode,
        immediate: i32,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
    }{
        .{ .opcode = .BEQ, .immediate = 0, .rs1 = 0, .rs2 = 0, .lhs = 0, .rhs = 0 },
        .{ .opcode = .BNE, .immediate = 8, .rs1 = 0, .rs2 = 7, .lhs = 0, .rhs = 1 },
        .{ .opcode = .BEQ, .immediate = 4, .rs1 = 9, .rs2 = 9, .lhs = 0xabcd_1234, .rhs = 0xabcd_1234 },
        .{ .opcode = .BNE, .immediate = 2052, .rs1 = 5, .rs2 = 7, .lhs = 1, .rhs = 2 },
        // imm=2054 exposes diagnostic rd=x7; equality makes BNE fall through,
        // so its legal halfword offset is never selected as a misaligned PC.
        .{ .opcode = .BNE, .immediate = 2054, .rs1 = 7, .rs2 = 7, .lhs = 42, .rhs = 42 },
    };
    for (cases) |case| {
        const word = encodeBranch(case.opcode, case.rs1, case.rs2, case.immediate);
        const instruction = try decode.DecodedInst.decode(word);
        var cpu = initializedCpu(0x4000);
        try installSources(&cpu, instruction, case.lhs, case.rhs);
        const before = cpu;
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        try subject.retireAtomic(
            &authority,
            &cpu,
            &trace,
            &tracker,
            instruction,
            word,
            1,
        );
        for (0..32) |index| try std.testing.expectEqual(
            before.readReg(@intCast(index)),
            cpu.readReg(@intCast(index)),
        );
        try std.testing.expectEqual(@as(usize, 2), tracker.accesses.items.len);
        if (instruction.rs1 == instruction.rs2) {
            try std.testing.expectEqual(
                access_clock.encode(1, .first),
                tracker.accesses.items[1].clk_prev,
            );
        }
    }
}

test "typed BRANCH_EQ malformed and stale plans expose no retirement prefix" {
    const authority = try authenticatedAuthority();
    {
        var cpu = initializedCpu(0x1000);
        cpu.writeReg(5, 1);
        cpu.writeReg(7, 2);
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        const word = encodeBranch(.BNE, 5, 7, 8);
        const instruction = try decode.DecodedInst.decode(word);
        try std.testing.expectError(
            error.InstructionWordMismatch,
            subject.stage(
                &authority,
                &cpu,
                &trace,
                &tracker,
                instruction,
                word ^ 1,
                1,
            ),
        );
        try std.testing.expectError(
            error.InstructionClockMismatch,
            subject.stage(
                &authority,
                &cpu,
                &trace,
                &tracker,
                instruction,
                word,
                2,
            ),
        );
        const misaligned_word = encodeBranch(.BEQ, 5, 5, 2);
        try std.testing.expectError(
            error.InstructionAddressMisaligned,
            subject.stage(
                &authority,
                &cpu,
                &trace,
                &tracker,
                try decode.DecodedInst.decode(misaligned_word),
                misaligned_word,
                1,
            ),
        );
    }

    inline for ([_]Mutation{
        .plan,
        .pc,
        .source_1,
        .source_2,
        .diagnostic,
        .trace,
        .tracker,
    }) |mutation| {
        var cpu = initializedCpu(0x1000);
        cpu.writeReg(5, 1);
        cpu.writeReg(7, 2);
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        try trace.reserveOne();
        try tracker.reserveTransitions(noGapReservation(2));
        const word = encodeBranch(.BNE, 5, 7, 8);
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
            .pc => cpu.pc +%= 4,
            .source_1 => cpu.writeReg(5, cpu.readReg(5) +% 1),
            .source_2 => cpu.writeReg(7, cpu.readReg(7) +% 1),
            .diagnostic => cpu.writeReg(plan.instruction.rd, cpu.readReg(plan.instruction.rd) ^ 1),
            .trace => trace.appendAssumeCapacity(plan.traceRow()),
            .tracker => tracker.reg_last_clk[5] +%= 1,
        }
        const cpu_before_commit = cpu;
        const trace_len = trace.rows.items.len;
        const access_len = tracker.accesses.items.len;
        try std.testing.expectError(
            error.StaleRetirement,
            prepared.commit(&cpu, &trace, &tracker),
        );
        try std.testing.expectEqualDeep(cpu_before_commit, cpu);
        try std.testing.expectEqual(trace_len, trace.rows.items.len);
        try std.testing.expectEqual(access_len, tracker.accesses.items.len);
    }
}

test "typed BRANCH_EQ prepared token is single use" {
    const authority = try authenticatedAuthority();
    var cpu = initializedCpu(0x1000);
    cpu.writeReg(5, 1);
    cpu.writeReg(7, 2);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const word = encodeBranch(.BNE, 5, 7, 8);
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
    try prepared.commit(&cpu, &trace, &tracker);
    try std.testing.expectError(
        error.AlreadyCommitted,
        prepared.commit(&cpu, &trace, &tracker),
    );
}

test "typed BRANCH_EQ transaction and plan footprints are exact and pointer-free" {
    try std.testing.expectEqual(@as(usize, 72), @sizeOf(subject.CompactTransaction));
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(subject.Plan));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(subject.Prepared));
    try std.testing.expect(!containsPointer(subject.CompactTransaction));
    try std.testing.expect(!containsPointer(subject.Plan));
}

test "typed BRANCH_EQ capacity failures are atomic and warm path allocates nothing" {
    const authority = try authenticatedAuthority();
    var observed_failures: usize = 0;
    var reached_success = false;
    for (0..8) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        var cpu = initializedCpu(0x1000);
        cpu.writeReg(5, 1);
        cpu.writeReg(7, 2);
        const before = cpu;
        var trace = Trace.init(failing.allocator());
        defer trace.deinit();
        var tracker = StateChainTracker.init(failing.allocator());
        defer tracker.deinit();
        const word = encodeBranch(.BNE, 5, 7, 8);
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
    var cpu = initializedCpu(0x1000);
    cpu.writeReg(5, 1);
    cpu.writeReg(7, 2);
    var trace = Trace.init(failing.allocator());
    defer trace.deinit();
    var tracker = StateChainTracker.init(failing.allocator());
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    const word = encodeBranch(.BNE, 5, 7, 8);
    const instruction = try decode.DecodedInst.decode(word);
    for (0..iterations) |index| try subject.retireAtomic(
        &authority,
        &cpu,
        &trace,
        &tracker,
        instruction,
        word,
        @intCast(index + 1),
    );
    try std.testing.expect(!failing.has_induced_failure);
}

test "typed BRANCH_EQ cold retirement releases every induced allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        coldRetirementAllocationCase,
        .{},
    );
}

test "typed BRANCH_EQ retirement retains at least 0.97x legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const authority = try authenticatedAuthority();
    const samples = 15;
    const iterations = 1 << 14;
    _ = try measureTyped(&authority, 1 << 10);
    _ = try measureOracle(1 << 10);
    var typed_samples: [samples]u64 = undefined;
    var oracle_samples: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        typed_samples[sample] = try measureTyped(&authority, iterations);
        oracle_samples[sample] = try measureOracle(iterations);
    } else {
        oracle_samples[sample] = try measureOracle(iterations);
        typed_samples[sample] = try measureTyped(&authority, iterations);
    };
    const typed_median = median(&typed_samples);
    const oracle_median = median(&oracle_samples);
    std.debug.print(
        "\n  typed BRANCH_EQ retirement={d} ns legacy={d} ns speed={d:.4}x plan={d}B transaction={d}B\n",
        .{
            typed_median,
            oracle_median,
            @as(f64, @floatFromInt(oracle_median)) /
                @as(f64, @floatFromInt(typed_median)),
            @sizeOf(subject.Plan),
            @sizeOf(subject.CompactTransaction),
        },
    );
    try std.testing.expect(
        @as(u128, typed_median) * 97 <= @as(u128, oracle_median) * 100,
    );
}

const Mutation = enum {
    plan,
    pc,
    source_1,
    source_2,
    diagnostic,
    trace,
    tracker,
};

fn oracleRetire(
    cpu: *Cpu,
    trace: *Trace,
    tracker: *StateChainTracker,
    instruction: decode.DecodedInst,
    inst_word: u32,
    clock: u32,
) !void {
    const pc_before = cpu.pc;
    const lhs = cpu.readReg(instruction.rs1);
    const rhs = cpu.readReg(instruction.rs2);
    const rd_metadata = cpu.readReg(instruction.rd);
    const access = access_witness.capture(tracker, instruction, clock);
    const taken = switch (instruction.opcode) {
        .BEQ => lhs == rhs,
        .BNE => lhs != rhs,
        else => return error.InvalidOracleInput,
    };
    const next_pc = if (taken)
        pc_before +% @as(u32, @bitCast(instruction.imm))
    else
        pc_before +% 4;
    if (next_pc & 3 != 0 or next_pc >= typed_authority.PC_BOUND)
        return error.InvalidOracleInput;
    cpu.pc = next_pc;
    try trace.append(.{
        .clk = clock,
        .pc = pc_before,
        .opcode = instruction.opcode,
        .rd = instruction.rd,
        .rs1 = instruction.rs1,
        .rs2 = instruction.rs2,
        .imm = instruction.imm,
        .rs1_val = lhs,
        .rs2_val = rhs,
        .rs1_prev_clk = access.rs1_prev_clock,
        .rs2_prev_clk = access.rs2_prev_clock,
        .rd_prev_val = rd_metadata,
        .rd_prev_clk = 0,
        .rd_val = rd_metadata,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = next_pc != pc_before +% 4,
        .next_pc = next_pc,
        .inst_word = inst_word,
    });
    try access.recordRegisters(
        tracker,
        instruction,
        lhs,
        rhs,
        rd_metadata,
        rd_metadata,
    );
}

fn measureTyped(
    authority: *const typed_authority.Authority,
    iterations: usize,
) !u64 {
    var cpu = initializedCpu(0x1000);
    cpu.writeReg(5, 1);
    cpu.writeReg(7, 2);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    const word = encodeBranch(.BNE, 5, 7, 8);
    const instruction = try decode.DecodedInst.decode(word);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| try subject.retireAtomic(
        authority,
        &cpu,
        &trace,
        &tracker,
        instruction,
        word,
        @intCast(index + 1),
    );
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(trace.rows.items.ptr);
    return elapsed;
}

fn measureOracle(iterations: usize) !u64 {
    var cpu = initializedCpu(0x1000);
    cpu.writeReg(5, 1);
    cpu.writeReg(7, 2);
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try trace.reserveAdditional(iterations);
    try tracker.reserveTransitions(noGapReservation(iterations * 2));
    const word = encodeBranch(.BNE, 5, 7, 8);
    const instruction = try decode.DecodedInst.decode(word);
    var timer = try std.time.Timer.start();
    for (0..iterations) |index| try oracleRetire(
        &cpu,
        &trace,
        &tracker,
        instruction,
        word,
        @intCast(index + 1),
    );
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(cpu);
    std.mem.doNotOptimizeAway(trace.rows.items.ptr);
    return elapsed;
}

fn authenticatedAuthority() !typed_authority.Authority {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

fn coldRetirementAllocationCase(allocator: std.mem.Allocator) !void {
    const authority = subject.PINNED_AUTHORITY;
    var cpu = initializedCpu(0x1000);
    cpu.writeReg(5, 1);
    cpu.writeReg(7, 2);
    var trace = Trace.init(allocator);
    defer trace.deinit();
    var tracker = StateChainTracker.init(allocator);
    defer tracker.deinit();
    const word = encodeBranch(.BNE, 5, 7, 8);
    try subject.retireAtomic(
        &authority,
        &cpu,
        &trace,
        &tracker,
        try decode.DecodedInst.decode(word),
        word,
        1,
    );
}

fn encodeBranch(opcode: Opcode, rs1: u5, rs2: u5, immediate: i32) u32 {
    std.debug.assert(opcode == .BEQ or opcode == .BNE);
    std.debug.assert(immediate >= -4096 and immediate <= 4094);
    const bits: u32 = @bitCast(immediate);
    std.debug.assert(bits & 1 == 0);
    const funct3: u3 = if (opcode == .BEQ) 0b000 else 0b001;
    return ((bits >> 12) & 1) << 31 |
        ((bits >> 5) & 0x3f) << 25 |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, funct3) << 12) |
        ((bits >> 1) & 0xf) << 8 |
        ((bits >> 11) & 1) << 7 |
        0b1100011;
}

fn initializedCpu(pc: u32) Cpu {
    var cpu = Cpu.init(pc, 0x7000_0000);
    for (1..32) |index| cpu.writeReg(
        @intCast(index),
        @as(u32, @intCast(index)) *% 0x0102_0305,
    );
    return cpu;
}

fn installSources(
    cpu: *Cpu,
    instruction: decode.DecodedInst,
    lhs: u32,
    rhs: u32,
) !void {
    if (instruction.rs1 == 0 and lhs != 0) return error.InvalidTestInput;
    if (instruction.rs2 == 0 and rhs != 0) return error.InvalidTestInput;
    if (instruction.rs1 == instruction.rs2 and lhs != rhs)
        return error.InvalidTestInput;
    cpu.writeReg(instruction.rs1, lhs);
    cpu.writeReg(instruction.rs2, rhs);
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
