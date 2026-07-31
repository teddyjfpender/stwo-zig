//! Real CPU/SIMD proof gates for independently constrained SM83 families.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const sm83_prover = frontend.prover;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const ProvingError = @import("stwo_prover_engine").prove.ProvingError;
const CpuProverEngine = sm83_prover.ProverEngineForBackend(CpuBackend);

const mixed_program = [_]u8{ 0x80, 0x27 } ** 8;
const small_family_program = [_]u8{ 0x03, 0x07 } ** 8;
const load8_program = [_]u8{ 0x41, 0x46 } ** 8;
const alu16_program = [_]u8{ 0x09, 0xe8, 0x01, 0x09, 0xf8, 0xff } ** 4;
const cb_rotate_shift_program =
    ([_]u8{ 0xcb, 0x00, 0xcb, 0x06 } ** 7) ++
    [_]u8{ 0xcb, 0x00, 0xcb, 0x00 };
const cb_bit_program = [_]u8{ 0xcb, 0x40, 0xcb, 0x46 } ** 8;
const cb_res_set_program =
    ([_]u8{ 0xcb, 0x80, 0xcb, 0x86, 0xcb, 0xc0, 0xcb, 0xc6 } ** 3) ++
    [_]u8{ 0xcb, 0x80, 0xcb, 0x86, 0xcb, 0xc0, 0xcb, 0x86 };
const load16_program =
    [_]u8{ 0x21, 0xef, 0xbe, 0xf9, 0x08, 0x00, 0x90, 0x01, 0x34, 0x12 } ** 4;
const misc_halt_program =
    ([_]u8{ 0x00, 0x2f, 0x37, 0x3f } ** 3) ++
    [_]u8{ 0x00, 0x2f, 0x37, 0x76 };
const misc_stop_program =
    ([_]u8{ 0x00, 0x2f, 0x37, 0x3f } ** 3) ++
    [_]u8{ 0x00, 0x2f, 0x37, 0x10, 0x00 };
const interrupt_program = ([_]u8{ 0xf3, 0xfb } ** 7) ++ [_]u8{ 0xf3, 0xd9 };
const stack_program = [_]u8{ 0xc5, 0xc1 } ** 8;
const branch_program = blk: {
    var bytes = [_]u8{0x80} ** 43;
    @memcpy(bytes[0..4], &[_]u8{ 0x20, 0x02, 0x28, 0x02 });
    @memcpy(
        bytes[6..13],
        &[_]u8{ 0xcd, 0x10, 0x00, 0x38, 0x02, 0x30, 0x07 },
    );
    bytes[16] = 0xc9;
    @memcpy(
        bytes[20..27],
        &[_]u8{ 0xcd, 0x10, 0x00, 0x20, 0x02, 0x28, 0x03 },
    );
    @memcpy(
        bytes[30..37],
        &[_]u8{ 0xcd, 0x10, 0x00, 0x38, 0x02, 0x30, 0x03 },
    );
    @memcpy(bytes[40..43], &[_]u8{ 0xcd, 0x10, 0x00 });
    break :blk bytes;
};

const ProgramBytes = struct {
    rom: [frontend.rom.SIZE]u8,
    memory: [frontend.memory.SIZE]u8,
};

fn testConfig() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
}

fn programBytes(program: []const u8) ProgramBytes {
    std.debug.assert(program.len <= frontend.rom.SIZE);
    var result = ProgramBytes{
        .rom = [_]u8{0x80} ** frontend.rom.SIZE,
        .memory = [_]u8{0} ** frontend.memory.SIZE,
    };
    @memcpy(result.rom[0..program.len], program);
    @memcpy(result.memory[0..frontend.rom.SIZE], &result.rom);
    return result;
}

fn programSteps(
    program: []const u8,
    initial: frontend.Cpu,
    data: ?u8,
) ![16]frontend.StepTrace {
    var memory = try frontend.Memory.init(std.testing.allocator);
    defer memory.deinit();
    for (program, 0..) |value, address| memory.write(@intCast(address), value);
    if (data) |value| memory.write(0x8000, value);
    var state = initial;
    var steps: [16]frontend.StepTrace = undefined;
    for (&steps) |*step_value| step_value.* = try frontend.step(&state, &memory);
    return steps;
}

fn proveAndVerify(
    config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    steps: []const frontend.StepTrace,
) !void {
    const output = try sm83_prover.proveExecutionWithEngine(
        CpuProverEngine,
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        steps,
    );
    try sm83_prover.verifyExecutionWithEngine(
        CpuProverEngine,
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
}

fn expectRejected(
    config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    steps: []const frontend.StepTrace,
) !void {
    if (sm83_prover.proveExecutionWithEngine(
        CpuProverEngine,
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        steps,
    )) |unexpected| {
        var proof = unexpected.proof;
        defer proof.deinit(std.testing.allocator);
        return error.ExpectedMutationRejection;
    } else |err| {
        try std.testing.expectEqual(ProvingError.ConstraintsNotSatisfied, err);
    }
}

fn expectMiscPrefix(steps: []const frontend.StepTrace) !void {
    try std.testing.expectEqual(@as(usize, 15), steps.len);
    for (steps) |step_value| {
        const fetch = step_value.activeCycles()[0];
        try std.testing.expectEqual(step_value.before.pc, fetch.address);
        try std.testing.expectEqual(@as(u8, @truncate(step_value.decoded.raw_opcode)), fetch.value);
        try std.testing.expectEqual(frontend.runner.BusAction.read, fetch.action);
        try std.testing.expectEqual(step_value.before.pc +% 1, step_value.after.pc);
        switch (step_value.decoded.raw_opcode) {
            0x00 => {
                try std.testing.expectEqual(step_value.before.a, step_value.after.a);
                try std.testing.expectEqual(step_value.before.f, step_value.after.f);
            },
            0x2f => {
                try std.testing.expectEqual(~step_value.before.a, step_value.after.a);
                try std.testing.expectEqual(step_value.before.flag(.zero), step_value.after.flag(.zero));
                try std.testing.expectEqual(step_value.before.flag(.carry), step_value.after.flag(.carry));
                try std.testing.expect(step_value.after.flag(.subtract));
                try std.testing.expect(step_value.after.flag(.half_carry));
            },
            0x37, 0x3f => {
                try std.testing.expectEqual(step_value.before.a, step_value.after.a);
                try std.testing.expectEqual(step_value.before.flag(.zero), step_value.after.flag(.zero));
                try std.testing.expect(!step_value.after.flag(.subtract));
                try std.testing.expect(!step_value.after.flag(.half_carry));
                try std.testing.expectEqual(
                    step_value.decoded.raw_opcode == 0x37 or
                        !step_value.before.flag(.carry),
                    step_value.after.flag(.carry),
                );
            },
            else => return error.UnexpectedMiscOpcode,
        }
    }
}

test "SM83 CPU proof composes ALU8 and DAA rows" {
    const config = try testConfig();
    const steps = try programSteps(
        &mixed_program,
        .{ .a = 0x9a, .b = 1 },
        null,
    );
    var bytes = programBytes(&mixed_program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try proveAndVerify(config, rom, memory, memory, &steps);
}

test "SM83 CPU proof composes INC16 and accumulator-rotate rows" {
    const config = try testConfig();
    const steps = try programSteps(
        &small_family_program,
        .{ .a = 0x81, .b = 0x12, .c = 0xfe, .f = 0x10 },
        null,
    );
    var bytes = programBytes(&small_family_program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try proveAndVerify(config, rom, memory, memory, &steps);

    var mutated_steps = steps;
    mutated_steps[0].after.setFlag(.half_carry, true);
    mutated_steps[1].before = mutated_steps[0].after;
    try expectRejected(config, rom, memory, memory, &mutated_steps);
}

test "SM83 CPU proof binds LOAD8 register and indirect-read rows" {
    const config = try testConfig();
    const steps = try programSteps(
        &load8_program,
        .{ .b = 0x12, .c = 0x33, .h = 0x80 },
        0x5a,
    );
    var bytes = programBytes(&load8_program);
    bytes.memory[0x8000] = 0x5a;
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);

    for (steps, 0..) |step_value, clock| {
        const bound = try frontend.air.load8.evaluateBound(
            frontend.air.load8.columns(
                try frontend.air.load8.ValidatedStep.init(step_value),
            ),
            frontend.air.execution.columns(step_value, @intCast(clock)),
        );
        try std.testing.expect(bound.allZero());
    }
    try proveAndVerify(config, rom, memory, memory, &steps);

    var mutated_steps = steps;
    mutated_steps[0].after.b +%= 1;
    mutated_steps[1].before = mutated_steps[0].after;
    try expectRejected(config, rom, memory, memory, &mutated_steps);
}

test "SM83 CPU proof composes ADD HL and signed-offset ALU16 rows" {
    const config = try testConfig();
    const steps = try programSteps(
        &alu16_program,
        .{
            .b = 0x01,
            .c = 0x01,
            .f = 0x80,
            .h = 0x0f,
            .l = 0xff,
            .sp = 0x80fc,
        },
        null,
    );
    var bytes = programBytes(&alu16_program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try proveAndVerify(config, rom, memory, memory, &steps);

    var mutated_steps = steps;
    mutated_steps[0].after.setFlag(
        .half_carry,
        !mutated_steps[0].after.flag(.half_carry),
    );
    mutated_steps[1].before = mutated_steps[0].after;
    try expectRejected(config, rom, memory, memory, &mutated_steps);
}

test "SM83 CPU proof binds CB rotate-shift register and indirect rows" {
    const config = try testConfig();
    const steps = try programSteps(
        &cb_rotate_shift_program,
        .{ .b = 0x81, .h = 0x80 },
        0x81,
    );
    var bytes = programBytes(&cb_rotate_shift_program);
    bytes.memory[0x8000] = 0x81;
    var final_bytes = bytes.memory;
    final_bytes[0x8000] = 0xc0;
    const rom = try frontend.Rom.init(&bytes.rom);
    const initial_memory = try frontend.MemoryImage.init(&bytes.memory);
    const final_memory = try frontend.MemoryImage.init(&final_bytes);
    try proveAndVerify(config, rom, initial_memory, final_memory, &steps);

    var mutated_steps = steps;
    mutated_steps[0].after.setFlag(.carry, false);
    mutated_steps[1].before = mutated_steps[0].after;
    try expectRejected(
        config,
        rom,
        initial_memory,
        final_memory,
        &mutated_steps,
    );
}

test "SM83 CPU proof binds CB BIT register and read-only indirect rows" {
    const config = try testConfig();
    const steps = try programSteps(
        &cb_bit_program,
        .{ .b = 0x01, .f = 0x10, .h = 0x80 },
        0x80,
    );
    var bytes = programBytes(&cb_bit_program);
    bytes.memory[0x8000] = 0x80;
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);

    for (steps, 0..) |step_value, row| {
        try std.testing.expectEqual(
            step_value.before.flag(.carry),
            step_value.after.flag(.carry),
        );
        try std.testing.expect(step_value.after.flag(.carry));
        try std.testing.expect(step_value.after.flag(.half_carry));
        try std.testing.expect(!step_value.after.flag(.subtract));
        try std.testing.expectEqual(
            row % 2 == 1,
            step_value.after.flag(.zero),
        );
        try std.testing.expectEqual(step_value.before.b, step_value.after.b);
        for (step_value.activeCycles()) |cycle|
            try std.testing.expect(cycle.action != .write);
    }
    try proveAndVerify(config, rom, memory, memory, &steps);

    var mutated_steps = steps;
    mutated_steps[0].after.setFlag(.zero, true);
    mutated_steps[1].before = mutated_steps[0].after;
    try expectRejected(config, rom, memory, memory, &mutated_steps);
}

test "SM83 CPU proof binds CB RES SET register and indirect writes" {
    const config = try testConfig();
    const steps = try programSteps(
        &cb_res_set_program,
        .{ .b = 0x81, .f = 0xb0, .h = 0x80 },
        0x81,
    );
    var bytes = programBytes(&cb_res_set_program);
    bytes.memory[0x8000] = 0x81;
    var final_bytes = bytes.memory;
    final_bytes[0x8000] = 0x80;
    const rom = try frontend.Rom.init(&bytes.rom);
    const initial_memory = try frontend.MemoryImage.init(&bytes.memory);
    const final_memory = try frontend.MemoryImage.init(&final_bytes);

    for (steps, 0..) |step_value, row| {
        try std.testing.expectEqual(step_value.before.f, step_value.after.f);
        const cycles = step_value.activeCycles();
        if (row % 2 == 1) {
            try std.testing.expectEqual(
                frontend.runner.BusAction.write,
                cycles[cycles.len - 1].action,
            );
            try std.testing.expectEqual(
                @as(u16, 0x8000),
                cycles[cycles.len - 1].address,
            );
        } else {
            for (cycles) |cycle|
                try std.testing.expect(cycle.action != .write);
        }
    }
    try proveAndVerify(config, rom, initial_memory, final_memory, &steps);

    var mutated_steps = steps;
    mutated_steps[0].after.b = 0x81;
    mutated_steps[1].before = mutated_steps[0].after;
    mutated_steps[1].after.b = 0x81;
    mutated_steps[2].before = mutated_steps[1].after;
    try expectRejected(
        config,
        rom,
        initial_memory,
        final_memory,
        &mutated_steps,
    );
}

test "SM83 CPU proof binds LOAD16 little-endian state and memory writes" {
    const config = try testConfig();
    const steps = try programSteps(
        &load16_program,
        .{ .f = 0xb0, .sp = 0x1111 },
        null,
    );
    var bytes = programBytes(&load16_program);
    var final_bytes = bytes.memory;
    final_bytes[0x9000] = 0xef;
    final_bytes[0x9001] = 0xbe;
    const rom = try frontend.Rom.init(&bytes.rom);
    const initial_memory = try frontend.MemoryImage.init(&bytes.memory);
    const final_memory = try frontend.MemoryImage.init(&final_bytes);

    for (steps, 0..) |step_value, row| {
        try std.testing.expectEqual(step_value.before.f, step_value.after.f);
        const cycles = step_value.activeCycles();
        switch (row % 4) {
            0 => {
                try std.testing.expectEqual(@as(u16, 0xbeef), step_value.after.hl());
                try std.testing.expectEqual(@as(u8, 0xef), cycles[1].value);
                try std.testing.expectEqual(@as(u8, 0xbe), cycles[2].value);
            },
            1 => {
                try std.testing.expectEqual(@as(u16, 0xbeef), step_value.after.sp);
                try std.testing.expectEqual(
                    frontend.runner.BusAction.idle,
                    cycles[1].action,
                );
            },
            2 => {
                try std.testing.expectEqual(
                    frontend.runner.BusCycle{
                        .address = 0x9000,
                        .value = 0xef,
                        .action = .write,
                    },
                    cycles[3],
                );
                try std.testing.expectEqual(
                    frontend.runner.BusCycle{
                        .address = 0x9001,
                        .value = 0xbe,
                        .action = .write,
                    },
                    cycles[4],
                );
            },
            3 => {
                try std.testing.expectEqual(@as(u16, 0x1234), step_value.after.bc());
                try std.testing.expectEqual(@as(u8, 0x34), cycles[1].value);
                try std.testing.expectEqual(@as(u8, 0x12), cycles[2].value);
            },
            else => unreachable,
        }
    }
    try proveAndVerify(config, rom, initial_memory, final_memory, &steps);

    var mutated_steps = steps;
    mutated_steps[2].cycles[3].value = 0xee;
    try expectRejected(
        config,
        rom,
        initial_memory,
        final_memory,
        &mutated_steps,
    );
}

test "SM83 CPU proof chains MISC flags into terminal HALT" {
    const config = try testConfig();
    const steps = try programSteps(
        &misc_halt_program,
        .{ .a = 0x96, .f = 0x80 },
        null,
    );
    try expectMiscPrefix(steps[0..15]);
    const terminal = steps[15];
    try std.testing.expectEqual(@as(u16, 0x76), terminal.decoded.raw_opcode);
    try std.testing.expectEqual(@as(u3, 1), terminal.cycle_count);
    try std.testing.expectEqual(terminal.before.pc +% 1, terminal.after.pc);
    try std.testing.expectEqual(terminal.before.a, terminal.after.a);
    try std.testing.expectEqual(terminal.before.f, terminal.after.f);
    try std.testing.expect(terminal.after.halted);
    try std.testing.expect(!terminal.after.stopped);

    var bytes = programBytes(&misc_halt_program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try proveAndVerify(config, rom, memory, memory, &steps);

    var mutated_steps = steps;
    mutated_steps[1].after.setFlag(.half_carry, false);
    mutated_steps[2].before = mutated_steps[1].after;
    try expectRejected(config, rom, memory, memory, &mutated_steps);
}

test "SM83 CPU proof binds terminal STOP second fetch" {
    const config = try testConfig();
    const steps = try programSteps(
        &misc_stop_program,
        .{ .a = 0x96, .f = 0x80 },
        null,
    );
    try expectMiscPrefix(steps[0..15]);
    const terminal = steps[15];
    const cycles = terminal.activeCycles();
    try std.testing.expectEqual(@as(u16, 0x10), terminal.decoded.raw_opcode);
    try std.testing.expectEqual(@as(u3, 2), terminal.cycle_count);
    try std.testing.expectEqual(terminal.before.pc +% 2, terminal.after.pc);
    try std.testing.expectEqual(
        frontend.runner.BusCycle{
            .address = terminal.before.pc +% 1,
            .value = 0,
            .action = .read,
        },
        cycles[1],
    );
    try std.testing.expectEqual(terminal.before.a, terminal.after.a);
    try std.testing.expectEqual(terminal.before.f, terminal.after.f);
    try std.testing.expect(!terminal.after.halted);
    try std.testing.expect(terminal.after.stopped);

    var bytes = programBytes(&misc_stop_program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try proveAndVerify(config, rom, memory, memory, &steps);
}

test "SM83 CPU proof binds conditional branches and CALL RET stack" {
    const config = try testConfig();
    const steps = try programSteps(
        &branch_program,
        .{ .f = 0x80, .sp = 0x9002 },
        null,
    );
    const pcs = [_]u16{
        0,  2,  6,  16, 9,  11, 20, 16, 23,
        25, 30, 16, 33, 35, 40, 16, 43,
    };
    const taken = [_]bool{
        false, true, true, true, false, true, true, true,
        false, true, true, true, false, true, true, true,
    };

    for (steps, 0..) |step_value, row| {
        const cycles = step_value.activeCycles();
        try std.testing.expectEqual(pcs[row], step_value.before.pc);
        try std.testing.expectEqual(pcs[row + 1], step_value.after.pc);
        try std.testing.expectEqual(taken[row], step_value.branch_taken);
        try std.testing.expectEqual(step_value.before.f, step_value.after.f);
        try std.testing.expectEqual(step_value.before.pc, cycles[0].address);
        try std.testing.expectEqual(
            branch_program[step_value.before.pc],
            cycles[0].value,
        );
        try std.testing.expectEqual(frontend.runner.BusAction.read, cycles[0].action);

        switch (step_value.decoded.raw_opcode) {
            0xcd => {
                const return_pc: u8 = @truncate(pcs[row] + 3);
                try std.testing.expectEqual(@as(u16, 0x9002), step_value.before.sp);
                try std.testing.expectEqual(@as(u16, 0x9000), step_value.after.sp);
                try std.testing.expectEqual(
                    frontend.runner.BusCycle{
                        .address = 0x9001,
                        .value = 0,
                        .action = .write,
                    },
                    cycles[4],
                );
                try std.testing.expectEqual(
                    frontend.runner.BusCycle{
                        .address = 0x9000,
                        .value = return_pc,
                        .action = .write,
                    },
                    cycles[5],
                );
            },
            0xc9 => {
                try std.testing.expectEqual(@as(u16, 0x9000), step_value.before.sp);
                try std.testing.expectEqual(@as(u16, 0x9002), step_value.after.sp);
                try std.testing.expectEqual(
                    frontend.runner.BusCycle{
                        .address = 0x9000,
                        .value = @truncate(pcs[row + 1]),
                        .action = .read,
                    },
                    cycles[1],
                );
                try std.testing.expectEqual(@as(u16, 0x9001), cycles[2].address);
                try std.testing.expectEqual(@as(u8, 0), cycles[2].value);
            },
            else => {
                try std.testing.expectEqual(step_value.before.sp, step_value.after.sp);
                try std.testing.expectEqual(
                    @as(u3, if (taken[row]) 3 else 2),
                    step_value.cycle_count,
                );
                if (taken[row])
                    try std.testing.expectEqual(
                        frontend.runner.BusAction.idle,
                        cycles[2].action,
                    );
            },
        }
    }

    var bytes = programBytes(&branch_program);
    var final_bytes = bytes.memory;
    final_bytes[0x9000] = 43;
    const rom = try frontend.Rom.init(&bytes.rom);
    const initial_memory = try frontend.MemoryImage.init(&bytes.memory);
    const final_memory = try frontend.MemoryImage.init(&final_bytes);
    try proveAndVerify(config, rom, initial_memory, final_memory, &steps);

    var mutated_steps = steps;
    mutated_steps[2].cycles[3].value = 1;
    try expectRejected(
        config,
        rom,
        initial_memory,
        final_memory,
        &mutated_steps,
    );
}

test "SM83 CPU proof binds STACK PUSH POP memory" {
    const config = try testConfig();
    const steps = try programSteps(
        &stack_program,
        .{ .b = 0x12, .c = 0x34, .f = 0xb0, .sp = 0x9002 },
        null,
    );
    var bytes = programBytes(&stack_program);
    var final_bytes = bytes.memory;
    final_bytes[0x9000] = 0x34;
    final_bytes[0x9001] = 0x12;
    const rom = try frontend.Rom.init(&bytes.rom);
    const initial_memory = try frontend.MemoryImage.init(&bytes.memory);
    const final_memory = try frontend.MemoryImage.init(&final_bytes);
    try std.testing.expectEqual(@as(u8, 0), initial_memory.bytes[0x9000]);
    try std.testing.expectEqual(@as(u8, 0), initial_memory.bytes[0x9001]);
    try std.testing.expectEqual(@as(u8, 0x34), final_memory.bytes[0x9000]);
    try std.testing.expectEqual(@as(u8, 0x12), final_memory.bytes[0x9001]);

    var mcycle: u32 = 0;
    for (steps, 0..) |step_value, row| {
        const bound = try frontend.air.stack.evaluateBound(
            frontend.air.stack.columns(
                try frontend.air.stack.ValidatedStep.init(step_value),
            ),
            frontend.air.execution.columns(step_value, mcycle),
        );
        try std.testing.expect(bound.allZero());
        mcycle += step_value.cycle_count;

        const cycles = step_value.activeCycles();
        try std.testing.expectEqual(step_value.before.f, step_value.after.f);
        try std.testing.expectEqual(step_value.before.pc +% 1, step_value.after.pc);
        if (row & 1 == 0) {
            try std.testing.expectEqual(@as(u16, 0x9002), step_value.before.sp);
            try std.testing.expectEqual(@as(u16, 0x9000), step_value.after.sp);
            try std.testing.expectEqual(
                frontend.runner.BusCycle{
                    .address = 0x9001,
                    .value = 0x12,
                    .action = .write,
                },
                cycles[2],
            );
            try std.testing.expectEqual(
                frontend.runner.BusCycle{
                    .address = 0x9000,
                    .value = 0x34,
                    .action = .write,
                },
                cycles[3],
            );
        } else {
            try std.testing.expectEqual(@as(u16, 0x9000), step_value.before.sp);
            try std.testing.expectEqual(@as(u16, 0x9002), step_value.after.sp);
            try std.testing.expectEqual(
                frontend.runner.BusCycle{
                    .address = 0x9000,
                    .value = 0x34,
                    .action = .read,
                },
                cycles[1],
            );
            try std.testing.expectEqual(
                frontend.runner.BusCycle{
                    .address = 0x9001,
                    .value = 0x12,
                    .action = .read,
                },
                cycles[2],
            );
            try std.testing.expectEqual(@as(u16, 0x1234), step_value.after.bc());
        }
    }
    try proveAndVerify(config, rom, initial_memory, final_memory, &steps);

    var semantic_mutation = steps;
    semantic_mutation[0].after.sp +%= 1;
    semantic_mutation[1].before = semantic_mutation[0].after;
    try expectRejected(
        config,
        rom,
        initial_memory,
        final_memory,
        &semantic_mutation,
    );

    var domain_mutation = steps;
    std.mem.swap(
        frontend.runner.BusCycle,
        &domain_mutation[0].cycles[2],
        &domain_mutation[0].cycles[3],
    );
    try expectRejected(
        config,
        rom,
        initial_memory,
        final_memory,
        &domain_mutation,
    );

    try std.testing.expectError(
        ProvingError.ConstraintsNotSatisfied,
        sm83_prover.testing.proveInactiveExecutionWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            rom,
            initial_memory,
            final_memory,
            &steps,
        ),
    );
}

test "SM83 CPU proof binds INTERRUPT DI EI RETI state and stack reads" {
    const config = try testConfig();
    var bytes = programBytes(&interrupt_program);
    bytes.memory[0x9000] = 0x34;
    bytes.memory[0x9001] = 0x12;
    var machine = try frontend.Memory.init(std.testing.allocator);
    defer machine.deinit();
    for (interrupt_program, 0..) |value, address|
        machine.write(@intCast(address), value);
    machine.write(0x9000, 0x34);
    machine.write(0x9001, 0x12);
    var state = frontend.Cpu{
        .a = 0xa5,
        .f = 0xb0,
        .sp = 0x9000,
        .ime = true,
        .ime_enable_pending = true,
    };
    var steps: [16]frontend.StepTrace = undefined;
    for (&steps) |*step_value| step_value.* = try frontend.step(&state, &machine);

    for (steps, 0..) |step_value, row| {
        if (row != 0)
            try std.testing.expectEqual(steps[row - 1].after, step_value.before);
        try std.testing.expectEqual(@as(u16, @intCast(row)), step_value.before.pc);
        try std.testing.expectEqual(step_value.before.a, step_value.after.a);
        try std.testing.expect((try frontend.air.interrupt.evaluateBound(
            frontend.air.interrupt.columns(
                try frontend.air.interrupt.ValidatedStep.init(step_value),
            ),
            frontend.air.execution.columns(step_value, @intCast(row)),
        )).allZero());
        const cycles = step_value.activeCycles();
        try std.testing.expectEqual(step_value.before.pc, cycles[0].address);
        switch (step_value.decoded.raw_opcode) {
            0xf3 => {
                try std.testing.expect(!step_value.after.ime);
                try std.testing.expect(!step_value.after.ime_enable_pending);
            },
            0xfb => {
                try std.testing.expectEqual(step_value.before.ime, step_value.after.ime);
                try std.testing.expect(step_value.after.ime_enable_pending);
            },
            0xd9 => {
                try std.testing.expect(step_value.after.ime);
                try std.testing.expect(!step_value.after.ime_enable_pending);
                try std.testing.expectEqual(@as(u16, 0x9002), step_value.after.sp);
                try std.testing.expectEqual(@as(u16, 0x1234), step_value.after.pc);
                try std.testing.expectEqual(frontend.runner.BusCycle{
                    .address = 0x9000,
                    .value = 0x34,
                    .action = .read,
                }, cycles[1]);
                try std.testing.expectEqual(frontend.runner.BusCycle{
                    .address = 0x9001,
                    .value = 0x12,
                    .action = .read,
                }, cycles[2]);
                try std.testing.expectEqual(frontend.runner.BusAction.idle, cycles[3].action);
            },
            else => unreachable,
        }
    }
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try proveAndVerify(config, rom, memory, memory, &steps);

    var semantic_mutation = steps;
    semantic_mutation[1].after.ime_enable_pending = false;
    semantic_mutation[2].before = semantic_mutation[1].after;
    try expectRejected(config, rom, memory, memory, &semantic_mutation);
    var domain_mutation = steps;
    std.mem.swap(
        frontend.runner.BusCycle,
        &domain_mutation[15].cycles[1],
        &domain_mutation[15].cycles[2],
    );
    try expectRejected(config, rom, memory, memory, &domain_mutation);
    try std.testing.expectError(
        ProvingError.ConstraintsNotSatisfied,
        sm83_prover.testing.proveInactiveExecutionWithEngine(
            CpuProverEngine,
            std.testing.allocator,
            config,
            rom,
            memory,
            memory,
            &steps,
        ),
    );
}

test "SM83 CPU prover rejects a committed DAA result mutation" {
    const config = try testConfig();
    var steps = try programSteps(
        &mixed_program,
        .{ .a = 0x9a, .b = 1 },
        null,
    );
    steps[15].after.a +%= 1;
    var bytes = programBytes(&mixed_program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try expectRejected(config, rom, memory, memory, &steps);
}

test "SM83 ALU8 CPU prover rejects a committed half-carry mutation" {
    const config = try testConfig();
    const program = [_]u8{0x80} ** 16;
    var steps = try programSteps(&program, .{ .a = 1, .b = 1 }, null);
    steps[0].after.setFlag(
        .half_carry,
        !steps[0].after.flag(.half_carry),
    );
    steps[1].before = steps[0].after;
    var bytes = programBytes(&program);
    const rom = try frontend.Rom.init(&bytes.rom);
    const memory = try frontend.MemoryImage.init(&bytes.memory);
    try expectRejected(config, rom, memory, memory, &steps);
}
