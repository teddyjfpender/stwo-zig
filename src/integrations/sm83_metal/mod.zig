//! Metal adapter for the backend-generic SM83 proving path.
const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const sm83_prover = frontend.prover;
const environment_adapter = @import("environment.zig");
const machine_environment = @import("machine_environment.zig");
const metal = @import("stwo_metal_backend");
const test_support = @import("test_support.zig");
const testConfig = test_support.config;
const testSteps = test_support.steps;
const test_rom_bytes = test_support.rom_bytes;
pub const MetalProverEngine = metal.MetalProverEngine;
pub const EnvironmentProverEngine = environment_adapter.ProverEngine;
pub const MachineEnvironmentProverEngine = machine_environment.ProverEngine;
pub const ExecutionStatement = sm83_prover.ExecutionStatement;
pub const EnvironmentExecutionStatement =
    environment_adapter.ExecutionStatement;
pub const ProveOutput = sm83_prover.ProveOutput;
pub const EnvironmentProveOutput = environment_adapter.ProveOutput;
pub const MachineEnvironmentExecutionStatement =
    machine_environment.ExecutionStatement;
pub const MachineEnvironmentProveOutput = machine_environment.ProveOutput;
pub const proveEnvironmentExecution =
    environment_adapter.proveExecution;
pub const verifyEnvironmentExecution =
    environment_adapter.verifyExecution;
pub const proveMachineEnvironmentExecution = machine_environment.proveExecution;
pub const verifyMachineEnvironmentExecution =
    machine_environment.verifyExecution;
pub const proveMachineExecution = @import("machine_proof.zig").proveExecution;
comptime {
    sm83_prover.assertProverEngine(MetalProverEngine);
}

test "api signature: SM83 Metal engine satisfies the shared prover contract" {
    comptime sm83_prover.assertProverEngine(MetalProverEngine);
}

pub fn proveExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    steps: []const frontend.StepTrace,
) !ProveOutput {
    return sm83_prover.proveExecutionWithEngine(
        MetalProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_memory,
        final_memory,
        steps,
    );
}

pub fn verifyExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    statement: ExecutionStatement,
    proof: sm83_prover.Proof,
) !void {
    return sm83_prover.verifyExecutionWithEngine(
        MetalProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_memory,
        final_memory,
        statement,
        proof,
    );
}

test "SM83 ALU8 and DAA Metal proof roundtrip verifies" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (0..16) |address| {
        bytes[address] = if (address % 2 == 0) 0x80 else 0x27;
    }
    const rom = try frontend.Rom.init(&bytes);
    var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        memory,
        .{ .a = 0x9a, .b = 1 },
    );
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        output.statement,
        output.proof,
    );
}

test "SM83 ADD A,(HL) memory reads prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    @memset(bytes[0..16], 0x86);
    const rom = try frontend.Rom.init(&bytes);
    var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
    memory_bytes[0x8000] = 2;
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        memory,
        .{ .a = 1, .h = 0x80 },
    );
    try std.testing.expectEqual(@as(u8, 0x21), steps[15].after.a);

    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        output.statement,
        output.proof,
    );
}

test "SM83 INC (HL) memory writes prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    @memset(bytes[0..16], 0x34);
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    initial_memory_bytes[0x8000] = 2;
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{ .h = 0x80 },
    );
    try std.testing.expectEqual(.write, steps[15].cycles[2].action);
    try std.testing.expectEqual(@as(u8, 0x12), steps[15].cycles[2].value);

    var final_memory_bytes = initial_memory_bytes;
    final_memory_bytes[0x8000] = 0x12;
    const final_memory = try frontend.MemoryImage.init(&final_memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
}

test "SM83 INC16 and accumulator rotates prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (bytes[0..16], 0..) |*opcode, index| {
        opcode.* = if (index % 2 == 0) 0x03 else 0x07;
    }
    const rom = try frontend.Rom.init(&bytes);
    var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        memory,
        .{ .a = 0x81, .b = 0xff, .c = 0xf7 },
    );
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        output.statement,
        output.proof,
    );
}

test "SM83 LOAD8 mixed register and (HL) reads prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (bytes[0..16], 0..) |*opcode, index|
        opcode.* = if (index % 2 == 0) 0x47 else 0x7e;
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    initial_memory_bytes[0x8000] = 0x5a;
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{ .a = 0x11, .h = 0x80 },
    );
    try std.testing.expectEqual(@as(u8, 0x11), steps[0].after.b);
    try std.testing.expectEqual(.read, steps[1].cycles[1].action);
    try std.testing.expectEqual(@as(u16, 0x8000), steps[1].cycles[1].address);
    try std.testing.expectEqual(@as(u8, 0x5a), steps[1].cycles[1].value);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        initial_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        initial_memory,
        output.statement,
        output.proof,
    );
}

test "SM83 ALU16 mixed arithmetic proves and verifies on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    var address: usize = 0;
    for (0..16) |index| {
        switch (index % 3) {
            0 => {
                bytes[address] = 0x09;
                address += 1;
            },
            1 => {
                bytes[address] = 0xe8;
                bytes[address + 1] = 0xff;
                address += 2;
            },
            2 => {
                bytes[address] = 0xf8;
                bytes[address + 1] = 2;
                address += 2;
            },
            else => unreachable,
        }
    }
    const rom = try frontend.Rom.init(&bytes);
    var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        memory,
        .{
            .b = 0,
            .c = 1,
            .f = 0x80,
            .h = 0xff,
            .l = 0xff,
            .sp = 2,
        },
    );
    try std.testing.expectEqual(@as(u16, 1), steps[1].after.sp);
    try std.testing.expectEqual(@as(u16, 3), steps[2].after.hl());
    try std.testing.expectEqual(@as(u16, 0), steps[15].after.hl());
    try std.testing.expectEqual(@as(u16, 0xfffd), steps[15].after.sp);
    try std.testing.expectEqual(@as(u8, 0x30), steps[15].after.f);

    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        output.statement,
        output.proof,
    );
}

test "SM83 CB rotate and (HL) shift prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (0..16) |index| {
        const address = 2 * index;
        bytes[address] = 0xcb;
        bytes[address + 1] = if (index % 2 == 0) 0x00 else 0x26;
    }
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    initial_memory_bytes[0x8000] = 0x81;
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{ .b = 0x81, .h = 0x80 },
    );
    try std.testing.expectEqual(@as(u8, 0x03), steps[0].after.b);
    try std.testing.expectEqual(.read, steps[1].cycles[2].action);
    try std.testing.expectEqual(.write, steps[1].cycles[3].action);
    try std.testing.expectEqual(@as(u16, 0x8000), steps[1].cycles[3].address);
    try std.testing.expectEqual(@as(u8, 0x02), steps[1].cycles[3].value);
    try std.testing.expectEqual(@as(u8, 0), steps[15].cycles[3].value);
    try std.testing.expectEqual(@as(u8, 0x90), steps[15].after.f);

    var final_memory_bytes = initial_memory_bytes;
    final_memory_bytes[0x8000] = 0;
    const final_memory = try frontend.MemoryImage.init(&final_memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
}

test "SM83 CB BIT register and (HL) reads prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (0..16) |index| {
        const address = 2 * index;
        bytes[address] = 0xcb;
        bytes[address + 1] = if (index % 2 == 0) 0x40 else 0x6e;
    }
    const rom = try frontend.Rom.init(&bytes);
    var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
    memory_bytes[0x8000] = 1;
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        memory,
        .{ .b = 1, .f = 0x10, .h = 0x80 },
    );
    try std.testing.expectEqual(@as(u8, 0x30), steps[0].after.f);
    try std.testing.expectEqual(@as(u8, 0xb0), steps[1].after.f);
    try std.testing.expectEqual(.read, steps[1].cycles[2].action);
    try std.testing.expectEqual(@as(u16, 0x8000), steps[1].cycles[2].address);
    try std.testing.expectEqual(@as(u8, 1), steps[1].cycles[2].value);
    try std.testing.expectEqual(@as(u8, 1), steps[15].cycles[2].value);

    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        memory,
        memory,
        output.statement,
        output.proof,
    );
}

test "SM83 CB RES SET register and (HL) writes prove and verify on Metal" {
    const config = try testConfig();
    const suffixes = [_]u8{ 0x80, 0xce, 0xf9, 0xbe };
    var bytes = test_rom_bytes;
    for (0..16) |index| {
        const address = 2 * index;
        bytes[address] = 0xcb;
        bytes[address + 1] = suffixes[index % suffixes.len];
    }
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    initial_memory_bytes[0x8000] = 0x81;
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{ .b = 0x81, .c = 1, .f = 0xf0, .h = 0x80 },
    );
    try std.testing.expectEqual(@as(u8, 0x80), steps[0].after.b);
    try std.testing.expectEqual(.read, steps[1].cycles[2].action);
    try std.testing.expectEqual(@as(u8, 0x81), steps[1].cycles[2].value);
    try std.testing.expectEqual(.write, steps[1].cycles[3].action);
    try std.testing.expectEqual(@as(u16, 0x8000), steps[1].cycles[3].address);
    try std.testing.expectEqual(@as(u8, 0x83), steps[1].cycles[3].value);
    try std.testing.expectEqual(@as(u8, 0x81), steps[2].after.c);
    try std.testing.expectEqual(@as(u8, 0x03), steps[3].cycles[3].value);
    try std.testing.expectEqual(@as(u8, 0xf0), steps[15].after.f);

    var final_memory_bytes = initial_memory_bytes;
    final_memory_bytes[0x8000] = 0x03;
    const final_memory = try frontend.MemoryImage.init(&final_memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
}

test "SM83 LOAD16 state and little-endian writes prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    var address: usize = 0;
    for (0..4) |group| {
        const low: u8 = @intCast(group + 1);
        const program = [_]u8{
            0x21, low,  0x12,
            0xf9, 0x01, low,
            0x56, 0x08, 0x00,
            0x80,
        };
        @memcpy(bytes[address..][0..program.len], &program);
        address += program.len;
    }
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{ .f = 0xf0 },
    );
    try std.testing.expectEqual(@as(u16, 0x1201), steps[0].after.hl());
    try std.testing.expectEqual(@as(u16, 0x1201), steps[1].after.sp);
    try std.testing.expectEqual(@as(u16, 0x5601), steps[2].after.bc());
    try std.testing.expectEqual(.write, steps[15].cycles[3].action);
    try std.testing.expectEqual(@as(u16, 0x8000), steps[15].cycles[3].address);
    try std.testing.expectEqual(@as(u8, 0x04), steps[15].cycles[3].value);
    try std.testing.expectEqual(.write, steps[15].cycles[4].action);
    try std.testing.expectEqual(@as(u16, 0x8001), steps[15].cycles[4].address);
    try std.testing.expectEqual(@as(u8, 0x12), steps[15].cycles[4].value);
    try std.testing.expectEqual(@as(u8, 0xf0), steps[15].after.f);

    var final_memory_bytes = initial_memory_bytes;
    final_memory_bytes[0x8000] = 0x04;
    final_memory_bytes[0x8001] = 0x12;
    const final_memory = try frontend.MemoryImage.init(&final_memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
}

test "SM83 MISC flag chain HALT and STOP prove and verify on Metal" {
    const config = try testConfig();
    for ([_]struct {
        terminal: u8,
        immediate: u8,
        final_pc: u16,
        halted: bool,
        stopped: bool,
    }{
        .{
            .terminal = 0x76,
            .immediate = 0,
            .final_pc = 16,
            .halted = true,
            .stopped = false,
        },
        .{
            .terminal = 0x10,
            .immediate = 0xa5,
            .final_pc = 17,
            .halted = false,
            .stopped = true,
        },
    }) |case| {
        var bytes = test_rom_bytes;
        const chain = [_]u8{ 0x00, 0x2f, 0x37, 0x3f };
        for (bytes[0..15], 0..) |*opcode, index|
            opcode.* = chain[index % chain.len];
        bytes[15] = case.terminal;
        bytes[16] = case.immediate;
        const rom = try frontend.Rom.init(&bytes);
        var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
        @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
        const memory = try frontend.MemoryImage.init(&memory_bytes);
        const steps = try testSteps(
            std.testing.allocator,
            memory,
            .{ .a = 0x96, .f = 0x80 },
        );
        try std.testing.expectEqual(@as(u8, 0x69), steps[1].after.a);
        try std.testing.expectEqual(@as(u8, 0xe0), steps[1].after.f);
        try std.testing.expectEqual(@as(u8, 0x90), steps[2].after.f);
        try std.testing.expectEqual(@as(u8, 0x80), steps[3].after.f);
        try std.testing.expectEqual(@as(u8, 0x96), steps[15].after.a);
        try std.testing.expectEqual(@as(u8, 0x90), steps[15].after.f);
        try std.testing.expectEqual(case.final_pc, steps[15].after.pc);
        try std.testing.expectEqual(case.halted, steps[15].after.halted);
        try std.testing.expectEqual(case.stopped, steps[15].after.stopped);
        if (case.stopped) {
            try std.testing.expectEqual(.read, steps[15].cycles[1].action);
            try std.testing.expectEqual(
                @as(u16, 16),
                steps[15].cycles[1].address,
            );
            try std.testing.expectEqual(
                case.immediate,
                steps[15].cycles[1].value,
            );
        }

        const output = try proveExecution(
            std.testing.allocator,
            config,
            rom,
            memory,
            memory,
            &steps,
        );
        try verifyExecution(
            std.testing.allocator,
            config,
            rom,
            memory,
            memory,
            output.statement,
            output.proof,
        );
    }
}

test "SM83 BRANCH conditions and CALL RET prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    const program = [_]u8{
        0x28, 0x00,
        0x20, 0x00,
        0xcd, 0x10,
        0x00, 0xc3,
        0x00, 0x00,
    };
    @memcpy(bytes[0..program.len], &program);
    bytes[0x10] = 0xc9;
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{ .f = 0x80, .sp = 0x9002 },
    );
    try std.testing.expect(steps[0].branch_taken);
    try std.testing.expectEqual(@as(u16, 2), steps[0].after.pc);
    try std.testing.expect(!steps[1].branch_taken);
    try std.testing.expectEqual(@as(u16, 4), steps[1].after.pc);
    try std.testing.expect(steps[2].branch_taken);
    try std.testing.expectEqual(@as(u16, 0x10), steps[2].after.pc);
    try std.testing.expectEqual(@as(u16, 0x9000), steps[2].after.sp);
    try std.testing.expectEqual(.write, steps[2].cycles[4].action);
    try std.testing.expectEqual(@as(u16, 0x9001), steps[2].cycles[4].address);
    try std.testing.expectEqual(@as(u8, 0), steps[2].cycles[4].value);
    try std.testing.expectEqual(.write, steps[2].cycles[5].action);
    try std.testing.expectEqual(@as(u16, 0x9000), steps[2].cycles[5].address);
    try std.testing.expectEqual(@as(u8, 7), steps[2].cycles[5].value);
    try std.testing.expect(steps[3].branch_taken);
    try std.testing.expectEqual(.read, steps[3].cycles[1].action);
    try std.testing.expectEqual(@as(u16, 0x9000), steps[3].cycles[1].address);
    try std.testing.expectEqual(@as(u8, 7), steps[3].cycles[1].value);
    try std.testing.expectEqual(.read, steps[3].cycles[2].action);
    try std.testing.expectEqual(@as(u16, 0x9001), steps[3].cycles[2].address);
    try std.testing.expectEqual(@as(u8, 0), steps[3].cycles[2].value);
    try std.testing.expectEqual(@as(u16, 7), steps[3].after.pc);
    try std.testing.expectEqual(@as(u16, 0x9002), steps[3].after.sp);
    try std.testing.expectEqual(@as(u16, 2), steps[15].after.pc);
    try std.testing.expectEqual(@as(u16, 0x9002), steps[15].after.sp);

    var final_memory_bytes = initial_memory_bytes;
    final_memory_bytes[0x9000] = 7;
    const final_memory = try frontend.MemoryImage.init(&final_memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
}

test "SM83 STACK PUSH POP and vacuity prove and verify on Metal" {
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (bytes[0..16], 0..) |*opcode, index|
        opcode.* = if (index % 2 == 0) 0xc5 else 0xd1;
    const rom = try frontend.Rom.init(&bytes);
    var initial_memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(initial_memory_bytes[0..frontend.rom.SIZE], &bytes);
    const initial_memory = try frontend.MemoryImage.init(&initial_memory_bytes);
    const steps = try testSteps(
        std.testing.allocator,
        initial_memory,
        .{
            .b = 0x12,
            .c = 0x34,
            .f = 0xa0,
            .sp = 0x9002,
        },
    );
    try std.testing.expectEqual(@as(u16, 0x9000), steps[0].after.sp);
    try std.testing.expectEqual(.write, steps[0].cycles[2].action);
    try std.testing.expectEqual(@as(u16, 0x9001), steps[0].cycles[2].address);
    try std.testing.expectEqual(@as(u8, 0x12), steps[0].cycles[2].value);
    try std.testing.expectEqual(.write, steps[0].cycles[3].action);
    try std.testing.expectEqual(@as(u16, 0x9000), steps[0].cycles[3].address);
    try std.testing.expectEqual(@as(u8, 0x34), steps[0].cycles[3].value);
    try std.testing.expectEqual(.read, steps[1].cycles[1].action);
    try std.testing.expectEqual(@as(u8, 0x34), steps[1].cycles[1].value);
    try std.testing.expectEqual(.read, steps[1].cycles[2].action);
    try std.testing.expectEqual(@as(u8, 0x12), steps[1].cycles[2].value);
    try std.testing.expectEqual(@as(u16, 0x1234), steps[1].after.de());
    try std.testing.expectEqual(@as(u16, 0x9002), steps[15].after.sp);
    try std.testing.expectEqual(@as(u16, 0x1234), steps[15].after.de());
    try std.testing.expectEqual(@as(u8, 0xa0), steps[15].after.f);

    var clock: u32 = 0;
    for (steps) |step_value| {
        const witness = frontend.air.stack.columns(
            try frontend.air.stack.ValidatedStep.init(step_value),
        );
        try std.testing.expect(
            (try frontend.air.stack.evaluate(witness)).allZero(),
        );
        try std.testing.expect((try frontend.air.stack.evaluateBound(
            witness,
            frontend.air.execution.columns(step_value, clock),
        )).allZero());
        clock += step_value.cycle_count;
    }

    var final_memory_bytes = initial_memory_bytes;
    final_memory_bytes[0x9000] = 0x34;
    final_memory_bytes[0x9001] = 0x12;
    const final_memory = try frontend.MemoryImage.init(&final_memory_bytes);
    const output = try proveExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        &steps,
    );
    try verifyExecution(
        std.testing.allocator,
        config,
        rom,
        initial_memory,
        final_memory,
        output.statement,
        output.proof,
    );
    try std.testing.expectError(
        error.ConstraintsNotSatisfied,
        sm83_prover.testing.proveInactiveExecutionWithEngine(
            MetalProverEngine,
            std.testing.allocator,
            config,
            rom,
            initial_memory,
            final_memory,
            &steps,
        ),
    );
}

test "SM83 INTERRUPT DI EI RETI and soundness prove and verify on Metal" {
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var bytes = test_rom_bytes;
    for (bytes[0..15], 0..) |*opcode, index|
        opcode.* = if (index & 1 == 0) 0xfb else 0xf3;
    bytes[15] = 0xd9;
    const rom = try frontend.Rom.init(&bytes);
    var memory_bytes = [_]u8{0} ** frontend.memory.SIZE;
    @memcpy(memory_bytes[0..frontend.rom.SIZE], &bytes);
    memory_bytes[0x9000] = 0x34;
    memory_bytes[0x9001] = 0x12;
    const memory = try frontend.MemoryImage.init(&memory_bytes);
    const steps = try testSteps(allocator, memory, .{ .sp = 0x9000, .ime = true });
    try std.testing.expect(
        steps[0].after.ime and !steps[0].after.ime_enable_pending,
    );
    try std.testing.expect(
        !steps[1].after.ime and !steps[1].after.ime_enable_pending,
    );
    try std.testing.expect(
        steps[15].after.ime and !steps[15].after.ime_enable_pending,
    );
    try std.testing.expectEqual(@as(u16, 0x1234), steps[15].after.pc);
    try std.testing.expectEqual(@as(u16, 0x9002), steps[15].after.sp);
    for (steps[0..15], steps[1..16]) |before, after|
        try std.testing.expectEqualDeep(before.after, after.before);
    const reti = steps[15];
    try std.testing.expect(
        reti.cycles[1].action == .read and
            reti.cycles[1].address == 0x9000 and
            reti.cycles[1].value == 0x34 and
            reti.cycles[2].action == .read and
            reti.cycles[2].address == 0x9001 and
            reti.cycles[2].value == 0x12,
    );

    var clock: u32 = 0;
    for (steps) |step_value| {
        const witness = frontend.air.interrupt.columns(
            try frontend.air.interrupt.ValidatedStep.init(step_value),
        );
        try std.testing.expect((try frontend.air.interrupt.evaluate(witness)).allZero());
        try std.testing.expect((try frontend.air.interrupt.evaluateBound(
            witness,
            frontend.air.execution.columns(step_value, clock),
        )).allZero());
        clock += step_value.cycle_count;
    }
    const output = try proveExecution(allocator, config, rom, memory, memory, &steps);
    try verifyExecution(allocator, config, rom, memory, memory, output.statement, output.proof);

    var pending_mutation = steps;
    pending_mutation[0].after.ime_enable_pending = true;
    pending_mutation[1].before.ime_enable_pending = true;
    try std.testing.expectError(
        error.ConstraintsNotSatisfied,
        proveExecution(
            allocator,
            config,
            rom,
            memory,
            memory,
            &pending_mutation,
        ),
    );
    try std.testing.expectError(
        error.ConstraintsNotSatisfied,
        sm83_prover.testing.proveInactiveExecutionWithEngine(
            MetalProverEngine,
            allocator,
            config,
            rom,
            memory,
            memory,
            &steps,
        ),
    );
}

test "SM83 Metal integration selects only the Metal backend" {
    try std.testing.expect(
        MetalProverEngine.Backend == metal.MetalCommitBackend and
            EnvironmentProverEngine.Backend == metal.MetalCommitBackend and
            MachineEnvironmentProverEngine.Backend ==
                metal.MetalCommitBackend,
    );
}
test {
    _ = @import("cartridge_test.zig");
    _ = @import("pokemon_checkpoint_proof.zig");
    std.testing.refAllDecls(@This());
}
