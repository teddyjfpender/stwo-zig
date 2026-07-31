const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");

pub const rom_bytes = [_]u8{0x80} ** frontend.rom.SIZE;

pub fn config() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(
            0,
            1,
            3,
        ),
    };
}

pub fn steps(
    allocator: std.mem.Allocator,
    initial_memory: frontend.MemoryImage,
    initial_state: frontend.Cpu,
) ![16]frontend.StepTrace {
    var memory = try frontend.Memory.init(allocator);
    defer memory.deinit();
    @memcpy(memory.bytes, initial_memory.bytes);
    var state = initial_state;
    var result: [16]frontend.StepTrace = undefined;
    for (&result) |*step_value|
        step_value.* = try frontend.step(&state, &memory);
    return result;
}
