//! Trusted-boundary admission for the new genesis-prefix driver. This does not
//! accept a proof or turn a later packet's checkpoint into initial authority.
const std = @import("std");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const Image = @import("expected_image.zig");
const Packet = @import("packet.zig").Packet;
pub fn boundary(packet: *const Packet) X.types.Boundary {
    const original = packet.public.statement;
    return .{ .steps = original.steps, .initial_pc = original.initial_pc, .final_pc = original.final_pc, .initial_registers = original.initial_registers, .final_registers = original.final_registers, .register_clocks = original.register_clocks };
}
pub fn requireGenesis(image: *const Image.Owner, packet: *const Packet) !void {
    if (packet.metadata.index != 0 or packet.metadata.first_step != 0 or packet.tape.initial_clock != 0 or packet.tape.initial_pc != image.initial_pc or packet.public.statement.initial_pc != image.initial_pc or !std.mem.eql(u64, &packet.public.statement.initial_registers, &image.initial_registers)) return error.UntrustedExecutionGenesis;
}
