//! Receiver-derived immutable ROM for the explicit Keccak service ABI.
//! This admits decode rows, not an unclosed CPU/crypto proof capability.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const base = @import("setup.zig");
const profile = @import("../../execution_profile.zig");
const L = @import("../layout.zig");
const ops = @import("../operations.zig");
pub const DOMAIN = base.SERVICE_DOMAIN;
pub fn init(a: std.mem.Allocator, program: base.Program) !base.Setup {
    return base.Setup.initWithProfile(a, program, .keccak_service_v1);
}

pub fn deriveRow(pc: u64, raw: u32) base.Row {
    var row = base.deriveRow(pc, raw);
    if (raw != 0x00000073) return row;
    row[base.field.valid] = M.one();
    row[base.field.opcode] = q(@intFromEnum(@import("../../decode.zig").Opcode.ECALL));
    row[base.field.rs1] = q(profile.POINTER_REGISTER);
    row[base.field.rs2] = q(profile.TAG_REGISTER);
    const slots = [4]bool{ true, true, false, false };
    for (slots, 0..) |enabled, i| row[base.field.slots + i] = q(@intFromBool(enabled));
    put(&row, base.field.increment, pc +% 4);
    put(&row, base.field.target, pc);
    for (0..L.WORDS) |i| row[base.field.words + i] = q(@intFromBool(ops.wordActive(@enumFromInt(i), .ECALL, slots)));
    return row;
}
fn q(x: u32) M {
    return M.fromCanonical(x);
}
fn put(row: *base.Row, start: usize, value: u64) void {
    for (0..8) |i| row[start + i] = q(@intCast((value >> @as(u6, @intCast(8 * i))) & 255));
}
