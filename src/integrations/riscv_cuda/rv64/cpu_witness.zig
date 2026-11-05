//! Borrowed narrow ingress from the native execution capture, before MAIN is
//! materialized. The caller uploads each span once, keeps it alive until the
//! copy joins, and binds program/statement/root identities through its scoped
//! resident session. The formatter is not an ISA or boundary verifier.
const std = @import("std");
const Source = @import("stwo_riscv_cpu_integration").rv64_cpu_source.Source;
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
pub const Input = struct {
    program_identity: [32]u8,
    log: u32,
    count: u32,
    rom_log: u32,
    final_pc: u32,
    metadata: []const u32,
    rom: []const u32,

    pub fn fromCapture(source: *const Source) !Input {
        if (!source.compact or !source.program.compact or source.main.len != 0 or
            source.main_projection_closed or source.program.fixed_retired or
            source.log_size < X.layout.MIN_LOG or source.log_size > X.layout.MAX_LOG or
            source.metadata.len != source.public.steps or source.public.steps >= source.size())
            return error.CpuDeviceIngressUnavailable;
        if (source.program.fixed.len != X.layout.rom.FIXED * source.program.size() or
            source.public.final_pc & 3 != 0 or !X.features.compactPcAdmitted(source.public.final_pc))
            return error.InvalidCpuDeviceIngress;
        return .{
            .program_identity = source.program.identity,
            .log = source.log_size,
            .count = @intCast(source.metadata.len),
            .rom_log = source.program.log_size,
            .final_pc = @intCast(source.public.final_pc),
            .metadata = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source.metadata)),
            .rom = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source.program.fixed)),
        };
    }
};

test "compact CPU ingress compiles against the native capture owner" {
    std.testing.refAllDecls(Input);
}
